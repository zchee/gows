package main

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	rand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// rawClient is an independent RFC 6455 client used to repeat decisive cells
// without either gows or gobwas framing helpers.
type rawClient struct {
	conn    net.Conn
	reader  *bufio.Reader
	opcode  byte
	maskRNG *rand.ChaCha8
	scratch []byte
}

func dialRawClient(ctx context.Context, rawURL string, kind messageKind, payloadLen int) (*rawClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("raw client: parse URL: %w", err)
	}
	if u.Scheme != "ws" {
		return nil, fmt.Errorf("raw client: scheme %q is unsupported; want ws", u.Scheme)
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("raw client: dial: %w", err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = conn.Close()
		}
	}()

	var keyBytes [16]byte
	if _, err := cryptorand.Read(keyBytes[:]); err != nil {
		return nil, fmt.Errorf("raw client: handshake key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+u.Host+path, nil)
	if err != nil {
		return nil, fmt.Errorf("raw client: request: %w", err)
	}
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("raw client: write handshake: %w", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("raw client: read handshake: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("raw client: handshake status %s", resp.Status)
	}
	acceptSum := sha1.Sum([]byte(key + websocketGUID))
	wantAccept := base64.StdEncoding.EncodeToString(acceptSum[:])
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerContainsToken(resp.Header.Values("Connection"), "upgrade") ||
		resp.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		return nil, fmt.Errorf("raw client: invalid upgrade response headers")
	}

	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("raw client: masking seed: %w", err)
	}
	opcode, err := rawOpcode(kind)
	if err != nil {
		return nil, err
	}
	succeeded = true
	return &rawClient{
		conn:    conn,
		reader:  reader,
		opcode:  opcode,
		maskRNG: rand.NewChaCha8(seed),
		scratch: make([]byte, payloadLen),
	}, nil
}

func headerContainsToken(values []string, token string) bool {
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func rawOpcode(kind messageKind) (byte, error) {
	switch kind {
	case messageBinary:
		return 0x2, nil
	case messageText:
		return 0x1, nil
	default:
		return 0, fmt.Errorf("raw client: unsupported message type %q", kind)
	}
}

func (c *rawClient) WriteMessage(payload []byte) error {
	return c.writeFrame(c.opcode, payload)
}

func (c *rawClient) writeFrame(opcode byte, payload []byte) error {
	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode)
	switch {
	case len(payload) <= 125:
		header = append(header, 0x80|byte(len(payload)))
	case len(payload) <= math.MaxUint16:
		header = append(header, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(len(payload)))
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(len(payload)))
	}
	var mask [4]byte
	_, _ = c.maskRNG.Read(mask[:])
	header = append(header, mask[:]...)
	if cap(c.scratch) < len(payload) {
		c.scratch = make([]byte, len(payload))
	}
	masked := c.scratch[:len(payload)]
	for i, value := range payload {
		masked[i] = value ^ mask[i&3]
	}
	if err := writeAll(c.conn, header); err != nil {
		return err
	}
	return writeAll(c.conn, masked)
}

func (c *rawClient) ReadMessage() ([]byte, error) {
	for {
		var head [2]byte
		if _, err := io.ReadFull(c.reader, head[:]); err != nil {
			return nil, err
		}
		fin := head[0]&0x80 != 0
		rsv := head[0] & 0x70
		opcode := head[0] & 0x0f
		masked := head[1]&0x80 != 0
		if !fin || rsv != 0 || masked {
			return nil, fmt.Errorf("raw client: unsupported server frame fin=%v rsv=%#x masked=%v", fin, rsv, masked)
		}
		length, err := c.readLength(head[1] & 0x7f)
		if err != nil {
			return nil, err
		}
		if length > uint64(math.MaxInt) {
			return nil, fmt.Errorf("raw client: server frame length %d overflows int", length)
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return nil, err
		}
		switch opcode {
		case c.opcode:
			return payload, nil
		case 0x8:
			return nil, io.EOF
		case 0x9:
			if err := c.writeFrame(0xA, payload); err != nil {
				return nil, err
			}
		case 0xA:
			continue
		default:
			return nil, fmt.Errorf("raw client: unexpected server opcode %#x", opcode)
		}
	}
}

func (c *rawClient) readLength(code byte) (uint64, error) {
	switch code {
	case 126:
		var raw [2]byte
		if _, err := io.ReadFull(c.reader, raw[:]); err != nil {
			return 0, err
		}
		length := uint64(binary.BigEndian.Uint16(raw[:]))
		if length < 126 {
			return 0, fmt.Errorf("raw client: non-canonical 16-bit length %d", length)
		}
		return length, nil
	case 127:
		var raw [8]byte
		if _, err := io.ReadFull(c.reader, raw[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint64(raw[:])
		if length < 65536 || length>>63 != 0 {
			return 0, fmt.Errorf("raw client: invalid 64-bit length %d", length)
		}
		return length, nil
	default:
		return uint64(code), nil
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func (c *rawClient) SetDeadline(deadline time.Time) error { return c.conn.SetDeadline(deadline) }

func (c *rawClient) Close() error { return c.conn.Close() }
