// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gows

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	fuzzInputLimit          = 64 << 10
	fuzzHeaderLimit         = 8192
	fuzzActionLimit         = 32
	fuzzReadLimit           = 64
	fuzzChunkLimit          = 4096
	fuzzValidUpgradeRequest = "GET /chat?room=1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
)

var errFuzzStreamReadLimit = errors.New("fuzz stream read limit exceeded")

// fuzzNetConn is a bounded synchronous transport. It deliberately models only
// net.Conn behavior; all protocol parsing remains in the production entrypoints.
type fuzzNetConn struct {
	in       []byte
	pos      int
	chunk    int
	out      bytes.Buffer
	closed   bool
	closeCnt int
	onWrite  func([]byte) []byte
}

func (c *fuzzNetConn) Read(p []byte) (int, error) {
	if c.closed || c.pos >= len(c.in) {
		return 0, io.EOF
	}
	n := min(len(p), len(c.in)-c.pos, fuzzChunkLimit)
	if c.chunk > 0 {
		n = min(n, c.chunk)
	}
	copy(p, c.in[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}

func (c *fuzzNetConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	_, _ = c.out.Write(p)
	if c.onWrite != nil {
		c.in = c.onWrite(p)
		c.pos = 0
		c.onWrite = nil
	}
	return len(p), nil
}

func (c *fuzzNetConn) Close() error {
	c.closeCnt++
	c.closed = true
	return nil
}

func (*fuzzNetConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (*fuzzNetConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (*fuzzNetConn) SetDeadline(time.Time) error      { return nil }
func (*fuzzNetConn) SetReadDeadline(time.Time) error  { return nil }
func (*fuzzNetConn) SetWriteDeadline(time.Time) error { return nil }

func boundedFuzzChunk(v uint16) int { return min(int(v)+1, fuzzChunkLimit) }

func FuzzUpgradeProtocolState(f *testing.F) {
	valid := []byte(fuzzValidUpgradeRequest)
	duplicate := []byte(strings.Replace(fuzzValidUpgradeRequest,
		"Upgrade: websocket\r\nConnection: Upgrade\r\n",
		"Upgrade: h2c\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nConnection: Upgrade\r\n", 1))
	missingHost := []byte(strings.Replace(fuzzValidUpgradeRequest, "Host: example.com\r\n", "", 1))
	missingKey := []byte(strings.Replace(fuzzValidUpgradeRequest, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "", 1))
	badFolding := []byte(strings.Replace(fuzzValidUpgradeRequest, "Host: example.com\r\n", "Host: example.com\r\n folded\r\n", 1))
	pipelined := append(append([]byte(nil), valid...), clientFrame(true, OpcodeBinary, []byte("next"))...)
	exact := paddedUpgradeRequest(fuzzHeaderLimit)
	over := paddedUpgradeRequest(fuzzHeaderLimit + 1)

	for _, seed := range [][]byte{valid, duplicate, missingHost, missingKey, badFolding, pipelined, exact, over, valid[:len(valid)-2]} {
		f.Add(seed, uint16(6))
	}

	f.Fuzz(func(t *testing.T, input []byte, chunk uint16) {
		if len(input) > fuzzInputLimit {
			return
		}
		conn := &fuzzNetConn{in: input, chunk: boundedFuzzChunk(chunk)}
		hs, err := (&Upgrader{MaxHeaderBytes: fuzzHeaderLimit, RawPath: true}).Upgrade(conn)

		switch {
		case bytes.Equal(input, valid), bytes.Equal(input, duplicate), bytes.Equal(input, pipelined), bytes.Equal(input, exact):
			if err != nil {
				t.Fatalf("semantic valid seed rejected: %v", err)
			}
		case bytes.Equal(input, missingHost), bytes.Equal(input, missingKey), bytes.Equal(input, badFolding), bytes.Equal(input, over), bytes.Equal(input, valid[:len(valid)-2]):
			if err == nil {
				t.Fatal("semantic invalid seed unexpectedly upgraded")
			}
		}

		if err != nil {
			if hs.RawPath() != nil || hs.RawQuery() != nil || len(hs.Buffered) != 0 {
				t.Fatal("failed Upgrade retained handshake-owned storage")
			}
		} else {
			if hs.RawPath() == nil {
				t.Fatal("successful RawPath Upgrade returned no raw path")
			}
			hs.Release()
			if hs.RawPath() != nil || hs.RawQuery() != nil {
				t.Fatal("Handshake.Release did not clear raw path/query")
			}
		}
		if conn.closeCnt != 0 {
			t.Fatalf("Upgrade changed transport ownership: close count = %d", conn.closeCnt)
		}
	})
}

func paddedUpgradeRequest(size int) []byte {
	const prefix = "GET /limit HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Pad: "
	const suffix = "\r\n\r\n"
	if size < len(prefix)+len(suffix) {
		return nil
	}
	return []byte(prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix)
}

func FuzzDialProtocolState(f *testing.F) {
	for mode := byte(0); mode < 12; mode++ {
		f.Add(mode, []byte{0x81, 0x00}, uint16(7))
	}

	f.Fuzz(func(t *testing.T, mode byte, pipelined []byte, chunk uint16) {
		if len(pipelined) > fuzzInputLimit {
			return
		}
		mode %= 12
		windowBits := 0
		if mode == 9 {
			windowBits = 15
		}
		fake := &fuzzNetConn{chunk: boundedFuzzChunk(chunk)}
		fake.onWrite = func(request []byte) []byte {
			key := requestHeaderValue(request, "Sec-WebSocket-Key")
			accept := websocketAccept(key)
			status := "HTTP/1.1 101 Switching Protocols\r\n"
			upgrade := "Upgrade: websocket\r\n"
			connection := "Connection: Upgrade\r\n"
			acceptLine := "Sec-WebSocket-Accept: " + accept + "\r\n"
			extra := ""
			switch mode {
			case 1:
				status = "HTTP/1.1 200 OK\r\n"
			case 2:
				acceptLine = ""
			case 3:
				acceptLine = "Sec-WebSocket-Accept: tampered\r\n"
			case 4:
				upgrade = ""
			case 5:
				connection = ""
			case 6:
				extra = "Sec-WebSocket-Protocol: unrequested\r\n"
			case 7:
				extra = "Sec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Extensions: permessage-deflate\r\n"
			case 8:
				status = "HTTP/1.1 101 Switching Protocols\n"
			case 9:
				extra = "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=15\r\n"
			case 10:
				extra = "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
			case 11:
				extra = "Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=15; server_max_window_bits=15\r\n"
			}
			response := []byte(status + upgrade + connection + acceptLine + extra + "\r\n")
			if mode == 0 {
				response = append(response, pipelined...)
			}
			return response
		}

		dialCalls := 0
		d := &Dialer{
			Subprotocols:             []string{"chat"},
			EnableCompression:        mode == 7 || mode >= 9,
			WindowBits:               windowBits,
			OfferClientMaxWindowBits: mode == 10,
			NetDial: func(context.Context, string, string) (net.Conn, error) {
				dialCalls++
				return fake, nil
			},
		}
		conn, hs, err := d.Dial(context.Background(), "ws://example.invalid/fuzz")
		if dialCalls != 1 {
			t.Fatalf("NetDial calls = %d, want 1", dialCalls)
		}
		if mode == 0 || mode == 7 || mode == 9 {
			if err != nil {
				t.Fatalf("valid response rejected: %v", err)
			}
			if conn != fake {
				t.Fatal("Dial success did not return the provided transport")
			}
			if fake.closed || fake.closeCnt != 0 {
				t.Fatal("Dial success closed caller-owned transport")
			}
			if mode == 0 {
				got := append([]byte(nil), hs.Buffered...)
				fake.chunk = fuzzChunkLimit
				buf := make([]byte, fuzzChunkLimit)
				for range fuzzReadLimit {
					n, readErr := fake.Read(buf)
					got = append(got, buf[:n]...)
					if errors.Is(readErr, io.EOF) {
						break
					}
					if readErr != nil {
						t.Fatalf("read pipelined transport bytes: %v", readErr)
					}
				}
				if !bytes.Equal(got, pipelined) {
					t.Fatalf("reconstructed pipelined bytes = %x, want %x", got, pipelined)
				}
			}
			if (mode == 7 || mode == 9) && !hs.Compressed {
				t.Fatal("duplicate valid extension response did not negotiate compression")
			}
			hs.Release()
			_ = conn.Close()
			if fake.closeCnt != 1 {
				t.Fatalf("harness close count = %d, want 1", fake.closeCnt)
			}
			return
		}
		if err == nil || conn != nil {
			t.Fatalf("invalid response mode %d returned conn=%v err=%v", mode, conn, err)
		}
		if !fake.closed || fake.closeCnt != 1 {
			t.Fatalf("Dial failure close state = closed:%v count:%d, want true/1", fake.closed, fake.closeCnt)
		}

		preNetworkCalls := 0
		_, _, preErr := (&Dialer{
			WindowBits: 7,
			NetDial: func(context.Context, string, string) (net.Conn, error) {
				preNetworkCalls++
				return nil, errors.New("unexpected network call")
			},
		}).Dial(context.Background(), "ws://example.invalid/")
		if !errors.Is(preErr, ErrInvalidWindowBits) || preNetworkCalls != 0 {
			t.Fatalf("pre-network validation = err:%v calls:%d", preErr, preNetworkCalls)
		}
	})
}

func requestHeaderValue(request []byte, name string) string {
	prefix := strings.ToLower(name) + ":"
	for _, line := range strings.Split(string(request), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func FuzzConnReadState(f *testing.F) {
	compressed, err := compressPayload(nil, []byte("compressed seed"))
	if err != nil {
		f.Fatal(err)
	}
	seeds := [][]byte{
		clientFrame(true, OpcodeBinary, []byte("one")),
		fragmentFrames(OpcodeText, []byte("split "), []byte("utf8 "), []byte("message")),
		append(append(clientFrame(false, OpcodeText, []byte("a")), clientFrame(true, OpcodePing, []byte("p"))...), clientFrame(true, OpcodeContinuation, []byte("b"))...),
		closeFrame(CloseNormalClosure, "bye"),
		clientFrame(true, OpcodeText, []byte{0xff}),
		frameBytes(true, OpcodeBinary, RSV2, true, testKey, []byte("bad-rsv")),
		clientFrame(true, OpcodeContinuation, []byte("orphan")),
		clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{'x'}, fuzzInputLimit)),
		clientFrame(true, OpcodeBinary, []byte("truncated"))[:5],
		frameBytes(true, OpcodeBinary, RSV1, true, testKey, compressed),
		serverFrame(true, OpcodeText, []byte("client-role")),
	}
	for i, seed := range seeds {
		if len(seed) <= fuzzInputLimit {
			actions := []byte{byte(i), 1, 2, 3, 4, 5}
			if i == len(seeds)-1 {
				actions[0] |= 0x80
			}
			f.Add(seed, actions, uint16(13), i == len(seeds)-2)
		}
	}

	f.Fuzz(func(t *testing.T, wire, actions []byte, chunk uint16, compression bool) {
		if len(wire) > fuzzInputLimit || len(actions) > fuzzInputLimit-len(wire) {
			return
		}
		clientRole := len(actions) > 0 && actions[0]&0x80 != 0
		parityChunk := fuzzChunkLimit
		readResult := readMessageFuzz(t, wire, parityChunk, compression, clientRole, false)
		streamResult := readMessageFuzz(t, wire, parityChunk, compression, clientRole, true)
		if !equalFuzzReadResults(readResult, streamResult) {
			t.Fatalf("ReadMessage/NextReader mismatch: direct=%+v stream=%+v", readResult, streamResult)
		}
		exerciseConnActions(t, wire, actions, boundedFuzzChunk(chunk), compression, clientRole)
	})
}

type fuzzReadResult struct {
	ok        bool
	op        Opcode
	payload   string
	closeCode CloseCode
	closed    bool
	errClass  string
	errID     string
}

func readMessageFuzz(t *testing.T, wire []byte, chunk int, compression, clientRole, stream bool) fuzzReadResult {
	t.Helper()
	conn := &fuzzNetConn{in: wire, chunk: chunk}
	opts := []ConnOption{WithReadLimit(fuzzInputLimit), WithCompression(compression)}
	var c *Conn
	if clientRole {
		c = NewClientConn(conn, opts...)
	} else {
		c = NewServerConn(conn, opts...)
	}
	var op Opcode
	var payload []byte
	var err error
	if stream {
		var r io.Reader
		op, r, err = c.NextReader()
		if err == nil {
			payload, err = readFuzzStream(r)
		}
	} else {
		op, payload, err = c.ReadMessage()
	}
	result := normalizeFuzzRead(op, payload, err)
	if errors.Is(err, errFuzzStreamReadLimit) {
		t.Fatal(err)
	}
	if err != nil && conn.closeCnt != 1 {
		t.Fatalf("terminal read close count = %d, want 1", conn.closeCnt)
	}
	if err != nil {
		_, _, sticky := c.ReadMessage()
		if sticky != err {
			t.Fatalf("terminal read error was not sticky: first=%v second=%v", err, sticky)
		}
	}
	if err == nil {
		_ = c.Close(CloseNormalClosure, "")
	}
	return result
}

func readFuzzStream(r io.Reader) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, fuzzChunkLimit)
	for reads := 0; reads < fuzzReadLimit; reads++ {
		n, err := r.Read(buf)
		_, _ = out.Write(buf[:n])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out.Bytes(), nil
			}
			return out.Bytes(), err
		}
	}
	return out.Bytes(), errFuzzStreamReadLimit
}

func normalizeFuzzRead(op Opcode, payload []byte, err error) fuzzReadResult {
	r := fuzzReadResult{ok: err == nil}
	if err == nil {
		r.op = op
		r.payload = string(payload)
		return r
	}
	if err == io.EOF {
		r.errClass = "EOF"
		r.errID = "io.EOF"
		return r
	}
	if err == io.ErrUnexpectedEOF {
		r.errClass = "unexpected EOF"
		r.errID = "io.ErrUnexpectedEOF"
		return r
	}
	var ce *CloseError
	if errors.As(err, &ce) {
		r.closeCode = ce.Code
	}
	r.closed = errors.Is(err, net.ErrClosed)
	r.errID = fmt.Sprintf("%T: %v", err, err)
	return r
}

// equalFuzzReadResults preserves exact error categories except for the one
// approved streaming parity pair: a bulk-read io.EOF and a stream-read
// io.ErrUnexpectedEOF both describe an incomplete transport. Bare io.EOF at
// a clean boundary remains comparable because both entrypoints retain EOF.
func equalFuzzReadResults(direct, stream fuzzReadResult) bool {
	if direct == stream {
		return true
	}
	if direct.errClass != "EOF" || stream.errClass != "unexpected EOF" {
		return false
	}
	direct.errClass, direct.errID = "incomplete transport", "incomplete transport"
	stream.errClass, stream.errID = "incomplete transport", "incomplete transport"
	return direct == stream
}

func TestEqualFuzzReadResults(t *testing.T) {
	tests := []struct {
		name   string
		direct fuzzReadResult
		stream fuzzReadResult
		want   bool
	}{
		{
			name:   "clean boundary EOFs match",
			direct: fuzzReadResult{errClass: "EOF", errID: "io.EOF"},
			stream: fuzzReadResult{errClass: "EOF", errID: "io.EOF"},
			want:   true,
		},
		{
			name:   "approved incomplete transport pair matches",
			direct: fuzzReadResult{errClass: "EOF", errID: "io.EOF"},
			stream: fuzzReadResult{errClass: "unexpected EOF", errID: "io.ErrUnexpectedEOF"},
			want:   true,
		},
		{
			name:   "reverse truncation pair stays distinct",
			direct: fuzzReadResult{errClass: "unexpected EOF", errID: "io.ErrUnexpectedEOF"},
			stream: fuzzReadResult{errClass: "EOF", errID: "io.EOF"},
			want:   false,
		},
		{
			name:   "close codes stay distinct",
			direct: fuzzReadResult{closeCode: CloseProtocolError, errID: "close"},
			stream: fuzzReadResult{closeCode: CloseInvalidFramePayloadData, errID: "close"},
			want:   false,
		},
		{
			name:   "closed sentinel stays distinct",
			direct: fuzzReadResult{closed: true, errID: "net.ErrClosed"},
			stream: fuzzReadResult{errID: "net.ErrClosed"},
			want:   false,
		},
		{
			name:   "other error types stay distinct",
			direct: fuzzReadResult{errID: "*errors.errorString: failure"},
			stream: fuzzReadResult{errID: "*gows.CloseError: failure"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := equalFuzzReadResults(tt.direct, tt.stream); got != tt.want {
				t.Fatalf("equalFuzzReadResults() = %v, want %v", got, tt.want)
			}
		})
	}
}

func exerciseConnActions(t *testing.T, wire, actions []byte, chunk int, compression, clientRole bool) {
	t.Helper()
	conn := &fuzzNetConn{in: wire, chunk: chunk}
	var c *Conn
	if clientRole {
		c = NewClientConn(conn, WithReadLimit(fuzzInputLimit), WithCompression(compression))
	} else {
		c = NewServerConn(conn, WithReadLimit(fuzzInputLimit), WithCompression(compression))
	}
	terminal := false
	streamReads := 0
	for _, action := range actions[:min(len(actions), fuzzActionLimit)] {
		var readSuccess bool
		var readSide bool
		var closesConn bool
		var err error
		switch action % 6 {
		case 0:
			readSide = true
			_, _, err = c.ReadMessage()
			readSuccess = err == nil
		case 1:
			readSide = true
			var r io.Reader
			_, r, err = c.NextReader()
			readSuccess = err == nil
			if err == nil {
				n, readErr := r.Read(nil)
				streamReads++
				if n != 0 {
					t.Fatalf("zero-byte stream read returned %d bytes", n)
				}
				if readErr != nil && !errors.Is(readErr, io.EOF) {
					err = readErr
				}
			}
		case 2:
			readSide = true
			var r io.Reader
			_, r, err = c.NextReader()
			readSuccess = err == nil
			if err == nil {
				buf := make([]byte, min(chunk, fuzzChunkLimit))
				_, readErr := r.Read(buf)
				streamReads++
				err = readErr
				if errors.Is(err, io.EOF) {
					err = nil
				}
			}
		case 3:
			readSide = true
			var r io.Reader
			_, r, err = c.NextReader()
			readSuccess = err == nil
			if err == nil {
				drained := false
				for streamReads < fuzzReadLimit {
					buf := make([]byte, fuzzChunkLimit)
					_, readErr := r.Read(buf)
					streamReads++
					if readErr != nil {
						if !errors.Is(readErr, io.EOF) {
							err = readErr
						}
						drained = true
						break
					}
				}
				if !drained {
					err = errFuzzStreamReadLimit
				}
			}
		case 4:
			readSide = true
			_, _, err = c.ReadMessage()
			readSuccess = err == nil
		case 5:
			closesConn = true
			err = c.Close(CloseNormalClosure, "")
		}
		if terminal && readSide && readSuccess {
			t.Fatal("terminal Conn path later returned successful read-side API result")
		}
		if err != nil || closesConn {
			terminal = true
		}
	}
	_ = c.Close(CloseNormalClosure, "")
	if conn.closeCnt != 1 {
		t.Fatalf("Conn transport close count = %d, want 1", conn.closeCnt)
	}
}
