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
	"encoding/binary"
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
	for mode := range byte(12) {
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
		conn, hs, err := d.Dial(t.Context(), "ws://example.invalid/fuzz")
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
		}).Dial(t.Context(), "ws://example.invalid/")
		if !errors.Is(preErr, ErrInvalidWindowBits) || preNetworkCalls != 0 {
			t.Fatalf("pre-network validation = err:%v calls:%d", preErr, preNetworkCalls)
		}
	})
}

func requestHeaderValue(request []byte, name string) string {
	prefix := strings.ToLower(name) + ":"
	for line := range strings.SplitSeq(string(request), "\r\n") {
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
	for range fuzzReadLimit {
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
	if ce, ok := errors.AsType[*CloseError](err); ok {
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

// --- Frame-header table differential validation -----------------------------

// The tests in this file validate the table-driven frame-header decoder
// ([decodeFrameHeaderFast] and its [headerTables]) against the semantics of the
// [DecodeHeader]+checkFrameHeader pair it replaced. The oracle below
// reconstructs that pair: it drives the still-present [DecodeHeader] and then
// applies checkFrameHeader's role/RSV rules exactly as reader.go did at commit
// 2c13770, so any divergence in accept/reject decision, decoded Header, or
// close message is a regression the differential fuzz and unit tests catch.

// oracleKind classifies an oracle decode: needs more bytes, a valid header, or
// a rejected header.
type oracleKind uint8

const (
	oracleShort  oracleKind = iota // more bytes are needed; not a violation.
	oracleAccept                   // a valid header was decoded.
	oracleReject                   // the header violated an RFC 6455 rule.
)

// oracleDecodeHeader is the independent reference implementation of the frame
// header hot path for a Conn with the given role and negotiated compression
// state. It composes the retained [DecodeHeader] with a verbatim
// reconstruction of the former checkFrameHeader (reader.go @2c13770), and
// reports, for a rejected header, the exact close code and message reader.go
// failed the connection with at that commit. It is deliberately written from the
// original two-step formulation, not in terms of [decodeFrameHeaderFast], so
// that it is a genuine oracle rather than a restatement of the code under test.
func oracleDecodeHeader(client, compression bool, b []byte) (h Header, n int, kind oracleKind, code CloseCode, msg string) {
	dh, dn, err := DecodeHeader(b)
	if err != nil {
		if errors.Is(err, ErrShortHeader) {
			return Header{}, 0, oracleShort, 0, ""
		}
		// Every other DecodeHeader error was mapped by readHeaderWithPartialEOF
		// to a 1002 close with this exact prefix.
		return Header{}, 0, oracleReject, CloseProtocolError, "malformed frame header: " + err.Error()
	}

	// checkFrameHeader (reader.go @2c13770), reconstructed verbatim.
	rsv1OK := compression && dh.Rsv == RSV1 && !dh.Opcode.IsControl() && dh.Opcode != OpcodeContinuation
	if dh.Rsv != 0 && !rsv1OK {
		return Header{}, 0, oracleReject, CloseProtocolError, "invalid RSV bit for the negotiated extension set"
	}
	if client && dh.Masked {
		return Header{}, 0, oracleReject, CloseProtocolError, "masked frame received by client"
	}
	if !client && !dh.Masked {
		return Header{}, 0, oracleReject, CloseProtocolError, "unmasked frame received by server"
	}
	return dh, dn, oracleAccept, 0, ""
}

// fastDecodeHeader drives the code under test and normalizes its result into
// the same (kind, code, message) shape as [oracleDecodeHeader], mirroring how
// readHeaderWithPartialEOF consumes [decodeFrameHeaderFast]'s [hdrReject].
func fastDecodeHeader(client, compression bool, b []byte) (h Header, n int, kind oracleKind, code CloseCode, msg string) {
	tbl, maskBit := headerTableFor(client, compression)
	fh, fn, reason := decodeFrameHeaderFast(tbl, maskBit, b)
	switch reason {
	case rejectNone:
		return fh, fn, oracleAccept, 0, ""
	case rejectShort:
		return Header{}, 0, oracleShort, 0, ""
	default:
		// reader.go fails every non-short rejection with a 1002 protocol close.
		return Header{}, 0, oracleReject, CloseProtocolError, reason.closeMessage(client)
	}
}

// roleMatrix is the full {role x compression} matrix a single header-byte
// sequence must decode identically under: the b0 classification is
// role-independent, but the mask-bit expectation and RSV1 legality are not.
var roleMatrix = [...]struct {
	name        string
	client      bool
	compression bool
}{
	{"server/plain", false, false},
	{"server/deflate", false, true},
	{"client/plain", true, false},
	{"client/deflate", true, true},
}

// diffHeaderDecode asserts the fast decoder agrees with the oracle for b across
// the whole role/compression matrix, on the decision, the decoded Header, and
// the close code/message. It returns without failing for inputs both classify
// as needing more bytes.
func diffHeaderDecode(t *testing.T, b []byte) {
	t.Helper()
	for _, rc := range roleMatrix {
		wantH, wantN, wantKind, wantCode, wantMsg := oracleDecodeHeader(rc.client, rc.compression, b)
		gotH, gotN, gotKind, gotCode, gotMsg := fastDecodeHeader(rc.client, rc.compression, b)

		if gotKind != wantKind {
			t.Fatalf("%s: decision = %d, want %d\n input: % x", rc.name, gotKind, wantKind, b)
		}
		switch wantKind {
		case oracleAccept:
			if gotH != wantH || gotN != wantN {
				t.Fatalf("%s: accept mismatch\n got  header=%+v n=%d\n want header=%+v n=%d\n input: % x",
					rc.name, gotH, gotN, wantH, wantN, b)
			}
		case oracleReject:
			if gotCode != wantCode {
				t.Fatalf("%s: close code = %d, want %d\n input: % x", rc.name, gotCode, wantCode, b)
			}
			if gotMsg != wantMsg {
				t.Fatalf("%s: close message = %q, want %q\n input: % x", rc.name, gotMsg, wantMsg, b)
			}
		}
	}
}

// FuzzHeaderTableDifferential drives random header-byte sequences through the
// table-driven [decodeFrameHeaderFast] and the [DecodeHeader]+checkFrameHeader
// oracle for every {role x compression} combination, asserting they agree on
// the accept/reject decision, the decoded Header fields, and the 1002 close
// code and message text of each rejection.
func FuzzHeaderTableDifferential(f *testing.F) {
	// Seed: every possible first header byte, with a complete 2-byte
	// (unmasked, zero-length) header, exercising each opcode/Fin/RSV
	// classification and the reserved-opcode rejection.
	for b0 := range 256 {
		f.Add([]byte{byte(b0), 0x00})
	}

	// Seed: boundary payload lengths in each length encoding, minimal and
	// non-minimal, masked and unmasked, plus the reserved 64-bit MSB.
	lengthSeeds := [][]byte{
		{0x82, 0x7d},                                     // 7-bit max (125), unmasked.
		{0x82, 0x00},                                     // 7-bit zero, unmasked.
		{0x82, 0xfd, 0xde, 0xad, 0xbe, 0xef},             // 7-bit max (125), masked.
		{0x82, 0x7e, 0x00, 0x7e},                         // 16-bit minimal boundary (126).
		{0x82, 0x7e, 0xff, 0xff},                         // 16-bit max (65535).
		{0x82, 0x7e, 0x00, 0x64},                         // 16-bit non-minimal (100).
		{0x82, 0x7e, 0x00, 0x7d},                         // 16-bit non-minimal boundary (125).
		{0x82, 0xfe, 0x03, 0xe8, 0xde, 0xad, 0xbe, 0xef}, // 16-bit masked (old fast-path shape).
		{0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},             // 64-bit minimal boundary (65536).
		{0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff},             // 64-bit non-minimal (65535).
		{0x82, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},             // 64-bit max (2^63-1).
		{0x82, 0x7f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},             // 64-bit reserved MSB set (2^63).
		{0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 1, 2, 3, 4}, // 64-bit masked (1<<20).
		{0x81, 0x85, 0xde, 0xad, 0xbe, 0xef},                                     // 7-bit masked text (5).
	}
	for _, s := range lengthSeeds {
		f.Add(s)
	}

	// Seed: RSV-bit combinations (legal only as RSV1 on a compressed data
	// frame), control-frame rules, reserved opcodes, and mask-bit violations
	// for both roles.
	otherSeeds := [][]byte{
		{0xc2, 0x00},               // RSV1 + binary (compressed data frame start).
		{0xc1, 0x00},               // RSV1 + text.
		{0xc0, 0x00},               // RSV1 + continuation (illegal even compressed).
		{0xc8, 0x00},               // RSV1 + close control (illegal even compressed).
		{0xa2, 0x00},               // RSV2 + binary (always illegal).
		{0x92, 0x00},               // RSV3 + binary (always illegal).
		{0xe2, 0x00},               // RSV1+RSV2 + binary (never legal, not bare RSV1).
		{0x88, 0x00},               // Close, Fin, empty (valid control).
		{0x08, 0x00},               // Close, not Fin (fragmented control).
		{0x88, 0x7e, 0x00, 0x7e},   // Close, 126 bytes (control too long).
		{0x89, 0x7d},               // Ping, 125 bytes (valid control boundary).
		{0x83, 0x00}, {0x87, 0x00}, // Reserved data opcodes.
		{0x8b, 0x00}, {0x8f, 0x00}, // Reserved control opcodes.
		{0x82, 0x80, 0x01, 0x02, 0x03, 0x04},         // Masked binary (rejected by a client).
		{0x82, 0x00},                                 // Unmasked binary (rejected by a server).
		{}, {0x82}, {0x82, 0xfe}, {0x82, 0xff, 0x00}, // Truncated at various points.
	}
	for _, s := range otherSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		diffHeaderDecode(t, b)
	})
}

// TestHeaderTableDifferentialSeeds runs the differential check over two
// header shapes per b0 value that the fuzz seed corpus lacks: a masked
// minimal header and a masked 16-bit-length header. (The unmasked two-byte
// shape needs no duplication here -- the seed corpus covers it for every b0,
// and a plain `go test` already executes FuzzHeaderTableDifferential's seeds.)
func TestHeaderTableDifferentialSeeds(t *testing.T) {
	t.Parallel()
	for b0 := range 256 {
		diffHeaderDecode(t, []byte{byte(b0), 0x80, 1, 2, 3, 4})
		diffHeaderDecode(t, []byte{byte(b0), 0xfe, 0x04, 0x00, 1, 2, 3, 4})
	}
}

// TestClassifyHeaderByte pins classifyHeaderByte's per-b0 classification
// against first-principles expectations across the opcode/Fin/RSV space and
// both compression states, including the RSV1-legality divergence RFC 7692
// introduces when permessage-deflate is negotiated.
func TestClassifyHeaderByte(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		b0          byte
		compression bool
		want        headerClass
	}{
		"text, fin, no rsv": {
			b0:   0x81,
			want: headerClass{opcode: OpcodeText, rsv: 0, fin: true},
		},
		"binary, fin, no rsv": {
			b0:   0x82,
			want: headerClass{opcode: OpcodeBinary, rsv: 0, fin: true},
		},
		"text, no fin": {
			b0:   0x01,
			want: headerClass{opcode: OpcodeText, rsv: 0, fin: false},
		},
		"continuation, no fin, no rsv": {
			b0:   0x00,
			want: headerClass{opcode: OpcodeContinuation, rsv: 0, fin: false},
		},
		"close control, fin": {
			b0:   0x88,
			want: headerClass{opcode: OpcodeClose, rsv: 0, fin: true, control: true},
		},
		"ping control, fin": {
			b0:   0x89,
			want: headerClass{opcode: OpcodePing, rsv: 0, fin: true, control: true},
		},
		"pong control, fin": {
			b0:   0x8a,
			want: headerClass{opcode: OpcodePong, rsv: 0, fin: true, control: true},
		},
		"reserved data opcode 0x3": {
			b0:   0x83,
			want: headerClass{opcode: Opcode(0x3), rsv: 0, fin: true, reserved: true},
		},
		"reserved data opcode 0x7": {
			b0:   0x87,
			want: headerClass{opcode: Opcode(0x7), rsv: 0, fin: true, reserved: true},
		},
		"reserved control opcode 0xB": {
			b0:   0x8b,
			want: headerClass{opcode: Opcode(0xb), rsv: 0, fin: true, control: true, reserved: true},
		},
		"reserved control opcode 0xF": {
			b0:   0x8f,
			want: headerClass{opcode: Opcode(0xf), rsv: 0, fin: true, control: true, reserved: true},
		},
		"rsv1 binary, no compression": {
			b0:   0xc2,
			want: headerClass{opcode: OpcodeBinary, rsv: RSV1, fin: true, rsvBad: true},
		},
		"rsv1 binary, compression": {
			b0:          0xc2,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV1, fin: true, rsvBad: false},
		},
		"rsv1 text, compression": {
			b0:          0xc1,
			compression: true,
			want:        headerClass{opcode: OpcodeText, rsv: RSV1, fin: true, rsvBad: false},
		},
		"rsv1 continuation, compression": {
			b0:          0xc0,
			compression: true,
			want:        headerClass{opcode: OpcodeContinuation, rsv: RSV1, fin: true, rsvBad: true},
		},
		"rsv1 close control, compression": {
			b0:          0xc8,
			compression: true,
			want:        headerClass{opcode: OpcodeClose, rsv: RSV1, fin: true, control: true, rsvBad: true},
		},
		"rsv2 binary, compression": {
			b0:          0xa2,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV2, fin: true, rsvBad: true},
		},
		"rsv3 binary, compression": {
			b0:          0x92,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV3, fin: true, rsvBad: true},
		},
		"rsv1+rsv2 binary, compression": {
			b0:          0xe2,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV1 | RSV2, fin: true, rsvBad: true},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := classifyHeaderByte(tt.b0, tt.compression)
			if got != tt.want {
				t.Errorf("classifyHeaderByte(%#02x, %v) = %+v, want %+v", tt.b0, tt.compression, got, tt.want)
			}
			// The package-level table must hold precisely this value.
			idx := 0
			if tt.compression {
				idx = 1
			}
			if tbl := headerTables[idx][tt.b0]; tbl != tt.want {
				t.Errorf("headerTables[%d][%#02x] = %+v, want %+v", idx, tt.b0, tbl, tt.want)
			}
		})
	}
}

// TestHeaderTablesExhaustive cross-checks every entry of both precomputed
// tables against an inline recomputation of the classification rules, covering
// all 256 first-byte values under both compression states.
func TestHeaderTablesExhaustive(t *testing.T) {
	t.Parallel()
	for _, compression := range []bool{false, true} {
		idx := 0
		if compression {
			idx = 1
		}
		for b0 := range 256 {
			op := Opcode(byte(b0) & 0x0f)
			rsv := (byte(b0) >> 4) & 0x7
			control := op&0x8 != 0
			reserved := op >= 0x3 && op <= 0x7 || op >= 0xB
			rsv1OK := compression && rsv == RSV1 && !control && op != OpcodeContinuation
			want := headerClass{
				opcode:   op,
				rsv:      rsv,
				fin:      byte(b0)&0x80 != 0,
				control:  control,
				reserved: reserved,
				rsvBad:   rsv != 0 && !rsv1OK,
			}
			if got := headerTables[idx][b0]; got != want {
				t.Fatalf("headerTables[%d][%#02x] = %+v, want %+v", idx, b0, got, want)
			}
		}
	}
}

// TestHeaderTableFor verifies role/compression selection of the b0 table and
// the b1 mask-bit expectation (0x80 for a server, 0x00 for a client).
func TestHeaderTableFor(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		client      bool
		compression bool
		wantMaskBit byte
		wantIdx     int
	}{
		"server, plain":   {client: false, compression: false, wantMaskBit: 0x80, wantIdx: 0},
		"server, deflate": {client: false, compression: true, wantMaskBit: 0x80, wantIdx: 1},
		"client, plain":   {client: true, compression: false, wantMaskBit: 0x00, wantIdx: 0},
		"client, deflate": {client: true, compression: true, wantMaskBit: 0x00, wantIdx: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tbl, maskBit := headerTableFor(tt.client, tt.compression)
			if maskBit != tt.wantMaskBit {
				t.Errorf("maskBit = %#02x, want %#02x", maskBit, tt.wantMaskBit)
			}
			if tbl != &headerTables[tt.wantIdx] {
				t.Errorf("table = %p, want &headerTables[%d] (%p)", tbl, tt.wantIdx, &headerTables[tt.wantIdx])
			}
		})
	}
}

// TestDecodeFrameHeaderFastRejects pins the fast decoder's reject reason, 1002
// close message, and (on the accept path) decoded Header and consumed length
// for one representative input per rule, including the compression-dependent
// RSV1 divergence and the role-dependent mask rule.
func TestDecodeFrameHeaderFastRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		client      bool
		compression bool
		in          []byte
		wantReason  hdrReject
		wantMsg     string // close message (empty for accept/short).
		wantHeader  Header // meaningful only when wantReason == rejectNone.
		wantN       int    // consumed bytes when wantReason == rejectNone.
	}{
		"reserved opcode": {
			in:         []byte{0x83, 0x80, 0, 0, 0, 0},
			wantReason: rejectReservedOpcode,
			wantMsg:    "malformed frame header: gows: reserved opcode",
		},
		"reserved control opcode": {
			in:         []byte{0x8b, 0x80, 0, 0, 0, 0},
			wantReason: rejectReservedOpcode,
			wantMsg:    "malformed frame header: gows: reserved opcode",
		},
		"non-minimal 16-bit length": {
			in:         []byte{0x82, 0xfe, 0x00, 0x64, 0, 0, 0, 0},
			wantReason: rejectNonMinimalLength,
			wantMsg:    "malformed frame header: gows: non-minimal length encoding",
		},
		"non-minimal 64-bit length": {
			in:         []byte{0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4},
			wantReason: rejectNonMinimalLength,
			wantMsg:    "malformed frame header: gows: non-minimal length encoding",
		},
		"reserved length bit": {
			in:         []byte{0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
			wantReason: rejectReservedLengthBit,
			wantMsg:    "malformed frame header: gows: reserved length bit set",
		},
		"fragmented control": {
			in:         []byte{0x08, 0x80, 0, 0, 0, 0},
			wantReason: rejectControlFragmented,
			wantMsg:    "malformed frame header: gows: fragmented control frame",
		},
		"oversized control": {
			in:         []byte{0x88, 0xfe, 0x00, 0x7e, 0, 0, 0, 0},
			wantReason: rejectControlTooLong,
			wantMsg:    "malformed frame header: gows: control frame payload exceeds 125 bytes",
		},
		"bad rsv2 without compression": {
			in:         []byte{0xa2, 0x80, 0, 0, 0, 0},
			wantReason: rejectRSV,
			wantMsg:    "invalid RSV bit for the negotiated extension set",
		},
		"rsv1 without compression": {
			in:         []byte{0xc2, 0x80, 0, 0, 0, 0},
			wantReason: rejectRSV,
			wantMsg:    "invalid RSV bit for the negotiated extension set",
		},
		"rsv1 on continuation with compression": {
			compression: true,
			in:          []byte{0xc0, 0x80, 0, 0, 0, 0},
			wantReason:  rejectRSV,
			wantMsg:     "invalid RSV bit for the negotiated extension set",
		},
		"unmasked frame to server": {
			in:         []byte{0x82, 0x00},
			wantReason: rejectMask,
			wantMsg:    "unmasked frame received by server",
		},
		"masked frame to client": {
			client:     true,
			in:         []byte{0x82, 0x80, 0, 0, 0, 0},
			wantReason: rejectMask,
			wantMsg:    "masked frame received by client",
		},
		"short: one byte": {
			in:         []byte{0x82},
			wantReason: rejectShort,
		},
		"short: 16-bit length truncated": {
			in:         []byte{0x82, 0xfe, 0x04},
			wantReason: rejectShort,
		},
		"accept masked binary, server": {
			in:         []byte{0x82, 0x81, 0xde, 0xad, 0xbe, 0xef},
			wantReason: rejectNone,
			wantHeader: Header{Fin: true, Opcode: OpcodeBinary, Masked: true, MaskKey: binary.LittleEndian.Uint32([]byte{0xde, 0xad, 0xbe, 0xef}), Length: 1},
			wantN:      6,
		},
		"accept unmasked binary, client": {
			client:     true,
			in:         []byte{0x82, 0x05},
			wantReason: rejectNone,
			wantHeader: Header{Fin: true, Opcode: OpcodeBinary, Length: 5},
			wantN:      2,
		},
		"accept rsv1 compressed, server": {
			compression: true,
			in:          []byte{0xc2, 0x81, 0xde, 0xad, 0xbe, 0xef},
			wantReason:  rejectNone,
			wantHeader:  Header{Fin: true, Rsv: RSV1, Opcode: OpcodeBinary, Masked: true, MaskKey: binary.LittleEndian.Uint32([]byte{0xde, 0xad, 0xbe, 0xef}), Length: 1},
			wantN:       6,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tbl, maskBit := headerTableFor(tt.client, tt.compression)
			h, n, reason := decodeFrameHeaderFast(tbl, maskBit, tt.in)
			if reason != tt.wantReason {
				t.Fatalf("reason = %d, want %d", reason, tt.wantReason)
			}
			if got := reason.closeMessage(tt.client); got != tt.wantMsg {
				t.Errorf("closeMessage = %q, want %q", got, tt.wantMsg)
			}
			if tt.wantReason == rejectNone {
				if h != tt.wantHeader {
					t.Errorf("header = %+v, want %+v", h, tt.wantHeader)
				}
				if n != tt.wantN {
					t.Errorf("consumed = %d, want %d", n, tt.wantN)
				}
			} else if n != 0 {
				t.Errorf("consumed = %d on reject, want 0", n)
			}
		})
	}
}

// TestFrameHeaderRejectReasonParity drives the whole reader (not just the pure
// decoder) so that the 1002 close code and the exact reason string surfaced to
// the peer and the caller through [Conn.ReadMessage] match the former two-step
// decode's text.
// It complements TestReadMessageProtocolErrors, which asserts the code but not
// the message, closing the error-string parity gap at the integration boundary.
func TestFrameHeaderRejectReasonParity(t *testing.T) {
	t.Parallel()
	oversizedControl := frameBytes(true, OpcodeClose, 0, true, testKey, make([]byte, 126))
	tests := map[string]struct {
		client     bool
		in         []byte
		wantReason string
	}{
		"reserved opcode": {
			in:         frameBytes(true, Opcode(0x3), 0, true, testKey, []byte("x")),
			wantReason: "malformed frame header: gows: reserved opcode",
		},
		"non-minimal 16-bit length": {
			in:         []byte{0x82, 0xfe, 0x00, 0x64, 1, 2, 3, 4},
			wantReason: "malformed frame header: gows: non-minimal length encoding",
		},
		"oversized control": {
			in:         oversizedControl,
			wantReason: "malformed frame header: gows: control frame payload exceeds 125 bytes",
		},
		"bad rsv to server": {
			in:         frameBytes(true, OpcodeBinary, RSV1, true, testKey, []byte("x")),
			wantReason: "invalid RSV bit for the negotiated extension set",
		},
		"unmasked frame to server": {
			in:         serverFrame(true, OpcodeText, []byte("x")),
			wantReason: "unmasked frame received by server",
		},
		"masked frame to client": {
			client:     true,
			in:         clientFrame(true, OpcodeText, []byte("x")),
			wantReason: "masked frame received by client",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := &scriptConn{in: tt.in}
			var c *Conn
			if tt.client {
				c = NewClientConn(sc)
			} else {
				c = NewServerConn(sc)
			}
			_, _, err := c.ReadMessage()
			var ce *CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("error = %v, want *CloseError", err)
			}
			if ce.Code != CloseProtocolError {
				t.Errorf("close code = %d, want %d", ce.Code, CloseProtocolError)
			}
			if ce.Reason != tt.wantReason {
				t.Errorf("close reason = %q, want %q", ce.Reason, tt.wantReason)
			}
			// The peer must have received a Close frame carrying the same code.
			if code, reason, ok := firstClose(t, parseFrames(t, sc.out.Bytes())); !ok {
				t.Errorf("no Close frame sent to peer")
			} else if code != CloseProtocolError || reason != tt.wantReason {
				t.Errorf("sent close = (%d, %q), want (%d, %q)", code, reason, CloseProtocolError, tt.wantReason)
			}
		})
	}
}

// headerBenchShape is one frame-header wire shape the decode benchmark
// exercises, together with the receiving role that makes its mask bit valid.
type headerBenchShape struct {
	name   string
	client bool // receiving-side role: a client receives unmasked frames, a server masked.
	buf    []byte
}

// headerBenchShapes returns the benchmark shapes shared by the new
// (decodeFrameHeaderFast) and old (DecodeHeader+checkFrameHeader) header
// decoders, so the two can be compared across a git worktree. Masked frames
// are decoded as a server (their mask bit is valid there); unmasked frames as a
// client.
func headerBenchShapes() []headerBenchShape {
	mask := []byte{0xde, 0xad, 0xbe, 0xef}
	shape := func(name string, client bool, head []byte, masked bool) headerBenchShape {
		buf := append([]byte(nil), head...)
		if masked {
			buf = append(buf, mask...)
		}
		return headerBenchShape{name: name, client: client, buf: buf}
	}
	var len16 [2]byte
	binary.BigEndian.PutUint16(len16[:], 1000)
	var len64 [8]byte
	binary.BigEndian.PutUint64(len64[:], 1<<20)
	return []headerBenchShape{
		shape("7bit-text-masked", false, []byte{0x81, 0x80 | 100}, true),
		shape("7bit-binary-masked", false, []byte{0x82, 0x80 | 100}, true),
		shape("16bit-binary-masked", false, append([]byte{0x82, 0x80 | 126}, len16[:]...), true),
		shape("16bit-unmasked-server", true, append([]byte{0x82, 126}, len16[:]...), false),
		shape("64bit-masked", false, append([]byte{0x82, 0x80 | 127}, len64[:]...), true),
	}
}

// BenchmarkHeaderDecode measures the table-driven frame-header decoder across
// representative wire shapes, including the 16-bit masked binary shape the
// former code special-cased. The identically named benchmark in the
// 2c13770 worktree measures the old DecodeHeader+checkFrameHeader path over the
// same shapes for an apples-to-apples comparison.
func BenchmarkHeaderDecode(b *testing.B) {
	for _, sh := range headerBenchShapes() {
		tbl, maskBit := headerTableFor(sh.client, false)
		buf := sh.buf
		b.Run(sh.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, r := decodeFrameHeaderFast(tbl, maskBit, buf); r != rejectNone {
					b.Fatalf("unexpected reject %d", r)
				}
			}
		})
	}
}
