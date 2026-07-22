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
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows/internal/mask"
)

// --- test transport ---------------------------------------------------------

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// scriptConn is a net.Conn whose reads are served from a fixed script of
// bytes, optionally capped at chunk bytes per Read to exercise partial-read
// and buffer-compaction paths, and whose writes are captured for inspection.
type scriptConn struct {
	in    []byte
	pos   int
	chunk int // max bytes returned per Read; 0 means unlimited
	out   bytes.Buffer
}

func (s *scriptConn) Read(p []byte) (int, error) {
	if s.pos >= len(s.in) {
		return 0, io.EOF
	}
	n := min(len(s.in)-s.pos, len(p))
	if s.chunk > 0 {
		n = min(n, s.chunk)
	}
	copy(p, s.in[s.pos:s.pos+n])
	s.pos += n
	return n, nil
}

func (s *scriptConn) Write(p []byte) (int, error)        { return s.out.Write(p) }
func (s *scriptConn) Close() error                       { return nil }
func (s *scriptConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (s *scriptConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (s *scriptConn) SetDeadline(_ time.Time) error      { return nil }
func (s *scriptConn) SetReadDeadline(_ time.Time) error  { return nil }
func (s *scriptConn) SetWriteDeadline(_ time.Time) error { return nil }

// --- frame construction / parsing ------------------------------------------

const testKey = 0x89abcdef

// frameBytes encodes one frame on the wire, masking the payload when masked.
func frameBytes(fin bool, op Opcode, rsv byte, masked bool, key uint32, payload []byte) []byte {
	h := Header{Fin: fin, Rsv: rsv, Opcode: op, Masked: masked, MaskKey: key, Length: int64(len(payload))}
	b := AppendHeader(nil, h)
	body := append([]byte(nil), payload...)
	if masked {
		mask.Mask(body, key)
	}
	return append(b, body...)
}

// clientFrame builds a masked frame (as a client sends to a server).
func clientFrame(fin bool, op Opcode, payload []byte) []byte {
	return frameBytes(fin, op, 0, true, testKey, payload)
}

// serverFrame builds an unmasked frame (as a server sends to a client).
func serverFrame(fin bool, op Opcode, payload []byte) []byte {
	return frameBytes(fin, op, 0, false, 0, payload)
}

// closeFrame builds a masked Close frame carrying code and reason.
func closeFrame(code CloseCode, reason string) []byte {
	body := AppendCloseBody(nil, code, []byte(reason))
	return clientFrame(true, OpcodeClose, body)
}

type frameRec struct {
	h       Header
	payload []byte
}

// parseFrames decodes every complete frame in b, unmasking payloads.
func parseFrames(t *testing.T, b []byte) []frameRec {
	t.Helper()
	var out []frameRec
	for len(b) > 0 {
		h, n, err := DecodeHeader(b)
		if err != nil {
			t.Fatalf("parseFrames: DecodeHeader: %v", err)
		}
		b = b[n:]
		if int64(len(b)) < h.Length {
			t.Fatalf("parseFrames: truncated payload: have %d want %d", len(b), h.Length)
		}
		p := append([]byte(nil), b[:h.Length]...)
		if h.Masked {
			mask.Mask(p, h.MaskKey)
		}
		b = b[h.Length:]
		out = append(out, frameRec{h, p})
	}
	return out
}

// firstClose returns the first Close frame among the parsed frames.
func firstClose(t *testing.T, frames []frameRec) (CloseCode, string, bool) {
	t.Helper()
	for _, f := range frames {
		if f.h.Opcode == OpcodeClose {
			code, reason, err := ParseCloseBody(f.payload)
			if err != nil {
				t.Fatalf("firstClose: bad close body: %v", err)
			}
			return code, string(reason), true
		}
	}
	return 0, "", false
}

// --- read-side tests --------------------------------------------------------

func TestReadMessageSingleFrame(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		op      Opcode
		payload []byte
	}{
		"text ascii":       {OpcodeText, []byte("hello, websocket")},
		"text multibyte":   {OpcodeText, []byte("héllo 日本語 🎉")},
		"binary":           {OpcodeBinary, bytes.Repeat([]byte{0x00, 0xff, 0x7f}, 100)},
		"empty text":       {OpcodeText, []byte("")},
		"empty binary":     {OpcodeBinary, []byte("")},
		"exactly buffer-1": {OpcodeBinary, bytes.Repeat([]byte{0xab}, 4095)},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, chunk := range []int{0, 1, 3, 7} {
				sc := &scriptConn{in: clientFrame(true, tt.op, tt.payload), chunk: chunk}
				c := NewServerConn(sc)
				op, got, err := c.ReadMessage()
				if err != nil {
					t.Fatalf("chunk=%d: ReadMessage: %v", chunk, err)
				}
				if op != tt.op {
					t.Errorf("chunk=%d: opcode = %v, want %v", chunk, op, tt.op)
				}
				if !bytes.Equal(got, tt.payload) {
					t.Errorf("chunk=%d: payload = %q, want %q", chunk, got, tt.payload)
				}
			}
		})
	}
}

func TestReadMessageFragmented(t *testing.T) {
	t.Parallel()

	payload := []byte("first-second-third-continued")
	// Split into 3 fragments: Text(fin=0), Continuation(fin=0), Continuation(fin=1).
	var in []byte
	in = append(in, clientFrame(false, OpcodeText, payload[:6])...)
	in = append(in, clientFrame(false, OpcodeContinuation, payload[6:15])...)
	in = append(in, clientFrame(true, OpcodeContinuation, payload[15:])...)

	for _, chunk := range []int{0, 1, 5} {
		sc := &scriptConn{in: in, chunk: chunk}
		c := NewServerConn(sc)
		op, got, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("chunk=%d: %v", chunk, err)
		}
		if op != OpcodeText || !bytes.Equal(got, payload) {
			t.Fatalf("chunk=%d: op=%v got=%q want text %q", chunk, op, got, payload)
		}
	}
}

// TestReadMessageByteFragments splits a multibyte-UTF-8 message into 1-byte
// fragments, exercising the streaming UTF-8 validator across every possible
// code-point boundary.
func TestReadMessageByteFragments(t *testing.T) {
	t.Parallel()

	msg := []byte(strings.Repeat("a£あ🎉Z", 64)) // 1,2,3,4-byte runes + ascii
	var in []byte
	for i := range msg {
		op := OpcodeContinuation
		if i == 0 {
			op = OpcodeText
		}
		fin := i == len(msg)-1
		in = append(in, clientFrame(fin, op, msg[i:i+1])...)
	}

	sc := &scriptConn{in: in}
	c := NewServerConn(sc)
	op, got, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if op != OpcodeText || !bytes.Equal(got, msg) {
		t.Fatalf("reassembly mismatch: op=%v len(got)=%d len(want)=%d", op, len(got), len(msg))
	}
}

// TestReadMessageLargeFrameDirectRead exercises readFramePayload's direct
// read into the reassembly buffer for a single frame whose payload exceeds
// the read buffer: once rbuf is exhausted mid-frame, the remainder is read
// straight from the connection in one logical call (letting scriptConn hand
// back as much as its own chunk cap allows per underlying Read), then
// masked/validated separately in cap(rbuf)-sized sub-chunks. Using
// non-multiple-of-4 scriptConn chunk sizes deliberately misaligns the
// underlying Read boundaries against both the drain-then-direct-read split
// and the fixed processing-chunk boundaries, so the resumable key must
// carry across all of them correctly for the payload to unmask to the exact
// original bytes.
func TestReadMessageLargeFrameDirectRead(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		size  int
		chunk int // scriptConn per-Read byte cap; 0 means unlimited
	}{
		"one byte over the adaptive bound, unlimited chunks":         {size: maxAdaptiveReadSize + 1, chunk: 0},
		"large message, unlimited chunks":                            {size: 20000, chunk: 0},
		"large message, chunk size misaligned with mask width (37B)": {size: 20000, chunk: 37},
		"large message, chunk size misaligned with mask width (3B)":  {size: 20000, chunk: 3},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			payload := pseudoRandomBytes(tt.size)
			frame := clientFrame(true, OpcodeBinary, payload)
			sc := &scriptConn{in: frame, chunk: tt.chunk}
			c := NewServerConn(sc)
			op, got, err := c.ReadMessage()
			if err != nil {
				t.Fatalf("ReadMessage: %v", err)
			}
			if op != OpcodeBinary || !bytes.Equal(got, payload) {
				t.Fatalf("mismatch: op=%v len(got)=%d len(want)=%d", op, len(got), len(payload))
			}
		})
	}
}

// TestReadMessageMultiFrameDirectRead is
// TestReadMessageLargeFrameDirectRead's multi-frame counterpart: each of
// several Continuation fragments individually exceeds the read buffer, so
// readFramePayload's direct-read branch must engage once per frame and
// compose correctly across frame boundaries in the same reassembly buffer.
func TestReadMessageMultiFrameDirectRead(t *testing.T) {
	t.Parallel()

	const fragSize = defaultReadBufferSize + 500
	payload := pseudoRandomBytes(fragSize * 3)

	var in []byte
	in = append(in, clientFrame(false, OpcodeBinary, payload[:fragSize])...)
	in = append(in, clientFrame(false, OpcodeContinuation, payload[fragSize:2*fragSize])...)
	in = append(in, clientFrame(true, OpcodeContinuation, payload[2*fragSize:])...)

	for _, chunk := range []int{0, 37, 4096} {
		sc := &scriptConn{in: in, chunk: chunk}
		c := NewServerConn(sc)
		op, got, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("chunk=%d: ReadMessage: %v", chunk, err)
		}
		if op != OpcodeBinary || !bytes.Equal(got, payload) {
			t.Fatalf("chunk=%d: mismatch: op=%v len(got)=%d len(want)=%d", chunk, op, len(got), len(payload))
		}
	}
}

func TestReadMessageProtocolErrors(t *testing.T) {
	t.Parallel()

	badUTF8 := []byte{0xff, 0xfe}
	incompleteUTF8 := []byte{0xe6, 0x97} // start of a 3-byte rune, truncated

	tests := map[string]struct {
		client   bool // build a client-side Conn instead of server
		in       []byte
		wantCode CloseCode
	}{
		"unmasked frame to server": {
			in:       serverFrame(true, OpcodeText, []byte("x")),
			wantCode: CloseProtocolError,
		},
		"masked frame to client": {
			client:   true,
			in:       clientFrame(true, OpcodeText, []byte("x")),
			wantCode: CloseProtocolError,
		},
		"rsv bit set": {
			in:       frameBytes(true, OpcodeBinary, RSV1, true, testKey, []byte("x")),
			wantCode: CloseProtocolError,
		},
		"reserved opcode": {
			in:       frameBytes(true, Opcode(0x3), 0, true, testKey, []byte("x")),
			wantCode: CloseProtocolError,
		},
		"non-minimal 16-bit length": {
			in:       []byte{0x82, 0xfe, 0, 100, 1, 2, 3, 4},
			wantCode: CloseProtocolError,
		},
		"data while awaiting continuation": {
			in: append(
				clientFrame(false, OpcodeText, []byte("a")),
				clientFrame(true, OpcodeText, []byte("b"))...,
			),
			wantCode: CloseProtocolError,
		},
		"continuation with no message": {
			in:       clientFrame(true, OpcodeContinuation, []byte("a")),
			wantCode: CloseProtocolError,
		},
		"invalid utf8 text": {
			in:       clientFrame(true, OpcodeText, badUTF8),
			wantCode: CloseInvalidFramePayloadData,
		},
		"incomplete utf8 text": {
			in:       clientFrame(true, OpcodeText, incompleteUTF8),
			wantCode: CloseInvalidFramePayloadData,
		},
		"close invalid code": {
			in:       closeFrame(CloseCode(999), ""),
			wantCode: CloseProtocolError,
		},
		"close one-byte body": {
			in:       clientFrame(true, OpcodeClose, []byte{0x03}),
			wantCode: CloseProtocolError,
		},
		"close invalid utf8 reason": {
			in:       clientFrame(true, OpcodeClose, append(AppendCloseBody(nil, CloseNormalClosure, nil), badUTF8...)),
			wantCode: CloseInvalidFramePayloadData,
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
			if ce.Code != tt.wantCode {
				t.Errorf("close code = %d, want %d", ce.Code, tt.wantCode)
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("error does not satisfy errors.Is(net.ErrClosed): %v", err)
			}
			// A Close frame with the same code must have been sent to the peer.
			if code, _, ok := firstClose(t, parseFrames(t, sc.out.Bytes())); !ok {
				t.Errorf("no Close frame sent to peer")
			} else if code != tt.wantCode {
				t.Errorf("sent close code = %d, want %d", code, tt.wantCode)
			}
			// The error is sticky.
			if _, _, err2 := c.ReadMessage(); err2 != err {
				t.Errorf("second ReadMessage error = %v, want sticky %v", err2, err)
			}
		})
	}
}

func TestReadLimit(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		bufSize int
		limit   int64
		size    int
		wantErr bool
	}{
		"fast path at limit":    {bufSize: 4096, limit: 100, size: 100, wantErr: false},
		"fast path over limit":  {bufSize: 4096, limit: 100, size: 101, wantErr: true},
		"accumulate at limit":   {bufSize: 64, limit: 100, size: 100, wantErr: false},
		"accumulate over limit": {bufSize: 64, limit: 100, size: 101, wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			payload := bytes.Repeat([]byte{0x42}, tt.size)
			sc := &scriptConn{in: clientFrame(true, OpcodeBinary, payload)}
			c := NewServerConn(sc, WithReadBufferSize(tt.bufSize), WithReadLimit(tt.limit))

			_, got, err := c.ReadMessage()
			if tt.wantErr {
				var ce *CloseError
				if !errors.As(err, &ce) || ce.Code != CloseMessageTooBig {
					t.Fatalf("error = %v, want CloseError 1009", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadMessage: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload mismatch: len(got)=%d want %d", len(got), tt.size)
			}
		})
	}
}

func TestReadControlFramesInterleaved(t *testing.T) {
	t.Parallel()

	// Text(fin=0) "a", Ping "pp", Continuation(fin=1) "b" => message "ab" and a
	// Pong echoing "pp".
	var in []byte
	in = append(in, clientFrame(false, OpcodeText, []byte("a"))...)
	in = append(in, clientFrame(true, OpcodePing, []byte("pp"))...)
	in = append(in, clientFrame(true, OpcodeContinuation, []byte("b"))...)

	sc := &scriptConn{in: in}
	c := NewServerConn(sc)
	op, got, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if op != OpcodeText || string(got) != "ab" {
		t.Fatalf("op=%v got=%q, want text \"ab\"", op, got)
	}

	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 || frames[0].h.Opcode != OpcodePong || string(frames[0].payload) != "pp" {
		t.Fatalf("expected one Pong echoing \"pp\", got %+v", frames)
	}
}

func TestReadPeerCloseHandshake(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{in: closeFrame(CloseNormalClosure, "bye")}
	c := NewServerConn(sc)

	_, _, err := c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v, want *CloseError", err)
	}
	if ce.Code != CloseNormalClosure || ce.Reason != "bye" || ce.Sent {
		t.Errorf("CloseError = %+v, want {1000 bye received}", ce)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("errors.Is(net.ErrClosed) = false")
	}
	// We must reply with a Close echoing the code.
	if code, _, ok := firstClose(t, parseFrames(t, sc.out.Bytes())); !ok || code != CloseNormalClosure {
		t.Errorf("reply close code = %d ok=%v, want 1000", code, ok)
	}
}

func TestReadEmptyPeerClose(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{in: clientFrame(true, OpcodeClose, nil)}
	c := NewServerConn(sc)
	_, _, err := c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseNoStatusReceived {
		t.Fatalf("error = %v, want CloseError 1005", err)
	}
	// Reply must have an empty body (echoing 1005 on the wire is illegal).
	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 || frames[0].h.Opcode != OpcodeClose || len(frames[0].payload) != 0 {
		t.Fatalf("expected one empty Close reply, got %+v", frames)
	}
}

func TestPrebufferedBytes(t *testing.T) {
	t.Parallel()

	first := clientFrame(true, OpcodeText, []byte("first"))
	second := clientFrame(true, OpcodeBinary, []byte("second-message"))

	// Buffered carries the whole first frame plus the first 3 bytes of the
	// second; the rest of the second arrives from the connection.
	split := 3
	buffered := append(append([]byte(nil), first...), second[:split]...)
	sc := &scriptConn{in: second[split:]}

	c := NewServerConn(sc, WithBuffered(buffered))

	op, got, err := c.ReadMessage()
	if err != nil || op != OpcodeText || string(got) != "first" {
		t.Fatalf("first ReadMessage: op=%v got=%q err=%v", op, got, err)
	}
	op, got, err = c.ReadMessage()
	if err != nil || op != OpcodeBinary || string(got) != "second-message" {
		t.Fatalf("second ReadMessage: op=%v got=%q err=%v", op, got, err)
	}
}

func TestCloseInitiatedHandshake(t *testing.T) {
	t.Parallel()

	// The peer's Close reply is preloaded so Close's drain reads it.
	sc := &scriptConn{in: closeFrame(CloseNormalClosure, "")}
	c := NewServerConn(sc)

	if err := c.Close(CloseNormalClosure, "done"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// We sent a Close(1000, "done").
	code, reason, ok := firstClose(t, parseFrames(t, sc.out.Bytes()))
	if !ok || code != CloseNormalClosure || reason != "done" {
		t.Fatalf("sent close = %d %q ok=%v, want 1000 \"done\"", code, reason, ok)
	}
	// Idempotent.
	if err := c.Close(CloseNormalClosure, ""); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestCloseInvalidCode(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc)
	if err := c.Close(CloseCode(1005), ""); err == nil {
		t.Fatal("Close with reserved code 1005 = nil, want error")
	}
}

func TestCloseReasonUTF8Validation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		reason  string
		wantErr bool
	}{
		"valid ASCII reason": {
			reason:  "bye",
			wantErr: false,
		},
		"valid multi-byte UTF-8 reason": {
			reason:  "さようなら",
			wantErr: false,
		},
		"empty reason": {
			reason:  "",
			wantErr: false,
		},
		"invalid UTF-8 reason": {
			reason:  "bad reason: \xff\xfe",
			wantErr: true,
		},
		"lone continuation byte": {
			reason:  "\x80",
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sc := &scriptConn{in: closeFrame(CloseNormalClosure, "")}
			c := NewServerConn(sc)

			err := c.Close(CloseNormalClosure, tt.reason)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidCloseReason) {
					t.Fatalf("Close(%q) = %v, want ErrInvalidCloseReason", tt.reason, err)
				}
				// Nothing should have been sent: an invalid reason is
				// rejected before sendClose runs.
				if sc.out.Len() != 0 {
					t.Errorf("Close(%q) wrote %d bytes on invalid reason, want 0", tt.reason, sc.out.Len())
				}
				return
			}
			if err != nil {
				t.Fatalf("Close(%q): unexpected error %v", tt.reason, err)
			}
		})
	}
}

func TestSetDeadlines(t *testing.T) {
	t.Parallel()
	c := NewServerConn(&scriptConn{})
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

func TestCloseErrorFormat(t *testing.T) {
	t.Parallel()
	withReason := &CloseError{Code: CloseNormalClosure, Reason: "bye", Sent: true}
	noReason := &CloseError{Code: CloseProtocolError, Sent: false}
	if !strings.Contains(withReason.Error(), "bye") || !strings.Contains(withReason.Error(), "1000") {
		t.Errorf("Error() = %q, want it to mention reason and code", withReason.Error())
	}
	if !strings.Contains(noReason.Error(), "1002") {
		t.Errorf("Error() = %q, want it to mention code", noReason.Error())
	}
}

func TestReadTruncatedFrameEOF(t *testing.T) {
	t.Parallel()
	full := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{1}, 100))
	sc := &scriptConn{in: full[:len(full)-90]} // header + only 10 payload bytes
	_, _, err := NewServerConn(sc).ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("truncated-frame error = %v, want io.EOF", err)
	}
}

func TestCloseTimeoutDrain(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, b) }() // read our Close but never reply

	srv := NewServerConn(a, WithCloseTimeout(50*time.Millisecond))
	start := time.Now()
	if err := srv.Close(CloseNormalClosure, ""); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("Close drain took %v; close timeout not honored", el)
	}
}

// mustNotPanic runs fn and fails the test if it panics.
func mustNotPanic(t *testing.T, name string, fn func() error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked on a torn-down Conn: %v", name, r)
		}
	}()
	_ = fn()
}

// TestTornDownNoPanic terminates a Conn through every teardown path and then
// exercises every public method, asserting none panics and each honors its
// contract. This reproduces the Autobahn `defer c.Close(...)` usage that a
// stale-read-index bug turned into a process-killing panic (a Close re-entering
// the read path after a protocol/IO teardown indexed the freed read buffer).
func TestTornDownNoPanic(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		opts      []ConnOption
		in        []byte
		selfClose bool      // terminate via Close instead of ReadMessage
		wantCode  CloseCode // nonzero => terminal error is a *CloseError with this code
	}{
		"peer close frame": {
			in:       closeFrame(CloseNormalClosure, "bye"),
			wantCode: CloseNormalClosure,
		},
		"protocol violation (unmasked to server)": {
			in:       serverFrame(true, OpcodeText, []byte("x")),
			wantCode: CloseProtocolError,
		},
		"read limit 1009": {
			opts:     []ConnOption{WithReadLimit(100)},
			in:       clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{1}, 200)),
			wantCode: CloseMessageTooBig,
		},
		"io error (abrupt disconnect)": {
			in: clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{1}, 100))[:8], // truncated payload
		},
		"self close": {
			in:        closeFrame(CloseNormalClosure, ""), // peer's reply for the drain
			selfClose: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := NewServerConn(&scriptConn{in: tt.in}, tt.opts...)

			// Terminate the connection via the path under test.
			if tt.selfClose {
				if err := c.Close(CloseNormalClosure, ""); err != nil {
					t.Fatalf("initial Close: %v", err)
				}
			} else {
				_, _, err := c.ReadMessage()
				if err == nil {
					t.Fatal("ReadMessage did not terminate the connection")
				}
				if tt.wantCode != 0 {
					var ce *CloseError
					if !errors.As(err, &ce) || ce.Code != tt.wantCode {
						t.Fatalf("terminal error = %v, want *CloseError code %d", err, tt.wantCode)
					}
				}
			}

			// Every public method on a torn-down Conn must not panic.
			mustNotPanic(t, "Close", func() error { return c.Close(CloseNormalClosure, "x") })
			mustNotPanic(t, "Close#2", func() error { return c.Close(CloseNormalClosure, "x") })
			mustNotPanic(t, "ReadMessage", func() error { _, _, e := c.ReadMessage(); return e })
			mustNotPanic(t, "WriteMessage", func() error { return c.WriteMessage(OpcodeText, []byte("x")) })
			mustNotPanic(t, "SetReadDeadline", func() error { return c.SetReadDeadline(time.Now()) })
			mustNotPanic(t, "SetWriteDeadline", func() error { return c.SetWriteDeadline(time.Now()) })

			// Contract checks after teardown.
			if err := c.Close(CloseNormalClosure, ""); err != nil {
				t.Errorf("Close after teardown = %v, want nil (idempotent)", err)
			}
			if _, _, err := c.ReadMessage(); err == nil {
				t.Error("ReadMessage after teardown = nil, want sticky terminal error")
			}
			if err := c.WriteMessage(OpcodeText, []byte("x")); !errors.Is(err, net.ErrClosed) {
				t.Errorf("WriteMessage after teardown = %v, want errors.Is(net.ErrClosed)", err)
			}
		})
	}
}

// TestTornDownNoPanicRealConn repeats the essence of TestTornDownNoPanic
// against real net.Conn implementations (net.Pipe and a TCP loopback
// socket) instead of the fake scriptConn, whose SetReadDeadline/
// SetWriteDeadline are no-op stubs that can't exercise real
// already-closed-connection behavior. This specifically verifies that
// [Conn.SetReadDeadline]/[Conn.SetWriteDeadline] on a torn-down Conn
// forward to a genuinely closed net.Conn without panicking, and that the
// resulting error is reported rather than swallowed.
func TestTornDownNoPanicRealConn(t *testing.T) {
	t.Parallel()

	newPipe := func(t *testing.T) (server, client net.Conn) {
		t.Helper()
		server, client = net.Pipe()
		return server, client
	}
	newTCP := func(t *testing.T) (server, client net.Conn) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
		accepted := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			accepted <- c
		}()
		client, err = net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		server = <-accepted
		if server == nil {
			t.Fatal("accept: got nil conn")
		}
		return server, client
	}

	transports := map[string]func(t *testing.T) (server, client net.Conn){
		"net.Pipe":     newPipe,
		"TCP loopback": newTCP,
	}

	for tname, newTransport := range transports {
		t.Run(tname+"/self close, drain times out", func(t *testing.T) {
			t.Parallel()
			server, client := newTransport(t)
			defer client.Close()

			// net.Pipe's Write blocks until read; drain (and discard) the
			// client side in the background so the server's outgoing Close
			// frame can actually be delivered instead of blocking Close()
			// forever. The client never replies, so the drain's read
			// deadline fires, ending the close handshake via a real timeout
			// error.
			go io.Copy(io.Discard, client)

			c := NewServerConn(server, WithCloseTimeout(100*time.Millisecond))
			if err := c.Close(CloseNormalClosure, ""); err != nil {
				t.Fatalf("initial Close: %v", err)
			}
			assertTornDownNoPanic(t, c)
		})

		t.Run(tname+"/io error, peer disconnects", func(t *testing.T) {
			t.Parallel()
			server, client := newTransport(t)
			client.Close() // abrupt disconnect before the server ever reads

			c := NewServerConn(server, WithCloseTimeout(100*time.Millisecond))
			if _, _, err := c.ReadMessage(); err == nil {
				t.Fatal("ReadMessage did not terminate the connection")
			}
			assertTornDownNoPanic(t, c)
		})
	}
}

// assertTornDownNoPanic exercises every public method on an already
// torn-down Conn, asserting none panics, and that the two deadline
// setters -- which forward to the real underlying net.Conn rather than
// being intercepted -- report the connection is closed instead of
// silently succeeding.
func assertTornDownNoPanic(t *testing.T, c *Conn) {
	t.Helper()

	mustNotPanic(t, "Close", func() error { return c.Close(CloseNormalClosure, "x") })
	mustNotPanic(t, "Close#2", func() error { return c.Close(CloseNormalClosure, "x") })
	mustNotPanic(t, "ReadMessage", func() error { _, _, e := c.ReadMessage(); return e })
	mustNotPanic(t, "WriteMessage", func() error { return c.WriteMessage(OpcodeText, []byte("x")) })
	mustNotPanic(t, "SetReadDeadline", func() error { return c.SetReadDeadline(time.Now().Add(time.Second)) })
	mustNotPanic(t, "SetWriteDeadline", func() error { return c.SetWriteDeadline(time.Now().Add(time.Second)) })

	if err := c.Close(CloseNormalClosure, ""); err != nil {
		t.Errorf("Close after teardown = %v, want nil (idempotent)", err)
	}
	if _, _, err := c.ReadMessage(); err == nil {
		t.Error("ReadMessage after teardown = nil, want sticky terminal error")
	}
	if err := c.WriteMessage(OpcodeText, []byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("WriteMessage after teardown = %v, want errors.Is(net.ErrClosed)", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		t.Error("SetReadDeadline on a torn-down real net.Conn = nil, want an error")
	}
	if err := c.SetWriteDeadline(time.Now().Add(time.Second)); err == nil {
		t.Error("SetWriteDeadline on a torn-down real net.Conn = nil, want an error")
	}
}

func TestSkipUTF8Validation(t *testing.T) {
	t.Parallel()

	bad := []byte{0xff, 0xfe, 0xfd} // never valid UTF-8

	// Default: invalid UTF-8 in a Text frame is rejected with 1007.
	sc := &scriptConn{in: clientFrame(true, OpcodeText, bad)}
	if _, _, err := NewServerConn(sc).ReadMessage(); err == nil {
		t.Fatal("default: invalid UTF-8 text accepted, want rejection")
	}

	// Skipped: the same bytes are delivered verbatim (benchmark off-config).
	sc2 := &scriptConn{in: clientFrame(true, OpcodeText, bad)}
	c := NewServerConn(sc2, WithSkipUTF8Validation(true))
	op, got, err := c.ReadMessage()
	if err != nil || op != OpcodeText || !bytes.Equal(got, bad) {
		t.Fatalf("skip: op=%v got=% x err=%v, want text % x", op, got, err, bad)
	}
}
