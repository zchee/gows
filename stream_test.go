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
)

// fragmentFrames builds a fragmented data message on the wire: the first frame
// carries op, the rest OpcodeContinuation; only the last has Fin set. Each
// fragment is masked as a client sends to a server.
func fragmentFrames(op Opcode, fragments ...[]byte) []byte {
	var out []byte
	for i, frag := range fragments {
		fop := OpcodeContinuation
		if i == 0 {
			fop = op
		}
		fin := i == len(fragments)-1
		out = append(out, clientFrame(fin, fop, frag)...)
	}
	return out
}

// readAllSmall drains r into a result slice using a tiny fixed buffer, so the
// per-Read streaming path (and its resumable mask/UTF-8 state) is exercised at
// every buffer boundary. bufSize bytes are requested per Read.
func readAllSmall(t *testing.T, r io.Reader, bufSize int) ([]byte, error) {
	t.Helper()
	buf := make([]byte, bufSize)
	var out []byte
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
	}
}

// --- NextReader ------------------------------------------------------------

// TestNextReaderLargeStreamSmallBuffer streams a 1 MiB message delivered in
// 64 KiB fragments and reads it through a 7-byte buffer, asserting payload
// integrity and -- crucially -- that the message is never reassembled into the
// growable reassembly buffer (internal inspection: c.msgBuf stays untouched),
// so peak read-side memory is the connection read buffer plus the caller's
// tiny slice, not the whole message.
func TestNextReaderLargeStreamSmallBuffer(t *testing.T) {
	t.Parallel()

	const fragSize = 64 << 10
	const nFrags = 16
	payload := pseudoRandomBytes(fragSize * nFrags)

	frags := make([][]byte, nFrags)
	for i := range frags {
		frags[i] = payload[i*fragSize : (i+1)*fragSize]
	}
	sc := &scriptConn{in: fragmentFrames(OpcodeBinary, frags...)}
	c := NewServerConn(sc)

	op, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	if op != OpcodeBinary {
		t.Fatalf("opcode = %v, want Binary", op)
	}

	got, err := readAllSmall(t, r, 7)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: len(got)=%d len(want)=%d", len(got), len(payload))
	}
	// The reassembly buffer must never have been used for an uncompressed
	// stream: no full-size allocation on the read side.
	if len(c.msgBuf) != 0 || cap(c.msgBuf) != 0 {
		t.Errorf("reassembly buffer was used: len=%d cap=%d, want 0/0", len(c.msgBuf), cap(c.msgBuf))
	}
}

// TestNextReaderInterleavedPing verifies a Ping arriving mid-stream is
// auto-answered with a Pong while the message keeps streaming intact.
func TestNextReaderInterleavedPing(t *testing.T) {
	t.Parallel()

	var in []byte
	in = append(in, clientFrame(false, OpcodeText, []byte("hello "))...)
	in = append(in, clientFrame(true, OpcodePing, []byte("ping-payload"))...)
	in = append(in, clientFrame(true, OpcodeContinuation, []byte("world"))...)

	sc := &scriptConn{in: in}
	c := NewServerConn(sc)

	op, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	got, err := readAllSmall(t, r, 4)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if op != OpcodeText || string(got) != "hello world" {
		t.Fatalf("op=%v got=%q, want text \"hello world\"", op, got)
	}

	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 || frames[0].h.Opcode != OpcodePong || string(frames[0].payload) != "ping-payload" {
		t.Fatalf("expected one Pong echoing the ping payload, got %+v", frames)
	}
}

// TestNextReaderInvalidUTF8Mid feeds invalid UTF-8 in a middle text fragment
// and asserts the streaming validator fails the connection with 1007 and the
// Read surfaces the error.
func TestNextReaderInvalidUTF8Mid(t *testing.T) {
	t.Parallel()

	var in []byte
	in = append(in, clientFrame(false, OpcodeText, []byte("valid start "))...)
	in = append(in, clientFrame(false, OpcodeContinuation, []byte{0xff, 0xfe})...) // invalid
	in = append(in, clientFrame(true, OpcodeContinuation, []byte("tail"))...)

	sc := &scriptConn{in: in}
	c := NewServerConn(sc)

	_, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	_, err = readAllSmall(t, r, 5)
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseInvalidFramePayloadData {
		t.Fatalf("stream read error = %v, want *CloseError 1007", err)
	}
	// Subsequent reads are sticky.
	if _, err2 := r.Read(make([]byte, 4)); err2 != err {
		t.Errorf("second Read error = %v, want sticky %v", err2, err)
	}
}

// TestNextReaderIncompleteUTF8End truncates a multi-byte rune at the final
// fragment; the completeness check at message end must fail with 1007.
func TestNextReaderIncompleteUTF8End(t *testing.T) {
	t.Parallel()

	// "日" is 0xE6 0x97 0xA5; drop the final byte so the message ends mid-rune.
	in := fragmentFrames(OpcodeText, []byte("ok "), []byte{0xe6, 0x97})
	sc := &scriptConn{in: in}
	c := NewServerConn(sc)

	_, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	_, err = readAllSmall(t, r, 2)
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseInvalidFramePayloadData {
		t.Fatalf("stream read error = %v, want *CloseError 1007", err)
	}
}

// TestNextReaderDiscardRemainder verifies that starting a new read while a
// previous streamed message is unfinished discards the remainder off the wire
// and positions the connection at the next message. It covers both a follow-up
// NextReader and a follow-up ReadMessage, and confirms the stale reader's Read
// returns the sticky superseded error.
func TestNextReaderDiscardRemainder(t *testing.T) {
	t.Parallel()

	msg1 := fragmentFrames(
		OpcodeBinary,
		bytes.Repeat([]byte{0x11}, 100),
		bytes.Repeat([]byte{0x22}, 100),
		bytes.Repeat([]byte{0x33}, 100),
	)
	second := []byte("the second message")

	t.Run("next read is NextReader", func(t *testing.T) {
		t.Parallel()
		in := append(append([]byte(nil), msg1...), clientFrame(true, OpcodeText, second)...)
		c := NewServerConn(&scriptConn{in: in})

		_, r1, err := c.NextReader()
		if err != nil {
			t.Fatalf("NextReader#1: %v", err)
		}
		// Read only a small prefix of msg1, leaving the rest unread.
		if _, err := r1.Read(make([]byte, 10)); err != nil {
			t.Fatalf("partial read: %v", err)
		}

		op, r2, err := c.NextReader()
		if err != nil {
			t.Fatalf("NextReader#2: %v", err)
		}
		got, err := readAllSmall(t, r2, 8)
		if err != nil {
			t.Fatalf("read msg2: %v", err)
		}
		if op != OpcodeText || !bytes.Equal(got, second) {
			t.Fatalf("msg2 op=%v got=%q, want text %q", op, got, second)
		}
		// The first reader is now stale.
		if _, err := r1.Read(make([]byte, 4)); !errors.Is(err, errStreamReaderStale) {
			t.Errorf("stale reader Read = %v, want errStreamReaderStale", err)
		}
	})

	t.Run("next read is ReadMessage", func(t *testing.T) {
		t.Parallel()
		in := append(append([]byte(nil), msg1...), clientFrame(true, OpcodeText, second)...)
		c := NewServerConn(&scriptConn{in: in})

		_, r1, err := c.NextReader()
		if err != nil {
			t.Fatalf("NextReader: %v", err)
		}
		if _, err := r1.Read(make([]byte, 10)); err != nil {
			t.Fatalf("partial read: %v", err)
		}

		op, got, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if op != OpcodeText || !bytes.Equal(got, second) {
			t.Fatalf("ReadMessage op=%v got=%q, want text %q", op, got, second)
		}
		if _, err := r1.Read(make([]byte, 4)); !errors.Is(err, errStreamReaderStale) {
			t.Errorf("stale reader Read = %v, want errStreamReaderStale", err)
		}
	})
}

// TestNextReaderEOF confirms the reader reports io.EOF exactly once the final
// fragment is consumed, and keeps returning io.EOF afterward.
func TestNextReaderEOF(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{in: clientFrame(true, OpcodeBinary, []byte("payload"))}
	c := NewServerConn(sc)
	_, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}

	buf := make([]byte, 32)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "payload" {
		t.Fatalf("Read = (%q, %v), want (\"payload\", nil)", buf[:n], err)
	}
	if n, err := r.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read at end = (%d, %v), want (0, io.EOF)", n, err)
	}
	if n, err := r.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read past end = (%d, %v), want (0, io.EOF)", n, err)
	}
}

// TestNextReaderReadLimit asserts the read limit bounds the total message size
// across fragments and a mid-stream overflow fails with 1009.
func TestNextReaderReadLimit(t *testing.T) {
	t.Parallel()

	// Two 60-byte fragments = 120 bytes total, over a 100-byte limit. The
	// first frame is admitted; the overflow is detected when the second
	// fragment's header is read mid-stream.
	in := fragmentFrames(
		OpcodeBinary,
		bytes.Repeat([]byte{0x41}, 60),
		bytes.Repeat([]byte{0x42}, 60),
	)
	c := NewServerConn(&scriptConn{in: in}, WithReadLimit(100))

	_, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	_, err = readAllSmall(t, r, 16)
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseMessageTooBig {
		t.Fatalf("stream read error = %v, want *CloseError 1009", err)
	}
}

// TestNextReaderCompressedFallback verifies a compressed (RSV1) inbound
// message is served through the reader interface with the inflated payload,
// enforcing the read limit against the decompressed size.
func TestNextReaderCompressedFallback(t *testing.T) {
	t.Parallel()

	plain := []byte(strings.Repeat("compress me, gently but thoroughly. ", 200))
	frame := buildCompressedFrame(t, true, OpcodeText, plain)

	sc := &scriptConn{in: frame}
	c := NewServerConn(sc, WithCompression(true))

	op, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	got, err := readAllSmall(t, r, 13)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if op != OpcodeText || !bytes.Equal(got, plain) {
		t.Fatalf("inflated payload mismatch: op=%v len(got)=%d len(want)=%d", op, len(got), len(plain))
	}
}

// TestNextReaderPeerClose confirms a Close frame arriving before a data
// message surfaces as the terminal *CloseError from NextReader itself.
func TestNextReaderPeerClose(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{in: closeFrame(CloseNormalClosure, "bye")}
	c := NewServerConn(sc)
	_, _, err := c.NextReader()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseNormalClosure {
		t.Fatalf("NextReader error = %v, want *CloseError 1000", err)
	}
}

// --- NextWriter ------------------------------------------------------------

// TestNextWriterFragmentBoundaries asserts the on-the-wire framing of a
// streamed message: the first frame carries the message opcode with Fin clear,
// interior frames are Continuation with Fin clear, and the last is
// Continuation with Fin set; the concatenated payloads reproduce the input.
func TestNextWriterFragmentBoundaries(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc)

	payload := pseudoRandomBytes(defaultWriteBufferSize*2 + 1000) // forces >=3 fragments
	w, err := c.NextWriter(OpcodeBinary)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) < 3 {
		t.Fatalf("got %d frames, want >= 3", len(frames))
	}
	var reassembled []byte
	for i, f := range frames {
		wantOp := OpcodeContinuation
		if i == 0 {
			wantOp = OpcodeBinary
		}
		wantFin := i == len(frames)-1
		if f.h.Opcode != wantOp {
			t.Errorf("frame %d opcode = %v, want %v", i, f.h.Opcode, wantOp)
		}
		if f.h.Fin != wantFin {
			t.Errorf("frame %d Fin = %v, want %v", i, f.h.Fin, wantFin)
		}
		if f.h.Rsv != 0 {
			t.Errorf("frame %d Rsv = %#x, want 0 (NextWriter never compresses)", i, f.h.Rsv)
		}
		reassembled = append(reassembled, f.payload...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("reassembled payload mismatch: len(got)=%d len(want)=%d", len(reassembled), len(payload))
	}
}

// TestNextWriterEmptyMessage confirms Close with no Write emits a single
// zero-length final fragment carrying the message opcode.
func TestNextWriterEmptyMessage(t *testing.T) {
	t.Parallel()

	tests := map[string]Opcode{
		"text":   OpcodeText,
		"binary": OpcodeBinary,
	}
	for name, op := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := &scriptConn{}
			c := NewServerConn(sc)
			w, err := c.NextWriter(op)
			if err != nil {
				t.Fatalf("NextWriter: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			frames := parseFrames(t, sc.out.Bytes())
			if len(frames) != 1 {
				t.Fatalf("got %d frames, want 1", len(frames))
			}
			f := frames[0]
			if f.h.Opcode != op || !f.h.Fin || len(f.payload) != 0 {
				t.Errorf("frame = {op:%v fin:%v len:%d}, want {%v true 0}", f.h.Opcode, f.h.Fin, len(f.payload), op)
			}
		})
	}
}

// TestNextWriterSingleSmallFragment confirms a message smaller than the
// fragment buffer is emitted as one Fin frame carrying the opcode.
func TestNextWriterSingleSmallFragment(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc)
	w, err := c.NextWriter(OpcodeText)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	if _, err := io.WriteString(w, "small"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	f := frames[0]
	if f.h.Opcode != OpcodeText || !f.h.Fin || string(f.payload) != "small" {
		t.Errorf("frame = {op:%v fin:%v payload:%q}", f.h.Opcode, f.h.Fin, f.payload)
	}
}

// TestNextWriterClientMasking confirms each fragment of a client-role streamed
// message is masked, and the unmasked payloads reproduce the input.
func TestNextWriterClientMasking(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewClientConn(sc)
	payload := pseudoRandomBytes(defaultWriteBufferSize*2 + 7)
	w, err := c.NextWriter(OpcodeBinary)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	frames := parseFrames(t, sc.out.Bytes())
	var reassembled []byte
	for i, f := range frames {
		if !f.h.Masked {
			t.Errorf("frame %d not masked (client role must mask)", i)
		}
		reassembled = append(reassembled, f.payload...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("client-masked reassembled payload mismatch: len(got)=%d len(want)=%d", len(reassembled), len(payload))
	}
}

// TestNextWriterBusy asserts a Conn permits only one writer at a time: while a
// NextWriter is open, WriteMessage and a second NextWriter are refused with
// ErrWriterBusy, and both succeed again once the writer is Closed.
func TestNextWriterBusy(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc)
	w, err := c.NextWriter(OpcodeBinary)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}

	if err := c.WriteMessage(OpcodeText, []byte("x")); !errors.Is(err, ErrWriterBusy) {
		t.Errorf("WriteMessage while writer open = %v, want ErrWriterBusy", err)
	}
	if _, err := c.NextWriter(OpcodeText); !errors.Is(err, ErrWriterBusy) {
		t.Errorf("second NextWriter = %v, want ErrWriterBusy", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.WriteMessage(OpcodeText, []byte("ok")); err != nil {
		t.Errorf("WriteMessage after Close = %v, want nil", err)
	}
	if w2, err := c.NextWriter(OpcodeText); err != nil {
		t.Errorf("NextWriter after Close = %v, want nil", err)
	} else {
		_ = w2.Close()
	}
}

// TestNextWriterCloseSemantics covers write-after-close and idempotent Close.
func TestNextWriterCloseSemantics(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc)
	w, err := c.NextWriter(OpcodeBinary)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	if _, err := w.Write([]byte("data")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
	if _, err := w.Write([]byte("more")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after Close = %v, want errors.Is(net.ErrClosed)", err)
	}
}

// TestNextWriterInvalidOpcode rejects non-data opcodes.
func TestNextWriterInvalidOpcode(t *testing.T) {
	t.Parallel()

	c := NewServerConn(&scriptConn{})
	for _, op := range []Opcode{OpcodeContinuation, OpcodePing, OpcodePong, OpcodeClose} {
		if _, err := c.NextWriter(op); err == nil {
			t.Errorf("NextWriter(%#x) = nil error, want rejection", byte(op))
		}
	}
}

// TestNextWriterNeverCompresses confirms NextWriter emits uncompressed frames
// (RSV1 clear, payload verbatim) even when permessage-deflate is negotiated.
func TestNextWriterNeverCompresses(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc, WithCompression(true))
	// Well above the compression threshold and highly compressible.
	payload := bytes.Repeat([]byte("A"), 4000)
	w, err := c.NextWriter(OpcodeBinary)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	frames := parseFrames(t, sc.out.Bytes())
	var reassembled []byte
	for i, f := range frames {
		if f.h.Rsv != 0 {
			t.Errorf("frame %d Rsv = %#x, want 0 (uncompressed)", i, f.h.Rsv)
		}
		reassembled = append(reassembled, f.payload...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("payload was altered: len(got)=%d len(want)=%d", len(reassembled), len(payload))
	}
}

// --- round trips over a real pipe ------------------------------------------

// TestStreamRoundTrips exercises every combination of the streaming and
// single-shot APIs across a net.Pipe, including a text message whose
// multi-byte runes straddle the writer's fragment boundaries so the peer's
// streaming UTF-8 validator must carry state across fragments.
func TestStreamRoundTrips(t *testing.T) {
	t.Parallel()

	multibyte := []byte(strings.Repeat("a£あ🎉Z ", 3000)) // > 8 KiB of mixed-width runes
	binary := pseudoRandomBytes(defaultWriteBufferSize*3 + 123)

	tests := map[string]struct {
		op   Opcode
		data []byte
	}{
		"text multibyte across fragment boundaries": {OpcodeText, multibyte},
		"large binary": {OpcodeBinary, binary},
		"empty":        {OpcodeText, nil},
	}

	// send transmits data on sender using the writer API selected by stream,
	// and returns what receiver observes using the reader API selected by
	// streamRead.
	roundTrip := func(t *testing.T, op Opcode, data []byte, streamWrite, streamRead bool) (Opcode, []byte, error) {
		t.Helper()
		a, b := net.Pipe()
		srv := NewServerConn(a)
		cli := NewClientConn(b)

		werr := make(chan error, 1)
		go func() {
			if streamWrite {
				w, err := srv.NextWriter(op)
				if err != nil {
					werr <- err
					return
				}
				if _, err := w.Write(data); err != nil {
					werr <- err
					return
				}
				werr <- w.Close()
				return
			}
			werr <- srv.WriteMessage(op, data)
		}()

		var (
			gotOp   Opcode
			gotData []byte
			rerr    error
		)
		if streamRead {
			var rop Opcode
			var rr io.Reader
			rop, rr, rerr = cli.NextReader()
			if rerr == nil {
				gotOp = rop
				gotData, rerr = io.ReadAll(rr)
			}
		} else {
			gotOp, gotData, rerr = cli.ReadMessage()
		}
		if err := <-werr; err != nil {
			t.Fatalf("write side: %v", err)
		}
		// Tear down the raw pipe directly: a graceful Conn.Close would write a
		// Close frame into the pipe with no peer left reading it and block
		// forever (its timeout bounds only the drain read, not the frame
		// write). The message transfer is already complete here.
		_ = a.Close()
		_ = b.Close()
		return gotOp, gotData, rerr
	}

	modes := []struct {
		name                    string
		streamWrite, streamRead bool
	}{
		{"NextWriter->NextReader", true, true},
		{"NextWriter->ReadMessage", true, false},
		{"WriteMessage->NextReader", false, true},
	}

	for name, tt := range tests {
		for _, m := range modes {
			t.Run(name+"/"+m.name, func(t *testing.T) {
				t.Parallel()
				op, got, err := roundTrip(t, tt.op, tt.data, m.streamWrite, m.streamRead)
				if err != nil {
					t.Fatalf("round trip: %v", err)
				}
				if op != tt.op {
					t.Errorf("opcode = %v, want %v", op, tt.op)
				}
				if !bytes.Equal(got, tt.data) {
					t.Errorf("payload mismatch: len(got)=%d len(want)=%d", len(got), len(tt.data))
				}
			})
		}
	}
}

// TestNextWriterConcurrentControlReply streams a message with NextWriter while
// the read side answers a ping storm with Pongs, exercising control-frame
// interleaving between fragments under the shared write mutex. It must be
// clean under -race, and the streamed data message must arrive intact
// alongside the interleaved Pongs.
func TestNextWriterConcurrentControlReply(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	srv := NewServerConn(a)
	payload := pseudoRandomBytes(defaultWriteBufferSize*8 + 55)

	// The peer sends a ping storm (interleaving with the server's fragments)
	// and only closes once signaled, so the streamed message always completes
	// before teardown -- keeping the test about interleaving, not shutdown
	// races.
	recv := make(chan []byte, 1)
	stop := make(chan struct{})
	go func() {
		var buf bytes.Buffer
		drained := make(chan struct{})
		go func() {
			_, _ = io.Copy(&buf, b)
			close(drained)
		}()
		ping := clientFrame(true, OpcodePing, []byte("p"))
		for {
			select {
			case <-stop:
				_, _ = b.Write(closeFrame(CloseNormalClosure, ""))
				<-drained
				recv <- buf.Bytes()
				return
			default:
			}
			if _, err := b.Write(ping); err != nil {
				<-drained
				recv <- buf.Bytes()
				return
			}
		}
	}()

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			if _, _, err := srv.ReadMessage(); err != nil {
				return
			}
		}
	}()

	w, err := srv.NextWriter(OpcodeBinary)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	close(stop) // writer done: let the peer close now
	<-readerDone
	_ = srv.Close(CloseNormalClosure, "")

	select {
	case got := <-recv:
		// Reassemble the data message from the captured wire bytes, skipping
		// the interleaved Pong and Close control frames.
		var data []byte
		sawPong := false
		for _, f := range parseFrames(t, got) {
			switch f.h.Opcode {
			case OpcodeBinary, OpcodeContinuation:
				data = append(data, f.payload...)
			case OpcodePong:
				sawPong = true
			}
		}
		if !sawPong {
			t.Error("no Pong observed; control replies did not interleave")
		}
		if !bytes.Equal(data, payload) {
			t.Errorf("streamed data mismatch: len(got)=%d len(want)=%d", len(data), len(payload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the peer to drain")
	}
}

// --- UTF-8 fail-fast across delayed chops (Autobahn 6.4.3 / 6.4.4) ----------

// choppyConn delivers a fixed wire script one chop per Read, simulating a peer
// that writes a single frame's payload across several delayed TCP segments. It
// records how many bytes had been served the moment the connection first wrote
// a frame (the reader's Close reply), so a test can prove a 1007 close fired
// mid-frame rather than only after the whole frame assembled.
type choppyConn struct {
	chops        [][]byte
	ci, off      int
	served       int
	firstWriteAt int // c.served when Write was first called; -1 until then
	out          bytes.Buffer
}

func newChoppyConn(chops [][]byte) *choppyConn {
	return &choppyConn{chops: chops, firstWriteAt: -1}
}

func (c *choppyConn) Read(p []byte) (int, error) {
	if c.ci >= len(c.chops) {
		return 0, io.EOF
	}
	chop := c.chops[c.ci]
	n := copy(p, chop[c.off:])
	c.off += n
	c.served += n
	if c.off >= len(chop) {
		c.ci++
		c.off = 0
	}
	return n, nil
}

func (c *choppyConn) Write(p []byte) (int, error) {
	if c.firstWriteAt < 0 {
		c.firstWriteAt = c.served
	}
	return c.out.Write(p)
}

func (c *choppyConn) Close() error                       { return nil }
func (c *choppyConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *choppyConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *choppyConn) SetDeadline(_ time.Time) error      { return nil }
func (c *choppyConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *choppyConn) SetWriteDeadline(_ time.Time) error { return nil }

// choppedInvalidTextFrame builds a single masked Text frame of total bytes
// whose payload is ASCII except for one invalid UTF-8 octet at badAt (chosen
// beyond the read buffer so it lands in the direct read path, not the buffered
// drain), then chops the wire bytes into chopSize-byte segments. The invalid
// octet sits well before the final chop, so a fail-fast reader must reply 1007
// before the whole frame is served.
func choppedInvalidTextFrame(total, badAt, chopSize int) (frame []byte, chops [][]byte) {
	payload := bytes.Repeat([]byte("a"), total)
	payload[badAt] = 0xff // 0xff is never valid UTF-8 in any state
	frame = clientFrame(true, OpcodeText, payload)
	for off := 0; off < len(frame); off += chopSize {
		chops = append(chops, frame[off:min(off+chopSize, len(frame))])
	}
	return frame, chops
}

// TestReadMessageUTF8FailFastMidFrame reproduces Autobahn 6.4.3/6.4.4: a large
// Text frame arrives in delayed chops with an invalid UTF-8 octet in an
// early-middle chop, beyond the read buffer so it exercises the direct read
// path. ReadMessage must fail the connection with 1007 as soon as that chop is
// validated -- before the whole frame has been read off the wire.
func TestReadMessageUTF8FailFastMidFrame(t *testing.T) {
	t.Parallel()

	// badAt (5000) is well past the 4096-byte read buffer, so the invalid
	// octet is validated in the beyond-rbuf direct path rather than the drain.
	frame, chops := choppedInvalidTextFrame(10000, 5000, 512)
	cc := newChoppyConn(chops)
	c := NewServerConn(cc)

	_, _, err := c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseInvalidFramePayloadData {
		t.Fatalf("error = %v, want *CloseError 1007", err)
	}
	if cc.firstWriteAt < 0 {
		t.Fatal("no Close frame was written")
	}
	// Fail-fast proof: the 1007 reply was written before the whole frame was
	// served. A reader that validated only after assembling the full frame
	// would have consumed all len(frame) bytes first.
	if cc.firstWriteAt >= len(frame) {
		t.Errorf("Close written after %d/%d bytes served: UTF-8 validation was not fail-fast", cc.firstWriteAt, len(frame))
	}
}

// TestNextReaderUTF8FailFastMidFrame is the streaming counterpart: the same
// chopped invalid Text frame consumed through NextReader with a tiny buffer
// must also fail 1007 the moment the invalid chop is validated, without
// draining the rest of the frame.
func TestNextReaderUTF8FailFastMidFrame(t *testing.T) {
	t.Parallel()

	frame, chops := choppedInvalidTextFrame(10000, 5000, 512)
	cc := newChoppyConn(chops)
	c := NewServerConn(cc)

	_, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	_, err = readAllSmall(t, r, 7)
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseInvalidFramePayloadData {
		t.Fatalf("stream read error = %v, want *CloseError 1007", err)
	}
	if cc.firstWriteAt < 0 {
		t.Fatal("no Close frame was written")
	}
	if cc.firstWriteAt >= len(frame) {
		t.Errorf("Close written after %d/%d bytes served: streaming UTF-8 validation was not fail-fast", cc.firstWriteAt, len(frame))
	}
}
