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
	"slices"
	"testing"
)

// serveBufferedEcho drives Serve with a handler that echoes every message back
// through the buffered-write path, so replies coalesce per drain round.
func serveBufferedEcho(c *Conn) error {
	return c.Serve(func(op Opcode, p []byte) error {
		return c.WriteMessageBuffered(op, p)
	})
}

// --- functional correctness -------------------------------------------------

// TestServeEchoRoundTrip drives Serve end-to-end over scripted inbound frames
// and verifies every handler invocation and coalesced reply byte-for-byte.
func TestServeEchoRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		msgs []struct {
			op Opcode
			p  []byte
		}
	}{
		"mixed sizes and encodings": {msgs: []struct {
			op Opcode
			p  []byte
		}{
			{OpcodeText, []byte("hello")},
			{OpcodeText, []byte("日本語 mixed ascii")},
			{OpcodeBinary, bytes.Repeat([]byte{0x00, 0x9f}, 32)},
			{OpcodeBinary, bytes.Repeat([]byte{0x5a}, 8000)}, // exceeds read buffer
			{OpcodeText, []byte("")},                         // empty payload
		}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a, b := net.Pipe()
			srv := NewServerConn(a)
			cli := NewClientConn(b)

			done := make(chan error, 1)
			go func() { done <- serveBufferedEcho(srv) }()

			for i, m := range tt.msgs {
				if err := cli.WriteMessage(m.op, m.p); err != nil {
					t.Fatalf("client write %d: %v", i, err)
				}
				op, got, err := cli.ReadMessage()
				if err != nil {
					t.Fatalf("client read %d: %v", i, err)
				}
				if op != m.op || !bytes.Equal(got, m.p) {
					t.Fatalf("echo %d: op=%v len(got)=%d len(want)=%d", i, op, len(got), len(m.p))
				}
			}

			_ = cli.Close(CloseNormalClosure, "bye")
			if err := <-done; !errors.As(err, new(*CloseError)) {
				t.Fatalf("Serve returned %v, want *CloseError", err)
			}
		})
	}
}

// TestServeChoppedStream feeds a multi-message stream one small chunk at a time,
// forcing the drain loop through its blocking round-boundary path (fragments
// never fully resident) and confirming reassembly and echo stay correct.
func TestServeChoppedStream(t *testing.T) {
	t.Parallel()

	msgs := []struct {
		op Opcode
		p  []byte
	}{
		{OpcodeText, []byte("hello")},
		{OpcodeText, []byte("日本語")},
		{OpcodeBinary, bytes.Repeat([]byte{0xa5}, 300)},
		{OpcodeText, []byte("z")},
	}
	var in []byte
	for _, m := range msgs {
		in = append(in, clientFrame(true, m.op, m.p)...)
	}

	tests := map[string]struct{ chunk int }{
		"one byte at a time": {chunk: 1},
		"three bytes":        {chunk: 3},
		"unlimited":          {chunk: 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sc := &scriptConn{in: bytes.Clone(in), chunk: tt.chunk}
			c := NewServerConn(sc)
			if err := serveBufferedEcho(c); !errors.Is(err, io.EOF) {
				t.Fatalf("Serve returned %v, want io.EOF", err)
			}
			frames := parseFrames(t, sc.out.Bytes())
			if len(frames) != len(msgs) {
				t.Fatalf("echoed %d frames, want %d", len(frames), len(msgs))
			}
			for i, m := range msgs {
				if frames[i].h.Opcode != m.op || !bytes.Equal(frames[i].payload, m.p) {
					t.Fatalf("echo %d: op=%v payload=%q, want op=%v payload=%q",
						i, frames[i].h.Opcode, frames[i].payload, m.op, m.p)
				}
			}
		})
	}
}

// TestServeCoalescesReplies proves the headline behavior: multiple pipelined
// messages already resident in the read buffer are drained in one pass and
// their buffered replies leave in a single write syscall.
func TestServeCoalescesReplies(t *testing.T) {
	t.Parallel()

	const n = 4
	var in []byte
	for i := range n {
		in = append(in, clientFrame(true, OpcodeBinary, []byte{byte(i)})...)
	}
	wire := &countingConn{scriptConn: &scriptConn{in: in}}
	c := NewServerConn(wire)

	if err := serveBufferedEcho(c); !errors.Is(err, io.EOF) {
		t.Fatalf("Serve returned %v, want io.EOF", err)
	}
	if wire.writes != 1 {
		t.Fatalf("underlying writes = %d, want 1 (all replies coalesced)", wire.writes)
	}
	frames := parseFrames(t, wire.out.Bytes())
	if len(frames) != n {
		t.Fatalf("echoed %d frames, want %d", len(frames), n)
	}
	for i := range n {
		if !bytes.Equal(frames[i].payload, []byte{byte(i)}) {
			t.Fatalf("echo %d payload = %v, want %v", i, frames[i].payload, []byte{byte(i)})
		}
	}
}

// TestServeFairnessBudget feeds two full budgets of tiny frames, all resident
// at once, and checks the drain round stops at the budget so replies flush in
// exactly two coalesced writes rather than one unbounded write -- while every
// message is still echoed in order.
func TestServeFairnessBudget(t *testing.T) {
	t.Parallel()

	const n = 2 * serveDrainBudget
	var in []byte
	for i := range n {
		in = append(in, clientFrame(true, OpcodeBinary, []byte{byte(i)})...)
	}
	wire := &countingConn{scriptConn: &scriptConn{in: in}}
	c := NewServerConn(wire)

	if err := serveBufferedEcho(c); !errors.Is(err, io.EOF) {
		t.Fatalf("Serve returned %v, want io.EOF", err)
	}
	if wire.writes != 2 {
		t.Fatalf("underlying writes = %d, want 2 (one coalesced write per budget)", wire.writes)
	}
	frames := parseFrames(t, wire.out.Bytes())
	if len(frames) != n {
		t.Fatalf("echoed %d frames, want %d", len(frames), n)
	}
	for i := range n {
		if !bytes.Equal(frames[i].payload, []byte{byte(i)}) {
			t.Fatalf("echo %d payload = %v, want %v", i, frames[i].payload, []byte{byte(i)})
		}
	}
}

// TestServeControlInterleave interleaves a Ping and a Close inside a pipelined
// burst and checks the auto-Pong and closing handshake keep exact ReadMessage
// ordering: each control reply flushes the pending data batch ahead of itself.
func TestServeControlInterleave(t *testing.T) {
	t.Parallel()

	var in []byte
	in = append(in, clientFrame(true, OpcodeText, []byte("one"))...)
	in = append(in, clientFrame(true, OpcodePing, []byte("png"))...)
	in = append(in, clientFrame(true, OpcodeText, []byte("two"))...)
	in = append(in, closeFrame(CloseNormalClosure, "")...)

	sc := &scriptConn{in: in}
	c := NewServerConn(sc)

	err := serveBufferedEcho(c)
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseNormalClosure {
		t.Fatalf("Serve returned %v, want *CloseError code %d", err, CloseNormalClosure)
	}

	frames := parseFrames(t, sc.out.Bytes())
	want := []struct {
		op Opcode
		p  string
	}{
		{OpcodeText, "one"},
		{OpcodePong, "png"},
		{OpcodeText, "two"},
		{OpcodeClose, ""}, // payload checked separately (carries the close code)
	}
	if len(frames) != len(want) {
		t.Fatalf("wrote %d frames, want %d: %+v", len(frames), len(want), frames)
	}
	for i, w := range want {
		if frames[i].h.Opcode != w.op {
			t.Fatalf("frame %d op = %v, want %v", i, frames[i].h.Opcode, w.op)
		}
		if w.op != OpcodeClose && string(frames[i].payload) != w.p {
			t.Fatalf("frame %d payload = %q, want %q", i, frames[i].payload, w.p)
		}
	}
	if code, _, ok := firstClose(t, frames); !ok || code != CloseNormalClosure {
		t.Fatalf("close reply code = %d (present=%v), want %d", code, ok, CloseNormalClosure)
	}
}

// TestServeHandlerError confirms an error returned by the handler stops the
// loop and is propagated verbatim.
func TestServeHandlerError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("handler stop")
	sc := &scriptConn{in: clientFrame(true, OpcodeBinary, []byte("x"))}
	c := NewServerConn(sc)

	calls := 0
	got := c.Serve(func(op Opcode, p []byte) error {
		calls++
		return wantErr
	})
	if !errors.Is(got, wantErr) {
		t.Fatalf("Serve returned %v, want %v", got, wantErr)
	}
	if calls != 1 {
		t.Fatalf("handler called %d times, want 1", calls)
	}
}

// TestServeFlushBeforeBlockingRead pins Serve's guarantee that pending
// buffered replies are flushed before every blocking read: a drain round whose
// resident bytes end in a control frame that writes no reply (a Pong) must not
// carry the batch into the next transport read. The script's EOF stands in for
// a peer that sends nothing further until it sees the reply; with the
// guarantee violated the echo never reaches the wire at all.
func TestServeFlushBeforeBlockingRead(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		in        []byte
		wantEchos []string
	}{
		"pong ends the resident burst": {
			in: slices.Concat(
				clientFrame(true, OpcodeText, []byte("one")),
				clientFrame(true, OpcodePong, []byte("pp")),
			),
			wantEchos: []string{"one"},
		},
		"pong between resident data frames": {
			in: slices.Concat(
				clientFrame(true, OpcodeText, []byte("one")),
				clientFrame(true, OpcodePong, []byte("pp")),
				clientFrame(true, OpcodeText, []byte("two")),
			),
			wantEchos: []string{"one", "two"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sc := &scriptConn{in: tt.in}
			c := NewServerConn(sc)
			if err := serveBufferedEcho(c); !errors.Is(err, io.EOF) {
				t.Fatalf("Serve returned %v, want io.EOF", err)
			}
			frames := parseFrames(t, sc.out.Bytes())
			if len(frames) != len(tt.wantEchos) {
				t.Fatalf("wrote %d frames, want %d: %+v", len(frames), len(tt.wantEchos), frames)
			}
			for i, want := range tt.wantEchos {
				if frames[i].h.Opcode != OpcodeText || string(frames[i].payload) != want {
					t.Fatalf("frame %d = {%v %q}, want {Text %q}", i, frames[i].h.Opcode, frames[i].payload, want)
				}
			}
		})
	}
}

// TestServeHandlerErrorDiscardsBatch pins the Serve contract that a handler
// error discards not-yet-flushed buffered replies: a later direct write must
// not resurrect the stale batch ahead of its own frame.
func TestServeHandlerErrorDiscardsBatch(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("handler stop")
	sc := &scriptConn{in: clientFrame(true, OpcodeText, []byte("stale"))}
	c := NewServerConn(sc)

	err := c.Serve(func(op Opcode, p []byte) error {
		if err := c.WriteMessageBuffered(op, p); err != nil {
			t.Errorf("WriteMessageBuffered: %v", err)
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Serve returned %v, want %v", err, wantErr)
	}

	if err := c.WriteMessage(OpcodeText, []byte("fresh")); err != nil {
		t.Fatalf("WriteMessage after handler error: %v", err)
	}
	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 || string(frames[0].payload) != "fresh" {
		t.Fatalf("wire frames = %+v, want exactly one \"fresh\" frame", frames)
	}
}

// TestServeCloseError confirms a peer Close frame ends Serve with the
// terminal *CloseError and never dispatches it as a data message.
func TestServeCloseError(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{in: closeFrame(CloseGoingAway, "later")}
	c := NewServerConn(sc)

	called := false
	err := c.Serve(func(op Opcode, p []byte) error {
		called = true
		return nil
	})
	if called {
		t.Fatal("handler was called for a Close frame")
	}
	var ce *CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("Serve returned %v, want *CloseError", err)
	}
	if ce.Code != CloseGoingAway || ce.Reason != "later" {
		t.Fatalf("CloseError = {code:%d reason:%q}, want {%d %q}", ce.Code, ce.Reason, CloseGoingAway, "later")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("CloseError does not match net.ErrClosed")
	}
}

// TestServeConcurrentWriteAndControl runs Serve with a buffered echo handler
// while a Ping storm drives auto-Pongs and a second goroutine issues direct
// WriteMessages, exercising the write mutex across buffered flushes, control
// replies, direct writes, and teardown. It must be clean under -race.
func TestServeConcurrentWriteAndControl(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	srv := NewServerConn(a)

	const n = 300
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		go func() { _, _ = io.Copy(io.Discard, b) }() // drain everything the server writes
		ping := clientFrame(true, OpcodePing, []byte("ping"))
		data := clientFrame(true, OpcodeBinary, []byte("data"))
		for range n {
			_, _ = b.Write(ping)
			_, _ = b.Write(data)
		}
		_, _ = b.Write(closeFrame(CloseNormalClosure, ""))
	}()

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(func(op Opcode, p []byte) error {
			return srv.WriteMessageBuffered(op, p)
		})
	}()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		out := []byte("server-out")
		for range n {
			if err := srv.WriteMessage(OpcodeBinary, out); err != nil {
				return
			}
		}
	}()

	<-serveDone
	<-writerDone
	<-peerDone
	_ = srv.Close(CloseNormalClosure, "")
}

// --- buffered write semantics ----------------------------------------------

// TestWriteMessageBufferedAutoFlush checks the byte-cap auto-flush: buffering
// enough frames to cross maxBufferedWriteSize writes the batch mid-accumulation
// without an explicit Flush.
func TestWriteMessageBufferedAutoFlush(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte{0x33}, 64<<10) // 65536 -> 10-byte header
	frameLen := 10 + len(payload)
	perBatch := maxBufferedWriteSize/frameLen + 1 // frames needed to cross the cap

	wire := &countingConn{scriptConn: &scriptConn{}}
	c := NewServerConn(wire)

	for i := range perBatch {
		if err := c.WriteMessageBuffered(OpcodeBinary, payload); err != nil {
			t.Fatalf("WriteMessageBuffered %d: %v", i, err)
		}
	}
	if wire.writes != 1 {
		t.Fatalf("underlying writes = %d after crossing the cap, want 1", wire.writes)
	}
	frames := parseFrames(t, wire.out.Bytes())
	if len(frames) != perBatch {
		t.Fatalf("auto-flushed %d frames, want %d", len(frames), perBatch)
	}
	for i, f := range frames {
		if f.h.Opcode != OpcodeBinary || !bytes.Equal(f.payload, payload) {
			t.Fatalf("frame %d mismatch: op=%v len=%d", i, f.h.Opcode, len(f.payload))
		}
	}
}

// TestWriteMessageBufferedFlushOrdering confirms a direct WriteMessage flushes a
// pending buffered batch first, so frame order on the wire matches call order.
func TestWriteMessageBufferedFlushOrdering(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc)

	if err := c.WriteMessageBuffered(OpcodeText, []byte("m1")); err != nil {
		t.Fatalf("buffered m1: %v", err)
	}
	if err := c.WriteMessageBuffered(OpcodeText, []byte("m2")); err != nil {
		t.Fatalf("buffered m2: %v", err)
	}
	// A direct WriteMessage must flush the batch [m1, m2] before writing m3.
	if err := c.WriteMessage(OpcodeText, []byte("m3")); err != nil {
		t.Fatalf("WriteMessage m3: %v", err)
	}

	frames := parseFrames(t, sc.out.Bytes())
	want := []string{"m1", "m2", "m3"}
	if len(frames) != len(want) {
		t.Fatalf("wrote %d frames, want %d", len(frames), len(want))
	}
	for i, w := range want {
		if string(frames[i].payload) != w {
			t.Fatalf("frame %d = %q, want %q", i, frames[i].payload, w)
		}
	}
}

// TestWriteMessageBufferedClientMasks confirms the client role masks each
// buffered frame and leaves the caller's payload untouched.
func TestWriteMessageBufferedClientMasks(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewClientConn(sc)
	payload := []byte("client buffered")
	orig := bytes.Clone(payload)

	if err := c.WriteMessageBuffered(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessageBuffered: %v", err)
	}
	if err := c.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !bytes.Equal(payload, orig) {
		t.Fatalf("client buffered write mutated caller's payload: %q != %q", payload, orig)
	}
	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 || !frames[0].h.Masked || !bytes.Equal(frames[0].payload, orig) {
		t.Fatalf("client buffered frame not masked/wrong payload: %+v", frames)
	}
}

// TestWriteMessageBufferedAfterClose confirms buffered writes and Flush honor
// the write-closed contract.
func TestWriteMessageBufferedAfterClose(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{in: closeFrame(CloseNormalClosure, "")}
	c := NewServerConn(sc)
	if _, _, err := c.ReadMessage(); !errors.As(err, new(*CloseError)) {
		t.Fatalf("ReadMessage: %v", err)
	}
	if err := c.WriteMessageBuffered(OpcodeText, []byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteMessageBuffered after close = %v, want errors.Is(net.ErrClosed)", err)
	}
	if err := c.Flush(); err != nil {
		t.Fatalf("Flush on empty batch after close = %v, want nil", err)
	}
}

// --- allocation acceptance --------------------------------------------------

// TestServeEchoZeroAllocs exercises the steady-state Serve echo path -- read a
// message, buffer its reply, flush the coalesced batch -- and asserts zero
// allocations per message in both directions after warm-up.
func TestServeEchoZeroAllocs(t *testing.T) {
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, 1024))
	c := NewServerConn(&loopConn{frame: frame})

	// One drain-round's worth of messages per closure exercises batch growth,
	// coalesced flush, and capacity reuse together.
	const perRound = 32
	round := func() {
		for range perRound {
			op, p, err := c.readMessageBody()
			if err != nil {
				t.Fatalf("readMessageBody: %v", err)
			}
			if err := c.WriteMessageBuffered(op, p); err != nil {
				t.Fatalf("WriteMessageBuffered: %v", err)
			}
		}
		if err := c.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}
	for range 8 { // warm up rbuf and grow the batch to its steady capacity
		round()
	}

	allocs := testing.AllocsPerRun(200, round)
	t.Logf("Serve echo allocs/round = %v (%v msgs, race=%v)", allocs, perRound, raceEnabledInternal)
	if !raceEnabledInternal && allocs != 0 {
		t.Errorf("Serve echo allocs/round = %v, want 0", allocs)
	}
}

// --- benchmarks -------------------------------------------------------------

// countingLoopConn serves an endless frame like loopConn and counts writes so a
// benchmark can report the coalescing ratio (writes per message).
type countingLoopConn struct {
	loopConn
	writes int
}

func (c *countingLoopConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

// BenchmarkServeEchoDrain measures the drain + reply-coalescing path: N
// pipelined frames are consumed and their replies buffered, with one coalesced
// write per drain budget. It reports writes/msg to quantify the syscall saving.
func BenchmarkServeEchoDrain(b *testing.B) {
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, 1024))
	cc := &countingLoopConn{loopConn: loopConn{frame: frame}}
	c := NewServerConn(cc)

	b.SetBytes(1024)
	b.ReportAllocs()

	msgs, pending := 0, 0
	for b.Loop() {
		op, p, err := c.readMessageBody()
		if err != nil {
			b.Fatal(err)
		}
		if err := c.WriteMessageBuffered(op, p); err != nil {
			b.Fatal(err)
		}
		msgs++
		if pending++; pending == serveDrainBudget {
			if err := c.Flush(); err != nil {
				b.Fatal(err)
			}
			pending = 0
		}
	}
	_ = c.Flush()
	if msgs > 0 {
		b.ReportMetric(float64(cc.writes)/float64(msgs), "writes/msg")
	}
}

// BenchmarkReadWriteEcho is the per-message baseline (one ReadMessage + one
// WriteMessage per message, one write syscall each) for BenchmarkServeEchoDrain.
func BenchmarkReadWriteEcho(b *testing.B) {
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, 1024))
	cc := &countingLoopConn{loopConn: loopConn{frame: frame}}
	c := NewServerConn(cc)

	b.SetBytes(1024)
	b.ReportAllocs()

	msgs := 0
	for b.Loop() {
		op, p, err := c.ReadMessage()
		if err != nil {
			b.Fatal(err)
		}
		if err := c.WriteMessage(op, p); err != nil {
			b.Fatal(err)
		}
		msgs++
	}
	if msgs > 0 {
		b.ReportMetric(float64(cc.writes)/float64(msgs), "writes/msg")
	}
}
