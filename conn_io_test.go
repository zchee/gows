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
	"sync"
	"testing"
	"time"
)

// loopConn is a net.Conn whose Read serves an endless repetition of a fixed
// frame (for zero-allocation read benchmarks) and whose Write discards. It
// never blocks or errors.
type loopConn struct {
	frame []byte
	pos   int
}

func (l *loopConn) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if l.pos == len(l.frame) {
			l.pos = 0
		}
		m := copy(p[n:], l.frame[l.pos:])
		l.pos += m
		n += m
	}
	return n, nil
}

func (l *loopConn) Write(p []byte) (int, error)        { return len(p), nil }
func (l *loopConn) Close() error                       { return nil }
func (l *loopConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (l *loopConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (l *loopConn) SetDeadline(_ time.Time) error      { return nil }
func (l *loopConn) SetReadDeadline(_ time.Time) error  { return nil }
func (l *loopConn) SetWriteDeadline(_ time.Time) error { return nil }

type countingConn struct {
	*scriptConn
	reads  int
	writes int
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reads++
	return c.scriptConn.Read(p)
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	return c.scriptConn.Write(p)
}

func TestReadMessageAdaptsLargeSingleFrameBuffer(t *testing.T) {
	t.Parallel()

	const size = 16 << 10
	payload := bytes.Repeat([]byte{0x7f}, size)
	frame := clientFrame(true, OpcodeBinary, payload)
	wire := &countingConn{scriptConn: &scriptConn{in: bytes.Repeat(frame, 2)}}
	c := NewServerConn(wire, WithReadBufferSize(defaultReadBufferSize))

	for i := range 2 {
		op, got, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		if op != OpcodeBinary || !bytes.Equal(got, payload) {
			t.Fatalf("message %d: op=%v len=%d, want binary len=%d", i, op, len(got), len(payload))
		}
	}

	if wire.reads != 3 {
		t.Fatalf("underlying reads = %d, want 3", wire.reads)
	}
	if cap(c.rbuf) < size+MaxHeaderSize {
		t.Fatalf("read buffer capacity = %d, want at least %d", cap(c.rbuf), size+MaxHeaderSize)
	}
	if c.msgBuf != nil {
		t.Fatalf("reassembly buffer retained with adaptive zero-copy: cap=%d", cap(c.msgBuf))
	}
}

func TestAdaptReadBufferBounds(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		readLimit int64
		payload   int64
	}{
		"already fits": {readLimit: defaultReadLimit, payload: defaultReadBufferSize},
		"read limit":   {readLimit: 8 << 10, payload: 16 << 10},
		"size cap":     {readLimit: defaultReadLimit, payload: maxAdaptiveReadSize + 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := NewServerConn(&scriptConn{}, WithReadLimit(tt.readLimit))
			before := cap(c.rbuf)
			c.adaptReadBuffer(tt.payload)
			if got := cap(c.rbuf); got != before {
				t.Fatalf("read buffer capacity = %d, want unchanged %d", got, before)
			}
		})
	}
}

// TestAdaptReadBufferRecyclesToPoolClass verifies the adaptive single-frame
// buffer swap draws its replacement from the shared pool at a power-of-two
// class capacity, so pool.Put at teardown retains it. Previously the swap
// used an exact-size make([]byte, payload+MaxHeaderSize) whose
// non-class capacity pool.Put silently dropped at teardown, leaking the adapted
// buffer past the pool. Recyclability is exactly pool.go's retain rule: a
// class-sized capacity within [128B, 256KiB].
func TestAdaptReadBufferRecyclesToPoolClass(t *testing.T) {
	t.Parallel()

	c := NewServerConn(&scriptConn{}, WithReadBufferSize(defaultReadBufferSize))
	const payload = 8 << 10 // within (cap(rbuf), maxAdaptiveReadSize]
	c.adaptReadBuffer(payload)

	got := cap(c.rbuf)
	if int64(got) < payload {
		t.Fatalf("adapted cap = %d, want >= payload %d", got, payload)
	}
	const (
		minClassSize = 1 << 7
		maxClassSize = 1 << 18
	)
	if got < minClassSize || got > maxClassSize || got&(got-1) != 0 {
		t.Fatalf("adapted cap = %d is not a pool size class; pool.Put would drop it at teardown", got)
	}
}

func TestWriteMessageServerSmallFrameSingleWrite(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte{0x5a}, 1024)
	wire := &countingConn{scriptConn: &scriptConn{}}
	c := NewServerConn(wire)
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if wire.writes != 1 {
		t.Fatalf("underlying writes = %d, want 1", wire.writes)
	}
	frames := parseFrames(t, wire.out.Bytes())
	if len(frames) != 1 || frames[0].h.Opcode != OpcodeBinary || !bytes.Equal(frames[0].payload, payload) {
		t.Fatalf("frame mismatch: frames=%d", len(frames))
	}
}

// --- write-side correctness -------------------------------------------------

func TestWriteMessageServerRole(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewServerConn(sc)
	payload := []byte("hello world")
	orig := bytes.Clone(payload)

	if err := c.WriteMessage(OpcodeText, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 {
		t.Fatalf("wrote %d frames, want 1", len(frames))
	}
	f := frames[0]
	if f.h.Opcode != OpcodeText || f.h.Masked || !f.h.Fin || string(f.payload) != "hello world" {
		t.Errorf("frame = {op:%v masked:%v fin:%v payload:%q}", f.h.Opcode, f.h.Masked, f.h.Fin, f.payload)
	}
	if !bytes.Equal(payload, orig) {
		t.Errorf("server WriteMessage mutated caller's payload")
	}
}

func TestWriteMessageClientRole(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{}
	c := NewClientConn(sc)
	payload := []byte("client says hi")
	orig := append([]byte(nil), payload...)

	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 || !frames[0].h.Masked || string(frames[0].payload) != "client says hi" {
		t.Fatalf("client frame not masked/wrong payload: %+v", frames)
	}
	if !bytes.Equal(payload, orig) {
		t.Errorf("client WriteMessage mutated caller's payload: %q != %q", payload, orig)
	}
}

func TestWriteAfterClose(t *testing.T) {
	t.Parallel()

	sc := &scriptConn{in: closeFrame(CloseNormalClosure, "")}
	c := NewServerConn(sc)
	if _, _, err := c.ReadMessage(); !errors.As(err, new(*CloseError)) {
		t.Fatalf("ReadMessage: %v", err)
	}
	if err := c.WriteMessage(OpcodeText, []byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("WriteMessage after close = %v, want errors.Is(net.ErrClosed)", err)
	}
}

// --- echo round trips -------------------------------------------------------

// runEcho reads and echoes every message on c until it errors.
func runEcho(c *Conn) {
	for {
		op, p, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(op, p); err != nil {
			return
		}
	}
}

func testEcho(t *testing.T, srvConn, cliConn net.Conn) {
	t.Helper()

	srv := NewServerConn(srvConn)
	cli := NewClientConn(cliConn)

	done := make(chan struct{})
	go func() {
		runEcho(srv)
		close(done)
	}()

	msgs := []struct {
		op Opcode
		p  []byte
	}{
		{OpcodeText, []byte("hello")},
		{OpcodeText, []byte("日本語 mixed ascii ✓")},
		{OpcodeBinary, bytes.Repeat([]byte{0x00, 0x9f}, 32)},
		{OpcodeBinary, bytes.Repeat([]byte{0x5a}, 8000)}, // exceeds read buffer
	}
	for _, m := range msgs {
		if err := cli.WriteMessage(m.op, m.p); err != nil {
			t.Fatalf("client write: %v", err)
		}
		op, got, err := cli.ReadMessage()
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		if op != m.op || !bytes.Equal(got, m.p) {
			t.Fatalf("echo mismatch: op=%v len(got)=%d len(want)=%d", op, len(got), len(m.p))
		}
	}

	_ = cli.Close(CloseNormalClosure, "bye")
	<-done
}

func TestEchoPipe(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	testEcho(t, a, b)
}

func TestEchoTCP(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	cliConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	testEcho(t, a.c, cliConn)
}

// --- concurrency ------------------------------------------------------------

// TestConcurrentWriteAndAutoPong runs a reader that answers a ping storm with
// Pongs while a separate writer sends messages, exercising the write-serialization
// mutex. It must be clean under -race.
func TestConcurrentWriteAndAutoPong(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	srv := NewServerConn(a)

	const N = 300
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		go func() { _, _ = io.Copy(io.Discard, b) }() // drain everything the server writes
		ping := clientFrame(true, OpcodePing, []byte("ping"))
		data := clientFrame(true, OpcodeBinary, []byte("data"))
		for range N {
			_, _ = b.Write(ping)
			_, _ = b.Write(data)
		}
		_, _ = b.Write(closeFrame(CloseNormalClosure, ""))
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	// Reader: consumes data messages and auto-answers pings.
	go func() {
		defer wg.Done()
		for {
			if _, _, err := srv.ReadMessage(); err != nil {
				return
			}
		}
	}()
	// Writer: concurrently sends its own messages.
	go func() {
		defer wg.Done()
		out := []byte("server-out")
		for range N {
			if err := srv.WriteMessage(OpcodeBinary, out); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	<-peerDone
	_ = srv.Close(CloseNormalClosure, "")
}

// --- allocation acceptance (AC3) --------------------------------------------

func TestReadMessageZeroAllocs(t *testing.T) {
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, 1024))
	c := NewServerConn(&loopConn{frame: frame})
	for range 8 { // warm up buffers
		if _, _, err := c.ReadMessage(); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}
	allocs := testing.AllocsPerRun(500, func() {
		_, _, _ = c.ReadMessage()
	})
	t.Logf("ReadMessage allocs/op = %v (race=%v)", allocs, raceEnabledInternal)
	// The race detector's sync.Pool instrumentation can add a phantom alloc;
	// enforce the strict AC3 bound only on non-race builds.
	if !raceEnabledInternal && allocs != 0 {
		t.Errorf("ReadMessage allocs/op = %v, want 0 (AC3)", allocs)
	}
}

func TestReadMessage16KBZeroAllocs(t *testing.T) {
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, 16<<10))
	c := NewServerConn(&loopConn{frame: frame})
	for range 8 {
		if _, _, err := c.ReadMessage(); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}
	allocs := testing.AllocsPerRun(500, func() {
		_, _, _ = c.ReadMessage()
	})
	t.Logf("ReadMessage 16 KiB allocs/op = %v (race=%v)", allocs, raceEnabledInternal)
	if !raceEnabledInternal && allocs != 0 {
		t.Errorf("ReadMessage 16 KiB allocs/op = %v, want 0", allocs)
	}
}

func TestWriteMessageServerAllocs(t *testing.T) {
	c := NewServerConn(&loopConn{frame: []byte{0x00}})
	payload := bytes.Repeat([]byte{0x41}, 1024)
	for range 8 {
		if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}
	allocs := testing.AllocsPerRun(500, func() {
		_ = c.WriteMessage(OpcodeBinary, payload)
	})
	t.Logf("server WriteMessage allocs/op = %v (race=%v)", allocs, raceEnabledInternal)
	if !raceEnabledInternal && allocs != 0 {
		t.Errorf("server WriteMessage allocs/op = %v, want 0", allocs)
	}
}

// TestWriteMessageCompressedZeroAllocs pins the deflate write path to zero
// steady-state allocations. Previously the pooled compressor path allocated
// a &sliceWriter{} sink and a release closure on every compressed
// WriteMessage; both are gone -- the sink is the reusable per-Conn c.wslice and
// the release is carried by value in the compressorLease.
func TestWriteMessageCompressedZeroAllocs(t *testing.T) {
	c := NewServerConn(&loopConn{frame: []byte{0x00}}, WithCompression(true))
	// At or above defaultCompressMinSize and highly compressible, so the pooled
	// compressor engages and the framed output stays within one coalesced Write.
	payload := bytes.Repeat([]byte("A"), 1024)
	for range 8 { // warm the pooled compressor and the c.wslice/c.wcomp buffers
		if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
			t.Fatalf("warmup: %v", err)
		}
	}
	allocs := testing.AllocsPerRun(500, func() {
		_ = c.WriteMessage(OpcodeBinary, payload)
	})
	t.Logf("compressed WriteMessage allocs/op = %v (race=%v)", allocs, raceEnabledInternal)
	if !raceEnabledInternal && allocs != 0 {
		t.Errorf("compressed WriteMessage allocs/op = %v, want 0 (deflate write-path hygiene)", allocs)
	}
}

// TestStreamingEchoAllocs guards the steady-state per-message allocation of a
// streamed echo (NextReader -> drain -> NextWriter -> Close) at its irreducible
// floor of two: one for the io.Reader handle returned by NextReader and one for
// the io.WriteCloser returned by NextWriter. Both are irreducible under this
// package's documented sticky-invalidation contract: a superseded reader's Read
// must permanently return errStreamReaderStale and a closed writer's Write must
// permanently return errWriterClosed (see TestNextReaderDiscardRemainder and
// TestNextWriterCloseSemantics). That permanence forbids reusing a fixed set of
// embedded handle objects across messages -- recycling a handle's storage for a
// later message would resurrect a caller's stale handle into live state,
// silently serving a different message's bytes instead of the sticky error.
// The fragment buffer NextWriter borrows is already pool-recycled (zero steady
// allocs), so the two handles are the whole cost. io.Copy is deliberately not
// used here: its own 32 KiB scratch buffer is a caller-side allocation that
// would mask the library's per-message cost this test pins.
func TestStreamingEchoAllocs(t *testing.T) {
	payload := bytes.Repeat([]byte{0x7f}, 1024)
	frame := clientFrame(true, OpcodeBinary, payload)
	c := NewServerConn(&loopConn{frame: frame})
	scratch := make([]byte, 4096)

	echo := func() {
		op, r, err := c.NextReader()
		if err != nil {
			t.Fatalf("NextReader: %v", err)
		}
		n := 0
		for {
			m, rerr := r.Read(scratch[n:])
			n += m
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				t.Fatalf("Read: %v", rerr)
			}
		}
		w, err := c.NextWriter(op)
		if err != nil {
			t.Fatalf("NextWriter: %v", err)
		}
		if _, err := w.Write(scratch[:n]); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for range 8 {
		echo()
	}
	allocs := testing.AllocsPerRun(200, echo)
	t.Logf("streaming echo allocs/op = %v (race=%v)", allocs, raceEnabledInternal)
	if !raceEnabledInternal && allocs > 2 {
		t.Errorf("streaming echo allocs/op = %v, want <= 2 (reader + writer handles)", allocs)
	}
}

// --- benchmarks -------------------------------------------------------------

func BenchmarkConnReadMessage(b *testing.B) {
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, 1024))
	c := NewServerConn(&loopConn{frame: frame})
	b.SetBytes(1024)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := c.ReadMessage(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnWriteMessage(b *testing.B) {
	c := NewServerConn(&loopConn{frame: []byte{0x00}})
	payload := bytes.Repeat([]byte{0x41}, 1024)
	b.SetBytes(1024)
	b.ReportAllocs()
	for b.Loop() {
		if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnWriteMessage16KB(b *testing.B) {
	c := NewServerConn(&loopConn{frame: []byte{0x00}})
	payload := bytes.Repeat([]byte{0x41}, 16<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConnReadMessage16KB exercises adaptive zero-copy growth for a
// bounded single frame. BenchmarkConnReadMessage64KB remains above that bound
// and exercises readFramePayload's direct-to-reassembly path.
func BenchmarkConnReadMessage16KB(b *testing.B) {
	const size = 16 << 10
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, size))
	c := NewServerConn(&loopConn{frame: frame})
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := c.ReadMessage(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnReadMessage64KB(b *testing.B) {
	const size = 64 << 10
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, size))
	c := NewServerConn(&loopConn{frame: frame})
	b.SetBytes(size)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := c.ReadMessage(); err != nil {
			b.Fatal(err)
		}
	}
}
