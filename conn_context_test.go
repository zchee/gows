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
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// deadlineCountConn counts every deadline change on the transport it wraps.
type deadlineCountConn struct {
	*closeCountConn
	deadlines atomic.Int32
}

func (c *deadlineCountConn) SetDeadline(t time.Time) error {
	c.deadlines.Add(1)
	return c.closeCountConn.SetDeadline(t)
}

func (c *deadlineCountConn) SetReadDeadline(t time.Time) error {
	c.deadlines.Add(1)
	return c.closeCountConn.SetReadDeadline(t)
}

func (c *deadlineCountConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.Add(1)
	return c.closeCountConn.SetWriteDeadline(t)
}

// endedContexts are the two ways a context ends. Each returns the context,
// a function that ends it, and the cause the call's error must also match,
// when there is a distinct one. The test ends each context itself, so no
// timer decides whether the call blocked first.
var endedContexts = map[string]func(testing.TB) (ctx context.Context, end func(), cause error){
	"canceled with cause": func(tb testing.TB) (context.Context, func(), error) {
		cause := errors.New("caller gave up")
		ctx, cancel := context.WithCancelCause(tb.Context())
		return ctx, func() { cancel(cause) }, cause
	},
	"deadline exceeded": func(tb testing.TB) (context.Context, func(), error) {
		ctx := newDeadlineContext(tb.Context())
		return ctx, ctx.end, nil
	},
}

// deadlineContext is a context whose deadline passes when the test calls end:
// Done closes and Err reports [context.DeadlineExceeded], as for a context
// whose timer fired. Values come from the parent.
type deadlineContext struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newDeadlineContext(parent context.Context) *deadlineContext {
	return &deadlineContext{Context: parent, done: make(chan struct{})}
}

func (c *deadlineContext) Done() <-chan struct{} { return c.done }

func (c *deadlineContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *deadlineContext) end() { c.once.Do(func() { close(c.done) }) }

// awaitEntered waits until a call has reached the transport. The call must
// not return before its context ends; when it has returned anyway, entered
// is checked again so the failure says whether it reached the transport.
func awaitEntered(t *testing.T, what string, entered <-chan struct{}, result <-chan error) {
	t.Helper()
	select {
	case <-entered:
	case err := <-result:
		select {
		case <-entered:
			t.Fatalf("%s reached the transport but returned %v before its context ended", what, err)
		default:
			t.Fatalf("%s returned %v before reaching the transport", what, err)
		}
	}
}

// wantContextError fails the test unless err matches ctx.Err and, when
// given, the distinct cancellation cause.
func wantContextError(t *testing.T, what string, err error, ctx context.Context, cause error) {
	t.Helper()
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("%s = %v, want errors.Is %v", what, err, ctx.Err())
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("%s = %v, want errors.Is the cause %v", what, err, cause)
	}
}

func TestReadWriteMessageContextSuccess(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	cc := newCloseCountConn(a)
	c := NewServerConn(cc)
	ctx, cancel := context.WithCancel(t.Context())

	go func() { _, _ = b.Write(clientFrame(true, OpcodeText, []byte("in"))) }()
	op, p, err := c.ReadMessageContext(ctx)
	if err != nil || op != OpcodeText || string(p) != "in" {
		t.Fatalf("ReadMessageContext = (%v, %q, %v), want (Text, \"in\", nil)", op, p, err)
	}

	got := make(chan []frameRec, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := b.Read(buf)
		got <- parseFrames(t, buf[:n])
	}()
	if err := c.WriteMessageContext(ctx, OpcodeBinary, []byte("out")); err != nil {
		t.Fatalf("WriteMessageContext = %v, want nil", err)
	}
	if f := <-got; len(f) != 1 || f[0].h.Opcode != OpcodeBinary || string(f[0].payload) != "out" {
		t.Fatalf("peer received %+v, want one Binary \"out\" frame", f)
	}

	// Ending ctx after the calls returned does not touch the connection.
	cancel()
	go func() { _, _ = b.Write(clientFrame(true, OpcodeText, []byte("again"))) }()
	if _, p, err := c.ReadMessage(); err != nil || string(p) != "again" {
		t.Fatalf("ReadMessage after ctx ended = (%q, %v), want (\"again\", nil)", p, err)
	}
	if n := cc.closes.Load(); n != 0 {
		t.Fatalf("transport closed %d times after successful calls, want 0", n)
	}
}

func TestReadWriteMessageContextAlreadyEnded(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	cc := newCloseCountConn(a)
	c := NewServerConn(cc)
	cause := errors.New("ended before the call")
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(cause)

	_, _, err := c.ReadMessageContext(ctx)
	wantContextError(t, "ReadMessageContext", err, ctx, cause)
	err = c.WriteMessageContext(ctx, OpcodeText, []byte("never"))
	wantContextError(t, "WriteMessageContext", err, ctx, cause)

	// No I/O happened and the connection is untouched and usable.
	select {
	case <-cc.readEntered:
		t.Fatal("ReadMessageContext read from the transport")
	case <-cc.writeEntered:
		t.Fatal("WriteMessageContext wrote to the transport")
	default:
	}
	if n := cc.closes.Load(); n != 0 {
		t.Fatalf("transport closed %d times, want 0", n)
	}
	go func() { _, _ = b.Write(clientFrame(true, OpcodeText, []byte("ok"))) }()
	if _, p, err := c.ReadMessage(); err != nil || string(p) != "ok" {
		t.Fatalf("ReadMessage afterwards = (%q, %v), want (\"ok\", nil)", p, err)
	}
}

func TestReadMessageContextEndsWhileBlocked(t *testing.T) {
	t.Parallel()
	for name, newCtx := range endedContexts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := net.Pipe()
			defer b.Close()
			cc := newCloseCountConn(a)
			c := NewServerConn(cc)
			ctx, end, cause := newCtx(t)

			readErr := make(chan error, 1)
			go func() {
				_, _, err := c.ReadMessageContext(ctx)
				readErr <- err
			}()
			awaitEntered(t, "ReadMessageContext", cc.readEntered, readErr)
			end()
			err := awaitResult(t, "ReadMessageContext", readErr)
			wantContextError(t, "ReadMessageContext", err, ctx, cause)

			// The connection is closed, once, and the read side released.
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
			if c.rbuf != nil || !c.tornDown.Load() {
				t.Fatal("ReadMessageContext returned without releasing the read side")
			}
			if n, err := b.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("peer Read = (%d, %v), want (0, io.EOF)", n, err)
			}
			wantStickyReadError(t, c, err)
		})
	}
}

func TestWriteMessageContextEndsWhileBlocked(t *testing.T) {
	t.Parallel()
	for name, newCtx := range endedContexts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := net.Pipe()
			defer b.Close()
			cc := newCloseCountConn(a)
			c := NewServerConn(cc)
			ctx, end, cause := newCtx(t)

			// The peer never reads, so the pipe blocks the write.
			writeErr := make(chan error, 1)
			go func() { writeErr <- c.WriteMessageContext(ctx, OpcodeBinary, []byte("stuck")) }()
			awaitEntered(t, "WriteMessageContext", cc.writeEntered, writeErr)
			end()
			wantContextError(t, "WriteMessageContext", awaitResult(t, "WriteMessageContext", writeErr), ctx, cause)

			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
			wantClosed(t, "later WriteMessage", c.WriteMessage(OpcodeText, []byte("late")))
			// The write side does not own the read buffers; Close releases them.
			if err := c.Close(CloseNormalClosure, ""); err != nil {
				t.Fatalf("Close = %v, want nil", err)
			}
			if c.rbuf != nil {
				t.Fatal("Close did not release the read buffers")
			}
		})
	}
}

// TestWriteMessageContextLeavesReaderDeadline pins that the context variants
// never set a deadline on the transport: a deadline would replace the one a
// concurrent reader or writer relies on.
func TestWriteMessageContextLeavesReaderDeadline(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	dc := &deadlineCountConn{closeCountConn: newCloseCountConn(a)}
	c := NewServerConn(dc)
	go func() { _, _ = io.Copy(io.Discard, b) }()

	readErr := make(chan error, 1)
	go func() {
		_, _, err := c.ReadMessageContext(t.Context())
		readErr <- err
	}()
	<-dc.readEntered

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for range 10 {
		if err := c.WriteMessageContext(ctx, OpcodeText, []byte("beside the reader")); err != nil {
			t.Fatalf("WriteMessageContext = %v, want nil", err)
		}
	}
	if n := dc.deadlines.Load(); n != 0 {
		t.Fatalf("context calls set %d deadlines on the transport, want 0", n)
	}
	select {
	case err := <-readErr:
		t.Fatalf("the blocked reader returned %v while only writes ran", err)
	default:
	}
	_ = c.CloseNow()
	wantClosed(t, "reader after CloseNow", awaitResult(t, "ReadMessageContext", readErr))
}

func TestMessageContextNeverEndingAllocs(t *testing.T) {
	frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{0x7f}, 1024))
	r := NewServerConn(&loopConn{frame: frame})
	w := NewServerConn(&loopConn{frame: []byte{0x00}})
	payload := bytes.Repeat([]byte{0x41}, 1024)
	ctx := context.WithoutCancel(t.Context())
	if ctx.Done() != nil {
		t.Fatal("context.WithoutCancel returned a context that can end")
	}
	for range 8 {
		if _, _, err := r.ReadMessageContext(ctx); err != nil {
			t.Fatalf("warmup read: %v", err)
		}
		if err := w.WriteMessageContext(ctx, OpcodeBinary, payload); err != nil {
			t.Fatalf("warmup write: %v", err)
		}
	}
	readAllocs := testing.AllocsPerRun(500, func() { _, _, _ = r.ReadMessageContext(ctx) })
	writeAllocs := testing.AllocsPerRun(500, func() { _ = w.WriteMessageContext(ctx, OpcodeBinary, payload) })
	t.Logf("never-ending ctx: ReadMessageContext allocs/op = %v, WriteMessageContext allocs/op = %v (race=%v)", readAllocs, writeAllocs, RaceEnabled)
	if !RaceEnabled && (readAllocs != 0 || writeAllocs != 0) {
		t.Errorf("allocs/op = (read %v, write %v), want (0, 0)", readAllocs, writeAllocs)
	}
}

func TestMessageContextModeExclusion(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := NewServerConn(a)
	go func() { _, _ = io.Copy(io.Discard, b) }()
	if err := c.WriteFrame(OpcodeText, true, []byte("x"), false); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := c.ReadMessageContext(ctx); !errors.Is(err, ErrConnMode) {
		t.Fatalf("ReadMessageContext on a frame-mode Conn = %v, want ErrConnMode", err)
	}
	if err := c.WriteMessageContext(ctx, OpcodeText, nil); !errors.Is(err, ErrConnMode) {
		t.Fatalf("WriteMessageContext on a frame-mode Conn = %v, want ErrConnMode", err)
	}
}

// cancelOnReadConn ends the call's context from inside its first Read,
// waits until the context's callback has closed the transport, and then
// still returns a whole frame, so the read succeeds exactly as the context
// ends.
type cancelOnReadConn struct {
	net.Conn
	frame     []byte
	cancel    func()
	served    bool
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *cancelOnReadConn) Read(p []byte) (int, error) {
	if c.served {
		<-c.closed
		return 0, net.ErrClosed
	}
	c.served = true
	c.cancel()
	<-c.closed
	return copy(p, c.frame), nil
}

func (c *cancelOnReadConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// TestReadMessageContextEndsAsReadSucceeds pins the call whose context ends
// just as its read completes: the connection is already closed, so the call
// drops the message, reports the context error, releases the read side, and
// leaves that error sticky for later reads.
func TestReadMessageContextEndsAsReadSucceeds(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cause := errors.New("caller gave up")
	ctx, cancel := context.WithCancelCause(t.Context())
	tc := &cancelOnReadConn{
		Conn:   a,
		frame:  clientFrame(true, OpcodeText, []byte("dropped")),
		cancel: func() { cancel(cause) },
		closed: make(chan struct{}),
	}
	c := NewServerConn(tc)

	op, p, err := c.ReadMessageContext(ctx)
	if op != 0 || p != nil {
		t.Fatalf("ReadMessageContext = (%v, %q, %v), want no message", op, p, err)
	}
	wantContextError(t, "ReadMessageContext", err, ctx, cause)
	if c.rbuf != nil || !c.tornDown.Load() {
		t.Fatal("ReadMessageContext returned without releasing the read side")
	}
	wantStickyReadError(t, c, err)
}

// wantStickyReadError fails the test unless every later read entry point
// returns exactly err, the error a context call returned when its context
// closed the connection.
func wantStickyReadError(t *testing.T, c *Conn, err error) {
	t.Helper()
	if _, _, again := c.ReadMessage(); again != err {
		t.Fatalf("later ReadMessage = %v, want the same error %v", again, err)
	}
	if _, _, again := c.ReadMessageContext(t.Context()); again != err {
		t.Fatalf("later ReadMessageContext = %v, want the same error %v", again, err)
	}
	if again := c.Serve(func(Opcode, []byte) error { return nil }); again != err {
		t.Fatalf("later Serve = %v, want the same error %v", again, err)
	}
	if _, _, again := c.NextReader(); again != err {
		t.Fatalf("later NextReader = %v, want the same error %v", again, err)
	}
}

// gatedCloseConn ends the call's context from inside Write and lets the write
// succeed once the context's callback is inside Close, where the callback
// then stays until the test opens gate.
type gatedCloseConn struct {
	*scriptConn
	cancel       func()
	closeEntered chan struct{}
	gate         chan struct{}
}

func (c *gatedCloseConn) Write(p []byte) (int, error) {
	c.cancel()
	<-c.closeEntered
	return len(p), nil
}

func (c *gatedCloseConn) Close() error {
	close(c.closeEntered)
	<-c.gate
	return nil
}

// TestWriteMessageContextWaitsForCallback pins that a context call does not
// return while the callback its context started is still closing the
// connection, so nothing that callback does can follow the return. The
// synctest bubble makes "the call is still waiting" observable without a
// timer: once every goroutine is blocked, the call must not have returned.
func TestWriteMessageContextWaitsForCallback(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		tc := &gatedCloseConn{
			scriptConn:   &scriptConn{},
			cancel:       cancel,
			closeEntered: make(chan struct{}),
			gate:         make(chan struct{}),
		}
		c := NewServerConn(tc)

		result := make(chan error, 1)
		go func() { result <- c.WriteMessageContext(ctx, OpcodeText, []byte("written")) }()
		synctest.Wait()
		select {
		case err := <-result:
			close(tc.gate) // let the callback finish so the bubble can exit
			t.Fatalf("WriteMessageContext returned %v while its context's callback was still closing the connection", err)
		default:
		}
		close(tc.gate)
		wantContextError(t, "WriteMessageContext", <-result, ctx, nil)
		wantClosed(t, "later WriteMessage", c.WriteMessage(OpcodeText, []byte("late")))
	})
}
