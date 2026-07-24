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
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// readWireFrame reads exactly one control-sized (<126-byte payload)
// frame from the raw side of a pipe, unmasking it.
func readWireFrame(t *testing.T, c net.Conn) frameRec {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("readWireFrame: header: %v", err)
	}
	rest := int(hdr[1] & 0x7f)
	if hdr[1]&0x80 != 0 {
		rest += 4
	}
	buf := make([]byte, rest)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("readWireFrame: body: %v", err)
	}
	frames := parseFrames(t, append(hdr, buf...))
	if len(frames) != 1 {
		t.Fatalf("readWireFrame: parsed %d frames, want 1", len(frames))
	}
	return frames[0]
}

// assertNoWireBytes asserts nothing arrives on c within a short window,
// proving a rejected call put nothing on the wire.
func assertNoWireBytes(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	one := make([]byte, 1)
	n, err := c.Read(one)
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unexpected wire activity: n=%d err=%v", n, err)
	}
	_ = c.SetReadDeadline(time.Time{})
}

func TestWriteClose(t *testing.T) {
	longestReason := strings.Repeat("r", 123)

	tests := map[string]struct {
		code    CloseCode
		reason  string
		wantErr error
	}{
		"success: normal code with reason": {code: CloseNormalClosure, reason: "bye"},
		"success: empty reason":            {code: CloseNormalClosure},
		"success: 123-byte reason":         {code: CloseNormalClosure, reason: longestReason},
		"error: zero code":                 {code: 0, wantErr: ErrInvalidCloseCode},
		"error: reserved 1005":             {code: CloseNoStatusReceived, wantErr: ErrInvalidCloseCode},
		"error: 124-byte reason":           {code: CloseNormalClosure, reason: longestReason + "r", wantErr: ErrCloseReasonTooLong},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			c := NewServerConn(a)

			errCh := make(chan error, 1)
			go func() { errCh <- c.WriteClose(tt.code, tt.reason) }()

			if tt.wantErr == nil {
				f := readWireFrame(t, b)
				if f.h.Opcode != OpcodeClose || !f.h.Fin {
					t.Fatalf("wire frame = %+v, want a Fin Close frame", f.h)
				}
				code, reason, perr := ParseCloseBody(f.payload)
				if perr != nil || code != tt.code || string(reason) != tt.reason {
					t.Fatalf("close body = (%d, %q, %v), want (%d, %q)", code, reason, perr, tt.code, tt.reason)
				}
				if err := <-errCh; err != nil {
					t.Fatalf("WriteClose = %v, want nil", err)
				}
				return
			}

			err := <-errCh
			if err == nil {
				t.Fatal("WriteClose = nil, want validation error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("WriteClose = %v, want errors.Is %v", err, tt.wantErr)
			}
			assertNoWireBytes(t, b)
		})
	}
}

func TestWriteCloseIdempotent(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := NewServerConn(a)

	done := make(chan error, 2)
	go func() {
		done <- c.WriteClose(CloseNormalClosure, "first")
		done <- c.WriteClose(CloseGoingAway, "second")
	}()

	f := readWireFrame(t, b)
	code, reason, err := ParseCloseBody(f.payload)
	if err != nil || code != CloseNormalClosure || string(reason) != "first" {
		t.Fatalf("close body = (%d, %q, %v), want (1000, \"first\")", code, reason, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("first WriteClose = %v, want nil", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("second WriteClose = %v, want idempotent nil", err)
	}
	assertNoWireBytes(t, b)
}

// failWriteConn fails every Write, for exercising transport-error
// propagation out of the close-frame write.
type failWriteConn struct {
	net.Conn
	err error
}

func (c *failWriteConn) Write(p []byte) (int, error) { return 0, c.err }

type deadlineCaptureConn struct {
	net.Conn
	deadlineErr error
	writeErr    error
	deadline    time.Time
	closed      bool
}

func (c *deadlineCaptureConn) SetDeadline(tm time.Time) error {
	c.deadline = tm
	return c.deadlineErr
}

func (c *deadlineCaptureConn) Write([]byte) (int, error) {
	return 0, c.writeErr
}

func (c *deadlineCaptureConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func TestWriteCloseWriteError(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	boom := errors.New("transport exploded")
	c := NewServerConn(&failWriteConn{Conn: a, err: boom})

	if err := c.WriteClose(CloseNormalClosure, "bye"); !errors.Is(err, boom) {
		t.Fatalf("WriteClose = %v, want the transport error", err)
	}
	// The Close frame was consumed by the attempt (closeSent), so a
	// retry reports the idempotent nil rather than re-emitting.
	if err := c.WriteClose(CloseNormalClosure, "bye"); err != nil {
		t.Fatalf("second WriteClose = %v, want nil", err)
	}
}

func TestWriteCloseConcurrent(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := NewServerConn(a)

	// Drain everything the pipe delivers within the window; net.Pipe is
	// synchronous, so the successful writer completes only through this.
	var wire []byte
	wireDone := make(chan struct{})
	go func() {
		defer close(wireDone)
		_ = b.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 512)
		for {
			n, err := b.Read(buf)
			wire = append(wire, buf[:n]...)
			if err != nil {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			errs[i] = c.WriteClose(CloseNormalClosure, "bye")
		})
	}
	wg.Wait()
	<-wireDone

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent WriteClose[%d] = %v, want nil", i, err)
		}
	}
	frames := parseFrames(t, wire)
	if len(frames) != 1 || frames[0].h.Opcode != OpcodeClose {
		t.Fatalf("wire carried %d frames (%v), want exactly one Close", len(frames), frames)
	}
}

// TestWriteCloseWithActiveReader pins the coexistence contract: a
// blocked reader keeps consuming data frames while WriteClose runs, a
// post-Close inbound Ping is tolerated without a Pong (RFC 6455
// §5.5.3), and the peer's eventual Close surfaces as the reader's
// [*CloseError].
func TestWriteCloseWithActiveReader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := NewServerConn(a)

	type msg struct {
		op      Opcode
		payload string
	}
	msgs := make(chan msg, 4)
	readerErr := make(chan error, 1)
	go func() {
		for {
			op, p, err := c.ReadMessage()
			if err != nil {
				readerErr <- err
				return
			}
			msgs <- msg{op, string(p)}
		}
	}()

	if _, err := b.Write(clientFrame(true, OpcodeText, []byte("hello"))); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	if m := <-msgs; m.payload != "hello" {
		t.Fatalf("first message = %q, want \"hello\"", m.payload)
	}

	wcErr := make(chan error, 1)
	go func() { wcErr <- c.WriteClose(CloseNormalClosure, "bye") }()
	f := readWireFrame(t, b)
	if f.h.Opcode != OpcodeClose {
		t.Fatalf("peer received %v, want the Close frame", f.h.Opcode)
	}
	if err := <-wcErr; err != nil {
		t.Fatalf("WriteClose = %v, want nil", err)
	}

	// A Ping after this side's Close must neither be answered nor kill
	// the reader; a following data frame proves the reader survived.
	if _, err := b.Write(clientFrame(true, OpcodePing, []byte("p"))); err != nil {
		t.Fatalf("peer ping write: %v", err)
	}
	if _, err := b.Write(clientFrame(true, OpcodeText, []byte("world"))); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	if m := <-msgs; m.payload != "world" {
		t.Fatalf("post-ping message = %q, want \"world\"", m.payload)
	}

	if _, err := b.Write(closeFrame(CloseNormalClosure, "done")); err != nil {
		t.Fatalf("peer close write: %v", err)
	}
	err := <-readerErr
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseNormalClosure || ce.Reason != "done" || ce.Sent {
		t.Fatalf("reader error = %v, want received *CloseError(1000, \"done\")", err)
	}

	// Teardown (on the reader's goroutine) closed the transport.
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer read succeeded after teardown, want closed transport")
	}
}

func TestCloseContextSuccess(t *testing.T) {
	a, b := net.Pipe()
	c := NewServerConn(a)
	peer := NewClientConn(b)

	peerErr := make(chan error, 1)
	go func() {
		_, _, err := peer.ReadMessage()
		peerErr <- err
	}()

	if err := c.CloseContext(t.Context(), CloseNormalClosure, "done"); err != nil {
		t.Fatalf("CloseContext = %v, want nil", err)
	}
	var ce *CloseError
	if err := <-peerErr; !errors.As(err, &ce) || ce.Code != CloseNormalClosure || ce.Reason != "done" {
		t.Fatalf("peer reader = %v, want *CloseError(1000, \"done\")", err)
	}
	if err := c.CloseContext(t.Context(), CloseNormalClosure, "again"); err != nil {
		t.Fatalf("second CloseContext = %v, want idempotent nil", err)
	}
}

func TestCloseContextValidationLeavesConnUsable(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := NewServerConn(a)

	if err := c.CloseContext(t.Context(), 0, ""); err == nil {
		t.Fatal("CloseContext(0) = nil, want validation error")
	}
	assertNoWireBytes(t, b)

	// Validation precedes every side effect: the connection is neither
	// torn down nor poisoned, so a valid close still completes.
	done := make(chan error, 1)
	go func() { done <- c.WriteClose(CloseNormalClosure, "ok") }()
	f := readWireFrame(t, b)
	if f.h.Opcode != OpcodeClose {
		t.Fatalf("frame after rejected CloseContext = %v, want Close", f.h.Opcode)
	}
	if err := <-done; err != nil {
		t.Fatalf("WriteClose after rejected CloseContext = %v, want nil", err)
	}
}

func TestCloseContextAlreadyCanceled(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewServerConn(a)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := c.CloseContext(ctx, CloseNormalClosure, "late")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ctx.Err()) {
		t.Fatalf("CloseContext = %v, want errors.Is ctx.Err (context.Canceled)", err)
	}
	// Nothing was written and the transport is closed.
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	n, rerr := b.Read(make([]byte, 1))
	if n != 0 || rerr == nil {
		t.Fatalf("peer read = (%d, %v), want (0, closed-transport error)", n, rerr)
	}
	if errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Fatalf("peer read timed out (%v): connection was not closed", rerr)
	}
}

func TestCloseContextCancelCauseMatchesErrAndCause(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewServerConn(a)
	cause := errors.New("close canceled by caller")
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(cause)

	err := c.CloseContext(ctx, CloseNormalClosure, "late")
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("CloseContext = %v, want errors.Is ctx.Err (%v)", err, ctx.Err())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("CloseContext = %v, want errors.Is cancel cause", err)
	}
}

func TestCloseContextUsesCallerAbsoluteDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	armErr := errors.New("deadline rejected")
	rec := &deadlineCaptureConn{
		Conn:        a,
		deadlineErr: armErr,
		writeErr:    errors.New("write should not be reached"),
	}
	c := NewServerConn(rec, WithCloseTimeout(time.Nanosecond))
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()

	err := c.CloseContext(ctx, CloseNormalClosure, "bye")
	if !errors.Is(err, armErr) {
		t.Fatalf("CloseContext = %v, want errors.Is SetDeadline failure", err)
	}
	if !rec.deadline.Equal(deadline) {
		t.Fatalf("SetDeadline = %v, want caller deadline %v", rec.deadline, deadline)
	}
	if !rec.closed {
		t.Error("CloseContext left the raw connection open after SetDeadline failed")
	}
}

func TestCloseContextCanceledDuringPeerCloseWait(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewServerConn(a)

	ctx, cancel := context.WithCancel(t.Context())
	sawClose := make(chan struct{})
	go func() {
		f := readWireFrame(t, b)
		if f.h.Opcode == OpcodeClose {
			close(sawClose)
		}
		// Never reply: only cancellation can unblock the drain.
	}()
	go func() {
		<-sawClose
		cancel()
	}()

	start := time.Now()
	err := c.CloseContext(ctx, CloseNormalClosure, "going away")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ctx.Err()) {
		t.Fatalf("CloseContext = %v, want errors.Is ctx.Err (context.Canceled)", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("CloseContext took %v to observe cancellation", elapsed)
	}
	// The force-close released the transport.
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	if _, rerr := b.Read(make([]byte, 1)); rerr == nil || errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Fatalf("peer read = %v, want closed-transport error", rerr)
	}
}

// TestCloseContextBlockedWriteBounded pins the single-budget contract on
// the write phase: a peer that never reads blocks the Close-frame write
// (net.Pipe is synchronous), and the whole call still ends within one
// close-timeout budget -- not the write-timeout-plus-wait-timeout double
// budget the API explicitly rejects.
func TestCloseContextBlockedWriteBounded(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close() // b never reads during the call; net.Pipe blocks the write
	c := NewServerConn(a, WithCloseTimeout(500*time.Millisecond))

	start := time.Now()
	err := c.CloseContext(t.Context(), CloseNormalClosure, "bye")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrCloseTimeout) {
		t.Fatalf("CloseContext = %v, want errors.Is ErrCloseTimeout", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("CloseContext = %v, want the deadline cause in the chain", err)
	}
	if elapsed < 400*time.Millisecond || elapsed > 950*time.Millisecond {
		t.Fatalf("CloseContext took %v, want roughly one 500ms budget (no per-phase extension)", elapsed)
	}
}

// TestCloseContextDrainBounded is the read-phase twin: the write goes
// through, the peer never sends its Close, and write plus drain share
// the one absolute deadline.
func TestCloseContextDrainBounded(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := NewServerConn(a, WithCloseTimeout(500*time.Millisecond))

	go func() {
		readWireFrame(t, b) // consume the Close frame, then go silent
	}()

	start := time.Now()
	err := c.CloseContext(t.Context(), CloseNormalClosure, "bye")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrCloseTimeout) {
		t.Fatalf("CloseContext = %v, want errors.Is ErrCloseTimeout", err)
	}
	if elapsed < 400*time.Millisecond || elapsed > 950*time.Millisecond {
		t.Fatalf("CloseContext took %v, want roughly one 500ms budget (no per-phase extension)", elapsed)
	}
}

func TestCloseContextDeadlineFromContext(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	// The Conn's own close timeout is far larger; the ctx deadline must
	// be the binding half of the single absolute deadline.
	c := NewServerConn(a, WithCloseTimeout(30*time.Second))

	go func() {
		readWireFrame(t, b) // consume the Close frame, never reply
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.CloseContext(ctx, CloseNormalClosure, "bye")
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext = %v, want errors.Is context.DeadlineExceeded", err)
	}
	if elapsed > 950*time.Millisecond {
		t.Fatalf("CloseContext took %v, want the ctx deadline to bind", elapsed)
	}
}

// TestCloseContextCancelRace drives cancellation into the success
// boundary -- the peer's Close echo and ctx cancellation race by
// construction (both are released by the peer observing the closing
// handshake) -- and accepts either outcome while the race detector
// checks the callback synchronization. Exercised repeatedly under
// -race -count=100 by the verification gates.
func TestCloseContextCancelRace(t *testing.T) {
	a, b := net.Pipe()
	c := NewServerConn(a)
	peer := NewClientConn(b)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		_, _, _ = peer.ReadMessage() // observes Close, echoes, tears down
	}()
	cancelerDone := make(chan struct{})
	go func() {
		defer close(cancelerDone)
		<-peerDone
		cancel()
	}()

	err := c.CloseContext(ctx, CloseNormalClosure, "racing")
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("CloseContext = %v, want nil or errors.Is context.Canceled", err)
	}
	<-peerDone
	<-cancelerDone
	// Whatever the outcome, the Conn is closed and stays idempotent.
	if err := c.CloseContext(ctx, CloseNormalClosure, "again"); err != nil {
		t.Fatalf("follow-up CloseContext = %v, want nil", err)
	}
}
