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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// closeCountConn counts Close calls on the transport it wraps and reports
// the first Write and Read that reach it, so a test can act once a call is
// inside the transport. Wrapping hides *net.TCPConn, so a Conn over it uses
// the staged write path.
type closeCountConn struct {
	net.Conn
	closes       atomic.Int32
	writeOnce    sync.Once
	writeEntered chan struct{}
	readOnce     sync.Once
	readEntered  chan struct{}
}

func newCloseCountConn(c net.Conn) *closeCountConn {
	return &closeCountConn{Conn: c, writeEntered: make(chan struct{}), readEntered: make(chan struct{})}
}

func (c *closeCountConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeEntered) })
	return c.Conn.Write(p)
}

func (c *closeCountConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readEntered) })
	return c.Conn.Read(p)
}

func (c *closeCountConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// transportPairs are the two transports the abrupt-close tests run on: a
// synchronous in-memory pipe, whose closed end reports io.ErrClosedPipe, and
// loopback TCP, whose closed end reports net.ErrClosed.
var transportPairs = map[string]func(testing.TB) (net.Conn, net.Conn){
	"pipe": func(testing.TB) (net.Conn, net.Conn) { return net.Pipe() },
	"tcp":  loopbackPair,
}

// wantClosed fails the test unless err reports a closed connection.
func wantClosed(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s = %v, want errors.Is net.ErrClosed", what, err)
	}
}

// awaitResult waits for one result from ch, failing the test if the blocked
// call that sends it was not released.
func awaitResult[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("%s was still blocked 10s after it should have been released", what)
		panic("unreachable")
	}
}

func TestCloseNowReleasesBlockedReader(t *testing.T) {
	t.Parallel()
	for name, pair := range transportPairs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, peer := pair(t)
			defer peer.Close()
			cc := newCloseCountConn(raw)
			c := NewServerConn(cc)

			readErr := make(chan error, 1)
			go func() {
				_, _, err := c.ReadMessage()
				readErr <- err
			}()
			<-cc.readEntered
			if err := c.CloseNow(); err != nil {
				t.Fatalf("CloseNow = %v, want nil", err)
			}
			err := awaitResult(t, "ReadMessage", readErr)
			wantClosed(t, "blocked ReadMessage", err)

			// The reader released the buffers when it saw the closed transport,
			// and its error is sticky.
			if c.rbuf != nil || !c.tornDown.Load() {
				t.Fatalf("after the reader returned: rbuf=%v tornDown=%v, want released and torn down", c.rbuf != nil, c.tornDown.Load())
			}
			_, _, again := c.ReadMessage()
			wantClosed(t, "later ReadMessage", again)
			wantClosed(t, "later WriteMessage", c.WriteMessage(OpcodeText, []byte("late")))
			if err := c.Close(CloseNormalClosure, ""); err != nil {
				t.Fatalf("Close after CloseNow = %v, want nil", err)
			}
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
		})
	}
}

func TestCloseNowReleasesServe(t *testing.T) {
	t.Parallel()
	for name, pair := range transportPairs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, peer := pair(t)
			defer peer.Close()
			cc := newCloseCountConn(raw)
			c := NewServerConn(cc)

			// One message first, so Serve is past its handler and blocked in
			// its next read when CloseNow runs.
			handled := make(chan struct{}, 1)
			serveErr := make(chan error, 1)
			go func() {
				serveErr <- c.Serve(func(Opcode, []byte) error {
					handled <- struct{}{}
					return nil
				})
			}()
			if _, err := peer.Write(clientFrame(true, OpcodeText, []byte("hi"))); err != nil {
				t.Fatalf("peer write: %v", err)
			}
			<-handled
			if err := c.CloseNow(); err != nil {
				t.Fatalf("CloseNow = %v, want nil", err)
			}
			err := awaitResult(t, "Serve", serveErr)
			wantClosed(t, "Serve", err)
			wantServeEnded(t, c, err)
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
		})
	}
}

// TestCloseNowWithBufferedRepliesEndsServe covers CloseNow running while a
// Serve handler's replies are still buffered: Serve's own Flush then fails
// instead of its read, and Serve must end the read side all the same.
func TestCloseNowWithBufferedRepliesEndsServe(t *testing.T) {
	t.Parallel()
	for name, pair := range transportPairs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, peer := pair(t)
			defer peer.Close()
			cc := newCloseCountConn(raw)
			c := NewServerConn(cc)

			go func() { _, _ = peer.Write(clientFrame(true, OpcodeText, []byte("hi"))) }()
			err := c.Serve(func(op Opcode, p []byte) error {
				if err := c.WriteMessageBuffered(op, p); err != nil {
					return err
				}
				return c.CloseNow()
			})
			wantClosed(t, "Serve", err)
			wantServeEnded(t, c, err)
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
		})
	}
}

// wantServeEnded fails the test unless the Serve that returned err released
// the Conn's buffers and recorded err as the sticky read error.
func wantServeEnded(t *testing.T, c *Conn, err error) {
	t.Helper()
	if c.rbuf != nil || c.wbatch != nil || !c.tornDown.Load() {
		t.Fatalf("after Serve returned: rbuf=%v wbatch=%v tornDown=%v, want both released and torn down", c.rbuf != nil, c.wbatch != nil, c.tornDown.Load())
	}
	if _, _, again := c.ReadMessage(); again != err {
		t.Fatalf("later ReadMessage = %v, want Serve's error %v", again, err)
	}
	if again := c.Serve(func(Opcode, []byte) error { return nil }); again != err {
		t.Fatalf("later Serve = %v, want Serve's error %v", again, err)
	}
}

func TestCloseNowReleasesNextReaderStream(t *testing.T) {
	t.Parallel()
	for name, pair := range transportPairs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, peer := pair(t)
			defer peer.Close()
			c := NewServerConn(raw)

			// The peer sends a 100-byte frame's header and first 10 bytes;
			// the stream reads those and then blocks for the rest.
			frame := clientFrame(true, OpcodeBinary, bytes.Repeat([]byte{'x'}, 100))
			go func() { _, _ = peer.Write(frame[:2+4+10]) }()
			_, r, err := c.NextReader()
			if err != nil {
				t.Fatalf("NextReader: %v", err)
			}
			buf := make([]byte, 100)
			got := 0
			for got < 10 {
				n, err := r.Read(buf[got:])
				if err != nil {
					t.Fatalf("stream Read: %v", err)
				}
				got += n
			}

			readErr := make(chan error, 1)
			go func() {
				_, err := r.Read(buf[got:])
				readErr <- err
			}()
			if err := c.CloseNow(); err != nil {
				t.Fatalf("CloseNow = %v, want nil", err)
			}
			wantClosed(t, "blocked stream Read", awaitResult(t, "stream Read", readErr))
		})
	}
}

func TestCloseNowReleasesBlockedWriter(t *testing.T) {
	t.Parallel()
	for name, pair := range transportPairs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, peer := pair(t)
			defer peer.Close()
			cc := newCloseCountConn(raw)
			c := NewServerConn(cc)

			// The peer never reads. A pipe blocks the first Write; on TCP a
			// payload far larger than the socket buffers blocks it.
			payload := make([]byte, 64<<20)
			writeErr := make(chan error, 1)
			go func() { writeErr <- c.WriteMessage(OpcodeBinary, payload) }()
			<-cc.writeEntered

			// The writer holds the write lock while blocked: CloseNow returns
			// only because it closes the transport before taking that lock.
			closed := make(chan error, 1)
			go func() { closed <- c.CloseNow() }()
			if err := awaitResult(t, "CloseNow", closed); err != nil {
				t.Fatalf("CloseNow = %v, want nil", err)
			}
			wantClosed(t, "blocked WriteMessage", awaitResult(t, "WriteMessage", writeErr))
			wantClosed(t, "later WriteMessage", c.WriteMessage(OpcodeText, []byte("late")))
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
		})
	}
}

func TestCloseNowTLS(t *testing.T) {
	raw, peer := loopbackPair(t)
	if err := raw.(*net.TCPConn).SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	if err := peer.(*net.TCPConn).SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	probe := &writeProbe{Conn: raw}
	server := tls.Server(probe, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	client := tls.Client(peer, &tls.Config{InsecureSkipVerify: true}) // Test-only self-signed loopback.
	handshake := asyncResult(func() error { return client.HandshakeContext(t.Context()) })
	if err := server.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := awaitResult(t, "TLS handshake", handshake); err != nil {
		t.Fatal(err)
	}

	// A TCP write timeout proves backpressure. Resume the same record without
	// a deadline so TLS still has a Write in flight when CloseNow runs.
	blocked := make(chan struct{})
	probe.write = func(b []byte) (int, error) {
		if err := raw.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return 0, err
		}
		n, err := raw.Write(b)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			return n, err
		}
		if err := raw.SetWriteDeadline(time.Time{}); err != nil {
			return n, err
		}
		probe.write = raw.Write
		close(blocked)
		m, err := raw.Write(b[n:])
		return n + m, err
	}
	c := NewServerConn(server)
	writer := asyncResult(func() error { return c.WriteMessage(OpcodeBinary, make([]byte, 1<<20)) })
	awaitResult(t, "TCP backpressure", blocked)
	if err := within(t, "CloseNow with TLS write in flight", 2*time.Second, asyncResult(c.CloseNow)); err != nil {
		t.Fatalf("CloseNow: %v", err)
	}
	wantClosed(t, "blocked TLS WriteMessage", within(t, "WriteMessage", 2*time.Second, writer))
}

// TestCloseNowReleasesReaderBlockedInPong covers the read side blocked in a
// write of its own: the peer sends a Ping and stops reading, so the reader's
// automatic Pong blocks on the transport.
func TestCloseNowReleasesReaderBlockedInPong(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	cc := newCloseCountConn(a)
	c := NewServerConn(cc)

	readErr := make(chan error, 1)
	go func() {
		_, _, err := c.ReadMessage()
		readErr <- err
	}()
	if _, err := b.Write(clientFrame(true, OpcodePing, []byte("p"))); err != nil {
		t.Fatalf("peer Ping: %v", err)
	}
	<-cc.writeEntered
	if err := c.CloseNow(); err != nil {
		t.Fatalf("CloseNow = %v, want nil", err)
	}
	wantClosed(t, "ReadMessage blocked in its Pong", awaitResult(t, "ReadMessage", readErr))
	if c.rbuf != nil || !c.tornDown.Load() {
		t.Fatal("the reader returned without releasing the read side")
	}
	_, _, again := c.ReadMessage()
	wantClosed(t, "later ReadMessage", again)
	if n := cc.closes.Load(); n != 1 {
		t.Fatalf("transport closed %d times, want 1", n)
	}
}

func TestCloseNowWithoutReader(t *testing.T) {
	t.Parallel()

	followUps := map[string]func(*Conn) error{
		"Close": func(c *Conn) error { return c.Close(CloseNormalClosure, "bye") },
		"CloseContext": func(c *Conn) error {
			return c.CloseContext(t.Context(), CloseNormalClosure, "bye")
		},
		"CloseNow": func(c *Conn) error { return c.CloseNow() },
	}
	for name, followUp := range followUps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := net.Pipe()
			defer b.Close()
			cc := newCloseCountConn(a)
			c := NewServerConn(cc)

			if err := c.CloseNow(); err != nil {
				t.Fatalf("CloseNow = %v, want nil", err)
			}
			// No reader saw the closed transport, so the buffers are still
			// held: CloseNow itself never releases them.
			if c.rbuf == nil || c.tornDown.Load() {
				t.Fatal("CloseNow released the read side's buffers")
			}
			// The peer sees the transport close, with no Close frame first.
			if n, err := b.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("peer Read = (%d, %v), want (0, io.EOF)", n, err)
			}
			wantClosed(t, "WriteMessage", c.WriteMessage(OpcodeText, []byte("late")))
			if err := c.WriteClose(CloseNormalClosure, ""); err != errClosedNow {
				t.Fatalf("WriteClose after CloseNow = %v, want %v", err, errClosedNow)
			}

			if err := followUp(c); err != nil {
				t.Fatalf("%s after CloseNow = %v, want nil", name, err)
			}
			if name != "CloseNow" {
				if c.rbuf != nil || !c.tornDown.Load() {
					t.Fatalf("%s after CloseNow did not release the buffers", name)
				}
			}
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
		})
	}
}

func TestCloseNowBeforeAnyIO(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	c := NewClientConn(a)
	if err := c.CloseNow(); err != nil {
		t.Fatalf("CloseNow = %v, want nil", err)
	}
	if mode := c.mode.Load(); mode != 0 {
		t.Fatalf("mode after CloseNow = %d, want unselected", mode)
	}
	_, _, err := c.ReadMessage()
	wantClosed(t, "ReadMessage", err)
	if c.rbuf != nil {
		t.Fatal("the reader returned without releasing the read buffer")
	}
}

func TestCloseNowAnyMode(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		mode      uint32
		readFrame bool
	}{
		"unused then message": {},
		"unused then frame":   {readFrame: true},
		"message mode":        {mode: connModeMessage},
		"frame mode":          {mode: connModeFrame, readFrame: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			cc := newCloseCountConn(a)
			c := NewServerConn(cc)
			switch tt.mode {
			case connModeMessage:
				if err := c.Flush(); err != nil {
					t.Fatal(err)
				}
			case connModeFrame:
				if _, _, err := c.DecodeFrame(Frame{Header: Header{Opcode: OpcodeText, Fin: true}}); err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				if err := c.CloseNow(); err != nil {
					t.Fatalf("CloseNow: %v", err)
				}
			}
			if got := c.mode.Load(); got != tt.mode {
				t.Fatalf("mode after CloseNow = %d, want %d", got, tt.mode)
			}
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
			if !tt.readFrame {
				_, _, err := c.ReadMessage()
				wantClosed(t, "ReadMessage", err)
				return
			}
			if _, err := c.ReadFrame(); err != io.ErrClosedPipe {
				t.Fatalf("ReadFrame = %v, want the pipe's %v", err, io.ErrClosedPipe)
			}
			if err := c.WriteFrame(OpcodeText, true, nil, false); err != errClosedNow {
				t.Fatalf("WriteFrame = %v, want %v", err, errClosedNow)
			}
		})
	}
}

// TestCloseNowDeliversBufferedMessages pins what a read after CloseNow
// returns when complete messages are already in the read buffer: the read
// path checks no flag, so it delivers them, and only the read that needs
// more bytes from the closed transport fails with a closed-connection error.
func TestCloseNowDeliversBufferedMessages(t *testing.T) {
	t.Parallel()
	in := append(clientFrame(true, OpcodeText, []byte("one")), clientFrame(true, OpcodeText, []byte("two"))...)
	c := NewServerConn(&scriptConn{in: in})

	if _, p, err := c.ReadMessage(); err != nil || string(p) != "one" {
		t.Fatalf("first ReadMessage = (%q, %v), want (\"one\", nil)", p, err)
	}
	if err := c.CloseNow(); err != nil {
		t.Fatalf("CloseNow = %v, want nil", err)
	}
	if _, p, err := c.ReadMessage(); err != nil || string(p) != "two" {
		t.Fatalf("ReadMessage of the buffered message = (%q, %v), want (\"two\", nil)", p, err)
	}
	_, _, err := c.ReadMessage()
	wantClosed(t, "ReadMessage past the buffered messages", err)
	if c.rbuf != nil {
		t.Fatal("the read side kept its buffers after the closed transport failed it")
	}
}

// TestCloseContextEndedMidDrainClosesOnce pins the exactly-once transport
// close when the context bounding a closing handshake ends while the drain
// waits for the peer's Close: the force-close the context triggers and the
// teardown that follows must share one close.
func TestCloseContextEndedMidDrainClosesOnce(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer b.Close()
	cc := newCloseCountConn(a)
	c := NewServerConn(cc)
	cause := errors.New("caller gave up")
	ctx, cancel := context.WithCancelCause(t.Context())

	// The peer takes the Close frame and never replies; the caller gives up
	// once the drain is reading.
	go func() {
		readWireFrame(t, b)
		<-cc.readEntered
		cancel(cause)
	}()
	err := c.CloseContext(ctx, CloseNormalClosure, "bye")
	wantContextError(t, "CloseContext", err, ctx, cause)
	if n := cc.closes.Load(); n != 1 {
		t.Fatalf("transport closed %d times, want exactly 1", n)
	}
	if c.rbuf != nil || !c.tornDown.Load() {
		t.Fatal("CloseContext returned without releasing the buffers")
	}
}
