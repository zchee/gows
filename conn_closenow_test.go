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
			wantClosed(t, "Serve", awaitResult(t, "Serve", serveErr))
			if n := cc.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
		})
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
			return c.CloseContext(context.Background(), CloseNormalClosure, "bye")
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
			if err := c.WriteClose(CloseNormalClosure, ""); err != nil {
				t.Fatalf("WriteClose after CloseNow = %v, want nil", err)
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
	// The first call selected message mode.
	if err := c.Abort(); !errors.Is(err, ErrConnMode) {
		t.Fatalf("Abort after CloseNow = %v, want ErrConnMode", err)
	}
	_, _, err := c.ReadMessage()
	wantClosed(t, "ReadMessage", err)
	if c.rbuf != nil {
		t.Fatal("the reader returned without releasing the read buffer")
	}
}

func TestCloseNowModeExclusion(t *testing.T) {
	t.Parallel()

	t.Run("frame-mode CloseNow", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		c := NewServerConn(a)
		go func() { _, _ = io.Copy(io.Discard, b) }()
		if err := c.WriteFrame(OpcodeText, true, []byte("x"), false); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
		if err := c.CloseNow(); !errors.Is(err, ErrConnMode) {
			t.Fatalf("CloseNow on a frame-mode Conn = %v, want ErrConnMode", err)
		}
	})
	t.Run("message-mode Abort", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		c := NewServerConn(a)
		go func() { _, _ = io.Copy(io.Discard, b) }()
		if err := c.WriteMessage(OpcodeText, []byte("x")); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
		if err := c.Abort(); !errors.Is(err, ErrConnMode) {
			t.Fatalf("Abort on a message-mode Conn = %v, want ErrConnMode", err)
		}
	})
}
