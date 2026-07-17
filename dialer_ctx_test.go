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

package gows_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zchee/gows"
)

func TestDialContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	dialed := false
	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not be reached")
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ctx.Err()) {
		t.Fatalf("Dial = %v, want errors.Is ctx.Err (context.Canceled)", err)
	}
	if dialed {
		t.Error("Dial performed network I/O with an already-canceled context")
	}
}

func TestDialContextCanceledDuringNetDial(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	entered := make(chan struct{})
	go func() {
		<-entered
		cancel()
	}()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want errors.Is context.Canceled", err)
	}
}

// writeSignalConn closes ch just before the first Write starts, so a
// test can cancel while the handshake request write is in flight.
type writeSignalConn struct {
	net.Conn
	once sync.Once
	ch   chan struct{}
}

func (c *writeSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.ch) })
	return c.Conn.Write(p)
}

func TestDialContextCanceledDuringRequestWrite(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	// The server never reads: net.Pipe is unbuffered, so the request
	// write blocks until cancellation force-closes the connection.
	writing := make(chan struct{})
	rec := &closeRecorderConn{Conn: &writeSignalConn{Conn: clientConn, ch: writing}}

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-writing
		cancel()
	}()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want errors.Is context.Canceled", err)
	}
	if !rec.closed.Load() {
		t.Error("Dial left the raw connection open after a canceled request write")
	}
}

func TestDialContextCanceledDuringResponseRead(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	gotRequest := make(chan struct{})
	go func() {
		readRawHeaderBlock(t, serverConn)
		close(gotRequest)
		// Never respond: only the cancellation interrupt can unblock.
	}()

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-gotRequest
		cancel()
	}()

	rec := &closeRecorderConn{Conn: clientConn}
	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	start := time.Now()
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ctx.Err()) {
		t.Fatalf("Dial = %v, want errors.Is ctx.Err (context.Canceled)", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Dial took %v to observe cancellation", elapsed)
	}
	if !rec.closed.Load() {
		t.Error("Dial left the raw connection open after a canceled response read")
	}
}

func TestDialContextCanceledDuringTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	sawHello := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		one := make([]byte, 1)
		if _, rerr := conn.Read(one); rerr == nil {
			close(sawHello)
		}
		<-release // stall mid-TLS-handshake until the test ends
	}()

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-sawHello
		cancel()
	}()

	var d gows.Dialer
	start := time.Now()
	_, _, err = d.Dial(ctx, "wss://"+ln.Addr().String()+"/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want errors.Is context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Dial took %v to observe cancellation during TLS", elapsed)
	}
}

func TestDialContextDeadlineExceeded(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		readRawHeaderBlock(t, serverConn) // consume, never respond
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	start := time.Now()
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial = %v, want errors.Is context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Dial took %v to observe the deadline", elapsed)
	}
}

// TestDialSuccessClearsDeadlines pins the ownership handoff: the guard
// deadline derived from ctx is reset to the zero time on success, and
// the returned connection carries live traffic unbounded by it.
func TestDialSuccessClearsDeadlines(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	go func() {
		req := readRawHeaderBlock(t, serverConn)
		accept := mustAcceptFromRequest(t, req)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		serverConn.Write([]byte(resp))
	}()

	rec := &deadlineRecorderConn{Conn: clientConn}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	conn, _, err := d.Dial(ctx, "ws://example.invalid/")
	if err != nil {
		t.Fatalf("Dial: unexpected error %v", err)
	}

	last, ok := rec.last()
	if !ok {
		t.Fatal("Dial never set the ctx-derived handshake deadline")
	}
	if !last.IsZero() {
		t.Errorf("last SetDeadline = %v, want the zero time (deadline cleared on success)", last)
	}

	// Live traffic after the ctx deadline has passed proves neither the
	// deadline nor a late callback poisoned the connection.
	server := gows.NewServerConn(serverConn)
	client := gows.NewClientConn(conn)
	serverErr := make(chan error, 1)
	go func() {
		op, p, rerr := server.ReadMessage()
		if rerr == nil {
			rerr = server.WriteMessage(op, p)
		}
		serverErr <- rerr
	}()
	time.Sleep(300 * time.Millisecond) // outlive the original ctx deadline
	if err := client.WriteMessage(gows.OpcodeText, []byte("post-deadline")); err != nil {
		t.Fatalf("WriteMessage after Dial: %v", err)
	}
	if _, p, err := client.ReadMessage(); err != nil || string(p) != "post-deadline" {
		t.Fatalf("ReadMessage after Dial = (%q, %v), want the echo", p, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server echo: %v", err)
	}
	// The server goroutine has stopped reading, so a closing handshake
	// would block on the unbuffered pipe; release the raw transports.
	conn.Close()
	serverConn.Close()
}

// TestDialCancelAtSuccessBoundary drives cancellation into the exact
// success boundary: the fake server cancels the context the moment it
// finishes writing the 101 response, so the callback and Dial's
// release race by construction. Both outcomes are legal; the race
// detector (this test is exercised under -race -count=100 by the
// verification gates) checks the callback synchronization, and a
// successful connection must be fully usable.
func TestDialCancelAtSuccessBoundary(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		req := readRawHeaderBlock(t, serverConn)
		accept := mustAcceptFromRequest(t, req)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		serverConn.Write([]byte(resp))
		cancel()
	}()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	conn, _, err := d.Dial(ctx, "ws://example.invalid/")
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial = %v, want nil or errors.Is context.Canceled", err)
		}
		return
	}
	// Success: the callback was disarmed and joined, so the connection
	// belongs to the caller alone -- even though ctx is now canceled.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline on the dialed conn = %v, want usable connection", err)
	}
	conn.Close()
}
