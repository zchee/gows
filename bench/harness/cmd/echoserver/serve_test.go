package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// freeLoopbackAddr returns a loopback address that was free a moment ago; the
// raw-accept runners open their own listener from an address string.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestRawAcceptBackendsEchoAndStopOnCancel drives the raw net.Conn accept loop
// shared by the gows and gobwas backends: every accepted connection is served
// concurrently, and cancelling the context closes the listener and makes the
// runner return nil rather than the resulting accept error.
func TestRawAcceptBackendsEchoAndStopOnCancel(t *testing.T) {
	tests := map[string]struct {
		run func(ctx context.Context, addr string, cfg serverConfig) error
		cfg serverConfig
	}{
		"success: gows": {
			run: runGoWS,
			cfg: serverConfig{readBufSize: bufferSize},
		},
		"success: gows serve loop": {
			run: runGoWS,
			cfg: serverConfig{readBufSize: bufferSize, useServe: true},
		},
		"success: gobwas": {
			run: runGobwas,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr := freeLoopbackAddr(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- tt.run(ctx, addr, tt.cfg) }()

			var conns []*websocket.Conn
			deadline := time.Now().Add(5 * time.Second)
			for len(conns) < 2 {
				conn, _, err := websocket.DefaultDialer.DialContext(t.Context(), "ws://"+addr+"/", nil)
				if err != nil {
					if time.Now().After(deadline) {
						t.Fatalf("dial %s: %v", addr, err)
					}
					time.Sleep(10 * time.Millisecond)
					continue
				}
				defer conn.Close()
				conns = append(conns, conn)
			}
			// Both connections are open at once, so each must be served on
			// its own goroutine for the second echo to arrive.
			for i, conn := range slices.Backward(conns) {
				payload := []byte{'p', byte('0' + i), 0xff, 0x00}
				if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
					t.Fatalf("write on connection %d: %v", i, err)
				}
				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				op, got, err := conn.ReadMessage()
				if err != nil {
					t.Fatalf("read echo on connection %d: %v", i, err)
				}
				if op != websocket.BinaryMessage || !bytes.Equal(got, payload) {
					t.Fatalf("connection %d echo = (%d, %q), want (%d, %q)", i, op, got, websocket.BinaryMessage, payload)
				}
			}

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("runner returned %v after cancel, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runner did not return after cancel")
			}
		})
	}
}

// TestRawAcceptBackendsReportListenFailure checks that a listen error is
// returned to main instead of being swallowed by the accept loop.
func TestRawAcceptBackendsReportListenFailure(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	tests := map[string]func(ctx context.Context, addr string, cfg serverConfig) error{
		"error: gows":   runGoWS,
		"error: gobwas": runGobwas,
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			err := run(t.Context(), held.Addr().String(), serverConfig{})
			if opErr, ok := errors.AsType[*net.OpError](err); !ok || opErr.Op != "listen" {
				t.Fatalf("runner error = %v, want a listen *net.OpError", err)
			}
		})
	}
}
