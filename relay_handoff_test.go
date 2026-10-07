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
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadFrameBufferedCompressedPrefixes(t *testing.T) {
	payload := []byte("fragmented compressed payload")
	compressed, err := compressPayload(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	cut := len(compressed) / 2
	wire := append(frameBytes(false, OpcodeText, RSV1, true, 0x12345678, compressed[:cut]), clientFrame(true, OpcodeContinuation, compressed[cut:])...)
	for prefix := range len(wire) + 1 {
		nc := &scriptConn{in: wire[prefix:], chunk: 1}
		buffered := bytes.Clone(wire[:prefix])
		c := NewServerConn(nc, WithCompression(true), WithBuffered(buffered), WithReadBufferSize(16))
		clear(buffered)
		for i := range 2 {
			f, err := c.ReadFrame()
			if err != nil {
				t.Fatalf("prefix %d frame %d: %v", prefix, i, err)
			}
			out, complete, err := c.DecodeFrame(f)
			if err != nil {
				t.Fatalf("prefix %d: %v", prefix, err)
			}
			if complete != (i == 1) || i == 1 && !bytes.Equal(out, payload) {
				t.Fatalf("prefix %d decode %q complete %v", prefix, out, complete)
			}
		}
		if _, err := c.ReadFrame(); !errors.Is(err, io.EOF) {
			t.Fatalf("prefix %d EOF: %v", prefix, err)
		}
		if err := c.Abort(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpgradeBufferedFrameHandoff(t *testing.T) {
	server, peer := net.Pipe()
	defer peer.Close()
	type result struct {
		hs  Handshake
		err error
	}
	ready := make(chan result, 1)
	go func() { u := Upgrader{}; hs, err := u.Upgrade(server); ready <- result{hs, err} }()
	request := []byte("GET / HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	wire := clientFrame(true, OpcodeBinary, []byte("pipelined"))
	if _, err := peer.Write(append(request, wire...)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatalf("upgrade status %d", response.StatusCode)
	}
	r := <-ready
	if r.err != nil {
		t.Fatal(r.err)
	}
	if !bytes.Equal(r.hs.Buffered, wire) {
		t.Fatalf("buffered = %x, want %x", r.hs.Buffered, wire)
	}
	c := NewServerConn(server, WithBuffered(r.hs.Buffered))
	defer c.Abort()
	clear(r.hs.Buffered)
	f, err := c.ReadFrame()
	if err != nil || string(f.Payload) != "pipelined" {
		t.Fatalf("handoff = %q, %v", f.Payload, err)
	}
}

func TestFrameDeadlineInterruption(t *testing.T) {
	tests := map[string]struct{ write bool }{"read": {}, "write": {write: true}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			nc, peer := net.Pipe()
			defer peer.Close()
			c := NewClientConn(nc)
			defer c.Abort()
			done := make(chan error, 1)
			if tt.write {
				go func() { done <- c.WriteFrame(OpcodeBinary, true, []byte("unfinished"), false) }()
				if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				if err := c.SetWriteDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
			} else {
				go func() { _, err := c.ReadFrame(); done <- err }()
				if _, err := peer.Write([]byte{0x82, 1}); err != nil {
					t.Fatal(err)
				}
				if err := c.SetReadDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("deadline error = %v", err)
			}
		})
	}
}

type frameCountingConn struct {
	net.Conn
	reads, writes       chan struct{}
	readOnce, writeOnce sync.Once
	closes              atomic.Int32
}

func (c *frameCountingConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.reads) })
	return c.Conn.Read(p)
}

func (c *frameCountingConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writes) })
	return c.Conn.Write(p)
}
func (c *frameCountingConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func TestAbortConcurrentFrameIO(t *testing.T) {
	nc, peer := net.Pipe()
	defer peer.Close()
	counted := &frameCountingConn{Conn: nc, reads: make(chan struct{}), writes: make(chan struct{})}
	c := NewClientConn(counted, WithCompressionParams(CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}))
	readDone, writeDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := c.ReadFrame(); readDone <- err }()
	go func() { writeDone <- c.WriteFrame(OpcodeBinary, false, []byte("compressed pending"), true) }()
	<-counted.reads
	<-counted.writes
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := c.Abort(); err != nil {
				t.Errorf("Abort: %v", err)
			}
		})
	}
	wg.Wait()
	if err := <-readDone; err == nil {
		t.Fatal("interrupted read succeeded")
	}
	if err := <-writeDone; err == nil {
		t.Fatal("interrupted write succeeded")
	}
	if counted.closes.Load() != 1 {
		t.Fatalf("transport closed %d times", counted.closes.Load())
	}
	if c.rbuf != nil || c.msgBuf != nil || c.inflateBuf != nil || c.frameDecode.buf != nil || c.frameWrite.lease.w != nil || c.deflate != nil || c.wslice.b != nil {
		t.Fatal("Abort retained buffers or codec state")
	}
}
