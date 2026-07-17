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
	"io"
	"net"
	"testing"
)

// BenchmarkConnWriteMessage16KBTCP exercises the server WriteMessage path over
// a genuine *net.TCPConn -- the vectored (scatter-gather writev) strategy that
// production plain-TCP traffic takes, which the loopConn-backed
// BenchmarkConnWriteMessage16KB cannot represent (loopConn is not a
// buffersWriter, so net.Buffers degrades to the staged path there). It measures
// the real writev cost against a drained loopback peer.
func BenchmarkConnWriteMessage16KBTCP(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	closeOnCleanup(b, "benchmark TCP listener", ln)

	type accepted struct {
		c   net.Conn
		err error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ch <- accepted{c, err}
	}()

	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	a := <-ch
	if a.err != nil {
		b.Fatalf("accept: %v", a.err)
	}
	if _, ok := a.c.(*net.TCPConn); !ok {
		b.Fatalf("accepted conn is %T, want *net.TCPConn", a.c)
	}
	// Drain the server->client direction so writes never block on backpressure.
	drained := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, cli)
		close(drained)
	}()

	srv := NewServerConn(a.c)
	payload := bytes.Repeat([]byte{0x41}, 16<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if err := srv.WriteMessage(OpcodeBinary, payload); err != nil {
			b.Fatalf("WriteMessage: %v", err)
		}
	}
	b.StopTimer()
	if err := a.c.Close(); err != nil {
		b.Errorf("close benchmark server connection: %v", err)
	}
	if err := cli.Close(); err != nil {
		b.Errorf("close benchmark client connection: %v", err)
	}
	<-drained
}
