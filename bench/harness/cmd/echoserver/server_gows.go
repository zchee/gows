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

package main

import (
	"context"
	"net"

	"github.com/zchee/gows"
)

// rbuf1kSize is the read-buffer size for the gows-rbuf1k variant: a 1 KiB
// payload plus gows's maximum frame-header size ([gows.MaxHeaderSize]), so a
// full 1 KiB binary frame (header + payload) fits in a single buffered read.
// This tracks quickws's ~1038-byte default window, isolating read-buffer
// geometry as the manipulated variable in hypothesis H1.
const rbuf1kSize = 1024 + gows.MaxHeaderSize

// gowsVariant is one gows echo-server configuration, keyed by -lib name in
// gowsVariants. Keeping the variants in a table means the read-buffer sweep
// (hypothesis H1) is data-driven rather than a family of near-identical
// server functions.
type gowsVariant struct {
	// readBufSize is passed to [gows.WithReadBufferSize].
	readBufSize int
	// skipUTF8 opts out of gows's default UTF-8 validation.
	skipUTF8 bool
	// useServe selects the drain-and-coalesce echo loop ([gows.Conn.Serve] +
	// [gows.Conn.WriteMessageBuffered]) instead of the classic
	// ReadMessage/WriteMessage pull loop.
	useServe bool
}

// gowsVariants enumerates every -lib name served by runGows. "gows" and
// "gows-noutf8" keep the harness's shared 4096-byte read buffer (bufferSize);
// "gows-rbuf1k" and "gows-rbuf16k" are the read-buffer geometry variants for
// hypothesis H1. UTF-8 validation stays on for every variant except
// "gows-noutf8" (the paired validation-OFF reference config), matching gows's
// RFC 6455 §8.1-by-default posture that the AC5/AC6 gate is judged on.
var gowsVariants = map[string]gowsVariant{
	"gows":         {readBufSize: bufferSize},
	"gows-noutf8":  {readBufSize: bufferSize, skipUTF8: true},
	"gows-rbuf1k":  {readBufSize: rbuf1kSize},
	"gows-rbuf16k": {readBufSize: 16 * 1024},
	"gows-serve":   {readBufSize: bufferSize, useServe: true},
}

// runGows serves an echo using gows's zero-copy raw net.Conn upgrade path (no
// net/http), matching gobwas's integration style. The read-buffer size and
// UTF-8 setting come from cfg, which main populates from the gows variant named
// by -lib (see gowsVariants). The listener is obtained through newListener so
// the -notsent-lowat and -trace-file accept hooks apply here identically to the
// net/http-based backends.
func runGows(ctx context.Context, addr string, cfg serverConfig) error {
	ln, err := newListener(addr, cfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go serveGowsConn(conn, cfg)
	}
}

// serveGowsConn upgrades one accepted connection and runs its echo loop until
// the peer disconnects or a protocol error tears the connection down.
func serveGowsConn(conn net.Conn, cfg serverConfig) {
	defer conn.Close()

	hs, err := gows.Upgrade(conn)
	if err != nil {
		return
	}

	opts := []gows.ConnOption{
		gows.WithReadBufferSize(cfg.readBufSize),
		gows.WithBuffered(hs.Buffered),
	}
	if cfg.skipUTF8 {
		opts = append(opts, gows.WithSkipUTF8Validation(true))
	}
	c := gows.NewServerConn(conn, opts...)

	if cfg.useServe {
		// Drain-and-coalesce loop: Serve consumes every complete message
		// resident in the read buffer per round and flushes the buffered
		// replies in one write before blocking for more data.
		_ = c.Serve(func(op gows.Opcode, p []byte) error {
			return c.WriteMessageBuffered(op, p)
		})
		return
	}

	for {
		op, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(op, msg); err != nil {
			return
		}
	}
}
