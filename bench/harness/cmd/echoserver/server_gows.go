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

// runGows serves an echo using gows's zero-copy raw net.Conn upgrade path
// (no net/http), matching gobwas's integration style. UTF-8 validation is
// left at gows's default (on) -- unlike every other library in this
// harness, whose idiomatic default is unvalidated (see plan §4.1) -- since
// the plan's AC5/AC6 "beats everyone" gate is judged on the validation-ON
// numbers (plan §8/§13).
func runGows(ctx context.Context, addr string) error {
	return runGowsConfig(ctx, addr, false)
}

// runGowsNoUTF8 is runGows with [gows.WithSkipUTF8Validation] set, the
// harness's paired "validation OFF" reference config (plan §8): published
// alongside the validation-ON numbers, but not itself the AC5/AC6 gate.
func runGowsNoUTF8(ctx context.Context, addr string) error {
	return runGowsConfig(ctx, addr, true)
}

// runGowsConfig implements both gows variants: net.Listen + [gows.Upgrade]
// + [gows.NewServerConn], echoing every message back with the opcode it
// arrived with.
func runGowsConfig(ctx context.Context, addr string, skipUTF8 bool) error {
	ln, err := net.Listen("tcp", addr)
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
		go serveGowsConn(conn, skipUTF8)
	}
}

// serveGowsConn upgrades one accepted connection and runs its echo loop
// until the peer disconnects or a protocol error tears the connection down.
func serveGowsConn(conn net.Conn, skipUTF8 bool) {
	defer conn.Close()

	hs, err := gows.Upgrade(conn)
	if err != nil {
		return
	}

	opts := []gows.ConnOption{
		gows.WithReadBufferSize(bufferSize),
		gows.WithBuffered(hs.Buffered),
	}
	if skipUTF8 {
		opts = append(opts, gows.WithSkipUTF8Validation(true))
	}
	c := gows.NewServerConn(conn, opts...)

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
