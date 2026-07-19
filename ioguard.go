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
	"net"
	"sync"
	"time"
)

// connGuard binds a context to a net.Conn for the duration of one
// bounded I/O exchange -- a dial hop's proxy/TLS/handshake phases, or a
// [Conn.CloseContext] closing handshake. It is the single place that
// owns the ctx-to-connection lifecycle, so no phase spawns its own
// callback goroutine:
//
//   - Arming applies the exchange's absolute deadline to the connection
//     (bounding every blocking Read and Write of the exchange with one
//     budget) and registers a [context.AfterFunc] that force-closes the
//     connection when ctx ends, unblocking whichever I/O is in flight
//     even on a context with no deadline.
//   - [connGuard.release] and [connGuard.abort] disarm the callback and,
//     when it has already started, wait for it to complete -- a guard is
//     never left behind: after either returns, no late callback can run,
//     so it cannot poison a connection the caller now owns.
//   - The connection is closed at most once across the callback,
//     [connGuard.abort], and any direct [connGuard.closeConn] call.
type connGuard struct {
	ctx       context.Context
	conn      net.Conn
	done      chan struct{}
	stop      func() bool
	closeOnce sync.Once
}

// guardConn arms a connGuard for one exchange on conn governed by ctx,
// bounded by the absolute deadline (the zero time applies no deadline,
// leaving cancellation as the only interrupt). The caller must pair it
// with exactly one release or abort call. If applying the deadline fails,
// no cancellation callback is registered and the caller must close conn.
func guardConn(ctx context.Context, conn net.Conn, deadline time.Time) (*connGuard, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	g := &connGuard{ctx: ctx, conn: conn, done: make(chan struct{})}
	g.stop = context.AfterFunc(ctx, func() {
		defer close(g.done)
		g.closeConn()
	})
	return g, nil
}

// closeConn closes the guarded connection, exactly once no matter how
// many of the callback, abort, and direct callers race here.
func (g *connGuard) closeConn() {
	g.closeOnce.Do(func() { _ = g.conn.Close() })
}

// release disarms the cancellation callback and reports whether the
// exchange ended cleanly. false means ctx fired first: the callback ran
// (release waits for it to finish before returning, so the caller never
// races it) and the connection is closed; the caller should surface
// [context.Cause] of its ctx. On true the connection is untouched and
// still carries the guard's deadline; a caller keeping the connection
// must clear it.
func (g *connGuard) release() bool {
	if g.stop() {
		if g.ctx.Err() == nil {
			return true
		}
		g.closeConn()
		return false
	}
	<-g.done
	return false
}

// abort ends the exchange on failure: it disarms (joining the callback
// if it already started) and closes the connection. Safe regardless of
// whether ctx fired.
func (g *connGuard) abort() {
	g.release()
	g.closeConn()
}
