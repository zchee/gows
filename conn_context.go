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
	"fmt"
)

// ReadMessageContext is [Conn.ReadMessage] governed by ctx. It returns the
// same values with the same payload lifetime, and like ReadMessage it belongs
// to the Conn's single reader.
//
// When ctx ends while the call is in progress, the connection is closed
// abruptly as by [Conn.CloseNow] -- a WebSocket read cannot be abandoned
// halfway through a message and resumed -- and the returned error wraps
// ctx.Err and any distinct cancellation cause, so errors.Is matches both; the
// read side's buffers are released before it returns. A ctx that has already
// ended fails the call the same way without any I/O and without closing the
// connection. The cancellation callback is stopped, and waited for if it has
// started, before ReadMessageContext returns, so a ctx that ends after a
// successful return never closes the connection.
//
// ReadMessageContext never sets a deadline on the transport, so it leaves a
// concurrent writer's write deadline alone. A ctx that can never end
// (ctx.Done() returns nil) costs nothing over ReadMessage.
func (c *Conn) ReadMessageContext(ctx context.Context) (Opcode, []byte, error) {
	if ctx.Done() == nil {
		return c.ReadMessage()
	}
	return c.readMessageContext(ctx)
}

// readMessageContext is ReadMessageContext for a ctx that can end. It is a
// separate function so the closure it registers cannot make the never-ending
// path allocate.
func (c *Conn) readMessageContext(ctx context.Context) (Opcode, []byte, error) {
	if err := c.selectMode(connModeMessage); err != nil {
		return 0, nil, err
	}
	if ctx.Err() != nil {
		return 0, nil, fmt.Errorf("gows: read: %w", contextError(ctx))
	}
	stop := c.closeWhenDone(ctx)
	op, p, err := c.ReadMessage()
	if stop() {
		return op, p, err
	}
	// ctx ended during the read and the connection is closed. This goroutine
	// owns the read side, so release its buffers now rather than leaving them
	// to a later call; the read error, if any, stays sticky.
	c.teardown()
	return 0, nil, fmt.Errorf("gows: read: %w", contextError(ctx))
}

// WriteMessageContext is [Conn.WriteMessage] governed by ctx, and like
// WriteMessage it is safe to call from several goroutines at once.
//
// When ctx ends while the call is in progress, the connection is closed
// abruptly as by [Conn.CloseNow] -- a frame cut short cannot be completed
// later -- and the returned error wraps ctx.Err and any distinct cancellation
// cause, so errors.Is matches both. The read side's buffers are released by
// the reader when it observes the closed transport, or by a later
// [Conn.Close] or [Conn.CloseContext]. A ctx that has already ended fails the
// call the same way without any I/O and without closing the connection. The
// cancellation callback is stopped, and waited for if it has started, before
// WriteMessageContext returns, so a ctx that ends after a successful return
// never closes the connection.
//
// WriteMessageContext never sets a deadline on the transport, so it leaves a
// concurrent reader's read deadline alone. A ctx that can never end
// (ctx.Done() returns nil) costs nothing over WriteMessage.
func (c *Conn) WriteMessageContext(ctx context.Context, op Opcode, p []byte) error {
	if ctx.Done() == nil {
		return c.WriteMessage(op, p)
	}
	return c.writeMessageContext(ctx, op, p)
}

// writeMessageContext is WriteMessageContext for a ctx that can end.
func (c *Conn) writeMessageContext(ctx context.Context, op Opcode, p []byte) error {
	if err := c.selectMode(connModeMessage); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("gows: write: %w", contextError(ctx))
	}
	stop := c.closeWhenDone(ctx)
	err := c.WriteMessage(op, p)
	if stop() {
		return err
	}
	return fmt.Errorf("gows: write: %w", contextError(ctx))
}

// closeWhenDone arranges for the connection to be closed abruptly, as by
// [Conn.CloseNow], when ctx ends. The returned stop function disarms that and
// reports whether it did so in time: false means ctx ended and the connection
// is closed, and stop has waited for the close to finish, so nothing touches
// the connection after the caller returns. It never changes a deadline, which
// would overwrite the deadline a concurrent reader or writer relies on.
func (c *Conn) closeWhenDone(ctx context.Context) (stop func() bool) {
	done := make(chan struct{})
	stopCallback := context.AfterFunc(ctx, func() {
		defer close(done)
		c.closeNow()
	})
	return func() bool {
		if stopCallback() {
			return true
		}
		<-done
		return false
	}
}
