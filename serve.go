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
	"net"

	"github.com/zchee/gows/internal/mask"
	"github.com/zchee/gows/internal/pool"
)

const (
	// serveDrainBudget bounds how many complete data messages [Conn.Serve]
	// consumes from the read buffer in a single drain round before flushing
	// coalesced replies and returning to a blocking read. It caps the latency
	// an interleaved control frame (or a slow peer waiting on the replies) can
	// suffer while a burst of pipelined messages is processed, without giving
	// up the batching win for realistic burst depths.
	serveDrainBudget = 64
	// maxBufferedWriteSize is the byte ceiling at which [Conn.WriteMessageBuffered]
	// auto-flushes the pending batch mid-accumulation, and the staging bound at
	// which [Conn.stageWrite] splits an oversized frame on non-writev
	// transports. The ceiling is checked after a frame is appended, so the
	// batch can transiently exceed it by one frame before that flush. It equals
	// internal/pool's largest size class (1<<18): scratch that stays at this
	// cap round-trips through the pool at teardown, while pool.Put silently
	// drops larger capacities.
	maxBufferedWriteSize = 256 << 10
)

// Serve reads data messages from the connection in a single goroutine and
// dispatches each to h until the loop stops. It is an allocation-free,
// callback-shaped alternative to a hand-written [Conn.ReadMessage] loop that
// additionally drains every complete message already buffered from the
// transport in one pass -- so a burst of pipelined frames is decoded without a
// read syscall between them -- and, when h answers with
// [Conn.WriteMessageBuffered], coalesces those replies into one write syscall
// per drain round.
//
// h is invoked once per data message with its opcode ([OpcodeText] or
// [OpcodeBinary]) and payload. The payload slice has exactly the lifetime of a
// [Conn.ReadMessage] return value: it is owned by the Conn and valid only until
// h returns, after which the next message may overwrite it. A handler that
// needs to retain the bytes past its return must copy them. Interleaved control
// frames are handled transparently and never reach h: a Ping is answered with a
// Pong, a Pong is ignored, and a Close completes the closing handshake, exactly
// as [Conn.ReadMessage] does -- including the auto-Pong ordering, since a
// control reply flushes any pending buffered batch before it is written.
//
// Serve returns when: h returns a non-nil error (that error is returned, and
// any not-yet-flushed buffered replies are discarded -- call [Conn.Flush]
// before returning an error if they must be sent); the peer sends a Close frame
// or a protocol violation fails the connection (the corresponding [*CloseError]
// is returned, matching errors.Is(err, [net.ErrClosed])); or the transport
// fails (that I/O error is returned). Before every blocking read, Serve flushes
// pending buffered replies, so a handler that only ever calls
// WriteMessageBuffered still sends its output promptly. Once Serve returns an
// error it is sticky, exactly as for ReadMessage: a later Serve or ReadMessage
// call returns the same error.
//
// Concurrency: Serve occupies the Conn's single reader role for its whole
// duration and must not run concurrently with [Conn.ReadMessage],
// [Conn.NextReader], or [Conn.Close] (the same contract those methods share
// with each other); to unblock a Serve blocked in another goroutine, set a past
// [Conn.SetReadDeadline] and only then Close. The handler runs on Serve's
// goroutine, so writes it issues (WriteMessageBuffered, [Conn.WriteMessage], or
// a [Conn.NextWriter] stream) need no additional synchronization; a concurrent
// writer on another goroutine is still permitted and stays serialized by the
// write mutex, but then its frames interleave with the buffered batch only at
// frame boundaries.
func (c *Conn) Serve(h func(op Opcode, p []byte) error) error {
	// Entry guards, hoisted out of the per-message loop: they hold for every
	// iteration once verified here, so the drain path below re-checks none of
	// them (a message read that fails returns immediately, and the sticky
	// error is re-reported on any later entry).
	if c.readErr != nil {
		return c.readErr
	}
	if c.tornDown.Load() {
		return net.ErrClosed
	}
	if c.msgReader != nil {
		if err := c.discardStreamRemainder(); err != nil {
			return err
		}
	}

	for {
		// Flush replies coalesced during the previous drain round before
		// blocking for more input, so buffered output is never stranded behind
		// a read wait. On the first iteration, and whenever h wrote directly
		// rather than buffering, the batch is empty and this is a no-op.
		if err := c.Flush(); err != nil {
			return err
		}

		op, p, err := c.readMessageBody()
		if err != nil {
			return err
		}
		if err := h(op, p); err != nil {
			c.discardBuffered()
			return err
		}

		// Drain round: process further complete messages already resident in
		// the read buffer without a blocking read, bounded by the fairness
		// budget. bufferedMessageReady guarantees the next data message is
		// fully present, so readMessageBody cannot block here.
		for budget := serveDrainBudget - 1; budget > 0 && c.bufferedMessageReady(); budget-- {
			op, p, err := c.readMessageBody()
			if err != nil {
				return err
			}
			if err := h(op, p); err != nil {
				c.discardBuffered()
				return err
			}
		}
	}
}

// bufferedMessageReady reports whether the read buffer already holds a
// complete, self-contained data message that the drain loop can consume
// without blocking on the transport. It never advances the read window and
// performs no validation beyond what is needed to bound the resident bytes: an
// empty buffer, a partial frame, a fragmented message's opening frame, a
// malformed header, or a control frame all report false, deferring that case
// to the round-boundary blocking read, which decodes and validates it exactly
// as [Conn.ReadMessage] would. A control frame must end the round even when
// fully resident: one that writes no reply (a Pong) would send readMessageBody
// past it into a blocking read while the round's replies sit unflushed,
// breaking Serve's flush-before-blocking-read guarantee.
func (c *Conn) bufferedMessageReady() bool {
	if c.r0 == c.r1 {
		return false
	}
	h, n, err := DecodeHeader(c.rbuf[c.r0:c.r1])
	if err != nil {
		return false
	}
	// The frame's whole payload must be resident for readMessageBody to
	// complete without a refill.
	if int64(c.r1-c.r0-n) < h.Length {
		return false
	}
	// A final data frame is a whole single-frame message; anything else (a
	// fragment, a bare continuation, a control frame) is left to the blocking
	// path.
	return h.Fin && h.Opcode.IsData()
}

// WriteMessageBuffered appends p as a single complete WebSocket frame (header
// followed by payload) to an internal batch buffer instead of writing it to the
// transport immediately, so many replies can be coalesced into one write. The
// batch is sent by the next [Conn.Flush], by [Conn.Serve] at the end of each
// drain round, automatically once it reaches an internal byte ceiling, or
// implicitly by the next [Conn.WriteMessage], [Conn.NextWriter], or control
// reply (each flushes a pending batch first so frame order is preserved). It
// writes exactly one frame with Fin set and never mutates p.
//
// The frame is always sent uncompressed (RSV1 clear), which RFC 7692 §6 permits
// even on a permessage-deflate-negotiated Conn; use [Conn.WriteMessage] when a
// message must be compressed. On the client role the payload is copied into the
// batch and masked there per RFC 6455 §5.1, leaving p untouched. p is fully
// copied into the batch before WriteMessageBuffered returns, so the caller may
// reuse or overwrite p immediately -- in particular a payload obtained from
// [Conn.ReadMessage] or a [Conn.Serve] handler (whose lifetime ends at the next
// read) is safe to pass and safe to let expire.
//
// Like [Conn.WriteMessage] it serializes with every other frame write via the
// connection's write mutex and returns [ErrWriterBusy] while a [Conn.NextWriter]
// stream is open. It is designed for the single-goroutine [Conn.Serve] model;
// the accumulated batch is Conn state, so overlapping buffered writes from
// multiple goroutines, while serialized, share one batch and should be avoided.
func (c *Conn) WriteMessageBuffered(op Opcode, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent || c.tornDown.Load() {
		return errWriteClosed
	}
	if c.msgWriter != nil {
		return ErrWriterBusy
	}
	if c.wbatch == nil {
		c.wbatch = pool.Get(defaultWriteBufferSize)
	}
	c.wbatch = c.appendFrameLocked(c.wbatch, op, p)
	if len(c.wbatch) >= maxBufferedWriteSize {
		return c.flushBufferedLocked()
	}
	return nil
}

// appendFrameLocked encodes one complete final frame (header followed by
// payload) for op into dst and returns the extended buffer, masking the payload
// for the client role per RFC 6455 §5.1. It is the buffered counterpart of
// emitFrameLocked's server/client framing, targeting a caller-supplied batch
// buffer rather than the transport. The caller must hold wmu.
func (c *Conn) appendFrameLocked(dst []byte, op Opcode, payload []byte) []byte {
	h := Header{Fin: true, Opcode: op, Length: int64(len(payload))}
	if !c.client {
		dst = AppendHeader(dst, h)
		return append(dst, payload...)
	}
	// Client role: RFC 6455 §5.1 requires masking. Append a private copy into
	// the batch and mask it in place, so the caller's slice is never modified.
	key := maskingKey()
	h.Masked = true
	h.MaskKey = key
	dst = AppendHeader(dst, h)
	start := len(dst)
	dst = append(dst, payload...)
	mask.Mask(dst[start:], key)
	return dst
}

// discardBuffered drops any pending [Conn.WriteMessageBuffered] batch without
// writing it, retaining the buffer's capacity for reuse. [Conn.Serve] calls it
// when the handler returns an error, so the documented discard semantics hold
// and a later write cannot resurrect the stale replies.
func (c *Conn) discardBuffered() {
	c.wmu.Lock()
	c.wbatch = c.wbatch[:0]
	c.wmu.Unlock()
}

// Flush writes any frames accumulated by [Conn.WriteMessageBuffered] to the
// transport as a single write and resets the batch. It is a no-op when nothing
// is buffered. [Conn.Serve] calls Flush at the end of every drain round, so an
// explicit call is needed only when driving WriteMessageBuffered outside Serve,
// or to force pending replies out before the handler returns an error (which
// otherwise discards them).
//
// Flush serializes with every other frame write via the connection's write
// mutex. If the connection has been closed it discards the batch and returns a
// write-closed error (matching errors.Is(err, [net.ErrClosed])); a transport
// error from the underlying write is returned verbatim.
func (c *Conn) Flush() error {
	c.wmu.Lock()
	err := c.flushBufferedLocked()
	c.wmu.Unlock()
	return err
}

// flushBufferedLocked writes the pending WriteMessageBuffered batch to the
// transport in one call and resets it, retaining the buffer's capacity for
// reuse. The caller must hold wmu. An empty batch is a no-op; a batch present
// after the connection has closed is discarded with errWriteClosed rather than
// written.
func (c *Conn) flushBufferedLocked() error {
	if len(c.wbatch) == 0 {
		return nil
	}
	if c.closeSent || c.tornDown.Load() {
		c.wbatch = c.wbatch[:0]
		return errWriteClosed
	}
	_, err := c.conn.Write(c.wbatch)
	c.wbatch = c.wbatch[:0]
	return err
}
