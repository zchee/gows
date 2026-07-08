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
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zchee/gows/internal/pool"
	"github.com/zchee/gows/internal/utf8x"
)

// Default connection settings. They are overridable via the With* options.
const (
	defaultReadBufferSize  = 4096
	defaultWriteBufferSize = 4096     // fragment size for streaming NextWriter output.
	defaultReadLimit       = 32 << 20 // 32 MiB
	defaultCloseTimeout    = 5 * time.Second
	defaultCompressMinSize = 512 // bytes; RFC 7692 negotiated but below this, sent uncompressed.
)

// Conn is a WebSocket connection layered over a net.Conn, implementing the
// RFC 6455 framing, fragmentation, control-frame, and closing-handshake
// protocol on top of the low-level frame codec.
//
// Concurrency: a Conn supports at most one concurrent reader and one
// concurrent writer, matching the gorilla/websocket and coder/websocket
// contract. [Conn.ReadMessage] (and the automatic ping/close replies it
// issues) may run concurrently with one [Conn.WriteMessage]; all frame writes
// are serialized internally, so the read path's control replies never
// interleave with an application write. [Conn.Close] participates in the read
// side and must not run concurrently with [Conn.ReadMessage] -- this is a
// deliberate divergence from gorilla/websocket's looser ergonomics, so the
// safe pattern for the common "shut this connection down from another
// goroutine" need is worth spelling out explicitly: to interrupt a
// [Conn.ReadMessage] call that is blocked in another goroutine, first call
// [Conn.SetReadDeadline] with a time in the past (which unblocks the pending
// read with a timeout error) and only then call [Conn.Close]; calling Close
// directly while ReadMessage is still blocked races the read side's buffers.
//
// The zero value is not usable; construct a Conn with [NewServerConn] or
// [NewClientConn].
type Conn struct {
	conn   net.Conn
	client bool // true: client role (mask outbound, reject masked inbound)

	// --- read side (single reader goroutine) ---
	rbuf           []byte // connection read buffer; valid data is rbuf[r0:r1]
	r0, r1         int
	readLimit      int64
	skipUTF8       bool
	msgBuf         []byte // reassembly buffer for fragmented/oversized messages
	utf8v          utf8x.Validator
	msgIsText      bool
	msgCompressed  bool           // current message's first frame carried RSV1 (permessage-deflate)
	inflateBuf     []byte         // decompression output buffer, reused across messages
	inflateScratch []byte         // fixed-size read-chunk scratch for the inflate loop
	readErr        error          // sticky terminal read error once set
	msgReader      *messageReader // active NextReader stream, if any; nil on the ReadMessage-only hot path

	// --- write side (serialized by wmu) ---
	wmu       sync.Mutex
	whdr      []byte         // header encode scratch
	wpay      []byte         // client-role masked-payload scratch
	wcomp     []byte         // compression output scratch
	wclose    []byte         // close-body encode scratch
	wiov      [2][]byte      // writev scratch (header, payload)
	closeSent bool           // a Close frame has been written (guarded by wmu)
	msgWriter *messageWriter // open NextWriter stream, if any (guarded by wmu); nil on the WriteMessage-only hot path

	// --- extensions ---
	compression bool // permessage-deflate negotiated (RFC 7692); see WithCompression

	// --- shared / teardown ---
	closeRcvd    atomic.Bool
	tornDown     atomic.Bool // set once teardown has run; guards every re-entry
	teardownOnce sync.Once
	closeTimeout time.Duration
}

// ConnOption configures a [Conn] created by [NewServerConn] or
// [NewClientConn].
type ConnOption func(*connConfig)

// connConfig accumulates option values before a Conn is built.
type connConfig struct {
	readBufSize  int
	readLimit    int64
	skipUTF8     bool
	buffered     []byte
	closeTimeout time.Duration
	compression  bool
}

// WithReadBufferSize sets the size of the connection read buffer, which bounds
// the largest single frame served through [Conn.ReadMessage]'s zero-copy fast
// path; larger messages are reassembled into a growable buffer instead. A
// non-positive size selects the default (4096 bytes).
func WithReadBufferSize(n int) ConnOption {
	return func(c *connConfig) {
		if n > 0 {
			c.readBufSize = n
		}
	}
}

// WithReadLimit sets the maximum reassembled message size, in bytes. A message
// whose total payload across all fragments would exceed the limit is rejected
// with a Close of code 1009 (Message Too Big) and [Conn.ReadMessage] returns
// the corresponding error. A non-positive value selects the default (32 MiB).
func WithReadLimit(n int64) ConnOption {
	return func(c *connConfig) {
		if n > 0 {
			c.readLimit = n
		}
	}
}

// WithBuffered supplies bytes already read from the connection past the end of
// the opening handshake (see [Handshake.Buffered]) — most commonly the peer's
// first frame, pipelined into the handshake write. The Conn consumes these
// bytes before reading from the underlying net.Conn, so none are lost. The
// slice is copied into the read buffer; the caller may reuse it afterwards.
func WithBuffered(b []byte) ConnOption {
	return func(c *connConfig) {
		c.buffered = b
	}
}

// WithSkipUTF8Validation disables the RFC 6455 §8.1 UTF-8 validity check on
// inbound Text frames and Close-frame reasons. Validation is on by default;
// disabling it trades conformance for throughput and is intended for
// benchmarks and callers that validate payloads themselves (plan §8).
func WithSkipUTF8Validation(skip bool) ConnOption {
	return func(c *connConfig) {
		c.skipUTF8 = skip
	}
}

// WithCloseTimeout sets how long [Conn.Close] waits for the peer's Close frame
// while draining the connection during the closing handshake. A non-positive
// value selects the default (5 seconds).
func WithCloseTimeout(d time.Duration) ConnOption {
	return func(c *connConfig) {
		if d > 0 {
			c.closeTimeout = d
		}
	}
}

// WithCompression enables permessage-deflate (RFC 7692) framing for this
// Conn: an inbound message whose first frame carries RSV1 is decompressed
// before [Conn.ReadMessage] returns it, and an outbound data message at or
// above the compression threshold is compressed and sent with RSV1 set.
// Pass [Handshake.Compressed], not a hardcoded value -- constructing a Conn
// with compression enabled when the peer never agreed to it produces frames
// the peer will reject with a protocol error, and vice versa.
func WithCompression(enabled bool) ConnOption {
	return func(c *connConfig) {
		c.compression = enabled
	}
}

func newConn(nc net.Conn, client bool, opts []ConnOption) *Conn {
	cfg := connConfig{
		readBufSize:  defaultReadBufferSize,
		readLimit:    defaultReadLimit,
		closeTimeout: defaultCloseTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	size := max(cfg.readBufSize, len(cfg.buffered))
	rbuf := pool.Get(size)
	rbuf = rbuf[:cap(rbuf)]

	c := &Conn{
		conn:         nc,
		client:       client,
		rbuf:         rbuf,
		readLimit:    cfg.readLimit,
		skipUTF8:     cfg.skipUTF8,
		closeTimeout: cfg.closeTimeout,
		compression:  cfg.compression,
	}
	if n := len(cfg.buffered); n > 0 {
		copy(c.rbuf, cfg.buffered)
		c.r1 = n
	}
	return c
}

// NewServerConn returns a [Conn] for the server side of an already-upgraded
// WebSocket connection. Per RFC 6455 §5.1 the server expects every inbound
// frame to be masked and sends every outbound frame unmasked.
func NewServerConn(c net.Conn, opts ...ConnOption) *Conn {
	return newConn(c, false, opts)
}

// NewClientConn returns a [Conn] for the client side of an already-upgraded
// WebSocket connection. Per RFC 6455 §5.1 the client masks every outbound
// frame and expects every inbound frame to be unmasked.
func NewClientConn(c net.Conn, opts ...ConnOption) *Conn {
	return newConn(c, true, opts)
}

// CloseError is the error [Conn.ReadMessage] returns once the connection has
// closed, whether because the peer sent a Close frame or because the Conn
// failed the connection for a protocol violation. It carries the close code
// and reason. A CloseError also satisfies errors.Is(err, [net.ErrClosed]) so
// generic "is the connection closed" checks work without type assertions.
type CloseError struct {
	// Code is the close status code (RFC 6455 §7.4). For a peer Close frame
	// with no body it is [CloseNoStatusReceived] (1005).
	Code CloseCode
	// Reason is the close reason text, if any.
	Reason string
	// Sent reports whether this Conn originated the close (true) or observed
	// the peer's Close frame (false).
	Sent bool
}

// Error implements the error interface.
func (e *CloseError) Error() string {
	dir := "received"
	if e.Sent {
		dir = "sent"
	}
	if e.Reason == "" {
		return "gows: connection closed (" + dir + " code " + strconv.Itoa(int(e.Code)) + ")"
	}
	return "gows: connection closed (" + dir + " code " + strconv.Itoa(int(e.Code)) + "): " + e.Reason
}

// Is reports whether target is [net.ErrClosed], letting callers test a
// CloseError with errors.Is(err, net.ErrClosed).
func (e *CloseError) Is(target error) bool {
	return target == net.ErrClosed
}

// SetReadDeadline sets the read deadline on the underlying connection; see
// [net.Conn.SetReadDeadline].
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection; see
// [net.Conn.SetWriteDeadline].
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Close performs the WebSocket closing handshake (RFC 6455 §7): it sends a
// Close frame with the given code and reason (unless one was already sent),
// then, if the peer's Close frame has not yet been observed, drains inbound
// frames until the peer closes or the close timeout elapses, and finally
// closes the underlying connection.
//
// code must be a valid sendable close code ([ValidCloseCode]); reason must be
// valid UTF-8 ([ErrInvalidCloseReason] if not) and, with the 2-byte code, at
// most 125 bytes (RFC 6455 §5.5). Close is idempotent: after the first call
// the underlying connection is closed once and subsequent calls return nil.
//
// Close reads from the connection and therefore must not be called
// concurrently with [Conn.ReadMessage]; it takes over the read side.
func (c *Conn) Close(code CloseCode, reason string) error {
	// Idempotent: once the connection is torn down (by a peer Close, a
	// protocol/IO failure on the read path, or a prior Close), there is nothing
	// left to do and, critically, nothing left to read — re-entering the read
	// path here would index a freed buffer. Return nil per the doc contract.
	if c.tornDown.Load() {
		return nil
	}
	if !ValidCloseCode(code) {
		return &CloseError{Code: code, Reason: "invalid close code", Sent: true}
	}
	if !utf8x.Valid([]byte(reason)) {
		return ErrInvalidCloseReason
	}
	if 2+len(reason) > 125 {
		return fmt.Errorf("gows: close reason too long (%d bytes, max 123)", len(reason))
	}

	sendErr := c.sendClose(code, []byte(reason))

	if !c.closeRcvd.Load() {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.closeTimeout))
		for {
			if _, _, err := c.readMessage(); err != nil {
				break
			}
		}
	}
	c.teardown()
	return sendErr
}

// teardown closes the underlying connection and releases pooled buffers,
// exactly once. It resets the read-window indices and sets tornDown so that no
// later call can index the freed read buffer with stale offsets.
func (c *Conn) teardown() {
	c.teardownOnce.Do(func() {
		_ = c.conn.Close()
		if c.rbuf != nil {
			pool.Put(c.rbuf)
			c.rbuf = nil
		}
		if c.msgBuf != nil {
			pool.Put(c.msgBuf)
			c.msgBuf = nil
		}
		if c.inflateBuf != nil {
			pool.Put(c.inflateBuf)
			c.inflateBuf = nil
		}
		if c.inflateScratch != nil {
			pool.Put(c.inflateScratch)
			c.inflateScratch = nil
		}
		c.r0, c.r1 = 0, 0
		c.tornDown.Store(true)
	})
}

// errWriteClosed is returned by writes attempted after a Close frame has been
// sent. It wraps [net.ErrClosed] so errors.Is(err, net.ErrClosed) holds.
var errWriteClosed = fmt.Errorf("gows: write on closed connection: %w", net.ErrClosed)
