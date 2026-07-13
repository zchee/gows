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
	defaultCompressMinSize = 512      // bytes; RFC 7692 negotiated but below this, sent uncompressed.
	maxAdaptiveReadSize    = 16 << 10 // largest single-frame payload that may grow rbuf.
)

// maxCoalescedWriteSize is the largest server payload the vectored write path
// copies together with its header into one buffer to avoid a scatter-gather
// writev's fixed per-call cost; larger payloads stay zero-copy through
// [net.Buffers]. It is a var, not a const, purely so the threshold stays
// adjustable: the 2 KiB value is a provisional pick pending a benchstat
// calibration sweep with the load harness (a follow-up), not yet a measured
// optimum. It has no effect on the staged (non-vectored) transport path, which
// always copies header and payload contiguously regardless of size.
var maxCoalescedWriteSize = 2 << 10

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
// side and must not run concurrently with [Conn.ReadMessage] -- nor with
// reading from the reader returned by [Conn.NextReader], which drives
// the same read side and shares the same buffers -- this is a deliberate
// divergence from gorilla/websocket's looser ergonomics, so the safe
// pattern for the common "shut this connection down from another
// goroutine" need is worth spelling out explicitly: to interrupt a
// [Conn.ReadMessage] call (or a NextReader stream's Read) that is blocked
// in another goroutine, first call [Conn.SetReadDeadline] with a time in
// the past (which unblocks the pending read with a timeout error) and
// only then call [Conn.Close]; calling Close directly while either is
// still blocked races the read side's buffers.
//
// The zero value is not usable; construct a Conn with [NewServerConn] or
// [NewClientConn].
type Conn struct {
	conn     net.Conn
	client   bool // true: client role (mask outbound, reject masked inbound)
	vectored bool // true: transport yields a real writev from net.Buffers (*net.TCPConn/*net.UnixConn); fixed at construction

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
	wpay      []byte         // client masked payload / server small-frame coalescing scratch
	wcomp     []byte         // compression output scratch
	wclose    []byte         // close-body encode scratch
	wiov      [2][]byte      // writev scratch (header, payload)
	wbufs     net.Buffers    // mutable slice header consumed by Buffers.WriteTo
	wstage    []byte         // header+payload staging scratch for the non-writev (staged) transport path
	wbatch    []byte         // WriteMessageBuffered batch accumulator; nil until first buffered write (guarded by wmu)
	closeSent bool           // a Close frame has been written (guarded by wmu)
	msgWriter *messageWriter // open NextWriter stream, if any (guarded by wmu); nil on the WriteMessage-only hot path

	// --- extensions ---
	compression        bool          // permessage-deflate negotiated (RFC 7692); see WithCompression
	deflate            *deflateState // non-nil when context takeover and/or a sub-ceiling per-Conn writer is needed; see WithCompressionParams
	outgoingWindowCeil int           // effective ceiling on this Conn's own outgoing compression window (8..15); default 15

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
	readBufSize       int
	readLimit         int64
	skipUTF8          bool
	buffered          []byte
	closeTimeout      time.Duration
	compression       bool
	compressionParams CompressionParams
}

// WithReadBufferSize sets the initial size of the connection read buffer. For
// bounded, uncompressed single-frame messages, [Conn.ReadMessage] may grow the
// buffer for payloads up to 16 KiB so later messages of the same size remain a
// one-read, zero-copy operation. Larger or fragmented messages are reassembled
// into a separate growable buffer. A non-positive size selects the default
// (4096 bytes).
func WithReadBufferSize(n int) ConnOption {
	return func(c *connConfig) {
		if n > 0 {
			c.readBufSize = n
		}
	}
}

// adaptReadBuffer grows rbuf just enough to keep a bounded single-frame
// payload contiguous. The old oversized-message path already allocates and
// retains a msgBuf for this payload; replacing rbuf with one exact-size buffer
// instead avoids retaining both buffers and lets subsequent frames arrive in
// one Read without a reassembly copy.
func (c *Conn) adaptReadBuffer(payloadSize int64) {
	if payloadSize > c.readLimit ||
		payloadSize <= int64(cap(c.rbuf)) ||
		payloadSize > maxAdaptiveReadSize {
		return
	}

	next := make([]byte, int(payloadSize)+MaxHeaderSize)
	unread := copy(next, c.rbuf[c.r0:c.r1])
	pool.Put(c.rbuf)
	c.rbuf = next
	c.r0 = 0
	c.r1 = unread
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
//
// A Conn built with WithCompression alone always uses no-context-takeover
// for both directions (this package's original behavior), regardless of
// what was actually negotiated; use [WithCompressionParams] instead to
// honor a negotiated context takeover.
func WithCompression(enabled bool) ConnOption {
	return func(c *connConfig) {
		c.compression = enabled
	}
}

// WithCompressionParams always enables permessage-deflate -- unlike
// [WithCompression], there is no bool to pass false for; call this only
// when [Handshake.Compressed] is true, never unconditionally. It
// otherwise behaves exactly like [WithCompression](true), but
// additionally configures context takeover (RFC 7692 §7.1.1) per params
// for whichever direction(s) it reports -- pass [Handshake.CompressionParams],
// not a hardcoded value, for the same reason [WithCompression] warns
// against a hardcoded bool: a Conn that disagrees with what the peer
// actually agreed to produces frames (or expects decompression behavior)
// the peer will reject or fail to decode. The zero [CompressionParams]
// value (both fields false) is identical to calling only
// WithCompression(true).
//
// # Memory cost
//
// No-context-takeover compression/decompression (the default) borrows
// short-lived values from compress.go's shared pool -- no fixed
// per-Conn cost. Context takeover requires this Conn to instead keep
// state alive for the Conn's entire lifetime, one instance per
// direction it applies to:
//
//   - Outgoing (this Conn's own compression) needs a persistent
//     [DeflateWriter], not shared with any other Conn. Measured directly
//     against this package's active backend at [SetDeflateBackend]'s
//     default (stdlib compress/flate): level 1 (this package's default)
//     costs ~1.15 MB; levels 5-9 cost ~0.79 MB each -- level 1 is not the
//     cheapest here, perhaps counterintuitively, because stdlib flate's
//     fast-path encoder (levels 1-6) allocates a larger hash table than
//     its levels 7-9 path (see .omc/research/deflate-study.md for this
//     study's separate finding that pooled Reset cost is the more
//     consequential level/backend tradeoff for the no-context-takeover
//     path).
//   - Incoming (decompressing the peer's messages) is much cheaper: only
//     a growing/sliding dictionary buffer of the most recently decompressed
//     plaintext, not a persistent decompressor. Its default cap is 32 KiB
//     (15 bits). An actual peer-direction max-window-bits value emitted in
//     the handshake response sets a smaller binding cap. A server may also
//     explicitly opt into [Upgrader.TrustClientWindowBitsHint], which
//     carries a valid valued offer into
//     [CompressionParams.ClientMaxWindowBitsHint] as a server-local cap;
//     zero or invalid hints use the 32 KiB default, and client-role Conns
//     ignore the hint. The trusted hint is not negotiated wire state: when
//     the response omitted client_max_window_bits, a conforming peer may
//     still use the full RFC window. Such a stream can fail decompression
//     if it references history beyond the trusted local cap.
//
// A server or client handling many concurrent context-takeover
// connections should budget roughly 1 MB (compress/flate's default
// level) for the outgoing side plus up to 32 KiB for the incoming side,
// per negotiated direction per connection. A smaller-window backend
// (e.g. github.com/zchee/gows/flatekp) does not itself shrink either
// allocation: the outgoing side's internal tables are sized independently,
// while the incoming cap changes only through the peer-direction response
// bound or the server's explicit trusted-hint policy described above. For high
// connection counts, prefer leaving context takeover off (the default)
// and accepting the lower compression ratio of a fresh window per
// message.
func WithCompressionParams(params CompressionParams) ConnOption {
	return func(c *connConfig) {
		c.compression = true
		c.compressionParams = params
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

	// Choose the write strategy once, from the transport's concrete type.
	// [net.Buffers.WriteTo] issues a real scatter-gather writev only when the
	// underlying io.Writer implements the standard library's unexported
	// buffersWriter interface, which *net.TCPConn and *net.UnixConn do via their
	// embedded netFD; on any other net.Conn (crypto/tls.Conn, counting or
	// buffering wrappers, custom transports) it silently degrades to one Write
	// per buffer -- two write syscalls per message. The staged path below writes
	// such transports in one Write instead, so only the two types that truly
	// writev are marked vectored; the conservative default keeps every other
	// transport correct at one syscall.
	var vectored bool
	switch nc.(type) {
	case *net.TCPConn, *net.UnixConn:
		vectored = true
	}

	c := &Conn{
		conn:               nc,
		client:             client,
		vectored:           vectored,
		rbuf:               rbuf,
		readLimit:          cfg.readLimit,
		skipUTF8:           cfg.skipUTF8,
		closeTimeout:       cfg.closeTimeout,
		compression:        cfg.compression,
		outgoingWindowCeil: deflateWindowBits,
	}
	if cfg.compression {
		if client {
			c.outgoingWindowCeil = effectiveWindowBits(cfg.compressionParams.ClientMaxWindowBits)
		} else {
			c.outgoingWindowCeil = effectiveWindowBits(cfg.compressionParams.ServerMaxWindowBits)
		}
		c.deflate = newDeflateState(client, cfg.compressionParams)
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
		// Release the WriteMessageBuffered batch accumulator, if any. It is
		// write-side state guarded by wmu, and an in-flight WriteMessage MAY
		// still run concurrently with this teardown (only ReadMessage/Serve is
		// documented as mutually exclusive with Close), so both the test and
		// the clear take wmu -- reading the slice header unlocked would race a
		// concurrent buffered write. pool.Put drops a non-class capacity,
		// exactly as for msgBuf above.
		c.wmu.Lock()
		if c.wbatch != nil {
			pool.Put(c.wbatch)
			c.wbatch = nil
		}
		c.wmu.Unlock()
		// c.deflate's outgoing half (persistent DeflateWriter and its
		// destination adapter) is only ever touched under wmu (by
		// compressMessage, itself only reachable while WriteMessage holds
		// wmu) -- unlike the read-side buffers above, an in-flight
		// WriteMessage CAN run concurrently with this Close/teardown (only
		// ReadMessage is documented as mutually exclusive with Close), so
		// clearing it must take wmu too. There is nothing to release back
		// to any pool here (see deflateState's doc): a context-takeover
		// compressor/decompressor is owned solely by this Conn, never
		// shared, so dropping the references is the entire cleanup.
		if c.deflate != nil {
			c.wmu.Lock()
			c.deflate = nil
			c.wmu.Unlock()
		}
		c.tornDown.Store(true)
	})
}

// errWriteClosed is returned by writes attempted after a Close frame has been
// sent. It wraps [net.ErrClosed] so errors.Is(err, net.ErrClosed) holds.
var errWriteClosed = fmt.Errorf("gows: write on closed connection: %w", net.ErrClosed)
