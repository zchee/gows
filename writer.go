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
	"io"
	"math/rand/v2"
	"net"

	"github.com/zchee/gows/internal/mask"
	"github.com/zchee/gows/internal/pool"
)

// WriteMessage sends p as a single WebSocket message with the given opcode
// (typically [OpcodeText] or [OpcodeBinary]). It writes exactly one frame with
// Fin set; it never mutates p.
//
// On the server role the header and payload are written with a single
// scatter-gather write ([net.Buffers], i.e. writev where the OS supports it),
// so p is transmitted without a copy — steady-state cost is at most one
// allocation. On the client role RFC 6455 §5.1 requires masking; p is copied
// into an internal buffer and masked there so the caller's slice is left
// untouched.
//
// WriteMessage serializes with every other frame write on the connection
// (including the automatic ping/close replies issued by the read path); at
// most one WriteMessage may be in flight at a time.
func (c *Conn) WriteMessage(op Opcode, p []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// closeSent covers graceful/protocol closes; tornDown additionally covers
	// the I/O-error path, which tears down without sending a Close frame.
	if c.closeSent || c.tornDown.Load() {
		return errWriteClosed
	}
	// A NextWriter session owns the message stream until it is Closed; another
	// data message must not interleave with its fragments. On the
	// WriteMessage-only hot path msgWriter is always nil (one predictable nil
	// check).
	if c.msgWriter != nil {
		return ErrWriterBusy
	}

	// When permessage-deflate is negotiated ([WithCompression]) and op is a
	// data opcode with len(p) at or above [defaultCompressMinSize], p is
	// compressed into a private scratch buffer and RSV1 is set; the compressed
	// bytes replace p as the frame payload. When compression is not negotiated
	// (or p is below the threshold) this is a single bool check that
	// short-circuits, preserving the one-alloc, single-call hot path.
	payload := p
	var rsv byte
	if c.compression && op.IsData() && len(p) >= defaultCompressMinSize {
		compressed, err := c.compressMessage(c.wcomp[:0], p)
		if err != nil {
			return err
		}
		c.wcomp = compressed
		payload = compressed
		rsv = RSV1
	}
	return c.emitFrameLocked(op, true, rsv, payload)
}

// writeControl sends a control frame (its payload must be at most 125 bytes),
// acquiring the write lock. It is used by the read path to answer a Ping with
// a Pong. Control frames are never compressed (RFC 7692 §6.1), so it emits
// directly without a compression check.
func (c *Conn) writeControl(op Opcode, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return errWriteClosed
	}
	return c.emitFrameLocked(op, true, 0, payload)
}

// sendClose writes a single Close frame (idempotently: only the first call per
// connection emits one) with the given code and reason, acquiring the write
// lock. A zero code sends an empty Close body (RFC 6455 §7.1.5).
func (c *Conn) sendClose(code CloseCode, reason []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return nil
	}

	var body []byte
	if code != 0 {
		c.wclose = AppendCloseBody(c.wclose[:0], code, reason)
		body = c.wclose
	}
	// A Close frame is never compressed (RFC 7692 §6.1); emit directly.
	err := c.emitFrameLocked(OpcodeClose, true, 0, body)
	c.closeSent = true
	return err
}

// emitFrameLocked encodes and writes one frame carrying the already-final
// payload with the given opcode, Fin, and RSV bits (no compression decision of
// its own). The caller must hold wmu. For the server role the payload is
// written in place with a single scatter-gather write; for the client role
// RFC 6455 §5.1 requires masking, so the payload is copied into a private
// buffer and masked there, never mutating the caller's slice. It is the shared
// frame emitter for [Conn.WriteMessage], the control/Close writes, and the
// [Conn.NextWriter] fragment path -- each of which decides the RSV bits (and
// any compression) before calling in, so no path pays for a check it does not
// need and the hot single-frame write is a single call into this emitter.
func (c *Conn) emitFrameLocked(op Opcode, fin bool, rsv byte, payload []byte) error {
	h := Header{
		Fin:    fin,
		Rsv:    rsv,
		Opcode: op,
		Length: int64(len(payload)),
	}

	if !c.client {
		// Server role: no masking, no payload copy.
		c.whdr = AppendHeader(c.whdr[:0], h)
		return c.writev(c.whdr, payload)
	}

	// Client role: RFC 6455 §5.1 requires masking. Copy payload into a
	// private buffer and mask there so the caller's slice is never modified.
	key := maskingKey()
	h.Masked = true
	h.MaskKey = key
	c.whdr = AppendHeader(c.whdr[:0], h)
	c.wpay = append(c.wpay[:0], payload...)
	mask.Mask(c.wpay, key)
	return c.writev(c.whdr, c.wpay)
}

// writev writes the header a followed by the payload b as a single logical
// write. When b is empty only a is written; otherwise a [net.Buffers] carries
// both, which the standard library turns into a real writev on connections
// that support it (e.g. *net.TCPConn) and a sequential write elsewhere.
func (c *Conn) writev(a, b []byte) error {
	if len(b) == 0 {
		_, err := c.conn.Write(a)
		return err
	}
	// Slice the fixed backing array rather than a growable field: net.Buffers'
	// WriteTo consumes (nils out) the slice it is given, so reusing a field
	// would reallocate every call; the array field is reused instead.
	c.wiov[0], c.wiov[1] = a, b
	bufs := net.Buffers(c.wiov[:])
	_, err := bufs.WriteTo(c.conn)
	return err
}

// maskingKey returns an unpredictable 32-bit masking key. RFC 6455 §5.3
// requires the key to be derived from a strong source of entropy so an
// attacker cannot craft payloads that, once masked, spell chosen bytes on the
// wire (proxy cache-poisoning defense). math/rand/v2's top-level generator is
// a ChaCha8 stream seeded from the operating system's CSPRNG at startup, which
// meets that requirement while costing no per-frame syscall, and is safe for
// concurrent use.
func maskingKey() uint32 {
	return rand.Uint32()
}

// errWriterClosed is returned by a streaming writer's Write after its Close.
var errWriterClosed = fmt.Errorf("gows: write on a closed message writer: %w", net.ErrClosed)

// messageWriter streams one outbound data message as a sequence of frames
// through the [io.WriteCloser] returned by [Conn.NextWriter]. Writes are
// buffered into a fixed-size fragment buffer; each time it fills, a non-final
// frame is flushed (the first carrying the message opcode, the rest
// Continuation), and Close flushes the final Fin fragment.
//
// A messageWriter is not safe for concurrent use by multiple goroutines. Each
// frame it emits is serialized with the Conn's write mutex, so control replies
// issued by the read path stay safe and may interleave between fragments, but
// another WriteMessage/NextWriter is refused with [ErrWriterBusy] until Close.
type messageWriter struct {
	c       *Conn
	op      Opcode // message opcode carried by the first fragment
	buf     []byte // pooled fragment buffer; flushed when full
	started bool   // the first fragment has been emitted (subsequent => Continuation)
	closed  bool   // Close has been called
	err     error  // sticky terminal error
}

// NextWriter returns an [io.WriteCloser] that streams a single outbound data
// message with opcode op (which must be [OpcodeText] or [OpcodeBinary]) as a
// sequence of frames. Bytes written to it are buffered; each time the internal
// fragment buffer fills, a fragment is sent (the first frame carrying op, the
// rest Continuation), and Close sends the final Fin fragment -- which may be
// empty, an RFC 6455 §5.4-legal zero-length final fragment (so a message with
// no Write at all is sent as a single empty frame). Calling Close is
// mandatory: it both terminates the message on the wire and releases the
// writer's buffer.
//
// Concurrency: each fragment is written under the Conn's write mutex, so the
// read path's automatic Pong/Close replies remain safe and may interleave
// between this message's fragments (RFC 6455 §5.4 permits control frames
// between fragments). A concurrent [Conn.WriteMessage] or a second NextWriter
// is refused with [ErrWriterBusy] until this writer is Closed -- a Conn
// permits only one writer at a time (the same single-writer contract as
// gorilla/websocket). An un-Closed writer therefore blocks all future data
// writes on the Conn; the refusal is the safety net rather than silent stream
// corruption.
//
// Compression: NextWriter always sends the message uncompressed (RSV1 clear),
// even when permessage-deflate ([WithCompression]) is negotiated. Per-message
// compression is optional under RFC 7692 §6, so this is fully conformant;
// streaming compression is deferred. A message that should be compressed
// should be sent with [Conn.WriteMessage] instead.
//
// The returned writer masks each fragment on the client role as usual, and is
// not safe for concurrent use.
func (c *Conn) NextWriter(op Opcode) (io.WriteCloser, error) {
	if !op.IsData() {
		return nil, fmt.Errorf("gows: NextWriter opcode %#x is not a data opcode (Text or Binary)", byte(op))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent || c.tornDown.Load() {
		return nil, errWriteClosed
	}
	if c.msgWriter != nil {
		return nil, ErrWriterBusy
	}
	w := &messageWriter{c: c, op: op, buf: pool.Get(defaultWriteBufferSize)[:0]}
	c.msgWriter = w
	return w, nil
}

// Write buffers p into the fragment buffer, flushing a non-final fragment each
// time the buffer fills. It implements [io.Writer].
func (w *messageWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errWriterClosed
	}
	total := len(p)
	for len(p) > 0 {
		n := copy(w.buf[len(w.buf):cap(w.buf)], p)
		w.buf = w.buf[:len(w.buf)+n]
		p = p[n:]
		if len(w.buf) == cap(w.buf) {
			if err := w.flush(false); err != nil {
				w.err = err
				return total - len(p), err
			}
		}
	}
	return total, nil
}

// Close flushes the message's final Fin fragment, releases the fragment
// buffer, and clears the writer from the Conn so a later WriteMessage or
// NextWriter can proceed. It implements [io.Closer] and is idempotent. Close
// is mandatory: until it runs the Conn refuses other data writes with
// [ErrWriterBusy].
func (w *messageWriter) Close() error {
	if w.closed {
		return w.err // idempotent: nil after a clean close, else the sticky error
	}
	w.closed = true

	c := w.c
	c.wmu.Lock()
	err := w.err
	if err == nil {
		// Only emit the final fragment when the stream is still healthy; a
		// writer whose Write already failed must not try to frame more.
		err = w.flushLocked(true)
	}
	// Always release the writer slot so a mid-stream failure cannot wedge the
	// Conn in a permanent ErrWriterBusy state.
	if c.msgWriter == w {
		c.msgWriter = nil
	}
	c.wmu.Unlock()

	if w.buf != nil {
		pool.Put(w.buf)
		w.buf = nil
	}
	if err != nil {
		w.err = err
	}
	return err
}

// flush emits the buffered bytes as one frame under the write mutex.
func (w *messageWriter) flush(fin bool) error {
	w.c.wmu.Lock()
	defer w.c.wmu.Unlock()
	return w.flushLocked(fin)
}

// flushLocked emits the buffered bytes as one frame (the first as the message
// opcode, later ones as Continuation) with RSV1 clear, then resets the buffer.
// The caller must hold wmu.
func (w *messageWriter) flushLocked(fin bool) error {
	c := w.c
	if c.closeSent || c.tornDown.Load() {
		return errWriteClosed
	}
	op := OpcodeContinuation
	if !w.started {
		op = w.op
	}
	if err := c.emitFrameLocked(op, fin, 0, w.buf); err != nil {
		return err
	}
	w.started = true
	w.buf = w.buf[:0]
	return nil
}
