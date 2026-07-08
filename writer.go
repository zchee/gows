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
	"math/rand/v2"
	"net"

	"github.com/zchee/gows/internal/mask"
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
	return c.writeFrameLocked(op, true, p)
}

// writeControlLocked-free wrapper: writeControl sends a control frame (its
// payload must be at most 125 bytes), acquiring the write lock. It is used by
// the read path to answer a Ping with a Pong.
func (c *Conn) writeControl(op Opcode, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent {
		return errWriteClosed
	}
	return c.writeFrameLocked(op, true, payload)
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
	err := c.writeFrameLocked(OpcodeClose, true, body)
	c.closeSent = true
	return err
}

// writeFrameLocked encodes and writes one frame. The caller must hold wmu.
// For the client role the payload is masked into a private buffer (never
// mutating p); for the server role the payload is written in place.
//
// When permessage-deflate is negotiated ([WithCompression]) and op is a
// data opcode (never a control frame -- RFC 7692 §6.1) with len(p) at or
// above [defaultCompressMinSize], p is first compressed into a private
// scratch buffer and RSV1 is set; the compressed bytes replace p as the
// frame payload for the rest of this call. When compression is not
// negotiated, or op is a control opcode, or p is below the threshold,
// this adds a single bool check and behaves exactly as before --
// preserving the zero-alloc, zero-lock hot path for a connection that
// never negotiated compression.
func (c *Conn) writeFrameLocked(op Opcode, fin bool, p []byte) error {
	h := Header{
		Fin:    fin,
		Opcode: op,
	}

	payload := p
	if c.compression && op.IsData() && len(p) >= defaultCompressMinSize {
		compressed, err := compressPayload(c.wcomp[:0], p)
		if err != nil {
			return err
		}
		c.wcomp = compressed
		payload = compressed
		h.Rsv = RSV1
	}
	h.Length = int64(len(payload))

	if !c.client {
		// Server role: no masking, no payload copy.
		c.whdr = AppendHeader(c.whdr[:0], h)
		return c.writev(c.whdr, payload)
	}

	// Client role: RFC 6455 §5.1 requires masking. Copy payload into a
	// private buffer and mask there so the caller's slice is never
	// modified (payload is already gows-owned scratch when compressed,
	// but this branch stays uniform either way).
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
