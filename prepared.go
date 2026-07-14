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
	"errors"
	"fmt"
)

// errPreparedMessageClientRole indicates [Conn.WritePreparedMessage] was
// called on a client-role Conn. A [PreparedMessage]'s frames are
// precomputed unmasked; RFC 6455 §5.1 requires the client to mask every
// outbound frame with a fresh, unpredictable key per frame, which cannot
// be done once at [NewPreparedMessage] time and reused -- so
// WritePreparedMessage supports the server role only.
var errPreparedMessageClientRole = errors.New("gows: WritePreparedMessage is not supported for the client role")

// PreparedMessage holds the precomputed wire frame(s) for one message,
// built once by [NewPreparedMessage] and sent to many connections via
// [Conn.WritePreparedMessage] without repeating the framing -- or,
// crucially, the compression -- work per connection: the broadcast
// pattern gorilla/websocket's identically-named type and gws's
// Broadcaster both provide.
//
// A PreparedMessage's compressed frame (when it has one) is always
// compressed against a fresh, empty LZ77 window, independent of any
// individual connection's own negotiated context-takeover setting:
// reusing one connection's context-takeover state across a broadcast to
// many connections would be incorrect. On a Conn whose own outgoing direction has context takeover,
// [Conn.WritePreparedMessage] therefore sends the plain (uncompressed)
// frame instead: the peer's decompressor would append the prepared
// message's plaintext to its sliding dict, but this Conn's persistent
// compressor never saw those bytes, and every later compressMessage
// back-reference would resolve against the wrong dict content at the peer
// (silent corruption). Uncompressed RSV1-clear messages are invisible to
// the deflate context (RFC 7692 §6), so the plain frame is always safe.
// The same plain-frame fallback applies when the prepared frame was
// compressed at a window larger than the Conn's negotiated outgoing
// ceiling, or when the Conn's outgoing compression has been disabled.
//
// The zero value is not usable; construct a PreparedMessage with
// [NewPreparedMessage].
type PreparedMessage struct {
	plain          []byte // unmasked header + uncompressed payload
	compressed     []byte // unmasked header + compressed payload, RSV1 set
	hasCompressed  bool
	prepWindowBits int // activeDeflate windowBits at NewPreparedMessage time (meaningful when hasCompressed)
}

// NewPreparedMessage precomputes op/payload's wire frame(s): an
// uncompressed frame always, and -- when len(payload) meets
// [defaultCompressMinSize] -- a permessage-deflate compressed frame too,
// so [Conn.WritePreparedMessage] can pick whichever a given connection
// needs without recompressing per connection. It never mutates payload.
//
// The compressed frame, if any, is produced by whichever [DeflateBackend]
// is process-wide active at the moment NewPreparedMessage runs (see
// [SetDeflateBackend]); a *PreparedMessage already built keeps using its
// frozen-at-construction-time compressed bytes even if a later
// SetDeflateBackend call changes what newly compressed messages look
// like -- consistent with a PreparedMessage's whole purpose (compress
// once, reuse the same bytes for every connection that sends it).
func NewPreparedMessage(op Opcode, payload []byte) (*PreparedMessage, error) {
	pm := &PreparedMessage{}
	pm.plain = AppendHeader(nil, Header{Fin: true, Opcode: op, Length: int64(len(payload))})
	pm.plain = append(pm.plain, payload...)

	if len(payload) >= defaultCompressMinSize {
		cfg := activeDeflate.Load()
		compressed, err := compressPayloadWithConfig(nil, payload, cfg)
		if err != nil {
			return nil, fmt.Errorf("gows: prepare compressed message: %w", err)
		}
		pm.compressed = AppendHeader(nil, Header{Fin: true, Opcode: op, Rsv: RSV1, Length: int64(len(compressed))})
		pm.compressed = append(pm.compressed, compressed...)
		pm.hasCompressed = true
		pm.prepWindowBits = cfg.windowBits
	}
	return pm, nil
}

// WritePreparedMessage sends pm's precomputed frame to c: the compressed
// frame if pm has one, c negotiated permessage-deflate ([WithCompression]),
// and none of the plain-frame fallbacks apply (outgoing context takeover,
// outgoingDisabled, or prepWindowBits exceeding c's outgoing ceiling);
// the uncompressed frame otherwise. Like [Conn.WriteMessage], it
// serializes with every other frame write on c and refuses to run while a
// [Conn.NextWriter] stream is open ([ErrWriterBusy]): interleaving a
// complete data frame between fragments would violate RFC 6455 §5.4.
//
// WritePreparedMessage only supports the server role -- see
// [errPreparedMessageClientRole] -- since a PreparedMessage's frames are
// precomputed unmasked; calling it on a client-role Conn returns an
// error without writing anything.
func (c *Conn) WritePreparedMessage(pm *PreparedMessage) error {
	if c.client {
		return errPreparedMessageClientRole
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closeSent || c.tornDown.Load() {
		return errWriteClosed
	}
	if c.msgWriter != nil {
		return ErrWriterBusy
	}

	frame := pm.plain
	if c.compression && pm.hasCompressed {
		useCompressed := true
		if c.deflate != nil && c.deflate.outgoing != nil && c.deflate.outgoingTakeover {
			useCompressed = false
		}
		if c.deflate != nil && c.deflate.outgoingDisabled {
			useCompressed = false
		}
		if pm.prepWindowBits > c.outgoingWindowCeil {
			useCompressed = false
		}
		if useCompressed {
			frame = pm.compressed
		}
	}
	_, err := c.conn.Write(frame)
	return err
}
