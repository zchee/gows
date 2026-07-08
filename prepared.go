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
// individual connection's own negotiated context-takeover setting: see
// .omc/research/compress-design.md §6 for why reusing one connection's
// context-takeover state across a broadcast to many connections would be
// incorrect. Since this package's Conn only ever negotiates
// no-context-takeover (see [Upgrader.EnableCompression]), every
// compression-enabled connection can safely receive the same
// precomputed compressed frame.
//
// The zero value is not usable; construct a PreparedMessage with
// [NewPreparedMessage].
type PreparedMessage struct {
	plain         []byte // unmasked header + uncompressed payload
	compressed    []byte // unmasked header + compressed payload, RSV1 set
	hasCompressed bool
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
		compressed, err := compressPayload(nil, payload)
		if err != nil {
			return nil, fmt.Errorf("gows: prepare compressed message: %w", err)
		}
		pm.compressed = AppendHeader(nil, Header{Fin: true, Opcode: op, Rsv: RSV1, Length: int64(len(compressed))})
		pm.compressed = append(pm.compressed, compressed...)
		pm.hasCompressed = true
	}
	return pm, nil
}

// WritePreparedMessage sends pm's precomputed frame to c: the compressed
// frame if pm has one and c negotiated permessage-deflate
// ([WithCompression]), the uncompressed frame otherwise. Like
// [Conn.WriteMessage], it serializes with every other frame write on c.
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

	frame := pm.plain
	if c.compression && pm.hasCompressed {
		frame = pm.compressed
	}
	_, err := c.conn.Write(frame)
	return err
}
