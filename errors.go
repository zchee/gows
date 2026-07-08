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

import "errors"

// Sentinel errors returned by [Upgrader.Upgrade], [Upgrader.UpgradeHTTP],
// [Dialer.Dial], and [Conn.Close]. Each is comparable with [errors.Is].
// Errors originating from a malformed HTTP request/status line or header
// block (as opposed to a WebSocket-specific handshake requirement) are
// propagated from the internal/httpx package instead of being redefined
// here; wrap them with %w to preserve errors.Is compatibility, as this
// package's handshake code does.
var (
	// ErrHeaderTooLarge indicates a handshake request or response header
	// block did not fit within the configured (or default) size limit
	// before its terminating blank line was found.
	ErrHeaderTooLarge = errors.New("gows: handshake header block too large")
	// ErrMissingHost indicates a handshake request had no Host header,
	// which RFC 6455 §4.2.1 requires.
	ErrMissingHost = errors.New("gows: handshake request missing Host header")
	// ErrNotUpgrade indicates a handshake request's Upgrade header did
	// not contain "websocket" (RFC 6455 §4.2.1).
	ErrNotUpgrade = errors.New("gows: handshake request Upgrade header does not contain \"websocket\"")
	// ErrNotConnectionUpgrade indicates a handshake request's Connection
	// header did not contain the "Upgrade" token (RFC 6455 §4.2.1).
	ErrNotConnectionUpgrade = errors.New("gows: handshake request Connection header does not contain \"upgrade\"")
	// ErrUnsupportedVersion indicates a handshake request's
	// Sec-WebSocket-Version header was missing or was not "13", the only
	// version this package implements (RFC 6455 §4.4).
	ErrUnsupportedVersion = errors.New("gows: handshake Sec-WebSocket-Version is not 13")
	// ErrMissingKey indicates a handshake request's Sec-WebSocket-Key
	// header was missing or was not exactly 24 bytes (RFC 6455 §4.1).
	ErrMissingKey = errors.New("gows: handshake missing or invalid Sec-WebSocket-Key")
	// ErrOriginRejected indicates an [Upgrader.OriginCheck] callback
	// rejected a handshake request's Origin header.
	ErrOriginRejected = errors.New("gows: handshake Origin rejected")
	// ErrNotWebSocketScheme indicates a [Dialer.Dial] URL's scheme was
	// neither "ws" nor "wss".
	ErrNotWebSocketScheme = errors.New("gows: dial URL scheme is not ws or wss")
	// ErrUnexpectedStatus indicates a handshake response's status code
	// was not 101 (Switching Protocols).
	ErrUnexpectedStatus = errors.New("gows: handshake response status is not 101 Switching Protocols")
	// ErrAcceptMismatch indicates a handshake response's
	// Sec-WebSocket-Accept header did not match the value computed from
	// the Sec-WebSocket-Key this package sent, per RFC 6455 §4.1.
	ErrAcceptMismatch = errors.New("gows: handshake Sec-WebSocket-Accept does not match the expected value")
	// ErrUnrequestedSubprotocol indicates a handshake response selected
	// a Sec-WebSocket-Protocol value that [Dialer.Subprotocols] did not
	// offer, which RFC 6455 §4.1 forbids the server from doing.
	ErrUnrequestedSubprotocol = errors.New("gows: handshake response selected a subprotocol that was not offered")
	// ErrInvalidCompressionResponse indicates a handshake response's
	// Sec-WebSocket-Extensions header claimed to accept permessage-deflate
	// (RFC 7692) with a value that fails RFC 7692 §7's validation rules
	// (unknown or duplicate parameter, out-of-range window bits, or a
	// window/context-takeover value this [Dialer] never offered). It
	// wraps a more specific internal/extension error; see the wrapped
	// error's text for which condition failed.
	ErrInvalidCompressionResponse = errors.New("gows: handshake response's Sec-WebSocket-Extensions (permessage-deflate) is invalid")
	// ErrInvalidCloseReason indicates a [Conn.Close] call's reason string
	// was not valid UTF-8, which RFC 6455 §5.5.1 requires for a Close
	// frame's reason text. Close returns this before sending anything --
	// putting invalid UTF-8 on the wire would make this package the
	// non-conformant peer.
	ErrInvalidCloseReason = errors.New("gows: close reason is not valid UTF-8")
)
