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
	"strconv"
)

// Sentinel errors returned by [Upgrader.Upgrade], [Upgrader.UpgradeHTTP],
// [Dialer.Dial], [Conn.Close], [Conn.WriteMessage], and [Conn.NextWriter].
// Each is comparable with [errors.Is].
// Errors originating from a malformed HTTP request/status line or header
// block (as opposed to a WebSocket-specific handshake requirement) are
// propagated from the internal/httpx package instead of being redefined
// here; wrap them with %w to preserve errors.Is compatibility, as this
// package's handshake code does.
var (
	// ErrHeaderTooLarge indicates a handshake request or response header
	// block did not fit within the configured (or default) size limit
	// before its terminating blank line was found, or that the extra
	// request headers supplied via [Dialer.HTTPHeader] would serialize
	// past that same ceiling (reported before any network I/O).
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
	// ErrUnexpectedStatus indicates an HTTP response carried a
	// well-formed numeric status other than the one the exchange
	// required: 101 (Switching Protocols) for the opening handshake, or
	// 200 for a proxy CONNECT. It is surfaced via
	// [*UnexpectedStatusError], which carries the numeric status;
	// errors.Is(err, ErrUnexpectedStatus) matches it.
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
	// ErrInvalidWindowBits indicates a non-zero numeric public window-bits
	// configuration field was set outside RFC 7692's valid range (8-15).
	// This includes [Dialer.WindowBits], [Dialer.ServerWindowBits], and
	// [Upgrader.ClientWindowBits]. Dial validates its fields before dialing;
	// Upgrade reports an invalid ClientWindowBits while processing the
	// handshake, before emitting a successful response.
	ErrInvalidWindowBits = errors.New("gows: window bits outside the valid range (8-15)")
	// ErrConflictingClientWindowBits indicates that [Dialer.WindowBits]
	// and [Dialer.OfferClientMaxWindowBits] were both set. They encode the
	// mutually exclusive valued and bare client_max_window_bits offer
	// forms. [Dialer.Dial] returns this before URL parsing or network I/O.
	ErrConflictingClientWindowBits = errors.New("gows: conflicting valued and bare client_max_window_bits offers")
	// ErrUnsupportedWindowBits reports that a negotiated (or offered)
	// client_max_window_bits ceiling is smaller than anything the process's
	// active permessage-deflate backend can actually compress within
	// ([SetDeflateBackend]). [Dialer.Dial] returns this (wrapped with the
	// ceiling, backend name, and its MinWindowBits) either at offer time
	// — before any network I/O — when [Dialer.WindowBits] alone is already
	// unachievable, or after a successful handshake whose response tightens
	// the ceiling further. The connection is not established in either
	// case; install a backend whose MinWindowBits is at most the desired
	// ceiling (e.g. via github.com/zchee/gows/flatekp) before dialing.
	ErrUnsupportedWindowBits = errors.New("gows: negotiated window bits unsupported by the active deflate backend")
	// ErrInvalidCloseReason indicates a [Conn.Close] call's reason string
	// was not valid UTF-8, which RFC 6455 §5.5.1 requires for a Close
	// frame's reason text. Close returns this before sending anything --
	// putting invalid UTF-8 on the wire would make this package the
	// non-conformant peer.
	ErrInvalidCloseReason = errors.New("gows: close reason is not valid UTF-8")
	// ErrWriterBusy is returned by [Conn.WriteMessage] and
	// [Conn.NextWriter] when a previous [Conn.NextWriter] stream is
	// still open (its writer has not been Closed). A Conn allows at
	// most one writer at a time: a streaming message owns the
	// connection's outbound data-frame stream until it is Closed, so
	// another data message cannot be started meanwhile. Control replies
	// (Pong, Close) are exempt and may still interleave between
	// fragments.
	ErrWriterBusy = errors.New("gows: a NextWriter message is already open")
	// ErrReservedHeader indicates a [Dialer.HTTPHeader] entry named a
	// header this package owns as part of the opening handshake or of
	// the HTTP exchange carrying it: Host, Upgrade, Connection, any
	// Sec-WebSocket-* field, Content-Length, Transfer-Encoding, Trailer,
	// TE, or Proxy-Authorization. Reserved headers cannot be supplied
	// through the extra-header seam; use the dedicated configuration
	// field where one exists (e.g. [Dialer.Subprotocols] for
	// Sec-WebSocket-Protocol, the [Dialer.Proxy] URL for proxy
	// credentials). [Dialer.Dial] returns it (wrapped with the
	// offending name) before any network I/O.
	ErrReservedHeader = errors.New("gows: extra handshake header overrides a reserved header")
	// ErrMalformedHeader indicates a [Dialer.HTTPHeader] entry had a
	// name that is not a valid RFC 7230 token, or a value containing
	// bytes outside RFC 7230 field-content (CR, LF, NUL, or another
	// control byte), which could otherwise inject header lines into the
	// handshake block. [Dialer.Dial] returns it (wrapped with the
	// offending name, never the value) before any network I/O.
	ErrMalformedHeader = errors.New("gows: extra handshake header is malformed")
	// ErrCloseTimeout indicates a [Conn.CloseContext] closing handshake
	// did not complete within the Conn's own close-timeout budget
	// ([WithCloseTimeout]): the Close-frame write or the wait for the
	// peer's Close frame ran out of it. When the context's deadline is
	// the binding bound instead, CloseContext reports the context's
	// cause (matching ctx.Err()), not this sentinel. The connection is
	// closed either way; the error only means the closing handshake did
	// not complete cleanly.
	ErrCloseTimeout = errors.New("gows: closing handshake timed out")
	// ErrProxyUnsupportedScheme indicates [Dialer.Proxy] returned a
	// proxy URL whose scheme is not "http". [Dialer.Dial] returns it
	// before any network I/O for that hop.
	ErrProxyUnsupportedScheme = errors.New("gows: proxy URL scheme is not http")
	// ErrProxyConnectFailed indicates the HTTP proxy refused or failed
	// the CONNECT tunnel a "wss" dial requested through it. When the
	// proxy answered with a well-formed non-200 status the error also
	// carries the numeric status via [*UnexpectedStatusError] (matching
	// [ErrUnexpectedStatus]); no proxy-controlled text is included.
	ErrProxyConnectFailed = errors.New("gows: proxy CONNECT failed")
	// ErrTooManyRedirects indicates a [Dialer.CheckRedirect]-enabled
	// dial followed the maximum number of redirect hops (10) without
	// reaching a terminal response; a redirect loop surfaces as this
	// same error.
	ErrTooManyRedirects = errors.New("gows: too many redirects")
	// ErrMalformedLocation indicates a redirect response's Location
	// header did not parse as a URL or resolved to one with no host.
	// The offending Location value is deliberately not included.
	ErrMalformedLocation = errors.New("gows: redirect Location is malformed")
)

// UnexpectedStatusError reports a syntactically valid HTTP response
// whose status was not the one the exchange required: an opening
// handshake response other than 101 Switching Protocols or, wrapped in
// [ErrProxyConnectFailed], a proxy CONNECT response other than 200.
// errors.Is(err, [ErrUnexpectedStatus]) matches it.
type UnexpectedStatusError struct {
	// StatusCode is the numeric HTTP status the peer sent (e.g. 403).
	StatusCode int
	// Reason is the peer-controlled reason phrase, verbatim. It is
	// carried for callers that explicitly inspect it and deliberately
	// excluded from Error's text, so peer-reflected content (which may
	// echo credentials or other request material) never reaches logs
	// through the error chain.
	Reason string
}

// Error implements the error interface. The text carries only the
// locally computed numeric status -- never the peer's reason phrase,
// headers, or body.
func (e *UnexpectedStatusError) Error() string {
	return "gows: unexpected HTTP response status " + strconv.Itoa(e.StatusCode)
}

// Is reports whether target is [ErrUnexpectedStatus], letting callers
// test an UnexpectedStatusError with errors.Is without a type
// assertion.
func (e *UnexpectedStatusError) Is(target error) bool {
	return target == ErrUnexpectedStatus
}
