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
	"bytes"
	"compress/flate"
	"context"
	"crypto/tls"
	"io"
	"net"

	"github.com/zchee/gows/internal/pool"
)

// defaultMaxHeaderBytes is the handshake header block size limit used
// when [Upgrader.MaxHeaderBytes] is zero, and for the client-side
// handshake response read in [Dialer.Dial], which has no configurable
// limit of its own.
const defaultMaxHeaderBytes = 8192

// --- permessage-deflate (RFC 7692) backend seam -----------------------
//
// compress.go never calls compress/flate directly; it only calls
// newDeflateWriter/newDeflateReader through these package-level vars, so
// swapping the backend (e.g. to github.com/klauspost/compress/flate, once
// the bench/ deflate study picks a winner) means reassigning these two
// vars in one place, behind a build tag if that backend isn't zero-dep.
// The interfaces below are structural subsets both compress/flate and
// klauspost/compress/flate satisfy without either package needing to
// name gows's types.

// deflateWriter is the subset of *compress/flate.Writer's method set
// compress.go needs to run one permessage-deflate compression cycle:
// Write the payload, Flush to force the RFC 7692 §7.2.1 sync-flush
// marker, Reset to reuse the writer for the next message (or the next
// pooled borrower) without allocating a new one.
type deflateWriter interface {
	io.Writer
	Reset(dst io.Writer)
	Flush() error
}

// deflateReader is the subset of the value *compress/flate.NewReader
// returns (which also implements [flate.Resetter]) that compress.go
// needs to decompress one message and reuse the reader afterward without
// allocating a new one.
type deflateReader interface {
	io.Reader
	Reset(r io.Reader, dict []byte) error
}

// defaultDeflateLevel is the compression level compress.go's default
// (stdlib compress/flate) backend uses. The bench/ deflate study
// (bench/results/deflate-baseline-*.txt) measured stdlib level 6's
// Writer.Reset cost at ~11.6µs -- large enough to dominate small-message
// overhead under the no-context-takeover, pool-and-reset-per-message
// model this phase uses -- so level 1 (BestSpeed) is the default; level 6
// is not used unless a future option explicitly asks for it.
const defaultDeflateLevel = 1

// newDeflateWriter constructs a compressor at level. The returned
// writer's destination is meaningless until the first Reset(dst) call;
// callers always Reset before Write per compress.go's pooling contract.
var newDeflateWriter = func(level int) deflateWriter {
	w, err := flate.NewWriter(io.Discard, level)
	if err != nil {
		// Only returns an error for a level outside [flate.HuffmanOnly,
		// flate.BestCompression], and defaultDeflateLevel is a constant
		// within that range, so this is unreachable in practice.
		panic("gows: invalid compression level: " + err.Error())
	}
	return w
}

// newDeflateReader constructs a decompressor. Like newDeflateWriter's
// destination, the source given here is a placeholder; callers always
// call Reset(src, nil) before reading per compress.go's pooling
// contract.
var newDeflateReader = func() deflateReader {
	// flate.NewReader's returned io.ReadCloser also implements
	// flate.Resetter (Reset(io.Reader, []byte) error), a stable stdlib
	// guarantee this package relies on instead of redeclaring the
	// interface with an incompatible name.
	return flate.NewReader(bytes.NewReader(nil)).(deflateReader)
}

// Upgrader performs the server side of a WebSocket opening handshake
// (RFC 6455 §4.2). The zero value is a ready-to-use Upgrader with no
// subprotocols, no Origin check, and the default header size limit.
type Upgrader struct {
	// Subprotocols lists the server's supported subprotocols in order of
	// preference (RFC 6455 §4.1). When negotiating, [Upgrader.Upgrade]
	// and [Upgrader.UpgradeHTTP] select the first entry here that also
	// appears in the client's Sec-WebSocket-Protocol request header, and
	// report it as the string value already present in this slice (no
	// new string is allocated for the match). A nil or empty
	// Subprotocols never selects a subprotocol, even if the client
	// offered some.
	Subprotocols []string

	// OriginCheck, if non-nil, is called with the raw value of the
	// handshake request's Origin header (or nil if the request had no
	// Origin header at all) and must report whether the request should
	// be accepted. A nil OriginCheck accepts every origin, including a
	// missing one.
	//
	// The byte slice passed to OriginCheck is only valid for the
	// duration of the call: it references the Upgrader's internal read
	// buffer (from [Upgrader.Upgrade]) or is freshly allocated (from
	// [Upgrader.UpgradeHTTP]); OriginCheck must not retain it.
	OriginCheck func(origin []byte) bool

	// MaxHeaderBytes caps the size of the request line plus header block
	// [Upgrader.Upgrade] will read before giving up with
	// [ErrHeaderTooLarge]. Zero means [defaultMaxHeaderBytes] (8KB).
	// [Upgrader.UpgradeHTTP] does not use this field: net/http's own
	// server already enforces its http.Server.MaxHeaderBytes before an
	// http.Handler ever runs.
	MaxHeaderBytes int

	// RawPath, when true, makes [Upgrader.Upgrade] skip allocating
	// Handshake.Path and Handshake.Query as strings; the caller must use
	// [Handshake.RawPath] and [Handshake.RawQuery] instead, and must
	// call [Handshake.Release] once it is done with those bytes. This
	// trades the two allocations Upgrade otherwise makes on every call
	// for an explicit buffer-lifetime obligation; see [Handshake.Release]
	// for the exact contract. RawPath has no effect on
	// [Upgrader.UpgradeHTTP], whose Path and Query always come from the
	// already-parsed, already-allocated http.Request.URL.
	RawPath bool

	// EnableCompression, when true, makes [Upgrader.Upgrade] and
	// [Upgrader.UpgradeHTTP] negotiate permessage-deflate (RFC 7692) with
	// a client that offers it. This phase only ever responds with both
	// server_no_context_takeover and client_no_context_takeover set
	// (context takeover is a later opt-in), and declines any offer
	// requesting a server_max_window_bits other than 15 (the only window
	// size compress.go's default stdlib compress/flate backend can
	// actually honor), falling back to the client's next offer or no
	// compression per RFC 7692 §7's decline conditions. Declining is
	// never a handshake failure: the connection still succeeds, just
	// without compression. When negotiated, [Handshake.Compressed] is
	// true; pass it to [WithCompression] when constructing the [Conn].
	EnableCompression bool
}

// Dialer performs the client side of a WebSocket opening handshake
// (RFC 6455 §4.1). The zero value is a ready-to-use Dialer that dials
// plain TCP with [net.Dialer]'s defaults and offers no subprotocols.
type Dialer struct {
	// Subprotocols lists the subprotocols this client supports, sent as
	// the Sec-WebSocket-Protocol request header (RFC 6455 §4.1). If the
	// server's response selects a value not in this list, [Dialer.Dial]
	// fails with [ErrUnrequestedSubprotocol].
	Subprotocols []string

	// TLSConfig configures the TLS client connection used for "wss" URLs
	// (RFC 6455 §4.1: wss is WebSocket-over-TLS). If TLSConfig is nil, a
	// zero-value [tls.Config] is used. If TLSConfig.ServerName is empty,
	// [Dialer.Dial] sets it to the URL's hostname before use;
	// TLSConfig itself is never mutated (it is cloned first).
	// Unused for "ws" URLs.
	TLSConfig *tls.Config

	// NetDial, if non-nil, replaces [net.Dialer.DialContext] for
	// establishing the underlying TCP connection, e.g. to dial through a
	// proxy or use a custom resolver. It receives "tcp" as the network
	// argument and "host:port" as addr.
	NetDial func(ctx context.Context, network, addr string) (net.Conn, error)

	// EnableCompression, when true, makes [Dialer.Dial] offer
	// permessage-deflate (RFC 7692) in its handshake request, requesting
	// both server_no_context_takeover and client_no_context_takeover
	// (context takeover is a later opt-in) and no particular window size.
	// If the server declines (no Sec-WebSocket-Extensions in its
	// response), that is not a Dial failure: [Handshake.Compressed] is
	// simply false. If the server's response is present but invalid (see
	// [ErrInvalidCompressionResponse]), Dial fails.
	EnableCompression bool
}

// Handshake describes a completed WebSocket opening handshake, returned
// by [Upgrader.Upgrade], [Upgrader.UpgradeHTTP], and [Dialer.Dial].
type Handshake struct {
	// Path is the handshake request-target's path component (e.g.
	// "/chat"), not percent-decoded. From [Upgrader.Upgrade] with
	// [Upgrader.RawPath] set, Path is left as the empty string; use
	// [Handshake.RawPath] instead. Not meaningful for [Dialer.Dial]
	// (left as the empty string): the caller already knows the URL it
	// dialed.
	Path string
	// Query is the handshake request-target's query component (e.g.
	// "room=1"), without the leading "?", not percent-decoded. Subject to
	// the same [Upgrader.RawPath] caveat as Path.
	Query string
	// Subprotocol is the negotiated subprotocol, or the empty string if
	// none was negotiated. It is always either empty or exactly one of
	// the strings offered via [Upgrader.Subprotocols] /
	// [Dialer.Subprotocols] (never a newly allocated string).
	Subprotocol string
	// Buffered holds any bytes this package read from the connection
	// past the end of the handshake request/response, i.e. data the
	// peer pipelined immediately after the handshake bytes in the same
	// write (most commonly, the first WebSocket frame). It is nil when
	// there was none. A caller building a Conn on top of the returned
	// net.Conn must treat Buffered as already-read data logically
	// preceding anything subsequently read from the connection itself,
	// or those bytes are lost.
	Buffered []byte
	// Compressed reports whether permessage-deflate (RFC 7692) was
	// negotiated for this connection, via [Upgrader.EnableCompression] or
	// [Dialer.EnableCompression]. Pass it to [WithCompression] when
	// constructing the [Conn] on top of the handshake's net.Conn; passing
	// a hardcoded value instead of this field risks a Conn that
	// disagrees with what the peer actually agreed to.
	Compressed bool

	// buf, if non-nil, is the pooled read buffer backing rawPath and
	// rawQuery (only ever set by [Upgrader.Upgrade] with
	// [Upgrader.RawPath] set). It must not be returned to the pool until
	// the caller is done with those slices; see [Handshake.Release].
	buf               []byte
	rawPath, rawQuery []byte
}

// RawPath returns the handshake request-target's path component as a
// subslice of the Upgrader's internal read buffer, avoiding the
// allocation [Handshake.Path] requires. It is only populated when
// [Upgrader.Upgrade] was called on an [Upgrader] with RawPath set; it is
// nil otherwise (including always, for [Upgrader.UpgradeHTTP] and
// [Dialer.Dial]).
//
// The returned slice is valid until the first call to
// [Handshake.Release]; see there for the full lifetime contract.
func (h *Handshake) RawPath() []byte { return h.rawPath }

// RawQuery returns the handshake request-target's query component (RFC
// 6455 §4.2.1) as a subslice of the Upgrader's internal read buffer,
// avoiding the allocation [Handshake.Query] requires. See
// [Handshake.RawPath] for when it is populated, and [Handshake.Release]
// for its lifetime.
func (h *Handshake) RawQuery() []byte { return h.rawQuery }

// Release returns the handshake's internal read buffer, if any, to the
// shared buffer pool (internal/pool) for reuse by a future handshake.
// Call it once you are done with any slices returned by
// [Handshake.RawPath] or [Handshake.RawQuery]; [Handshake.Path] and
// [Handshake.Query], when populated, are independent strings and remain
// valid after Release regardless.
//
// After Release, RawPath and RawQuery return nil; the underlying array
// may be handed out to a wholly unrelated connection's handshake
// immediately afterwards; a slice obtained from RawPath/RawQuery before
// the call to Release must not be read after it.
//
// Release is a no-op, and safe to call, when there is nothing to
// release -- e.g. RawPath mode was never used for this Handshake, or
// Release was already called once.
func (h *Handshake) Release() {
	if h.buf == nil {
		return
	}
	pool.Put(h.buf)
	h.buf, h.rawPath, h.rawQuery = nil, nil, nil
}
