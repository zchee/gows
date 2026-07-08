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
// compress.go never calls compress/flate (or any other compression
// package) directly; it only goes through the pooled [DeflateWriter]/
// [DeflateReader] values a [DeflateBackend] constructs, so swapping the
// backend -- e.g. to github.com/klauspost/compress/flate via the
// separate github.com/zchee/gows/flatekp submodule, once the bench/
// deflate study (.omc/research/deflate-study.md) picked a winner --
// means calling [SetDeflateBackend] once, without core gows ever
// depending on klauspost/compress itself (AC9's zero-dependency
// invariant survives because flatekp is its own module).

// DeflateWriter is the subset of *compress/flate.Writer's method set (or
// a third-party backend's equivalent, e.g.
// *github.com/klauspost/compress/flate.Writer) compress.go needs to run
// one permessage-deflate compression cycle: Write the payload, Flush to
// force the RFC 7692 §7.2.1 sync-flush marker, Reset to reuse the writer
// for the next message (or the next pooled borrower) without allocating
// a new one.
type DeflateWriter interface {
	io.Writer
	Reset(dst io.Writer)
	Flush() error
}

// DeflateReader is the subset of the value *compress/flate.NewReader (or
// a third-party backend's equivalent) returns -- which also implements
// that package's own Resetter interface, Reset(io.Reader, []byte) error
// -- that compress.go needs to decompress one message and reuse the
// reader afterward without allocating a new one.
type DeflateReader interface {
	io.Reader
	Reset(r io.Reader, dict []byte) error
}

// DeflateBackend supplies compress.go's permessage-deflate (RFC 7692)
// compressor and decompressor implementation, installed process-wide
// with [SetDeflateBackend]. compress.go's built-in default (stdlib
// compress/flate, [defaultDeflateLevel], a fixed 32KB window) needs no
// DeflateBackend value at all; construct one to switch backends, e.g.
// via github.com/zchee/gows/flatekp's Backend function, which wraps
// github.com/klauspost/compress/flate (kept out of gows's own go.mod --
// AC9 -- by living in its own submodule).
//
// A connection's own negotiated window bits ([Upgrader.NegotiateWindowBits],
// [Dialer.WindowBits]) and the window bits [SetDeflateBackend] actually
// runs with are independent knobs a caller must keep consistent: see
// [SetDeflateBackend] for why compress.go's pools -- and so the backend,
// level, and window bits actually used to compress/decompress -- are a
// process-wide setting in this phase, not a per-Conn one.
type DeflateBackend struct {
	// Name identifies the backend for diagnostics (e.g. "compress/flate",
	// "klauspost/compress/flate"). Optional.
	Name string

	// NewWriter constructs a compressor at level, restricted to at most
	// 2^windowBits bytes of LZ77 history (RFC 7692 §7.1.2's window-bits
	// range, 8-15). By the time compress.go calls this, [SetDeflateBackend]
	// has already validated level against [DeflateBackend.MinLevel]/
	// [DeflateBackend.MaxLevel] and windowBits against
	// [DeflateBackend.MinWindowBits]/[DeflateBackend.MaxWindowBits].
	NewWriter func(level, windowBits int) (DeflateWriter, error)

	// NewReader constructs a decompressor for messages compressed with at
	// most 2^windowBits bytes of LZ77 history. Most DEFLATE
	// implementations (including stdlib compress/flate and
	// klauspost/compress/flate) need no window-size configuration on the
	// decompression side at all -- back-reference distances are
	// self-describing in the compressed stream -- so windowBits is often
	// unused by a NewReader implementation; it is still passed through
	// for backends that do size an internal buffer from it.
	NewReader func(windowBits int) DeflateReader

	// MinLevel and MaxLevel report the inclusive range of compression
	// levels NewWriter accepts when windowBits requests the full,
	// RFC 7692 default 32KB window (windowBits == 15). A backend whose
	// windowed mode (windowBits < 15) uses a fixed internal encoder
	// instead of an adjustable level -- true of both stdlib
	// compress/flate (which has no windowed mode at all) and
	// klauspost/compress/flate's NewWriterWindow -- should document that
	// caveat on NewWriter itself; MinLevel/MaxLevel describes the
	// windowBits == 15 case only.
	MinLevel, MaxLevel int

	// MinWindowBits and MaxWindowBits report the inclusive range of
	// window sizes (RFC 7692 §7.1.2) this backend's NewWriter/NewReader
	// honor. A backend that can only compress at the RFC 7692 default
	// 32KB window -- like compress.go's built-in stdlib compress/flate
	// backend -- reports MinWindowBits == MaxWindowBits == 15.
	MinWindowBits, MaxWindowBits int
}

// CompressionParams describes one negotiated permessage-deflate (RFC 7692)
// configuration's context-takeover settings: whether the server's own
// outgoing compression, and separately the client's own outgoing
// compression, may reuse their LZ77 sliding window across messages
// instead of starting fresh each time (RFC 7692 §7.1.1's
// server_no_context_takeover/client_no_context_takeover, inverted for a
// more direct name -- "true" here means takeover is in effect, matching
// how [WithCompressionParams] and [Upgrader.AllowContextTakeover]/
// [Dialer.AllowContextTakeover] are phrased).
//
// [Handshake.CompressionParams] reports what a completed handshake
// actually agreed; pass it to [WithCompressionParams] when constructing
// a [Conn] that should honor context takeover for whichever direction(s)
// were negotiated. The zero value (both false) describes this package's
// original permessage-deflate behavior: no-context-takeover in both
// directions, identical to a [Conn] built with only [WithCompression]
// and no [WithCompressionParams] call at all.
type CompressionParams struct {
	// ServerContextTakeover reports whether the server's own outgoing
	// (server-to-client) compression reuses its LZ77 window across
	// messages.
	ServerContextTakeover bool
	// ClientContextTakeover reports whether the client's own outgoing
	// (client-to-server) compression reuses its LZ77 window across
	// messages.
	ClientContextTakeover bool
}

// defaultDeflateLevel is the compression level compress.go's default
// (stdlib compress/flate) backend uses. The bench/ deflate study
// (bench/results/deflate-baseline-*.txt) measured stdlib level 6's
// Writer.Reset cost at ~11.6µs -- large enough to dominate small-message
// overhead under the no-context-takeover, pool-and-reset-per-message
// model this phase uses -- so level 1 (BestSpeed) is the default; level 6
// is not used unless [SetDeflateBackend] explicitly asks for it (e.g.
// with the flatekp/klauspost backend, whose Writer.Reset cost is flat
// across levels -- see .omc/research/deflate-study.md).
const defaultDeflateLevel = 1

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
	// (context takeover is a later opt-in), and -- unless
	// [Upgrader.NegotiateWindowBits] is also set -- declines any offer
	// requesting a server_max_window_bits other than 15 (the only window
	// size compress.go's default stdlib compress/flate backend can
	// actually honor), falling back to the client's next offer or no
	// compression per RFC 7692 §7's decline conditions. Declining is
	// never a handshake failure: the connection still succeeds, just
	// without compression. When negotiated, [Handshake.Compressed] is
	// true; pass it to [WithCompression] when constructing the [Conn].
	EnableCompression bool

	// NegotiateWindowBits, when true (and EnableCompression is also
	// true), lets [Upgrader.Upgrade] and [Upgrader.UpgradeHTTP] accept a
	// client's server_max_window_bits offer smaller than the RFC 7692
	// default 32KB window, provided the process's active permessage-
	// deflate backend ([SetDeflateBackend]) is actually configured to
	// compress at a window that small (or smaller) -- see
	// [SetDeflateBackend]'s doc for why that is a process-wide setting
	// this field only opts an individual Upgrader into consulting,
	// rather than a value configured directly here. The response echoes
	// exactly the active window bits (RFC 7692 §7.1.2.1) whenever they
	// are below 15.
	//
	// The zero value (false) preserves this package's original behavior
	// exactly: any server_max_window_bits other than 15 is declined,
	// falling back to the client's next offer, regardless of what
	// backend is process-wide active.
	NegotiateWindowBits bool

	// AllowContextTakeover, when true (and EnableCompression is also
	// true), lets [Upgrader.Upgrade] and [Upgrader.UpgradeHTTP] agree to
	// permessage-deflate context takeover (RFC 7692 §7.1.1) for either
	// direction the client's offer allows: the response's
	// server_no_context_takeover exactly echoes whether the offer
	// required it (binding per RFC 7692 §7.1.1 -- the client has final
	// say for its own receiving direction), and client_no_context_takeover
	// echoes the offer's own hint for its direction (the server's own
	// policy choice this package makes when opted in: honor the
	// client's stated intent rather than second-guessing it). A [Conn]
	// built from this handshake via [WithCompressionParams] (not
	// [WithCompression]) then keeps a persistent per-direction LZ77
	// window alive across messages for whichever direction(s) were
	// actually agreed -- see [WithCompressionParams] for the real,
	// non-trivial memory cost of doing so, which is why this defaults to
	// off.
	//
	// The zero value (false) preserves this package's original behavior
	// exactly: the response always sets both server_no_context_takeover
	// and client_no_context_takeover, regardless of what the client's
	// offer contained.
	AllowContextTakeover bool
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

	// WindowBits, if non-zero, must be 8-15 (RFC 7692 §7.1.2.2) and adds
	// a client_max_window_bits=WindowBits parameter to [Dialer.Dial]'s
	// permessage-deflate offer, restricting this connection's own
	// outgoing (client-to-server) compression to that window size --
	// meaningful only when the process's active permessage-deflate
	// backend ([SetDeflateBackend]) is actually configured to compress
	// that small; see there. [Dial] fails with [ErrInvalidWindowBits]
	// before dialing anything if WindowBits is out of range.
	//
	// The zero value adds no window-bits restriction to the offer,
	// matching this package's original behavior exactly.
	WindowBits int

	// AllowContextTakeover, when true (and EnableCompression is also
	// true), makes [Dialer.Dial]'s offer omit server_no_context_takeover
	// and client_no_context_takeover entirely, letting the server decide
	// context takeover for either or both directions (RFC 7692 §7.1.1)
	// instead of requiring no-context-takeover on both. [Handshake.CompressionParams]
	// reports what the server's response actually agreed to; pass it to
	// [WithCompressionParams] (not [WithCompression]) when constructing
	// a [Conn] that should honor it -- see [WithCompressionParams] for
	// the real, non-trivial memory cost of a persistent per-direction
	// LZ77 window, which is why this defaults to off.
	//
	// The zero value (false) preserves this package's original
	// behavior exactly: the offer always requests no-context-takeover on
	// both directions.
	AllowContextTakeover bool
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

	// CompressionParams reports the negotiated context-takeover
	// configuration when Compressed is true (the zero value -- both
	// directions no-context-takeover -- when Compressed is false, or
	// when true but neither [Upgrader.AllowContextTakeover] nor
	// [Dialer.AllowContextTakeover] was set). Pass it to
	// [WithCompressionParams] instead of [WithCompression] when
	// constructing a [Conn] that should honor context takeover;
	// constructing with only WithCompression(hs.Compressed) always
	// selects no-context-takeover for both directions regardless of what
	// this field reports.
	CompressionParams CompressionParams

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
