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
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/zchee/gows/internal/extension"
	"github.com/zchee/gows/internal/httpx"
	"github.com/zchee/gows/internal/pool"
)

// deflateWindowBits is the RFC 7692 default permessage-deflate window
// size (log2 of 32KB) -- the only server_max_window_bits value this
// package's default stdlib compress/flate backend can honor, since
// stdlib flate always compresses at the full window with no public API
// to shrink it. An offer requesting a smaller server_max_window_bits
// is declined unless the
// process's active [DeflateBackend] is actually configured (via
// [SetDeflateBackend]) to compress at a smaller window and the
// [Upgrader] negotiating this offer set [Upgrader.NegotiateWindowBits].
const deflateWindowBits = 15

// minDeflateWindowBits is RFC 7692 §7.1.2's window-bits lower bound,
// shared by server_max_window_bits and client_max_window_bits.
const minDeflateWindowBits = 8

// negotiateDeflate scans a client's Sec-WebSocket-Extensions header
// value (RFC 7692 §5) for the first permessage-deflate offer this server
// can actually honor, applying RFC 7692 §7's "first structurally valid
// offer, otherwise fall back to the next" rule alongside this server's
// own policy. client_max_window_bits, bare or valued, never causes a
// decline: it only bounds the client's own compressor, which this
// server's decompressor can always handle (at the negotiated incoming
// ceiling or the RFC default 32KB).
//
// server_max_window_bits governs this server's own outgoing compression
// window, which -- per [SetDeflateBackend]'s doc -- is a single
// process-wide value (activeBits below): [deflateWindowBits] (15) unless
// negotiateWindowBits is true and [SetDeflateBackend] installed a
// backend configured for less. An offer requesting a server_max_window_bits
// smaller than activeBits is declined and skipped in favor of the
// client's next offer, since the server cannot compress within a
// smaller ceiling than what it is actually configured to use; an offer
// requesting activeBits or more (or omitting the parameter entirely) is
// accepted, echoing activeBits back (RFC 7692 §7.1.2.1) whenever it is
// below 15 -- using less window than the offer's ceiling allows is
// always RFC-compliant.
//
// allowContextTakeover governs server_no_context_takeover/
// client_no_context_takeover in the response: when false (this
// package's original behavior), both are always forced on, declining
// context takeover for both directions regardless of what the offer
// asked for. When true, the response instead echoes the offer's own
// server_no_context_takeover (binding per RFC 7692 §7.1.1 -- the client
// has final say for its own receiving direction) and
// client_no_context_takeover (the offer's non-binding hint for its own
// direction; honoring it rather than overriding it is this server's own
// policy when opted in) -- this naturally produces all four possible
// per-direction combinations purely from what a given offer contains,
// with no separate switch needed for each direction.
//
// clientWindowBits, when non-zero (8-15), is this Upgrader's own
// [Upgrader.ClientWindowBits] policy: when the offer included
// client_max_window_bits at all (bare or valued), the response emits
// client_max_window_bits equal to min(clientWindowBits, offeredValue)
// (offeredValue only participates when the offer was valued). When the
// offer lacks the parameter, nothing is emitted regardless of this
// value (RFC 7692 §7.1.2.2 forbids it). A valued offer's
// client_max_window_bits is returned separately by
// negotiateDeflateWithHint when valued. Callers may expose that value as
// explicitly trusted server-local policy, but it is never copied into
// agreed unless clientWindowBits actually emits a binding response value.
//
// It reports ok=false if extensions contains no acceptable
// permessage-deflate offer at all; per RFC 7692 §7 the caller should
// then omit permessage-deflate from its response entirely -- this is
// never itself a handshake failure.
func negotiateDeflate(extensions []byte, policy deflateNegotiatePolicy) (extension.DeflateParams, bool) {
	agreed, _, ok := negotiateDeflateWithHint(extensions, policy)
	return agreed, ok
}

// deflateNegotiatePolicy bundles the Upgrader-side knobs that travel
// together through negotiateDeflate / negotiateDeflateWithHint.
type deflateNegotiatePolicy struct {
	negotiateWindowBits  bool
	allowContextTakeover bool
	clientWindowBits     int
}

func (u *Upgrader) deflateNegotiatePolicy() deflateNegotiatePolicy {
	return deflateNegotiatePolicy{
		negotiateWindowBits:  u.NegotiateWindowBits,
		allowContextTakeover: u.AllowContextTakeover,
		clientWindowBits:     u.ClientWindowBits,
	}
}

// negotiateDeflateWithHint additionally returns the valued offer-side
// client_max_window_bits hint for the accepted element. It remains separate
// from agreed, which contains response parameters only.
func negotiateDeflateWithHint(extensions []byte, policy deflateNegotiatePolicy) (extension.DeflateParams, int, bool) {
	activeBits := deflateWindowBits
	if policy.negotiateWindowBits {
		activeBits = currentDeflateWindowBits()
	}

	sc := extension.NewOfferScanner(extensions)
	for sc.Next() {
		if !httpx.EqualFold(sc.Name(), extension.DeflateExtensionName) {
			continue
		}
		params, ok := extension.ParseDeflateOfferParams(sc.Params())
		if !ok {
			continue
		}
		if params.ServerMaxWindowBits != 0 && params.ServerMaxWindowBits < activeBits {
			continue
		}
		agreed := extension.DeflateParams{
			ServerNoContextTakeover: true,
			ClientNoContextTakeover: true,
		}
		if policy.allowContextTakeover {
			agreed.ServerNoContextTakeover = params.ServerNoContextTakeover
			agreed.ClientNoContextTakeover = params.ClientNoContextTakeover
		}
		if activeBits < deflateWindowBits {
			agreed.ServerMaxWindowBits = activeBits
		}
		// Emit client_max_window_bits only when the offer included the
		// parameter (bare or valued) and the Upgrader opted in.
		if policy.clientWindowBits != 0 && params.HasClientMaxWindowBits() {
			agreed.ClientMaxWindowBits = policy.clientWindowBits
			if v := params.ClientMaxWindowBitsValue(); v != 0 && v < policy.clientWindowBits {
				agreed.ClientMaxWindowBits = v
			}
		}
		hint := params.ClientMaxWindowBitsValue()
		return agreed, hint, true
	}
	return extension.DeflateParams{}, 0, false
}

// compressionParamsFromDeflate translates an internal/extension
// [extension.DeflateParams] (the negotiation-layer representation, which
// this package cannot expose directly in a public API -- see
// [Handshake.CompressionParams]'s doc) into the exported
// [CompressionParams] a caller passes to [WithCompressionParams].
func compressionParamsFromDeflate(p extension.DeflateParams) CompressionParams {
	return CompressionParams{
		ServerContextTakeover: !p.ServerNoContextTakeover,
		ClientContextTakeover: !p.ClientNoContextTakeover,
		ServerMaxWindowBits:   p.ServerMaxWindowBits,
		// Never leak the bare-offer sentinel into the public API.
		ClientMaxWindowBits: p.ClientMaxWindowBitsValue(),
	}
}

// validateClientWindowBits reports [ErrInvalidWindowBits] when ClientWindowBits
// is set outside RFC 7692 §7.1.2's inclusive range [8, 15].
func (u *Upgrader) validateClientWindowBits() error {
	if u.ClientWindowBits != 0 && (u.ClientWindowBits < minDeflateWindowBits || u.ClientWindowBits > deflateWindowBits) {
		return ErrInvalidWindowBits
	}
	return nil
}

// doubleCRLF marks the end of an HTTP request or response header block.
var doubleCRLF = []byte("\r\n\r\n")

// Upgrade performs the server side of a WebSocket opening handshake on c
// using the zero-value [Upgrader] (no subprotocols, no Origin check, the
// default header size limit). It is a convenience equivalent to
// (&Upgrader{}).Upgrade(c).
func Upgrade(c net.Conn) (Handshake, error) {
	var u Upgrader
	return u.Upgrade(c)
}

// Upgrade performs the server side of a WebSocket opening handshake
// (RFC 6455 §4.2) directly on c, without net/http: it reads the request
// line and headers into a pooled buffer (growing it as needed, across
// as many reads as it takes, up to [Upgrader.MaxHeaderBytes]), validates
// it, and writes the "101 Switching Protocols" response (or a minimal
// HTTP error response on rejection) in a single Write.
//
// Upgrade requires the request to use GET and HTTP/1.1, to carry a Host
// header, an Upgrade header containing "websocket", a Connection header
// containing the "Upgrade" token, a Sec-WebSocket-Version header equal
// to "13", and a 24-byte Sec-WebSocket-Key header. On any failure it
// writes a best-effort HTTP error response (426, with a
// Sec-WebSocket-Version header, for a version mismatch; 403 for an
// [Upgrader.OriginCheck] rejection; 431 for a header block exceeding
// [Upgrader.MaxHeaderBytes]; 400 for everything else) and returns a
// typed error: one of this package's Err* sentinels for a WebSocket-level
// requirement, or a wrapped internal/httpx sentinel for a malformed
// request line or header.
//
// On success, Upgrade does not close c or read any further from it. The
// caller owns c from that point on (e.g. to build a [Conn] on top of it).
func (u *Upgrader) Upgrade(c net.Conn) (Handshake, error) {
	if err := u.validateClientWindowBits(); err != nil {
		return Handshake{}, err
	}
	maxHeader := u.MaxHeaderBytes
	if maxHeader <= 0 {
		maxHeader = defaultMaxHeaderBytes
	}
	initial := min(4096, maxHeader)

	data, filled, err := readHeaderBlock(c, pool.Get(initial), maxHeader)
	if err != nil {
		if errors.Is(err, ErrHeaderTooLarge) {
			writeErrorResponse(c, 431, "Request Header Fields Too Large", "")
		}
		pool.Put(data)
		return Handshake{}, err
	}

	reject := func(status int, reason, extraHeader string, rejErr error) (Handshake, error) {
		writeErrorResponse(c, status, reason, extraHeader)
		pool.Put(data)
		return Handshake{}, rejErr
	}

	idx := bytes.Index(data[:filled], doubleCRLF)
	headerBlock := data[:idx+4]

	reqLine, consumed, err := httpx.ParseRequestLine(headerBlock)
	if err != nil {
		return reject(400, "Bad Request", "", fmt.Errorf("gows: parse request line: %w", err))
	}
	headers := headerBlock[consumed:]

	hf, err := scanWSHandshakeHeaders(headers)
	if err != nil {
		return reject(400, "Bad Request", "", fmt.Errorf("gows: scan headers: %w", err))
	}

	switch {
	case !hf.versionOK:
		return reject(426, "Upgrade Required", "Sec-WebSocket-Version: 13", ErrUnsupportedVersion)
	case !hf.hostSeen:
		return reject(400, "Bad Request", "", ErrMissingHost)
	case !hf.upgradeOK:
		return reject(400, "Bad Request", "", ErrNotUpgrade)
	case !hf.connectionOK:
		return reject(400, "Bad Request", "", ErrNotConnectionUpgrade)
	case len(hf.key) != 24:
		return reject(400, "Bad Request", "", ErrMissingKey)
	}
	if u.OriginCheck != nil && !u.OriginCheck(hf.origin) {
		return reject(403, "Forbidden", "", ErrOriginRejected)
	}

	selected := ""
	if len(u.Subprotocols) > 0 && hf.protocol != nil {
		selected = negotiateSubprotocol(u.Subprotocols, hf.protocol)
	}

	var deflateParams extension.DeflateParams
	var clientWindowBitsHint int
	var deflateOK bool
	if u.EnableCompression && hf.extensions != nil {
		deflateParams, clientWindowBitsHint, deflateOK = negotiateDeflateWithHint(hf.extensions, u.deflateNegotiatePolicy())
	}

	resp := appendSwitchingProtocolsResponse(pool.Get(160+len(selected)), hf.key, selected, deflateParams, deflateOK)
	_, werr := c.Write(resp)
	pool.Put(resp)
	if werr != nil {
		pool.Put(data)
		return Handshake{}, werr
	}

	h := Handshake{Subprotocol: selected, Compressed: deflateOK}
	if deflateOK {
		h.CompressionParams = compressionParamsFromDeflate(deflateParams)
		if u.TrustClientWindowBitsHint && !deflateParams.HasClientMaxWindowBits() {
			h.CompressionParams.ClientMaxWindowBitsHint = clientWindowBitsHint
		}
	}
	if idx+4 < filled {
		h.Buffered = append([]byte(nil), data[idx+4:filled]...)
	}

	path, query := splitTarget(reqLine.Target)
	if u.RawPath {
		h.buf = data
		h.rawPath, h.rawQuery = path, query
	} else {
		h.Path = string(path)
		h.Query = string(query)
		pool.Put(data)
	}

	return h, nil
}

// readHeaderBlock reads from c into buf (growing it via the pool as
// needed, up to maxBytes total) until buf[:filled] contains a complete
// header block: some prefix ending in the blank-line terminator
// "\r\n\r\n". It returns the (possibly grown) buffer and the number of
// valid bytes read into it, which may extend past the terminator if the
// peer pipelined additional data right after the handshake bytes.
//
// The returned buffer always has len(out) == cap(out); callers are
// expected to look only at out[:filled] and to eventually pool.Put(out).
//
// readHeaderBlock returns [ErrHeaderTooLarge] if the header block does
// not fit within maxBytes, and whatever error c.Read returns otherwise
// (including io.EOF if the connection closes before a complete header
// block arrives).
func readHeaderBlock(c net.Conn, buf []byte, maxBytes int) (out []byte, filled int, err error) {
	filled = len(buf)
	buf = buf[:cap(buf)]
	for {
		if idx := bytes.Index(buf[:filled], doubleCRLF); idx >= 0 {
			return buf, filled, nil
		}

		limit := min(len(buf), maxBytes)
		if filled == limit {
			if limit >= maxBytes {
				return buf, filled, ErrHeaderTooLarge
			}
			grown := pool.Get(min(len(buf)*2, maxBytes))
			grown = grown[:filled]
			copy(grown, buf[:filled])
			pool.Put(buf)
			buf = grown[:cap(grown)]
			continue
		}

		n, rerr := c.Read(buf[filled:limit])
		filled += n
		if rerr != nil {
			return buf, filled, rerr
		}
		if n == 0 {
			return buf, filled, io.ErrNoProgress
		}
	}
}

// negotiateSubprotocol returns the first entry in offered (in preference
// order) that case-sensitively equals one of the comma-separated,
// OWS-trimmed tokens in clientList (RFC 6455 §4.1), or "" if none match.
// On a match, it returns the string value from offered itself rather
// than a substring of clientList, so the result never allocates and
// remains valid regardless of the underlying request buffer's lifetime.
func negotiateSubprotocol(offered []string, clientList []byte) string {
	for _, want := range offered {
		rest := clientList
		for len(rest) > 0 {
			var tok []byte
			if i := bytes.IndexByte(rest, ','); i >= 0 {
				tok, rest = rest[:i], rest[i+1:]
			} else {
				tok, rest = rest, nil
			}
			if string(httpx.TrimOWS(tok)) == want {
				return want
			}
		}
	}
	return ""
}

// splitTarget splits an origin-form request-target (RFC 7230 §5.3.1)
// into its path and query components at the first '?', per RFC 6455
// §4.1's "/resource name/" -- neither is percent-decoded.
func splitTarget(target []byte) (path, query []byte) {
	path, query, _ = bytes.Cut(target, []byte("?"))
	return path, query
}

// appendSwitchingProtocolsResponse appends a complete
// "101 Switching Protocols" response, accepting key (assumed already
// validated to be 24 bytes; see [httpx.AppendAccept]) and naming
// subprotocol if non-empty, to dst, returning the extended buffer. When
// deflateOK is true, a Sec-WebSocket-Extensions header naming
// permessage-deflate and deflate's agreed parameters is included too
// (see [negotiateDeflate]).
func appendSwitchingProtocolsResponse(dst, key []byte, subprotocol string, deflate extension.DeflateParams, deflateOK bool) []byte {
	dst = append(dst, "HTTP/1.1 101 Switching Protocols\r\n"...)
	dst = append(dst, "Upgrade: websocket\r\n"...)
	dst = append(dst, "Connection: Upgrade\r\n"...)
	dst = append(dst, "Sec-WebSocket-Accept: "...)
	dst = httpx.AppendAccept(dst, key)
	dst = append(dst, "\r\n"...)
	if subprotocol != "" {
		dst = append(dst, "Sec-WebSocket-Protocol: "...)
		dst = append(dst, subprotocol...)
		dst = append(dst, "\r\n"...)
	}
	if deflateOK {
		dst = append(dst, "Sec-WebSocket-Extensions: "...)
		dst = extension.AppendDeflateResponse(dst, deflate)
		dst = append(dst, "\r\n"...)
	}
	return append(dst, "\r\n"...)
}

// writeErrorResponse writes a minimal HTTP error response with the given
// status, reason phrase, and an optional extra header line (without its
// own CRLF), and closes out the response with Content-Length: 0 and
// Connection: close. It is best-effort: since the caller is already
// failing the handshake and returning an error regardless, a failure to
// write this courtesy response to the peer is not itself reported.
func writeErrorResponse(c net.Conn, status int, reason, extraHeader string) {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, reason)
	if extraHeader != "" {
		b.WriteString(extraHeader)
		b.WriteString("\r\n")
	}
	b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	_, _ = c.Write([]byte(b.String()))
}
