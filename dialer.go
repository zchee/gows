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
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/gows/internal/extension"
	"github.com/zchee/gows/internal/httpx"
	"github.com/zchee/gows/internal/pool"
)

// maxRedirects bounds a [Dialer.CheckRedirect]-enabled redirect chain:
// past this many followed hops, [Dialer.Dial] fails with
// [ErrTooManyRedirects]. It matches net/http's default policy, and a
// redirect loop necessarily hits it.
const maxRedirects = 10

// deflateOffer builds this Dialer's permessage-deflate offer: the header
// value for the handshake request's Sec-WebSocket-Extensions, and its
// [extension.DeflateParams] equivalent, passed to
// [extension.ValidateDeflateResponse] to validate the server's response
// against what this Dialer actually offered.
//
// Unless [Dialer.AllowContextTakeover] is set, the offer requests
// no-context-takeover on both directions (this package's original
// behavior). When set, the offer omits both
// server_no_context_takeover and client_no_context_takeover entirely,
// leaving the server free to agree to context takeover for either or
// both directions in its response (RFC 7692 §7.1.1); [Handshake.CompressionParams]
// reports what it actually agreed to.
//
// When [Dialer.WindowBits] is non-zero, the offer also restricts this
// Dialer's own outgoing (client-to-server) compression to that window
// size (RFC 7692 §7.1.2.2) -- meaningful only when the process's active
// permessage-deflate backend ([SetDeflateBackend]) is actually
// configured to compress that small; see there.
//
// When [Dialer.ServerWindowBits] is non-zero, the offer also requests
// that the server's own outgoing compression stay within that window
// (RFC 7692 §7.1.2.1); a server that cannot honor it declines
// permessage-deflate rather than failing the handshake.
func (d *Dialer) deflateOffer() (header string, params extension.DeflateParams) {
	var b strings.Builder
	b.WriteString(extension.DeflateExtensionName)
	if !d.AllowContextTakeover {
		b.WriteString("; server_no_context_takeover; client_no_context_takeover")
		params.ServerNoContextTakeover = true
		params.ClientNoContextTakeover = true
	}
	if d.WindowBits != 0 {
		fmt.Fprintf(&b, "; client_max_window_bits=%d", d.WindowBits)
		params.ClientMaxWindowBits = d.WindowBits
	} else if d.OfferClientMaxWindowBits {
		b.WriteString("; client_max_window_bits")
		params.ClientMaxWindowBits = -1
	}
	if d.ServerWindowBits != 0 {
		fmt.Fprintf(&b, "; server_max_window_bits=%d", d.ServerWindowBits)
		params.ServerMaxWindowBits = d.ServerWindowBits
	}
	return b.String(), params
}

// hasDeflateElement reports whether b (a Sec-WebSocket-Extensions header
// value) names permessage-deflate at all, regardless of whether its
// parameters are valid. It distinguishes "the server didn't negotiate
// compression" (fine, not an error) from "the server claimed to
// negotiate compression with an invalid response"
// ([ErrInvalidCompressionResponse]), which [extension.ValidateDeflateResponse]
// alone cannot: it returns the same error for both "no permessage-deflate
// element at all" and "a present but malformed one".
func hasDeflateElement(b []byte) bool {
	sc := extension.NewOfferScanner(b)
	for sc.Next() {
		if httpx.EqualFold(sc.Name(), extension.DeflateExtensionName) {
			return true
		}
	}
	return false
}

// Dial performs the client side of a WebSocket opening handshake to
// rawURL using the zero-value [Dialer] (no subprotocols, default TLS
// config, [net.Dialer]'s default dialing). It is a convenience
// equivalent to (&Dialer{}).Dial(ctx, rawURL).
func Dial(ctx context.Context, rawURL string) (net.Conn, Handshake, error) {
	var d Dialer
	return d.Dial(ctx, rawURL)
}

// Dial performs the client side of a WebSocket opening handshake
// (RFC 6455 §4.1) to rawURL, which must have scheme "ws" or "wss"
// (otherwise [ErrNotWebSocketScheme]). It connects (via
// [Dialer.NetDial] if set, else [net.Dialer.DialContext]), performs a
// TLS handshake for "wss" (via [Dialer.TLSConfig], defaulting
// ServerName to the URL's hostname), writes the handshake request, and
// validates the response: status 101, an Upgrade header containing
// "websocket", a Connection header containing the "Upgrade" token, and a
// Sec-WebSocket-Accept header matching the value computed from the
// Sec-WebSocket-Key this call generated. If the response selects a
// Sec-WebSocket-Protocol not in [Dialer.Subprotocols], Dial fails with
// [ErrUnrequestedSubprotocol]. A well-formed response status other than
// 101 fails Dial with a [*UnexpectedStatusError] (matching
// [ErrUnexpectedStatus]) carrying the numeric status.
//
// ctx governs every phase of the exchange, not just the TCP dial: the
// proxy CONNECT, the TLS handshake, the request write, the
// response-header read, and each redirect hop. Its deadline, if any, is
// applied to the connection, and its cancellation force-closes the
// connection to interrupt whichever phase is in flight -- also on a ctx
// with no deadline. When ctx ends the dial early, Dial returns an error
// wrapping both ctx.Err and any distinct cancellation cause, so
// errors.Is matches [context.Canceled], [context.DeadlineExceeded], and
// a [context.WithCancelCause] cause. An already-ended ctx fails before
// any network I/O. On success, the ctx-derived deadline is cleared from
// the returned net.Conn, and the cancellation callback is stopped and
// fully synchronized, before Dial returns -- a late callback can never
// close a connection the caller owns.
//
// [Dialer.HTTPHeader] adds extra request headers from a snapshot taken
// before any network I/O; [Dialer.Proxy] selects an HTTP proxy; and
// [Dialer.CheckRedirect] opts in to following redirects. See each
// field's documentation.
//
// On any failure after a connection was established, Dial closes it and
// returns a non-nil error alongside a nil net.Conn; a canceled or
// failed connection is never reused. On success, the caller owns the
// returned net.Conn (e.g. to build a Conn on top of it) and any bytes
// the server had already sent past the handshake response (e.g. a
// pipelined first WebSocket frame) are returned as Handshake.Buffered;
// see [Handshake] for the contract a caller building a Conn on top of
// the returned net.Conn must follow. When redirects are followed, only
// the final hop's Handshake (and Buffered) is returned.
//
// Dial is not on gows's zero-allocation hot path (a handshake happens
// once per connection, not once per message) and allocates freely to
// keep its implementation straightforward.
func (d *Dialer) Dial(ctx context.Context, rawURL string) (net.Conn, Handshake, error) {
	if d.WindowBits != 0 && d.OfferClientMaxWindowBits {
		return nil, Handshake{}, ErrConflictingClientWindowBits
	}
	if d.WindowBits != 0 && (d.WindowBits < minDeflateWindowBits || d.WindowBits > deflateWindowBits) {
		return nil, Handshake{}, ErrInvalidWindowBits
	}
	if d.ServerWindowBits != 0 && (d.ServerWindowBits < minDeflateWindowBits || d.ServerWindowBits > deflateWindowBits) {
		return nil, Handshake{}, ErrInvalidWindowBits
	}
	// Fail fast before any network I/O when the offer already requests a
	// client_max_window_bits ceiling the active backend cannot honor.
	if err := checkWindowBitsSupported(d.WindowBits); err != nil {
		return nil, Handshake{}, err
	}

	// Snapshot the caller's extra headers -- map and value slices both --
	// before any validation or network I/O. Everything downstream
	// (validation, redirect credential stripping, serialization) sees
	// only this snapshot, so the caller may mutate the source freely
	// once Dial returns.
	hdr := d.HTTPHeader.Clone()
	if err := validateExtraHeaders(hdr); err != nil {
		return nil, Handshake{}, err
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("gows: dial URL: %w", net.InvalidAddrError("malformed URL"))
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, Handshake{}, ErrNotWebSocketScheme
	}
	if u.Hostname() == "" {
		return nil, Handshake{}, fmt.Errorf("gows: dial URL: %w", net.InvalidAddrError("missing hostname"))
	}

	var via []*http.Request
	for {
		conn, hs, location, err := d.dialHop(ctx, u, hdr)
		if err != nil {
			return nil, Handshake{}, err
		}
		if location == "" {
			return conn, hs, nil
		}
		// The hop answered with a followable redirect and its connection
		// is already closed. Resolve and vet the next URL, consult the
		// caller's policy, and strip credentials on an origin change --
		// deletion from the snapshot is sticky, so a chain returning to
		// the original origin never resurrects a dropped credential.
		next, err := resolveRedirect(u, location)
		if err != nil {
			return nil, Handshake{}, err
		}
		via = append(via, newHopRequest(u, hdr))
		if len(via) > maxRedirects {
			return nil, Handshake{}, ErrTooManyRedirects
		}
		if !sameOrigin(u, next) {
			deleteHeaderFold(hdr, "Authorization")
			deleteHeaderFold(hdr, "Cookie")
		}
		// The policy callback sees the upcoming request exactly as it
		// will be sent -- after the credential stripping above, matching
		// net/http's CheckRedirect ordering.
		if err := d.CheckRedirect(newHopRequest(next, hdr), via); err != nil {
			return nil, Handshake{}, fmt.Errorf("gows: redirect blocked: %w", err)
		}
		u = next
	}
}

// dialHop performs one complete dial attempt against u: proxy
// resolution, TCP connect, an optional CONNECT tunnel, TLS, and the
// opening handshake exchange. It returns either an established
// connection (location == ""), or -- when [Dialer.CheckRedirect] is set
// and the hop answered with a redirect carrying a Location -- the raw
// Location value, with the hop's connection already closed. On error,
// the hop's connection is closed before dialHop returns.
func (d *Dialer) dialHop(ctx context.Context, u *url.URL, hdr http.Header) (net.Conn, Handshake, string, error) {
	useTLS := u.Scheme == "wss"

	var proxyURL *url.URL
	if d.Proxy != nil {
		var err error
		proxyURL, err = d.Proxy(newProxyRequest(u, hdr))
		if err != nil {
			return nil, Handshake{}, "", fmt.Errorf("gows: resolve proxy: %w", err)
		}
	}
	var proxyAuth string
	if proxyURL != nil {
		if proxyURL.Scheme != "http" {
			return nil, Handshake{}, "", ErrProxyUnsupportedScheme
		}
		if err := validateProxyAuthority(proxyURL); err != nil {
			return nil, Handshake{}, "", err
		}
		proxyAuth = proxyBasicAuth(proxyURL.User)
	}

	originAddr := net.JoinHostPort(u.Hostname(), effectivePort(u))
	dialAddr := originAddr
	if proxyURL != nil {
		port := proxyURL.Port()
		if port == "" {
			port = "80"
		}
		dialAddr = net.JoinHostPort(proxyURL.Hostname(), port)
	}

	// Fail before any network I/O on an already-ended context; a custom
	// [Dialer.NetDial] is not obliged to check it.
	if ctx.Err() != nil {
		return nil, Handshake{}, "", fmt.Errorf("gows: dial %s: %w", dialAddr, contextError(ctx))
	}

	dial := d.NetDial
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	conn, err := dial(ctx, "tcp", dialAddr)
	if err != nil {
		if ctx.Err() != nil && !errorContainsContext(err, ctx) {
			return nil, Handshake{}, "", fmt.Errorf("gows: dial %s: %w: %w", dialAddr, contextError(ctx), err)
		}
		return nil, Handshake{}, "", fmt.Errorf("gows: dial %s: %w", dialAddr, err)
	}

	// One guard owns the ctx-to-connection lifecycle for every phase of
	// this hop (CONNECT, TLS, request write, response read): the ctx
	// deadline bounds the connection's I/O directly, and cancellation
	// force-closes the raw connection to unblock whichever phase is in
	// flight (a TLS wrapper delegates deadlines and reads to it anyway).
	deadline, _ := ctx.Deadline()
	g, err := guardConn(ctx, conn, deadline)
	if err != nil {
		_ = conn.Close()
		return nil, Handshake{}, "", fmt.Errorf("gows: set handshake deadline: %w", err)
	}
	fail := func(err error) (net.Conn, Handshake, string, error) {
		g.abort()
		if ctx.Err() != nil && !errorContainsContext(err, ctx) {
			// When ctx ended mid-exchange the transport-level error is
			// usually just the interrupt's symptom (a closed connection or
			// expired deadline); report the cancellation cause as the
			// primary error, keeping the underlying error in the chain.
			return nil, Handshake{}, "", fmt.Errorf("gows: dial: %w: %w", contextError(ctx), err)
		}
		return nil, Handshake{}, "", err
	}

	if proxyURL != nil && useTLS {
		if err := proxyConnect(conn, originAddr, proxyAuth); err != nil {
			return fail(err)
		}
	}

	if useTLS {
		cfg := d.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{}
		} else {
			cfg = cfg.Clone()
		}
		if cfg.ServerName == "" {
			// Always the origin's hostname -- never the proxy's: inside a
			// CONNECT tunnel the TLS peer is the origin.
			cfg.ServerName = u.Hostname()
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fail(fmt.Errorf("gows: tls handshake: %w", err))
		}
		conn = tlsConn
	}

	hs, location, err := d.handshake(conn, u, hdr, proxyURL != nil && !useTLS, proxyAuth)
	if err != nil {
		return fail(err)
	}
	if location != "" {
		// Followable redirect: this hop's connection is finished. abort
		// both joins the cancellation callback and closes the connection;
		// if ctx ended concurrently, the next hop's entry check reports it.
		g.abort()
		return nil, Handshake{}, location, nil
	}
	if !g.release() {
		// ctx fired at the success boundary: the callback closed the
		// connection concurrently, and the caller asked for cancellation
		// regardless -- fail the dial, like [net.Dialer.DialContext] does.
		// release has already waited for the callback, so nothing can
		// touch the connection after this return.
		return nil, Handshake{}, "", fmt.Errorf("gows: handshake: %w", contextError(ctx))
	}
	// Do not leak the guard's handshake deadline into the caller's
	// ownership of the connection.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, Handshake{}, "", fmt.Errorf("gows: clear handshake deadline: %w", err)
	}
	return conn, hs, "", nil
}

// newHopRequest synthesizes the net/http-shaped request describing one
// dial hop, as handed to [Dialer.Proxy] and [Dialer.CheckRedirect]. The
// URL and header are copies, so a callback cannot mutate the validated
// snapshot or the loop's URL state.
func newHopRequest(u *url.URL, hdr http.Header) *http.Request {
	h := hdr.Clone()
	if h == nil {
		h = make(http.Header)
	}
	uu := *u
	return &http.Request{
		Method:     http.MethodGet,
		URL:        &uu,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     h,
		Host:       uu.Host,
	}
}

// newProxyRequest is [newHopRequest] with the URL scheme translated to
// the carrying HTTP protocol ("http" for ws, "https" for wss):
// [net/http.ProxyFromEnvironment] resolves proxies for http and https
// URLs only (it returns nil for a ws or wss URL), and the translation
// is what lets it be assigned to [Dialer.Proxy] directly.
func newProxyRequest(u *url.URL, hdr http.Header) *http.Request {
	req := newHopRequest(u, hdr)
	if req.URL.Scheme == "wss" {
		req.URL.Scheme = "https"
	} else {
		req.URL.Scheme = "http"
	}
	return req
}

// resolveRedirect resolves a redirect Location against the current hop
// URL and vets the result: ws and wss pass through, http and https map
// onto them, anything else fails with [ErrNotWebSocketScheme], and a
// hostless or unparseable result fails with [ErrMalformedLocation].
// Errors deliberately never include the Location value (url.Parse's own
// error would echo it, credentials, query and all).
func resolveRedirect(current *url.URL, location string) (*url.URL, error) {
	ref, err := url.Parse(location)
	if err != nil {
		return nil, ErrMalformedLocation
	}
	next := current.ResolveReference(ref)
	switch next.Scheme {
	case "ws", "wss":
	case "http":
		next.Scheme = "ws"
	case "https":
		next.Scheme = "wss"
	default:
		return nil, fmt.Errorf("gows: redirect: %w", ErrNotWebSocketScheme)
	}
	if next.Hostname() == "" {
		return nil, ErrMalformedLocation
	}
	// URL userinfo is neither dialed with nor forwarded; drop it so it
	// cannot resurface through [Dialer.CheckRedirect]'s req or an error.
	next.User = nil
	return next, nil
}

// sameOrigin reports whether a and b share scheme, canonical
// (case-insensitive) hostname, and effective port -- the definition the
// redirect path's credential stripping uses.
func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

// effectivePort returns u's explicit port, or the scheme default (443
// for wss, 80 for ws).
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "wss" {
		return "443"
	}
	return "80"
}

// validateProxyAuthority rejects malformed programmatic proxy URLs before
// their authority is converted into a network address. Re-parsing String's
// serialized form applies net/url's bracket and port syntax validation, while
// discarding its error prevents userinfo or query material from entering the
// returned error chain.
func validateProxyAuthority(u *url.URL) error {
	reparsed, err := url.Parse(u.String())
	if err != nil || reparsed.Host != u.Host || reparsed.Hostname() == "" || strings.HasSuffix(reparsed.Host, ":") {
		return fmt.Errorf("gows: proxy URL: %w", net.InvalidAddrError("malformed authority"))
	}
	if port := reparsed.Port(); port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return fmt.Errorf("gows: proxy URL: %w", net.InvalidAddrError("malformed authority"))
		}
	}
	return nil
}

// proxyBasicAuth renders proxy-URL userinfo as a Proxy-Authorization
// value (RFC 7617 basic credentials), or "" when user is nil.
func proxyBasicAuth(user *url.Userinfo) string {
	if user == nil {
		return ""
	}
	pass, _ := user.Password()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+pass))
}

// proxyConnect establishes an RFC 7231 §4.3.6 CONNECT tunnel to
// originAddr over the already-dialed proxy connection, sending
// proxyAuth (when non-empty) as Proxy-Authorization on the CONNECT
// only. Anything but a well-formed, body-less 200 response is an error;
// a non-200 status surfaces as [ErrProxyConnectFailed] wrapping a
// [*UnexpectedStatusError], with no proxy-controlled text.
func proxyConnect(conn net.Conn, originAddr, proxyAuth string) error {
	var req bytes.Buffer
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", originAddr, originAddr)
	if proxyAuth != "" {
		fmt.Fprintf(&req, "Proxy-Authorization: %s\r\n", proxyAuth)
	}
	req.WriteString("\r\n")
	if _, err := conn.Write(req.Bytes()); err != nil {
		return fmt.Errorf("gows: write proxy CONNECT: %w", err)
	}

	data, filled, err := readHeaderBlock(conn, pool.Get(4096), defaultMaxHeaderBytes)
	if err != nil {
		pool.Put(data)
		if errors.Is(err, ErrHeaderTooLarge) {
			return fmt.Errorf("%w: %w", ErrProxyConnectFailed, err)
		}
		return fmt.Errorf("gows: read proxy CONNECT response: %w", err)
	}
	defer pool.Put(data)

	idx := bytes.Index(data[:filled], doubleCRLF)
	status, _, err := httpx.ParseStatusLine(data[:idx+4])
	if err != nil {
		return fmt.Errorf("gows: parse proxy CONNECT response: %w", err)
	}
	code, ok := parseStatusCode(status.Code)
	if !ok {
		return fmt.Errorf("gows: parse proxy CONNECT response: %w", httpx.ErrMalformedStatusLine)
	}
	if code != 200 {
		return fmt.Errorf("%w: %w", ErrProxyConnectFailed, &UnexpectedStatusError{StatusCode: code, Reason: string(status.Reason)})
	}
	if idx+4 < filled {
		// A 2xx CONNECT response has no body (RFC 7231 §4.3.6), and the
		// origin cannot have spoken before this side's TLS ClientHello:
		// bytes here mean a broken or hostile proxy.
		return fmt.Errorf("%w: unexpected data after the CONNECT response", ErrProxyConnectFailed)
	}
	return nil
}

// parseStatusCode parses an HTTP status-code field: exactly three
// ASCII digits (RFC 7230 §3.1.2). A malformed field makes the whole
// status line malformed -- reported distinctly from a well-formed but
// unexpected status.
func parseStatusCode(b []byte) (int, bool) {
	if len(b) != 3 {
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// isRedirectStatus reports whether code is a followable redirect
// status: 301, 302, 303, 307, or 308.
func isRedirectStatus(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// findLocation returns the first Location value in the scanned header
// block, or "" when none is present, after validating every header line.
func findLocation(headers []byte) (string, error) {
	sc := httpx.NewHeaderScanner(headers)
	var location string
	for sc.Next() {
		if location == "" && httpx.EqualFold(sc.Key(), "location") {
			location = string(sc.Value())
		}
	}
	return location, sc.Err()
}

// handshake writes the handshake request to conn and validates the
// response, per RFC 6455 §4.1. hdr is the already-validated
// [Dialer.HTTPHeader] snapshot. absoluteForm selects the RFC 7230
// §5.3.2 absolute-form request-target used on the "ws"-through-proxy
// leg; proxyAuth, when non-empty, is emitted with it (and only with
// it), serialized apart from hdr. When [Dialer.CheckRedirect] is set
// and the response is a well-formed redirect carrying a Location,
// handshake returns that Location with a nil error and lets the caller
// decide; any other non-101 status fails with [*UnexpectedStatusError].
func (d *Dialer) handshake(conn net.Conn, u *url.URL, hdr http.Header, absoluteForm bool, proxyAuth string) (Handshake, string, error) {
	wsKey, err := httpx.AppendKey(nil)
	if err != nil {
		return Handshake{}, "", fmt.Errorf("gows: generate Sec-WebSocket-Key: %w", err)
	}

	var req bytes.Buffer
	if absoluteForm {
		// The proxy routes on the absolute-form target's authority. The
		// scheme is written as "http" -- the carrying protocol of the
		// opening handshake -- which any HTTP proxy understands, where a
		// literal "ws" scheme is one RFC 7230 intermediaries need not.
		fmt.Fprintf(&req, "GET http://%s%s HTTP/1.1\r\n", u.Host, requestTarget(u))
	} else {
		fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", requestTarget(u))
	}
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	if absoluteForm && proxyAuth != "" {
		// Proxy credentials ride the proxy leg only -- the absolute-form
		// GET here, or the CONNECT in proxyConnect -- never an origin
		// request inside a tunnel, and never merged into (or serialized
		// through) the caller's header snapshot, which rejected any
		// Proxy-Authorization entry during validation.
		fmt.Fprintf(&req, "Proxy-Authorization: %s\r\n", proxyAuth)
	}
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", wsKey)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	if len(d.Subprotocols) > 0 {
		fmt.Fprintf(&req, "Sec-WebSocket-Protocol: %s\r\n", joinComma(d.Subprotocols))
	}
	offerHeader, offerParams := d.deflateOffer()
	if d.EnableCompression {
		fmt.Fprintf(&req, "Sec-WebSocket-Extensions: %s\r\n", offerHeader)
	}
	if len(hdr) > 0 {
		req.Write(appendExtraHeaders(nil, hdr))
	}
	req.WriteString("\r\n")

	if _, err := conn.Write(req.Bytes()); err != nil {
		return Handshake{}, "", fmt.Errorf("gows: write handshake request: %w", err)
	}

	data, filled, err := readHeaderBlock(conn, pool.Get(4096), defaultMaxHeaderBytes)
	if err != nil {
		pool.Put(data)
		if errors.Is(err, ErrHeaderTooLarge) {
			return Handshake{}, "", err
		}
		return Handshake{}, "", fmt.Errorf("gows: read handshake response: %w", err)
	}
	defer pool.Put(data)

	idx := bytes.Index(data[:filled], doubleCRLF)
	headerBlock := data[:idx+4]

	status, consumed, err := httpx.ParseStatusLine(headerBlock)
	if err != nil {
		return Handshake{}, "", fmt.Errorf("gows: parse status line: %w", err)
	}
	headers := headerBlock[consumed:]
	code, ok := parseStatusCode(status.Code)
	if !ok {
		return Handshake{}, "", fmt.Errorf("gows: parse status line: %w", httpx.ErrMalformedStatusLine)
	}
	if code != 101 {
		if d.CheckRedirect != nil && isRedirectStatus(code) {
			loc, err := findLocation(headers)
			if err != nil {
				return Handshake{}, "", fmt.Errorf("gows: scan redirect response headers: %w", err)
			}
			if loc != "" {
				return Handshake{}, loc, nil
			}
		}
		return Handshake{}, "", &UnexpectedStatusError{StatusCode: code, Reason: string(status.Reason)}
	}

	var upgradeOK, connectionOK bool
	var accept, serverProtocol, serverExtensions []byte

	sc := httpx.NewHeaderScanner(headers)
	for sc.Next() {
		switch {
		case httpx.EqualFold(sc.Key(), "upgrade"):
			upgradeOK = upgradeOK || httpx.ContainsToken(sc.Value(), "websocket")
		case httpx.EqualFold(sc.Key(), "connection"):
			connectionOK = connectionOK || httpx.ContainsToken(sc.Value(), "upgrade")
		case httpx.EqualFold(sc.Key(), "sec-websocket-accept"):
			accept = sc.Value()
		case httpx.EqualFold(sc.Key(), "sec-websocket-protocol"):
			serverProtocol = sc.Value()
		case httpx.EqualFold(sc.Key(), "sec-websocket-extensions"):
			serverExtensions = sc.Value()
		}
	}
	if err := sc.Err(); err != nil {
		return Handshake{}, "", fmt.Errorf("gows: scan handshake response headers: %w", err)
	}

	if !upgradeOK {
		return Handshake{}, "", ErrNotUpgrade
	}
	if !connectionOK {
		return Handshake{}, "", ErrNotConnectionUpgrade
	}
	// The Sec-WebSocket-Accept comparison need not run in constant time:
	// it is a proof that the peer echoed a value derived from a nonce we
	// just generated, not a secret whose comparison timing could leak
	// anything an attacker doesn't already know.
	wantAccept := httpx.AppendAccept(nil, wsKey)
	if !bytes.Equal(accept, wantAccept) {
		return Handshake{}, "", ErrAcceptMismatch
	}

	selected := ""
	if len(serverProtocol) > 0 {
		for _, want := range d.Subprotocols {
			if string(serverProtocol) == want {
				selected = want
				break
			}
		}
		if selected == "" {
			return Handshake{}, "", ErrUnrequestedSubprotocol
		}
	}

	var compressed bool
	var agreedParams extension.DeflateParams
	if d.EnableCompression && serverExtensions != nil && hasDeflateElement(serverExtensions) {
		respParams, verr := extension.ValidateDeflateResponse(offerParams, serverExtensions)
		if verr != nil {
			return Handshake{}, "", fmt.Errorf("%w: %w", ErrInvalidCompressionResponse, verr)
		}
		agreedParams = respParams
		compressed = true
	}

	h := Handshake{Subprotocol: selected, Compressed: compressed}
	if compressed {
		cp := compressionParamsFromDeflate(agreedParams)
		// Client's own outgoing ceiling: response value if present, else the
		// self-imposed offer (WindowBits); when both present, take the min.
		switch {
		case agreedParams.ClientMaxWindowBits > 0 && d.WindowBits != 0:
			cp.ClientMaxWindowBits = min(agreedParams.ClientMaxWindowBits, d.WindowBits)
		case agreedParams.ClientMaxWindowBits > 0:
			cp.ClientMaxWindowBits = agreedParams.ClientMaxWindowBits
		case d.WindowBits != 0:
			cp.ClientMaxWindowBits = d.WindowBits
		}
		// A response may tighten the ceiling below what the offer-time check
		// already accepted (e.g. we offered 10, server replied 8).
		if err := checkWindowBitsSupported(cp.ClientMaxWindowBits); err != nil {
			return Handshake{}, "", err
		}
		h.CompressionParams = cp
	}
	if idx+4 < filled {
		h.Buffered = append([]byte(nil), data[idx+4:filled]...)
	}
	return h, "", nil
}

// requestTarget returns u's request-target (RFC 7230 §5.3.1) for a
// handshake request: the escaped path and, if present, query, exactly as
// [url.URL.RequestURI] computes it, defaulting to "/" for an empty path.
func requestTarget(u *url.URL) string {
	return u.RequestURI()
}

// joinComma joins ss with ", " -- the conventional separator for a
// #token list per RFC 7230 §7 -- for use as a Sec-WebSocket-Protocol
// request header value.
func joinComma(ss []string) string {
	var b bytes.Buffer
	for i, s := range ss {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s)
	}
	return b.String()
}
