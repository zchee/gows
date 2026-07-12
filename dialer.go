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
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/zchee/gows/internal/extension"
	"github.com/zchee/gows/internal/httpx"
	"github.com/zchee/gows/internal/pool"
)

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
// [ErrUnrequestedSubprotocol].
//
// On any failure after a connection was established, Dial closes it and
// returns a non-nil error alongside a nil net.Conn. On success, the
// caller owns the returned net.Conn (e.g. to build a Conn on top of it,
// once that type exists) and any bytes the server had already sent past
// the handshake response (e.g. a pipelined first WebSocket frame) are
// returned as Handshake.Buffered; see [Handshake] for the contract a
// caller building a Conn on top of the returned net.Conn must follow.
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

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("gows: parse dial URL: %w", err)
	}

	var useTLS bool
	switch u.Scheme {
	case "ws":
		useTLS = false
	case "wss":
		useTLS = true
	default:
		return nil, Handshake{}, ErrNotWebSocketScheme
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	dial := d.NetDial
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("gows: dial %s: %w", addr, err)
	}

	if useTLS {
		cfg := d.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{}
		} else {
			cfg = cfg.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, Handshake{}, fmt.Errorf("gows: tls handshake: %w", err)
		}
		conn = tlsConn
	}

	hs, err := d.handshake(conn, u)
	if err != nil {
		conn.Close()
		return nil, Handshake{}, err
	}
	return conn, hs, nil
}

// handshake writes the handshake request to conn and validates the
// response, per RFC 6455 §4.1.
func (d *Dialer) handshake(conn net.Conn, u *url.URL) (Handshake, error) {
	wsKey, err := httpx.AppendKey(nil)
	if err != nil {
		return Handshake{}, fmt.Errorf("gows: generate Sec-WebSocket-Key: %w", err)
	}

	var req bytes.Buffer
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\n", requestTarget(u))
	fmt.Fprintf(&req, "Host: %s\r\n", u.Host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", wsKey)
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	if len(d.Subprotocols) > 0 {
		fmt.Fprintf(&req, "Sec-WebSocket-Protocol: %s\r\n", joinComma(d.Subprotocols))
	}
	offerHeader, offerParams := d.deflateOffer()
	if d.EnableCompression {
		fmt.Fprintf(&req, "Sec-WebSocket-Extensions: %s\r\n", offerHeader)
	}
	req.WriteString("\r\n")

	if _, err := conn.Write(req.Bytes()); err != nil {
		return Handshake{}, fmt.Errorf("gows: write handshake request: %w", err)
	}

	data, filled, err := readHeaderBlock(conn, pool.Get(4096), defaultMaxHeaderBytes)
	if err != nil {
		pool.Put(data)
		if errors.Is(err, ErrHeaderTooLarge) {
			return Handshake{}, err
		}
		return Handshake{}, fmt.Errorf("gows: read handshake response: %w", err)
	}
	defer pool.Put(data)

	idx := bytes.Index(data[:filled], doubleCRLF)
	headerBlock := data[:idx+4]

	status, consumed, err := httpx.ParseStatusLine(headerBlock)
	if err != nil {
		return Handshake{}, fmt.Errorf("gows: parse status line: %w", err)
	}
	if string(status.Code) != "101" {
		return Handshake{}, fmt.Errorf("%w: %s %s", ErrUnexpectedStatus, status.Code, status.Reason)
	}
	headers := headerBlock[consumed:]

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
		return Handshake{}, fmt.Errorf("gows: scan handshake response headers: %w", err)
	}

	if !upgradeOK {
		return Handshake{}, ErrNotUpgrade
	}
	if !connectionOK {
		return Handshake{}, ErrNotConnectionUpgrade
	}
	// The Sec-WebSocket-Accept comparison need not run in constant time:
	// it is a proof that the peer echoed a value derived from a nonce we
	// just generated, not a secret whose comparison timing could leak
	// anything an attacker doesn't already know.
	wantAccept := httpx.AppendAccept(nil, wsKey)
	if !bytes.Equal(accept, wantAccept) {
		return Handshake{}, ErrAcceptMismatch
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
			return Handshake{}, ErrUnrequestedSubprotocol
		}
	}

	var compressed bool
	var agreedParams extension.DeflateParams
	if d.EnableCompression && serverExtensions != nil && hasDeflateElement(serverExtensions) {
		respParams, verr := extension.ValidateDeflateResponse(offerParams, serverExtensions)
		if verr != nil {
			return Handshake{}, fmt.Errorf("%w: %w", ErrInvalidCompressionResponse, verr)
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
			return Handshake{}, err
		}
		h.CompressionParams = cp
	}
	if idx+4 < filled {
		h.Buffered = append([]byte(nil), data[idx+4:filled]...)
	}
	return h, nil
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
