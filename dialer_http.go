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
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zchee/gows/internal/httpx"
)

// dialHTTP performs the opening handshake as one HTTP/1.1 GET through
// [Dialer.HTTPClient]. hdr is the already-validated [Dialer.HTTPHeader]
// snapshot. The response is checked by the same code as the native path's,
// and on success the returned net.Conn carries I/O through the 101 response
// body and deadlines to the connection the transport reported.
func (d *Dialer) dialHTTP(ctx context.Context, u *url.URL, hdr http.Header) (net.Conn, Handshake, error) {
	// Send with a copy, so the caller's client is never modified.
	hc := *d.HTTPClient
	if hc.Timeout > 0 {
		// net/http enforces Client.Timeout by wrapping the response body
		// in a timer, which makes a 101 body read-only and would cut the
		// established connection when the timer fires. Bound the handshake
		// with the same budget through its context instead, and send with
		// a Timeout of zero.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, hc.Timeout)
		defer cancel()
		hc.Timeout = 0
	}
	// Record what the redirect policy returns: that error is the caller's
	// own text, so it is the one Do error kept apart from the transport's.
	// A client without a policy gets net/http's default limit, reported as
	// [ErrTooManyRedirects] like the native path's redirect loop.
	var policyErr error
	policy := hc.CheckRedirect
	if policy == nil {
		policy = func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrTooManyRedirects
			}
			return nil
		}
	}
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		err := policy(req, via)
		if err != nil && err != http.ErrUseLastResponse {
			policyErr = err
		}
		return err
	}

	target := *u
	// net/http would turn URL userinfo into an Authorization header; the
	// native path never sends it, and neither does this one.
	target.User = nil
	if target.Scheme == "wss" {
		target.Scheme = "https"
	} else {
		target.Scheme = "http"
	}

	// Fail before any network I/O on an already-ended context.
	if ctx.Err() != nil {
		return nil, Handshake{}, fmt.Errorf("gows: dial %s: %w", target.Host, contextError(ctx))
	}

	var trace connTrace
	reqCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: trace.gotConn, TLSHandshakeDone: trace.tlsHandshakeDone})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("gows: dial URL: %w", net.InvalidAddrError("malformed URL"))
	}
	maps.Copy(req.Header, hdr)
	// The handshake fields are assigned by key rather than with Set, which
	// would canonicalize Sec-WebSocket-* to Sec-Websocket-*: net/http writes
	// keys as stored, so this sends the RFC 6455 spelling the native path
	// sends, for servers that match header names byte for byte. The snapshot
	// was validated to hold none of these names in any spelling.
	wsKey := httpx.AppendKey(nil)
	req.Header[`Upgrade`] = []string{`websocket`}
	req.Header[`Connection`] = []string{`Upgrade`}
	req.Header[`Sec-WebSocket-Key`] = []string{string(wsKey)}
	req.Header[`Sec-WebSocket-Version`] = []string{`13`}
	if len(d.Subprotocols) > 0 {
		req.Header[`Sec-WebSocket-Protocol`] = []string{strings.Join(d.Subprotocols, ", ")}
	}
	offerHeader := d.deflateOffer()
	if d.EnableCompression {
		req.Header[`Sec-WebSocket-Extensions`] = []string{offerHeader}
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, Handshake{}, httpDoError(ctx, target.Host, err, policyErr, &trace)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		_, reason, _ := strings.Cut(resp.Status, " ")
		e := &UnexpectedStatusError{StatusCode: resp.StatusCode, Reason: reason, Header: resp.Header}
		err := refusalError(e, resp.Body, d.MaxErrorBodyBytes)
		_ = resp.Body.Close()
		return nil, Handshake{}, withDialContext(ctx, err)
	}

	fail := func(err error) (net.Conn, Handshake, error) {
		_ = resp.Body.Close()
		return nil, Handshake{}, err
	}
	hs, err := d.checkUpgradeResponse(httpHandshakeHeaders(resp.Header), wsKey, offerHeader)
	if err != nil {
		return fail(err)
	}
	body, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return fail(fmt.Errorf("%w: the 101 response body is not writable", ErrUnsupportedHTTPTransport))
	}
	conn := trace.last()
	if conn == nil {
		return fail(fmt.Errorf("%w: the transport did not report its connection", ErrUnsupportedHTTPTransport))
	}
	// The caller owns the connection from here: clear any deadline on the
	// reported connection. That the call succeeds shows the connection
	// accepts deadlines, not that it is the one carrying the body.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(fmt.Errorf("gows: clear handshake deadline: %w", err))
	}
	// The dial context, which includes the client's Timeout, may have ended
	// after the 101 arrived. The caller asked for cancellation regardless:
	// fail the dial and close the connection, as the native path does.
	if ctx.Err() != nil {
		return fail(fmt.Errorf("gows: handshake: %w", contextError(ctx)))
	}
	return &httpConn{body: body, conn: conn}, hs, nil
}

// httpDoError turns an error from the HTTP client's Do into the error Dial
// returns. net/http's errors quote what the peer sent (a malformed status
// line or header, a Location value with its userinfo, a proxy's refusal
// reason), and this package's error text never carries peer-controlled
// content, so the original error is never returned or wrapped. Only what
// the native path also reports is kept, each rebuilt from the part net/http
// wrapped: the dial context's error and cause, the caller's own
// CheckRedirect error (policyErr), the TLS handshake error the transport
// reported to trace (or net/http's scheme-mismatch sentinel standing in
// for it), network errors, an early end of the response, and the fact of
// a transport timeout.
// Anything else becomes [ErrHTTPRequestFailed].
func httpDoError(ctx context.Context, host string, err, policyErr error, trace *connTrace) error {
	// The transport reports an ended request context as ctx.Err or as its
	// cancellation cause alone; either way the context is the error.
	if ctx.Err() != nil && (errorContainsContext(err, ctx) || errors.Is(err, context.Cause(ctx))) {
		return fmt.Errorf("gows: dial %s: %w", host, contextError(ctx))
	}
	var kept error
	switch tlsErr := trace.tlsErrorIn(err); {
	case policyErr != nil && errors.Is(err, policyErr):
		kept = fmt.Errorf("gows: redirect blocked: %w", policyErr)
	case tlsErr != nil:
		kept = fmt.Errorf("gows: tls handshake: %w", tlsErr)
	case errors.Is(err, http.ErrSchemeMismatch):
		// net/http replaces the TLS record error of a plain HTTP answer
		// to a TLS handshake with this fixed-text sentinel.
		kept = fmt.Errorf("gows: tls handshake: %w", http.ErrSchemeMismatch)
	default:
		if te := transportError(err); te != nil {
			kept = fmt.Errorf("gows: dial %s: %w", host, te)
		} else {
			kept = fmt.Errorf("gows: dial %s: %w", host, ErrHTTPRequestFailed)
		}
	}
	return withDialContext(ctx, kept)
}

// transportError returns the network-level error in err's chain whose text
// net/http does not build from the peer's bytes, or nil when there is none.
// A proxy dial wraps its failures in a *net.OpError whose Op is
// "proxyconnect". net/http puts the dial to the proxy and an https proxy's
// TLS handshake behind that wrapper today, and returns a refused CONNECT
// unwrapped; its Err is vetted all the same instead of trusted, so the
// result does not depend on what a later net/http wraps there.
func transportError(err error) error {
	if oe, ok := errors.AsType[*net.OpError](err); ok {
		if oe.Op != "proxyconnect" {
			return oe
		}
		inner := transportError(oe.Err)
		if inner == nil {
			return nil
		}
		return &net.OpError{Op: oe.Op, Net: oe.Net, Source: oe.Source, Addr: oe.Addr, Err: inner}
	}
	if de, ok := errors.AsType[*net.DNSError](err); ok {
		return de
	}
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		return io.ErrUnexpectedEOF
	case errors.Is(err, io.EOF):
		return io.EOF
	}
	// A timeout of the transport's own, such as its response-header
	// timeout, is reported as a deadline error; only the fact is kept.
	if ue, ok := errors.AsType[*url.Error](err); ok {
		if ne, ok := errors.AsType[net.Error](ue.Err); ok && ne.Timeout() {
			return os.ErrDeadlineExceeded
		}
	}
	return nil
}

// withDialContext reports ctx as the primary error when the dial context
// ended during the exchange and err does not already say so, keeping err in
// the chain; this matches how the native path reports an interrupted dial.
func withDialContext(ctx context.Context, err error) error {
	if ctx.Err() != nil && !errorContainsContext(err, ctx) {
		return fmt.Errorf("gows: dial: %w: %w", contextError(ctx), err)
	}
	return err
}

// httpHandshakeHeaders extracts the opening-handshake fields of a response
// header parsed by net/http, with the same semantics scanWSHandshakeHeaders
// applies to a raw header block: the Upgrade and Connection tokens may
// appear in any of their values, and for the other fields the last value
// wins.
func httpHandshakeHeaders(h http.Header) wsHandshakeHeaders {
	var f wsHandshakeHeaders
	for _, v := range h.Values(`Upgrade`) {
		f.upgradeOK = f.upgradeOK || httpx.ContainsToken([]byte(v), "websocket")
	}
	for _, v := range h.Values(`Connection`) {
		f.connectionOK = f.connectionOK || httpx.ContainsToken([]byte(v), "upgrade")
	}
	f.accept = lastHeaderValue(h, `Sec-WebSocket-Accept`)
	f.protocol = lastHeaderValue(h, `Sec-WebSocket-Protocol`)
	f.extensions = lastHeaderValue(h, `Sec-WebSocket-Extensions`)
	return f
}

// lastHeaderValue returns the last value of key in h, or nil when absent.
func lastHeaderValue(h http.Header, key string) []byte {
	vs := h.Values(key)
	if len(vs) == 0 {
		return nil
	}
	return []byte(vs[len(vs)-1])
}

// connTrace records the last connection a transport reported through
// [httptrace.ClientTrace.GotConn], and every failed TLS handshake it
// reported through [httptrace.ClientTrace.TLSHandshakeDone]. A request that
// follows redirects or is retried reports one connection per attempt; the
// last one carries the response that is returned, provided no round tripper
// sends another request with the same context afterwards (see
// [Dialer.HTTPClient]). The transport may call
// the hooks from its own goroutines, including for a dial it starts in the
// background and never uses, hence the lock and the list.
type connTrace struct {
	mu      sync.Mutex
	conn    net.Conn
	tlsErrs []error
}

func (t *connTrace) tlsHandshakeDone(_ tls.ConnectionState, err error) {
	if err == nil {
		return
	}
	t.mu.Lock()
	t.tlsErrs = append(t.tlsErrs, err)
	t.mu.Unlock()
}

// tlsErrorIn returns the recorded TLS handshake error that err's chain
// holds, or nil.
func (t *connTrace) tlsErrorIn(err error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tlsErr := range t.tlsErrs {
		if errors.Is(err, tlsErr) {
			return tlsErr
		}
	}
	return nil
}

func (t *connTrace) gotConn(info httptrace.GotConnInfo) {
	t.mu.Lock()
	t.conn = info.Conn
	t.mu.Unlock()
}

func (t *connTrace) last() net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn
}

// httpConn is the net.Conn [Dialer.Dial] returns on the [Dialer.HTTPClient]
// path. Reads, writes, and Close go through the 101 response body, which
// first yields any bytes the transport buffered past the response;
// deadlines and addresses go to the connection the transport reported,
// the one the body reads from and writes to.
type httpConn struct {
	body io.ReadWriteCloser
	conn net.Conn
}

// Read reads from the 101 response body.
func (c *httpConn) Read(p []byte) (int, error) { return c.body.Read(p) }

// Write writes to the 101 response body.
func (c *httpConn) Write(p []byte) (int, error) { return c.body.Write(p) }

// Close closes the 101 response body, which closes the connection.
func (c *httpConn) Close() error { return c.body.Close() }

// LocalAddr returns the reported connection's local address.
func (c *httpConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the reported connection's remote address.
func (c *httpConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// SetDeadline sets both deadlines on the reported connection.
func (c *httpConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the reported connection.
func (c *httpConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the reported connection.
func (c *httpConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
