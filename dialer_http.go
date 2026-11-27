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
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
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
	hc := d.HTTPClient
	if hc.Timeout > 0 {
		// net/http enforces Client.Timeout by wrapping the response body
		// in a timer, which makes a 101 body read-only and would cut the
		// established connection when the timer fires. Bound the handshake
		// with the same budget through its context instead, and send with
		// a copy whose Timeout is zero; the caller's client is untouched.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, hc.Timeout)
		defer cancel()
		c := *hc
		c.Timeout = 0
		hc = &c
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
	reqCtx := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: trace.gotConn})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, Handshake{}, fmt.Errorf("gows: dial URL: %w", net.InvalidAddrError("malformed URL"))
	}
	maps.Copy(req.Header, hdr)
	wsKey := httpx.AppendKey(nil)
	req.Header.Set(`Upgrade`, `websocket`)
	req.Header.Set(`Connection`, `Upgrade`)
	req.Header.Set(`Sec-WebSocket-Key`, string(wsKey))
	req.Header.Set(`Sec-WebSocket-Version`, `13`)
	if len(d.Subprotocols) > 0 {
		req.Header.Set(`Sec-WebSocket-Protocol`, strings.Join(d.Subprotocols, ", "))
	}
	offerHeader := d.deflateOffer()
	if d.EnableCompression {
		req.Header.Set(`Sec-WebSocket-Extensions`, offerHeader)
	}

	resp, err := hc.Do(req)
	if err != nil {
		// *url.Error repeats the full request URL, query included; keep
		// only its cause, as the native path's errors name the host alone.
		if ue, ok := err.(*url.Error); ok {
			err = ue.Err
		}
		return nil, Handshake{}, withDialContext(ctx, fmt.Errorf("gows: dial %s: %w", target.Host, err))
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
	// The caller owns the connection from here: start it with no deadline,
	// and prove deadlines reach the reported connection before handing it
	// over.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(fmt.Errorf("gows: clear handshake deadline: %w", err))
	}
	return &httpConn{body: body, conn: conn}, hs, nil
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
// [httptrace.ClientTrace.GotConn]. A request that follows redirects or is
// retried reports one connection per attempt; the last one carries the
// response that is returned. The transport may call the hook from its own
// goroutine, hence the lock.
type connTrace struct {
	mu   sync.Mutex
	conn net.Conn
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
