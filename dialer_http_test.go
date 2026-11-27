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

package gows_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/httpx"
)

// newHTTPClient returns a client with its own transport, so connection
// pooling never crosses tests, and closes its idle connections when the
// test ends.
func newHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// wsURL turns an httptest server URL into the matching ws or wss URL.
func wsURL(srv *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + path
}

// serveEcho echoes every message on c until the connection fails.
func serveEcho(c *gows.Conn) {
	for {
		op, p, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(op, p); err != nil {
			return
		}
	}
}

// upgradeServer is an httptest server whose handler upgrades every request
// with u and passes the connection and handshake to serve. requests
// receives each upgraded request's header.
type upgradeServer struct {
	*httptest.Server
	requests chan http.Header
}

// startHTTPUpgradeServer starts a plain or TLS httptest server whose handler
// upgrades with u and then calls serve. The server is closed when the test
// ends.
func startHTTPUpgradeServer(t *testing.T, useTLS bool, u *gows.Upgrader, serve func(net.Conn, gows.Handshake)) *upgradeServer {
	t.Helper()
	s := &upgradeServer{requests: make(chan http.Header, 4)}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests <- r.Header.Clone()
		conn, hs, err := u.UpgradeHTTP(w, r)
		if err != nil {
			t.Errorf("UpgradeHTTP: %v", err)
			return
		}
		defer conn.Close()
		serve(conn, hs)
	})
	if useTLS {
		s.Server = httptest.NewTLSServer(h)
	} else {
		s.Server = httptest.NewServer(h)
	}
	t.Cleanup(s.Close)
	return s
}

// echoServe is a serve function for startHTTPUpgradeServer that echoes until
// the client goes away.
func echoServe(conn net.Conn, hs gows.Handshake) {
	serveEcho(gows.NewServerConn(conn, compressionOptions(hs)...))
}

// compressionOptions returns the Conn options matching what hs negotiated.
func compressionOptions(hs gows.Handshake) []gows.ConnOption {
	if !hs.Compressed {
		return nil
	}
	return []gows.ConnOption{gows.WithCompressionParams(hs.CompressionParams)}
}

// roundTrip writes msg on c and fails the test unless the echo matches.
func roundTrip(t *testing.T, c *gows.Conn, msg string) {
	t.Helper()
	if err := c.WriteMessage(gows.OpcodeText, []byte(msg)); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	op, p, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if op != gows.OpcodeText || string(p) != msg {
		t.Fatalf("ReadMessage = (%v, %q), want (%v, %q)", op, p, gows.OpcodeText, msg)
	}
}

// headerRoundTripper wraps a transport and adds a header to every request,
// keeping the request's context.
type headerRoundTripper struct{ next http.RoundTripper }

func (h headerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Wrapped", "1")
	return h.next.RoundTrip(r)
}

// TestDialHTTPClientEcho dials through an HTTP client over plain TCP, TLS,
// and a RoundTripper that wraps the transport, then exchanges a message.
func TestDialHTTPClientEcho(t *testing.T) {
	tests := map[string]struct {
		useTLS  bool
		wrapped bool
	}{
		"success: plain transport":       {},
		"success: TLS transport":         {useTLS: true},
		"success: wrapping RoundTripper": {wrapped: true},
		"success: wrapped TLS transport": {useTLS: true, wrapped: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			srv := startHTTPUpgradeServer(t, tt.useTLS, &gows.Upgrader{}, echoServe)
			hc := srv.Client()
			if tt.wrapped {
				hc.Transport = headerRoundTripper{next: hc.Transport}
			}
			d := &gows.Dialer{
				HTTPClient: hc,
				HTTPHeader: http.Header{"X-Extra": {"extra-value"}},
			}
			conn, hs, err := d.Dial(t.Context(), wsURL(srv.Server, "/chat?room=1"))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()
			if hs.Buffered != nil {
				t.Errorf("Buffered = %q, want nil on the HTTP client path", hs.Buffered)
			}
			if got, want := conn.RemoteAddr().String(), srv.Listener.Addr().String(); got != want {
				t.Errorf("RemoteAddr = %s, want %s", got, want)
			}
			if conn.LocalAddr() == nil {
				t.Error("LocalAddr = nil")
			}

			req := <-srv.requests
			for key, want := range map[string]string{
				"Upgrade":               "websocket",
				"Connection":            "Upgrade",
				"Sec-Websocket-Version": "13",
				"X-Extra":               "extra-value",
			} {
				if got := req.Get(key); got != want {
					t.Errorf("request %s = %q, want %q", key, got, want)
				}
			}
			if got := req.Get("Sec-Websocket-Key"); len(got) != 24 {
				t.Errorf("request Sec-WebSocket-Key = %q, want a 24-byte key", got)
			}
			if got, want := req.Get("X-Wrapped"), map[bool]string{true: "1"}[tt.wrapped]; got != want {
				t.Errorf("request X-Wrapped = %q, want %q", got, want)
			}

			c := gows.NewClientConn(conn)
			roundTrip(t, c, "hello over the HTTP client")
			roundTrip(t, c, strings.Repeat("x", 70000))
			if err := c.Close(gows.CloseNormalClosure, ""); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

// TestDialHTTPClientNegotiation selects a subprotocol and negotiates
// permessage-deflate through an HTTP client, then exchanges a compressed
// message.
func TestDialHTTPClientNegotiation(t *testing.T) {
	srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{Subprotocols: []string{"v2"}, EnableCompression: true}, echoServe)
	d := &gows.Dialer{
		HTTPClient:        newHTTPClient(t),
		Subprotocols:      []string{"v1", "v2"},
		EnableCompression: true,
	}
	conn, hs, err := d.Dial(t.Context(), wsURL(srv.Server, "/"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if hs.Subprotocol != "v2" {
		t.Errorf("Subprotocol = %q, want v2", hs.Subprotocol)
	}
	if !hs.Compressed {
		t.Fatal("Compressed = false, want permessage-deflate negotiated")
	}
	req := <-srv.requests
	if got := req.Get("Sec-Websocket-Protocol"); got != "v1, v2" {
		t.Errorf("request Sec-WebSocket-Protocol = %q, want %q", got, "v1, v2")
	}
	if got := req.Get("Sec-Websocket-Extensions"); !strings.HasPrefix(got, "permessage-deflate") {
		t.Errorf("request Sec-WebSocket-Extensions = %q, want a permessage-deflate offer", got)
	}
	c := gows.NewClientConn(conn, compressionOptions(hs)...)
	roundTrip(t, c, strings.Repeat("compressible ", 4096))
	if err := c.Close(gows.CloseNormalClosure, ""); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// upgradeResponseWith is a 101 response that accepts req's key, with extra
// header lines (each ending in CRLF) appended.
func upgradeResponseWith(t *testing.T, req []byte, extra string) string {
	t.Helper()
	return "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n" +
		extra + "\r\n"
}

// TestDialHandshakeResponseRejections runs every handshake-response
// rejection against every dial path: each path must fail with the same
// error and close the connection.
func TestDialHandshakeResponseRejections(t *testing.T) {
	const noTakeover = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
	tests := map[string]struct {
		dialer  gows.Dialer
		respond func(t *testing.T, req []byte) string
		wantErr error
	}{
		// The refusal has no Content-Length, so its body runs until the
		// connection closes and no HTTP client can keep the connection
		// for another request: every path must close it.
		"error: wrong status code": {
			respond: func(*testing.T, []byte) string { return "HTTP/1.1 400 Bad Request\r\n\r\n" },
			wantErr: gows.ErrUnexpectedStatus,
		},
		"error: missing Upgrade header": {
			respond: func(t *testing.T, req []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n\r\n"
			},
			wantErr: gows.ErrNotUpgrade,
		},
		"error: missing Connection header": {
			respond: func(t *testing.T, req []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n\r\n"
			},
			wantErr: gows.ErrNotConnectionUpgrade,
		},
		"error: tampered Sec-WebSocket-Accept": {
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: dGhpc2lzd3Jvbmc9PQ==\r\n\r\n"
			},
			wantErr: gows.ErrAcceptMismatch,
		},
		"error: unrequested subprotocol": {
			dialer: gows.Dialer{Subprotocols: []string{"chat"}},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Protocol: not-offered\r\n")
			},
			wantErr: gows.ErrUnrequestedSubprotocol,
		},
		"error: subprotocol selected with none offered": {
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Protocol: chat\r\n")
			},
			wantErr: gows.ErrUnrequestedSubprotocol,
		},
		"error: extension response names an unrelated extension": {
			dialer: gows.Dialer{EnableCompression: true},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: x-foo\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: malformed permessage-deflate response": {
			dialer: gows.Dialer{EnableCompression: true},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: permessage-deflate; not_a_real_param\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: bare client_max_window_bits response to a plain offer": {
			dialer: gows.Dialer{EnableCompression: true},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: "+noTakeover+"; client_max_window_bits\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: unsolicited valued client_max_window_bits": {
			dialer: gows.Dialer{EnableCompression: true},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: "+noTakeover+"; client_max_window_bits=15\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: server_max_window_bits response above the offer": {
			dialer: gows.Dialer{EnableCompression: true, ServerWindowBits: 10},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: "+noTakeover+"; server_max_window_bits=11\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: permessage-deflate accepted but never offered": {
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: permessage-deflate\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: bare response to a bare client_max_window_bits offer": {
			dialer: gows.Dialer{EnableCompression: true, OfferClientMaxWindowBits: true},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: "+noTakeover+"; client_max_window_bits\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: out-of-range client_max_window_bits response": {
			dialer: gows.Dialer{EnableCompression: true, OfferClientMaxWindowBits: true},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: "+noTakeover+"; client_max_window_bits=7\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
		"error: client_max_window_bits the deflate backend cannot honor": {
			dialer: gows.Dialer{EnableCompression: true, OfferClientMaxWindowBits: true},
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: "+noTakeover+"; client_max_window_bits=9\r\n")
			},
			wantErr: gows.ErrUnsupportedWindowBits,
		},
	}
	for pathName, setPath := range dialPaths {
		for name, tt := range tests {
			t.Run(pathName+"/"+name, func(t *testing.T) {
				srv := startRawServer(t, func(req []byte) string { return tt.respond(t, req) })
				d := tt.dialer
				setPath(t, &d)
				conn, err := dialWithin(t, t.Context(), &d, srv.url, 5*time.Second)
				if conn != nil {
					conn.Close()
					t.Fatalf("Dial conn = %v, want nil on a rejected response", conn)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Dial err = %v, want errors.Is %v", err, tt.wantErr)
				}
				srv.awaitClosed(t)
			})
		}
	}
}

// TestDialDuplicatedResponseFields sends 101 responses that repeat a
// handshake field. Both paths take the last value of Sec-WebSocket-Accept,
// Sec-WebSocket-Protocol, and Sec-WebSocket-Extensions, so the same
// response must have the same outcome on each.
func TestDialDuplicatedResponseFields(t *testing.T) {
	const noTakeover = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
	tests := map[string]struct {
		respond        func(t *testing.T, req []byte) string
		wantErr        error
		wantProtocol   string
		wantCompressed bool
	}{
		"success: Sec-WebSocket-Accept repeated, wrong value first": {
			respond: func(t *testing.T, req []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: dGhpc2lzd3Jvbmc9PQ==\r\n" +
					"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n\r\n"
			},
		},
		"error: Sec-WebSocket-Accept repeated, wrong value last": {
			respond: func(t *testing.T, req []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n" +
					"Sec-WebSocket-Accept: dGhpc2lzd3Jvbmc9PQ==\r\n\r\n"
			},
			wantErr: gows.ErrAcceptMismatch,
		},
		"success: Sec-WebSocket-Protocol repeated, offered value last": {
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Protocol: not-offered\r\nSec-WebSocket-Protocol: chat\r\n")
			},
			wantProtocol: "chat",
		},
		"error: Sec-WebSocket-Protocol repeated, unoffered value last": {
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: not-offered\r\n")
			},
			wantErr: gows.ErrUnrequestedSubprotocol,
		},
		"success: Sec-WebSocket-Extensions repeated, permessage-deflate last": {
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: x-foo\r\nSec-WebSocket-Extensions: "+noTakeover+"\r\n")
			},
			wantCompressed: true,
		},
		"error: Sec-WebSocket-Extensions repeated, unrelated extension last": {
			respond: func(t *testing.T, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Extensions: "+noTakeover+"\r\nSec-WebSocket-Extensions: x-foo\r\n")
			},
			wantErr: gows.ErrInvalidCompressionResponse,
		},
	}
	for pathName, setPath := range dialPaths {
		for name, tt := range tests {
			t.Run(pathName+"/"+name, func(t *testing.T) {
				srv := startRawServer(t, func(req []byte) string { return tt.respond(t, req) })
				d := &gows.Dialer{Subprotocols: []string{"chat"}, EnableCompression: true}
				setPath(t, d)
				conn, hs, err := dialHandshakeWithin(t, t.Context(), d, srv.url, 5*time.Second)
				if tt.wantErr != nil {
					if conn != nil {
						conn.Close()
						t.Fatalf("Dial conn = %v, want nil", conn)
					}
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("Dial err = %v, want errors.Is %v", err, tt.wantErr)
					}
					srv.awaitClosed(t)
					return
				}
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				conn.Close()
				if hs.Subprotocol != tt.wantProtocol || hs.Compressed != tt.wantCompressed {
					t.Errorf("Handshake (Subprotocol, Compressed) = (%q, %v), want (%q, %v)", hs.Subprotocol, hs.Compressed, tt.wantProtocol, tt.wantCompressed)
				}
			})
		}
	}
}

// dialHandshakeWithin is dialWithin that also returns the Handshake.
func dialHandshakeWithin(t *testing.T, ctx context.Context, d *gows.Dialer, rawURL string, limit time.Duration) (net.Conn, gows.Handshake, error) {
	t.Helper()
	type result struct {
		conn net.Conn
		hs   gows.Handshake
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, hs, err := d.Dial(ctx, rawURL)
		done <- result{conn, hs, err}
	}()
	select {
	case r := <-done:
		return r.conn, r.hs, r.err
	case <-time.After(limit):
		t.Fatalf("Dial did not return within %v", limit)
		return nil, gows.Handshake{}, nil
	}
}

// TestDialResponsesThatDifferByPath pins the responses whose outcome
// depends on the dial path, because net/http parses the response before the
// shared checks see its 101 fields. Each row states what each path does.
func TestDialResponsesThatDifferByPath(t *testing.T) {
	tests := map[string]struct {
		respond func(t *testing.T, req []byte) string
		// want maps a dial path to the error Dial must match; nil means
		// the dial succeeds.
		want map[string]error
	}{
		"103 Early Hints before the 101": {
			respond: func(t *testing.T, req []byte) string {
				return "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n" + upgradeResponse(t, req)
			},
			// The transport skips 1xx responses; the native path reads the
			// first response only.
			want: map[string]error{"native": gows.ErrUnexpectedStatus, "http client": nil},
		},
		"Connection token on an obs-fold continuation line": {
			respond: func(t *testing.T, req []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: keep-alive,\r\n Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n\r\n"
			},
			// net/http joins the folded line; the native parser rejects it.
			want: map[string]error{"native": httpx.ErrObsoleteLineFolding, "http client": nil},
		},
		"Connection: Upgrade, close": {
			respond: func(t *testing.T, req []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade, close\r\n" +
					"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n\r\n"
			},
			// net/http deletes a Connection header that carries close, so
			// the shared check no longer sees the Upgrade token.
			want: map[string]error{"native": nil, "http client": gows.ErrNotConnectionUpgrade},
		},
	}
	for pathName, setPath := range dialPaths {
		for name, tt := range tests {
			t.Run(pathName+"/"+name, func(t *testing.T) {
				wantErr, ok := tt.want[pathName]
				if !ok {
					t.Fatalf("no expectation for dial path %q", pathName)
				}
				srv := startRawServer(t, func(req []byte) string { return tt.respond(t, req) })
				d := &gows.Dialer{}
				setPath(t, d)
				conn, err := dialWithin(t, t.Context(), d, srv.url, 5*time.Second)
				if wantErr == nil {
					if err != nil {
						t.Fatalf("Dial: %v", err)
					}
					conn.Close()
					srv.awaitClosed(t)
					return
				}
				if conn != nil {
					conn.Close()
					t.Fatalf("Dial conn = %v, want nil", conn)
				}
				if !errors.Is(err, wantErr) {
					t.Fatalf("Dial err = %v, want errors.Is %v", err, wantErr)
				}
				srv.awaitClosed(t)
			})
		}
	}
}

// TestDialHTTPClientRedirectPolicy checks that redirects on the HTTP
// client path follow the client's own policy: a client that stops at the
// redirect reports it as a refused handshake, Location header included.
func TestDialHTTPClientRedirectPolicy(t *testing.T) {
	srv := startRawServer(t, func([]byte) string {
		return "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\n\r\n"
	})
	hc := newHTTPClient(t)
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, err := dialWithin(t, t.Context(), &gows.Dialer{HTTPClient: hc}, srv.url, 5*time.Second)
	use := asUnexpectedStatus(t, err, "")
	if use.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want 302", use.StatusCode)
	}
	if got := use.Header.Get("Location"); got != "/elsewhere" {
		t.Errorf("Header.Get(Location) = %q, want /elsewhere", got)
	}
	srv.awaitClosed(t)
}

// TestDialHTTPClientFrameWithResponse has the server write the first
// WebSocket frame in the same write as its 101 response. The HTTP client
// path must deliver that frame through the returned connection.
func TestDialHTTPClientFrameWithResponse(t *testing.T) {
	frame := []byte{0x81, 0x05, 'e', 'a', 'r', 'l', 'y'}
	srv := startRawServer(t, func(req []byte) string { return upgradeResponse(t, req) + string(frame) })
	d := &gows.Dialer{HTTPClient: newHTTPClient(t)}
	conn, hs, err := d.Dial(t.Context(), srv.url)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if hs.Buffered != nil {
		t.Errorf("Buffered = %q, want nil on the HTTP client path", hs.Buffered)
	}
	c := gows.NewClientConn(conn)
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	op, p, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if op != gows.OpcodeText || string(p) != "early" {
		t.Fatalf("ReadMessage = (%v, %q), want (%v, %q)", op, p, gows.OpcodeText, "early")
	}
}

// failingRoundTripper fails the test if any request reaches it.
type failingRoundTripper struct{ t *testing.T }

func (f failingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("RoundTrip called for %s; want no network I/O", r.URL.Host)
	return nil, errors.New("unexpected round trip")
}

// TestDialHTTPClientRejectedBeforeNetworkIO checks the configurations Dial
// must refuse before sending anything through the HTTP client.
func TestDialHTTPClientRejectedBeforeNetworkIO(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	tests := map[string]struct {
		dialer  gows.Dialer
		ctx     context.Context
		wantErr error
	}{
		"error: NetDial set": {
			dialer:  gows.Dialer{NetDial: (&net.Dialer{}).DialContext},
			wantErr: gows.ErrConflictingHTTPClient,
		},
		"error: TLSConfig set": {
			dialer:  gows.Dialer{TLSConfig: &tls.Config{}},
			wantErr: gows.ErrConflictingHTTPClient,
		},
		"error: Proxy set": {
			dialer:  gows.Dialer{Proxy: http.ProxyFromEnvironment},
			wantErr: gows.ErrConflictingHTTPClient,
		},
		"error: CheckRedirect set": {
			dialer:  gows.Dialer{CheckRedirect: followAll},
			wantErr: gows.ErrConflictingHTTPClient,
		},
		"error: reserved extra header": {
			dialer:  gows.Dialer{HTTPHeader: http.Header{"Sec-Websocket-Key": {"x"}}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: not a WebSocket scheme": {
			wantErr: gows.ErrNotWebSocketScheme,
		},
		"error: context already canceled": {
			ctx:     canceled,
			wantErr: context.Canceled,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := tt.dialer
			d.HTTPClient = &http.Client{Transport: failingRoundTripper{t}}
			ctx := tt.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			rawURL := "ws://example.invalid/"
			if tt.wantErr == gows.ErrNotWebSocketScheme {
				rawURL = "http://example.invalid/"
			}
			conn, _, err := d.Dial(ctx, rawURL)
			if conn != nil {
				t.Fatalf("Dial conn = %v, want nil", conn)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Dial err = %v, want errors.Is %v", err, tt.wantErr)
			}
		})
	}
}

// TestDialHTTPClientTimeoutBoundsHandshake points a client with a Timeout
// at a server that never answers: the dial must fail when the Timeout
// elapses, and the caller's client must be left as it was.
func TestDialHTTPClientTimeoutBoundsHandshake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	hc := newHTTPClient(t)
	hc.Timeout = 200 * time.Millisecond
	d := &gows.Dialer{HTTPClient: hc}
	start := time.Now()
	_, err := dialWithin(t, t.Context(), d, wsURL(srv, "/"), 5*time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial err = %v, want errors.Is context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed < hc.Timeout {
		t.Errorf("Dial failed after %v, before the %v Timeout", elapsed, hc.Timeout)
	}
	if hc.Timeout != 200*time.Millisecond {
		t.Errorf("client Timeout = %v after Dial, want it unchanged", hc.Timeout)
	}
}

// TestDialHTTPClientHandshakeBoundsEndAtReturn checks that neither the
// client's Timeout nor the dial context reaches the established
// connection: after each has ended, the connection still carries messages.
func TestDialHTTPClientHandshakeBoundsEndAtReturn(t *testing.T) {
	const timeout = 100 * time.Millisecond
	tests := map[string]struct {
		clientTimeout time.Duration
		cancelDial    bool
	}{
		"success: client Timeout elapses after Dial": {clientTimeout: timeout},
		"success: dial context canceled after Dial":  {cancelDial: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, echoServe)
			hc := newHTTPClient(t)
			hc.Timeout = tt.clientTimeout
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			conn, _, err := (&gows.Dialer{HTTPClient: hc}).Dial(ctx, wsURL(srv.Server, "/"))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()
			if tt.cancelDial {
				cancel()
			}
			// Let the Timeout (or anything the cancellation might trigger)
			// run its course before using the connection.
			<-time.After(3 * timeout)
			c := gows.NewClientConn(conn)
			roundTrip(t, c, "still open")
			if err := c.Close(gows.CloseNormalClosure, ""); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

// TestDialHTTPClientConnDeadlines checks that deadlines set on the returned
// connection reach the transport's connection: a close against a silent
// peer ends at the close timeout, and a past read deadline unblocks a
// blocked ReadMessage.
func TestDialHTTPClientConnDeadlines(t *testing.T) {
	silent := func(peerGone chan<- struct{}) func(net.Conn, gows.Handshake) {
		return func(conn net.Conn, _ gows.Handshake) {
			// Never answer; just notice when the client closes.
			_, _ = io.Copy(io.Discard, conn)
			close(peerGone)
		}
	}

	t.Run("success: close timeout against a silent peer", func(t *testing.T) {
		peerGone := make(chan struct{})
		srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, silent(peerGone))
		conn, _, err := (&gows.Dialer{HTTPClient: newHTTPClient(t)}).Dial(t.Context(), wsURL(srv.Server, "/"))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		const closeTimeout = 200 * time.Millisecond
		c := gows.NewClientConn(conn, gows.WithCloseTimeout(closeTimeout))
		start := time.Now()
		_ = c.Close(gows.CloseNormalClosure, "")
		if elapsed := time.Since(start); elapsed < closeTimeout || elapsed > 3*time.Second {
			t.Errorf("Close returned after %v, want about the %v close timeout", elapsed, closeTimeout)
		}
		select {
		case <-peerGone:
		case <-time.After(5 * time.Second):
			t.Fatal("peer did not observe the connection closing")
		}
	})

	t.Run("success: past read deadline unblocks ReadMessage", func(t *testing.T) {
		peerGone := make(chan struct{})
		srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, silent(peerGone))
		conn, _, err := (&gows.Dialer{HTTPClient: newHTTPClient(t)}).Dial(t.Context(), wsURL(srv.Server, "/"))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()
		c := gows.NewClientConn(conn)
		readErr := make(chan error, 1)
		go func() {
			_, _, err := c.ReadMessage()
			readErr <- err
		}()
		select {
		case err := <-readErr:
			t.Fatalf("ReadMessage returned %v before any deadline was set", err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		select {
		case err := <-readErr:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("ReadMessage err = %v, want errors.Is os.ErrDeadlineExceeded", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a past read deadline did not unblock ReadMessage")
		}
	})
}

// contextDroppingRoundTripper sends every request with a fresh context,
// which drops the httptrace hooks the request carried, so the transport
// never reports its connection to the caller.
type contextDroppingRoundTripper struct{ next http.RoundTripper }

func (c contextDroppingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return c.next.RoundTrip(r.Clone(context.Background()))
}

// readOnlyBodyRoundTripper hides the writability of every response body.
type readOnlyBodyRoundTripper struct{ next http.RoundTripper }

func (b readOnlyBodyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := b.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = struct{ io.ReadCloser }{resp.Body}
	return resp, nil
}

// TestDialHTTPClientUnsupportedTransport uses transports that complete the
// upgrade but do not hand over a usable connection: Dial must fail with
// ErrUnsupportedHTTPTransport and close the connection.
func TestDialHTTPClientUnsupportedTransport(t *testing.T) {
	tests := map[string]struct {
		wrap func(http.RoundTripper) http.RoundTripper
	}{
		"error: transport does not report its connection": {
			wrap: func(rt http.RoundTripper) http.RoundTripper { return contextDroppingRoundTripper{next: rt} },
		},
		"error: 101 body is not writable": {
			wrap: func(rt http.RoundTripper) http.RoundTripper { return readOnlyBodyRoundTripper{next: rt} },
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			peerGone := make(chan struct{})
			srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, func(conn net.Conn, _ gows.Handshake) {
				_, _ = io.Copy(io.Discard, conn)
				close(peerGone)
			})
			hc := newHTTPClient(t)
			hc.Transport = tt.wrap(hc.Transport)
			conn, err := dialWithin(t, t.Context(), &gows.Dialer{HTTPClient: hc}, wsURL(srv.Server, "/"), 5*time.Second)
			if conn != nil {
				conn.Close()
				t.Fatalf("Dial conn = %v, want nil", conn)
			}
			if !errors.Is(err, gows.ErrUnsupportedHTTPTransport) {
				t.Fatalf("Dial err = %v, want errors.Is ErrUnsupportedHTTPTransport", err)
			}
			select {
			case <-peerGone:
			case <-time.After(5 * time.Second):
				t.Fatal("peer did not observe the connection closing")
			}
		})
	}
}

// TestDialHTTPClientComposesTrace checks that a ClientTrace the caller put
// in the dial context still sees the connection, alongside Dial's own hook.
func TestDialHTTPClientComposesTrace(t *testing.T) {
	srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, echoServe)
	var gotConn atomic.Int32
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { gotConn.Add(1) },
	})
	conn, _, err := (&gows.Dialer{HTTPClient: newHTTPClient(t)}).Dial(ctx, wsURL(srv.Server, "/"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if got := gotConn.Load(); got != 1 {
		t.Errorf("caller's GotConn ran %d times, want 1", got)
	}
	roundTrip(t, gows.NewClientConn(conn), "traced")
}

// TestDialHTTPClientFollowsClientRedirect has the first server redirect to
// a second one. The client's own redirect policy follows it, and the
// returned connection must be the final hop's.
func TestDialHTTPClientFollowsClientRedirect(t *testing.T) {
	final := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, echoServe)
	first := httptest.NewServer(http.RedirectHandler(final.URL+"/final", http.StatusTemporaryRedirect))
	t.Cleanup(first.Close)
	var hops atomic.Int32
	hc := newHTTPClient(t)
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		hops.Add(1)
		return nil
	}
	conn, _, err := (&gows.Dialer{HTTPClient: hc}).Dial(t.Context(), wsURL(first, "/start"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if got := hops.Load(); got != 1 {
		t.Errorf("client CheckRedirect ran %d times, want 1", got)
	}
	if got, want := conn.RemoteAddr().String(), final.Listener.Addr().String(); got != want {
		t.Errorf("RemoteAddr = %s, want the final hop %s", got, want)
	}
	roundTrip(t, gows.NewClientConn(conn), "after redirect")
}

// TestDialErrorsOmitURLSecrets dials URLs carrying userinfo and a query
// token. On every path the URL's credentials must stay out of the error
// text and out of the request headers.
func TestDialErrorsOmitURLSecrets(t *testing.T) {
	const (
		password = "PASSWORD-SECRET"
		token    = "QUERY-TOKEN-SECRET"
	)
	sawAuth := make(chan string, 1)
	refuser := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(refuser.Close)
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddr := closedLn.Addr().String()
	closedLn.Close()

	withSecrets := func(hostport string) string {
		return (&url.URL{Scheme: "ws", User: url.UserPassword("alice", password), Host: hostport, Path: "/", RawQuery: "token=" + token}).String()
	}
	for pathName, setPath := range dialPaths {
		t.Run(pathName, func(t *testing.T) {
			for name, rawURL := range map[string]string{
				"refused handshake":  withSecrets(strings.TrimPrefix(refuser.URL, "http://")),
				"connection refused": withSecrets(closedAddr),
			} {
				d := &gows.Dialer{}
				setPath(t, d)
				_, err := dialWithin(t, t.Context(), d, rawURL, 5*time.Second)
				if err == nil {
					t.Fatalf("%s: Dial succeeded, want an error", name)
				}
				for e := err; e != nil; e = errors.Unwrap(e) {
					if msg := e.Error(); strings.Contains(msg, password) || strings.Contains(msg, token) {
						t.Fatalf("%s: error text carries a URL secret: %q", name, msg)
					}
				}
			}
			if auth := <-sawAuth; auth != "" {
				t.Errorf("request Authorization = %q, want none: URL userinfo is never sent", auth)
			}
		})
	}
}

// TestDialRequestHeaderSpelling records the raw handshake request on every
// path. Header names are case-insensitive in HTTP, but servers that match
// them byte for byte exist, so both paths must spell the WebSocket fields
// as RFC 6455 does.
func TestDialRequestHeaderSpelling(t *testing.T) {
	for pathName, setPath := range dialPaths {
		t.Run(pathName, func(t *testing.T) {
			reqs := make(chan []byte, 1)
			srv := startRawServer(t, func(req []byte) string {
				reqs <- req
				return upgradeResponse(t, req)
			})
			d := &gows.Dialer{Subprotocols: []string{"a", "b"}, EnableCompression: true}
			setPath(t, d)
			conn, err := dialWithin(t, t.Context(), d, srv.url, 5*time.Second)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()
			req := <-reqs
			for _, want := range []string{
				"\r\nUpgrade: websocket\r\n",
				"\r\nConnection: Upgrade\r\n",
				"\r\nSec-WebSocket-Key: ",
				"\r\nSec-WebSocket-Version: 13\r\n",
				"\r\nSec-WebSocket-Protocol: a, b\r\n",
				"\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n",
			} {
				if !strings.Contains(string(req), want) {
					t.Errorf("request lacks %q:\n%s", want, req)
				}
			}
		})
	}
}
