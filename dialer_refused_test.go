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
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows"
)

// dialPaths lists every way a Dialer can carry the opening handshake. Each
// entry adjusts a Dialer for its path; the tests that range over it expect
// the same result from every path.
var dialPaths = map[string]func(t *testing.T, d *gows.Dialer){
	"native":      func(*testing.T, *gows.Dialer) {},
	"http client": func(t *testing.T, d *gows.Dialer) { d.HTTPClient = newHTTPClient(t) },
}

// rawServer is a loopback TCP server that answers one opening handshake
// with bytes the test chooses, then holds the connection open until the
// client closes it.
type rawServer struct {
	url string
	// closed receives the server's read error once the client side of the
	// connection is gone.
	closed chan error
}

// startRawServer accepts one connection on a loopback listener, reads the
// handshake request, and writes respond(request). It then reads until the
// client closes the connection and reports that on closed. Everything is
// torn down when the test ends.
func startRawServer(t *testing.T, respond func(req []byte) string) *rawServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &rawServer{url: "ws://" + ln.Addr().String() + "/", closed: make(chan error, 1)}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { conn.Close() })
		req := readRawHeaderBlock(t, conn)
		if _, err := conn.Write([]byte(respond(req))); err != nil {
			t.Errorf("raw server write: %v", err)
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		_, err = io.Copy(io.Discard, conn)
		if err == nil {
			err = io.EOF
		}
		s.closed <- err
	}()
	return s
}

// awaitClosed fails the test unless the client closed the connection.
func (s *rawServer) awaitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-s.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not close the connection")
	}
}

// stalledRefusal is a 401 response whose Content-Length promises more body
// than the server ever sends.
const stalledRefusal = "HTTP/1.1 401 Unauthorized\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 100\r\n" +
	"\r\n" +
	`{"partial`

// dialWithin runs d.Dial on its own goroutine and fails the test when it
// does not return within limit, so a Dial that waits on a stalled body
// fails the test instead of hanging it.
func dialWithin(t *testing.T, ctx context.Context, d *gows.Dialer, rawURL string, limit time.Duration) (net.Conn, error) {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, _, err := d.Dial(ctx, rawURL)
		done <- result{conn, err}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-time.After(limit):
		t.Fatalf("Dial did not return within %v", limit)
		return nil, nil
	}
}

// asUnexpectedStatus extracts the *UnexpectedStatusError from err and
// checks that its Error text is exactly the numeric-status text, with no
// peer-controlled content anywhere in the chain.
func asUnexpectedStatus(t *testing.T, err error, peerText string) *gows.UnexpectedStatusError {
	t.Helper()
	if !errors.Is(err, gows.ErrUnexpectedStatus) {
		t.Fatalf("Dial err = %v, want errors.Is ErrUnexpectedStatus", err)
	}
	var use *gows.UnexpectedStatusError
	if !errors.As(err, &use) {
		t.Fatalf("Dial err = %v, want a *UnexpectedStatusError in the chain", err)
	}
	if want := "gows: unexpected HTTP response status " + strconv.Itoa(use.StatusCode); use.Error() != want {
		t.Errorf("Error() = %q, want %q", use.Error(), want)
	}
	if peerText != "" {
		for e := err; e != nil; e = errors.Unwrap(e) {
			if strings.Contains(e.Error(), peerText) {
				t.Fatalf("error chain carries peer text %q: %q", peerText, e)
			}
		}
	}
	return use
}

// TestDialRefusedHandshakeDetails sends a 401 with a JSON body and
// application headers, and checks the refusal error carries those headers
// on every dial path, and the body up to Dialer.MaxErrorBodyBytes.
func TestDialRefusedHandshakeDetails(t *testing.T) {
	const body = `{"error":{"message":"Invalid API Key","type":"invalid_request_error"}}`
	tests := map[string]struct {
		limit    int
		chunked  bool
		wantBody string
	}{
		"success: limit zero leaves the body unread": {
			limit: 0,
		},
		"success: limit below the body size truncates": {
			limit:    9,
			wantBody: body[:9],
		},
		"success: limit above the body size reads it all": {
			limit:    4096,
			wantBody: body,
		},
		"success: chunked body below the limit": {
			limit:    4096,
			chunked:  true,
			wantBody: body,
		},
		"success: chunked body truncated by the limit": {
			limit:    20,
			chunked:  true,
			wantBody: body[:20],
		},
	}
	for pathName, setPath := range dialPaths {
		for name, tt := range tests {
			t.Run(pathName+"/"+name, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Request-Id", "req-123")
					w.Header().Add("Www-Authenticate", `Bearer realm="api"`)
					w.WriteHeader(http.StatusUnauthorized)
					if tt.chunked {
						io.WriteString(w, body[:5])
						w.(http.Flusher).Flush()
						io.WriteString(w, body[5:])
						return
					}
					io.WriteString(w, body)
				}))
				t.Cleanup(srv.Close)

				d := &gows.Dialer{MaxErrorBodyBytes: tt.limit}
				setPath(t, d)
				conn, err := dialWithin(t, t.Context(), d, "ws"+strings.TrimPrefix(srv.URL, "http")+"/v1/realtime", 5*time.Second)
				if conn != nil {
					t.Fatalf("Dial conn = %v, want nil on a refused handshake", conn)
				}
				use := asUnexpectedStatus(t, err, "Invalid API Key")
				if use.StatusCode != http.StatusUnauthorized || use.Reason != "Unauthorized" {
					t.Errorf("status = (%d, %q), want (401, %q)", use.StatusCode, use.Reason, "Unauthorized")
				}
				if use.Header == nil {
					t.Fatal("Header = nil, want the response header")
				}
				for key, want := range map[string]string{
					"Content-Type":     "application/json",
					"X-Request-Id":     "req-123",
					"Www-Authenticate": `Bearer realm="api"`,
				} {
					if got := use.Header.Get(key); got != want {
						t.Errorf("Header.Get(%q) = %q, want %q", key, got, want)
					}
				}
				if string(use.Body) != tt.wantBody {
					t.Errorf("Body = %q, want %q", use.Body, tt.wantBody)
				}
				if tt.limit == 0 && use.Body != nil {
					t.Errorf("Body = %q, want nil with a zero limit", use.Body)
				}
			})
		}
	}
}

// TestDialRefusedBodyUnreadAtZeroLimit refuses the handshake with a body
// that never completes. With a zero limit and no context deadline, Dial
// must not wait for the body, and the headers must still be reported.
func TestDialRefusedBodyUnreadAtZeroLimit(t *testing.T) {
	for pathName, setPath := range dialPaths {
		t.Run(pathName, func(t *testing.T) {
			srv := startRawServer(t, func([]byte) string { return stalledRefusal })
			d := &gows.Dialer{}
			setPath(t, d)
			_, err := dialWithin(t, t.Context(), d, srv.url, 5*time.Second)
			use := asUnexpectedStatus(t, err, "")
			if got := use.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Header.Get(Content-Type) = %q, want application/json", got)
			}
			if use.Body != nil {
				t.Errorf("Body = %q, want nil", use.Body)
			}
			srv.awaitClosed(t)
		})
	}
}

// TestDialRefusedBodyBoundedByContext refuses the handshake with a body
// that stalls midway. The body read must end with the dial context, and the
// error must report both the context and the refusal with the bytes that
// did arrive.
func TestDialRefusedBodyBoundedByContext(t *testing.T) {
	for pathName, setPath := range dialPaths {
		t.Run(pathName, func(t *testing.T) {
			srv := startRawServer(t, func([]byte) string { return stalledRefusal })
			d := &gows.Dialer{MaxErrorBodyBytes: 4096}
			setPath(t, d)
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			_, err := dialWithin(t, ctx, d, srv.url, 5*time.Second)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Dial err = %v, want errors.Is context.DeadlineExceeded", err)
			}
			use := asUnexpectedStatus(t, err, "")
			if use.StatusCode != http.StatusUnauthorized {
				t.Errorf("StatusCode = %d, want 401", use.StatusCode)
			}
			if got := use.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Header.Get(Content-Type) = %q, want application/json", got)
			}
			if string(use.Body) != `{"partial` {
				t.Errorf("Body = %q, want the bytes received before the stall", use.Body)
			}
			srv.awaitClosed(t)
		})
	}
}

// TestDialProxyConnectRefusalCarriesNoDetails pins that a refused proxy
// CONNECT reports only its numeric status: the proxy's headers and body
// stay out of the error even with a body limit set, because they come from
// the proxy, not from the origin the caller dialed.
func TestDialProxyConnectRefusalCarriesNoDetails(t *testing.T) {
	proxy := startRawServer(t, func([]byte) string {
		return "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"proxy\"\r\n" +
			"Content-Length: 7\r\n" +
			"\r\n" +
			"denied!"
	})
	d := &gows.Dialer{
		MaxErrorBodyBytes: 4096,
		Proxy:             proxyFor(t, "http"+strings.TrimPrefix(proxy.url, "ws"), nil),
	}
	_, err := dialWithin(t, t.Context(), d, "wss://origin.test:443/", 5*time.Second)
	if !errors.Is(err, gows.ErrProxyConnectFailed) {
		t.Fatalf("Dial err = %v, want errors.Is ErrProxyConnectFailed", err)
	}
	use := asUnexpectedStatus(t, err, "denied!")
	if use.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("StatusCode = %d, want 407", use.StatusCode)
	}
	if use.Header != nil || use.Body != nil {
		t.Errorf("Header, Body = %v, %q; want nil, nil for a CONNECT refusal", use.Header, use.Body)
	}
	proxy.awaitClosed(t)
}

// TestDialRefusalWithMalformedHeader refuses the handshake with a header
// line that has no colon. The native path still reports the refusal, with
// an empty Header; on the HTTP client path the transport rejects the
// response itself, so Dial fails with the transport's error instead.
func TestDialRefusalWithMalformedHeader(t *testing.T) {
	const response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nno colon here\r\n\r\n"
	t.Run("native", func(t *testing.T) {
		srv := startRawServer(t, func([]byte) string { return response })
		_, err := dialWithin(t, t.Context(), &gows.Dialer{MaxErrorBodyBytes: 4096}, srv.url, 5*time.Second)
		use := asUnexpectedStatus(t, err, "")
		if use.StatusCode != http.StatusForbidden {
			t.Errorf("StatusCode = %d, want 403", use.StatusCode)
		}
		if use.Header == nil || len(use.Header) != 0 {
			t.Errorf("Header = %v, want an empty non-nil map", use.Header)
		}
		if use.Body != nil {
			t.Errorf("Body = %q, want nil", use.Body)
		}
		srv.awaitClosed(t)
	})
	t.Run("http client", func(t *testing.T) {
		srv := startRawServer(t, func([]byte) string { return response })
		_, err := dialWithin(t, t.Context(), &gows.Dialer{HTTPClient: newHTTPClient(t)}, srv.url, 5*time.Second)
		if err == nil || errors.Is(err, gows.ErrUnexpectedStatus) {
			t.Fatalf("Dial err = %v, want the transport's malformed-response error", err)
		}
		srv.awaitClosed(t)
	})
}
