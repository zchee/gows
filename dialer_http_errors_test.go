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
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zchee/gows"
)

// peerSecret is text a peer controls. No error a Dial returns may carry it.
const peerSecret = "PEERSECRET"

// errorTexts returns the Error text of err and of every error it wraps,
// following both Unwrap() error and Unwrap() []error.
func errorTexts(err error) []string {
	if err == nil {
		return nil
	}
	texts := []string{err.Error()}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		texts = append(texts, errorTexts(u.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			texts = append(texts, errorTexts(e)...)
		}
	}
	return texts
}

// assertNoPeerText fails the test when secret appears in the text of err
// or of any error in its tree.
func assertNoPeerText(t *testing.T, err error, secret string) {
	t.Helper()
	for _, text := range errorTexts(err) {
		if strings.Contains(text, secret) {
			t.Fatalf("error tree carries peer text %q: %q (top: %v)", secret, text, err)
		}
	}
}

// serveEachConn accepts every connection on a loopback listener, runs
// handle on it and then closes it, until the test ends. It returns the
// listener's ws URL.
func serveEachConn(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return "ws://" + ln.Addr().String() + "/"
}

// TestDialHTTPClientErrorsCarryNoPeerText makes the HTTP client's Do fail
// with errors whose net/http text quotes the peer: a malformed response,
// an unparseable Location, and a proxy's CONNECT refusal reason. Dial must
// report each with ErrHTTPRequestFailed and drop the original error, so
// the peer's text appears nowhere in the error tree.
func TestDialHTTPClientErrorsCarryNoPeerText(t *testing.T) {
	tests := map[string]struct {
		response string
		viaProxy bool
		// pooled marks a complete response: the client keeps its
		// connection for reuse instead of closing it.
		pooled bool
	}{
		"error: malformed header line": {
			response: "HTTP/1.1 403 Forbidden\r\nX: y\r\n" + peerSecret + " no colon\r\n\r\n",
		},
		"error: malformed HTTP version": {
			response: "X" + peerSecret + " 403 Forbidden\r\n\r\n",
		},
		"error: malformed status code": {
			response: "HTTP/1.1 " + peerSecret + " Nope\r\n\r\n",
		},
		"error: Location with userinfo that does not parse": {
			response: "HTTP/1.1 302 Found\r\nLocation: http://u:" + peerSecret + "@[::1\r\nContent-Length: 0\r\n\r\n",
			pooled:   true,
		},
		"error: proxy refuses CONNECT with a reason": {
			response: "HTTP/1.1 403 denied " + peerSecret + "\r\nContent-Length: 0\r\n\r\n",
			viaProxy: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			srv := startRawServer(t, func([]byte) string { return tt.response })
			hc := newHTTPClient(t)
			target := srv.url
			if tt.viaProxy {
				proxyURL, err := url.Parse("http" + strings.TrimPrefix(srv.url, "ws"))
				if err != nil {
					t.Fatalf("parse proxy URL: %v", err)
				}
				hc.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
				target = "wss://origin.test:443/"
			}
			conn, err := dialWithin(t, t.Context(), &gows.Dialer{HTTPClient: hc}, target, 5*time.Second)
			if conn != nil {
				conn.Close()
				t.Fatalf("Dial conn = %v, want nil", conn)
			}
			if !errors.Is(err, gows.ErrHTTPRequestFailed) {
				t.Fatalf("Dial err = %v, want errors.Is ErrHTTPRequestFailed", err)
			}
			assertNoPeerText(t, err, peerSecret)
			if !tt.pooled {
				srv.awaitClosed(t)
			}
		})
	}
}

// TestDialHTTPClientKeepsCallerRedirectError has the client's own
// CheckRedirect stop a redirect with an error. That error is the caller's,
// not the peer's: Dial must keep it matchable with errors.Is, while the
// Location value stays out of the error text.
func TestDialHTTPClientKeepsCallerRedirectError(t *testing.T) {
	errPolicy := errors.New("caller policy: redirects are not allowed")
	srv := startRawServer(t, func([]byte) string {
		return "HTTP/1.1 302 Found\r\nLocation: /elsewhere?" + peerSecret + "\r\nContent-Length: 0\r\n\r\n"
	})
	hc := newHTTPClient(t)
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return errPolicy }
	_, err := dialWithin(t, t.Context(), &gows.Dialer{HTTPClient: hc}, srv.url, 5*time.Second)
	if !errors.Is(err, errPolicy) {
		t.Fatalf("Dial err = %v, want errors.Is the CheckRedirect error", err)
	}
	if errors.Is(err, gows.ErrHTTPRequestFailed) {
		t.Errorf("Dial err = %v, want the CheckRedirect error, not ErrHTTPRequestFailed", err)
	}
	assertNoPeerText(t, err, peerSecret)
}

// TestDialHTTPClientRedirectLoop checks that a client without a redirect
// policy reports a redirect loop as the native path does, with
// ErrTooManyRedirects, after the same number of requests net/http's default
// policy allows.
func TestDialHTTPClientRedirectLoop(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	_, err := dialWithin(t, t.Context(), &gows.Dialer{HTTPClient: newHTTPClient(t)}, wsURL(srv, "/"), 5*time.Second)
	if !errors.Is(err, gows.ErrTooManyRedirects) {
		t.Fatalf("Dial err = %v, want errors.Is ErrTooManyRedirects", err)
	}
	if got := requests.Load(); got != 10 {
		t.Errorf("server saw %d requests, want 10 as under net/http's default policy", got)
	}
}

// TestDialTransportErrorsMatchOnBothPaths checks that what callers test
// for today still matches on every dial path: the dial context's error and
// cause, a refused TCP connection, and a certificate that does not verify.
func TestDialTransportErrorsMatchOnBothPaths(t *testing.T) {
	cause := errors.New("caller gave up")
	tests := map[string]struct {
		target func(t *testing.T) string
		ctx    func(t *testing.T) context.Context
		check  func(t *testing.T, err error)
	}{
		"error: dial context canceled with a cause": {
			target: func(t *testing.T) string {
				// Read the request and never answer.
				return serveEachConn(t, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
			},
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithCancelCause(t.Context())
				time.AfterFunc(100*time.Millisecond, func() { cancel(cause) })
				return ctx
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
					t.Fatalf("Dial err = %v, want errors.Is context.Canceled and the cause", err)
				}
			},
		},
		"error: connection refused": {
			target: func(t *testing.T) string {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				addr := ln.Addr().String()
				ln.Close()
				return "ws://" + addr + "/"
			},
			check: func(t *testing.T, err error) {
				if _, ok := errors.AsType[*net.OpError](err); !ok || !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("Dial err = %v, want a *net.OpError matching syscall.ECONNREFUSED", err)
				}
			},
		},
		"error: certificate does not verify": {
			target: func(t *testing.T) string {
				srv := httptest.NewTLSServer(http.NotFoundHandler())
				t.Cleanup(srv.Close)
				return wsURL(srv, "/")
			},
			check: func(t *testing.T, err error) {
				if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
					t.Fatalf("Dial err = %v, want a *tls.CertificateVerificationError", err)
				}
			},
		},
		"error: server closes without answering": {
			target: func(t *testing.T) string {
				// Read the request, then close without a response.
				return serveEachConn(t, func(conn net.Conn) { _, _ = conn.Read(make([]byte, 4096)) })
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("Dial err = %v, want errors.Is io.EOF or io.ErrUnexpectedEOF", err)
				}
			},
		},
	}
	for pathName, setPath := range dialPaths {
		for name, tt := range tests {
			t.Run(pathName+"/"+name, func(t *testing.T) {
				ctx := t.Context()
				if tt.ctx != nil {
					ctx = tt.ctx(t)
				}
				d := &gows.Dialer{}
				setPath(t, d)
				conn, err := dialWithin(t, ctx, d, tt.target(t), 5*time.Second)
				if conn != nil {
					conn.Close()
					t.Fatalf("Dial conn = %v, want nil", conn)
				}
				tt.check(t, err)
				if errors.Is(err, gows.ErrHTTPRequestFailed) {
					t.Errorf("Dial err = %v, want the transport's error, not ErrHTTPRequestFailed", err)
				}
				t.Logf("Dial err = %v", err)
			})
		}
	}
}

// waitAfterUpgradeRoundTripper returns the transport's response only after
// the request context has ended, so the dial context is over by the time
// Dial sees the 101.
type waitAfterUpgradeRoundTripper struct{ next http.RoundTripper }

func (w waitAfterUpgradeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := w.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	<-r.Context().Done()
	return resp, nil
}

// TestDialHTTPClientContextEndsAfterUpgrade ends the dial context, through
// the caller's cancellation or the client's Timeout, after the 101 arrived
// but before Dial returns. Like the native path, Dial must fail with the
// context's error and close the connection.
func TestDialHTTPClientContextEndsAfterUpgrade(t *testing.T) {
	tests := map[string]struct {
		clientTimeout time.Duration
		cancelAfter   time.Duration
		wantErr       error
	}{
		"error: caller cancels the dial context": {
			cancelAfter: 100 * time.Millisecond,
			wantErr:     context.Canceled,
		},
		"error: client Timeout elapses": {
			clientTimeout: 100 * time.Millisecond,
			wantErr:       context.DeadlineExceeded,
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
			hc.Transport = waitAfterUpgradeRoundTripper{next: hc.Transport}
			hc.Timeout = tt.clientTimeout
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelAfter > 0 {
				time.AfterFunc(tt.cancelAfter, cancel)
			}
			conn, err := dialWithin(t, ctx, &gows.Dialer{HTTPClient: hc}, wsURL(srv.Server, "/"), 5*time.Second)
			if conn != nil {
				conn.Close()
				t.Fatalf("Dial conn = %v, want nil once the dial context has ended", conn)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Dial err = %v, want errors.Is %v", err, tt.wantErr)
			}
			select {
			case <-peerGone:
			case <-time.After(5 * time.Second):
				t.Fatal("peer did not observe the connection closing")
			}
		})
	}
}

// TestDialHTTPClientKeepsFixedTransportErrors makes the transport fail with
// errors net/http words itself, with no peer text: its response-header
// timeout, and the scheme mismatch it reports for a wss dial answered by a
// plain HTTP server (where the native path reports the TLS record error).
// Dial must keep them matchable instead of reporting ErrHTTPRequestFailed.
func TestDialHTTPClientKeepsFixedTransportErrors(t *testing.T) {
	tests := map[string]struct {
		target  func(t *testing.T, hc *http.Client) string
		wantErr error
	}{
		"error: response header timeout": {
			target: func(t *testing.T, hc *http.Client) string {
				hc.Transport.(*http.Transport).ResponseHeaderTimeout = 100 * time.Millisecond
				return serveEachConn(t, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
			},
			wantErr: os.ErrDeadlineExceeded,
		},
		"error: wss dial answered by a plain HTTP server": {
			target: func(t *testing.T, _ *http.Client) string {
				srv := httptest.NewServer(http.NotFoundHandler())
				t.Cleanup(srv.Close)
				return "wss" + strings.TrimPrefix(srv.URL, "http") + "/"
			},
			wantErr: http.ErrSchemeMismatch,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			hc := newHTTPClient(t)
			target := tt.target(t, hc)
			conn, err := dialWithin(t, t.Context(), &gows.Dialer{HTTPClient: hc}, target, 5*time.Second)
			if conn != nil {
				conn.Close()
				t.Fatalf("Dial conn = %v, want nil", conn)
			}
			if !errors.Is(err, tt.wantErr) || errors.Is(err, gows.ErrHTTPRequestFailed) {
				t.Fatalf("Dial err = %v, want errors.Is %v and not ErrHTTPRequestFailed", err, tt.wantErr)
			}
		})
	}
}
