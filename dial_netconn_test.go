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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/httpx"
)

// pipelinedUpgrade answers the client's fresh key with a 101 and a frame in one Read.
type pipelinedUpgrade struct {
	fakeConn
	t     *testing.T
	frame []byte
}

func (c *pipelinedUpgrade) Write(p []byte) (int, error) {
	c.readBuf = append([]byte(upgradeResponse(c.t, p)), c.frame...)
	return len(p), nil
}

func TestDialNetConnReturnsTransport(t *testing.T) {
	frame := []byte{0x81, 0x02, 'h', 'i'}
	for name, configure := range dialPaths {
		t.Run(name, func(t *testing.T) {
			srv := startRawServer(t, func(req []byte) string { return upgradeResponse(t, req) + string(frame) })
			var d gows.Dialer
			configure(t, &d)
			nc, hs, err := d.DialNetConn(t.Context(), srv.url)
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			if d.HTTPClient == nil {
				if _, ok := nc.(*net.TCPConn); !ok {
					t.Fatalf("native transport = %T, want *net.TCPConn", nc)
				}
			} else if hs.Buffered != nil {
				t.Fatalf("HTTP client Buffered = %x, want nil", hs.Buffered)
			}
			if err := nc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			op, p, err := gows.NewClientConn(nc, gows.WithHandshake(hs)).ReadMessage()
			if err != nil || op != gows.OpcodeText || string(p) != "hi" {
				t.Fatalf("first frame = (%v, %q, %v), want text hi", op, p, err)
			}
		})
	}
	t.Run("pipelined read", func(t *testing.T) {
		script := &pipelinedUpgrade{t: t, frame: frame}
		d := gows.Dialer{NetDial: func(context.Context, string, string) (net.Conn, error) { return script, nil }}
		nc, hs, err := d.DialNetConn(t.Context(), "ws://example.com")
		if err != nil || nc != script || !bytes.Equal(hs.Buffered, frame) {
			t.Fatalf("transport %T, buffered %x, error %v; want original transport and %x", nc, hs.Buffered, err, frame)
		}
		op, p, err := gows.NewClientConn(nc, gows.WithHandshake(hs)).ReadMessage()
		if err != nil || op != gows.OpcodeText || string(p) != "hi" {
			t.Fatalf("buffered frame = (%v, %q, %v), want text hi", op, p, err)
		}
	})
}

type callerConnSpy struct {
	*deadlineRecorderConn
	closes atomic.Int32
}

func (c *callerConnSpy) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func unixConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	// t.TempDir includes the subtest name, which can exceed the Unix socket path limit.
	dir, err := os.MkdirTemp("", "gows")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	addr := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ln.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	return client, peer
}

func TestDialCallerConnViaNetDial(t *testing.T) {
	const host = "socket.example"
	reused := errors.New("caller connection already used")
	proxyErr := errors.New("no proxy available")
	tests := map[string]struct {
		rawURL                 string
		unix, callerTLS, wss   bool
		preEnded, cancelOnRead bool
		configure              func(*gows.Dialer)
		response               string
		wantErr                error
		calls, closes          int
	}{
		"net.Pipe end":                           {calls: 1},
		"unix socket":                            {unix: true, calls: 1},
		"caller tls.Client with a ws URL":        {callerTLS: true, calls: 1},
		"plain caller connection with a wss URL": {wss: true, calls: 1},
		"refused handshake":                      {response: "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", wantErr: gows.ErrUnexpectedStatus, calls: 1, closes: 1},
		"ctx canceled mid-handshake":             {cancelOnRead: true, wantErr: context.Canceled, calls: 1, closes: 1},
		"pre-ended ctx":                          {preEnded: true, wantErr: context.Canceled},
		"NetDial and HTTPClient both set":        {configure: func(d *gows.Dialer) { d.HTTPClient = &http.Client{} }, wantErr: gows.ErrConflictingHTTPClient},
		"malformed URL":                          {rawURL: "ws://%", wantErr: net.InvalidAddrError("malformed URL")},
		"Proxy returns an error":                 {configure: func(d *gows.Dialer) { d.Proxy = func(*http.Request) (*url.URL, error) { return nil, proxyErr } }, wantErr: proxyErr},
		"redirect with CheckRedirect":            {response: redirectResponse("/next"), configure: func(d *gows.Dialer) { d.CheckRedirect = followAll }, wantErr: reused, calls: 2, closes: 1},
		"success":                                {calls: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var raw, peer net.Conn
			if tt.unix {
				raw, peer = unixConnPair(t)
			} else {
				raw, peer = net.Pipe()
			}
			defer raw.Close()
			defer peer.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if tt.preEnded {
				cancel()
			}
			d := gows.Dialer{}
			rawURL := tt.rawURL
			if rawURL == "" {
				rawURL = "ws://" + host
			}
			caller := raw
			if tt.callerTLS || tt.wss {
				cert, der := generateSelfSignedCert(t, host)
				root, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				roots.AddCert(root)
				cfg := &tls.Config{RootCAs: roots}
				peer = tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{cert}})
				if tt.callerTLS {
					cfg.ServerName = host
					caller = tls.Client(raw, cfg)
				} else {
					d.TLSConfig = cfg
					rawURL = "wss://" + host
				}
			}
			if tt.wantErr == nil || tt.response != "" || tt.cancelOnRead {
				done := make(chan struct{})
				t.Cleanup(func() { <-done })
				go func() {
					defer close(done)
					req, err := http.ReadRequest(bufio.NewReader(peer))
					if err != nil {
						t.Errorf("read opening request: %v", err)
						return
					}
					if tt.cancelOnRead {
						cancel()
						return
					}
					if tt.response != "" {
						if _, err := io.WriteString(peer, tt.response); err != nil {
							t.Errorf("write refusal or redirect: %v", err)
						}
						return
					}
					accept := httpx.AppendAccept(nil, []byte(req.Header.Get("Sec-WebSocket-Key")))
					if _, err := fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
						t.Errorf("write upgrade response: %v", err)
						return
					}
					serveEcho(gows.NewServerConn(peer))
				}()
			}
			if tt.callerTLS {
				if err := caller.(*tls.Conn).HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
			}
			spy := &callerConnSpy{deadlineRecorderConn: &deadlineRecorderConn{Conn: caller}}
			calls := 0
			d.NetDial = func(context.Context, string, string) (net.Conn, error) {
				calls++
				if calls > 1 {
					return nil, reused
				}
				return spy, nil
			}
			if tt.configure != nil {
				tt.configure(&d)
			}
			nc, hs, err := d.DialNetConn(ctx, rawURL)
			if !errors.Is(err, tt.wantErr) || calls != tt.calls || int(spy.closes.Load()) != tt.closes {
				t.Fatalf("error %v, dials %d, closes %d; want %v, %d, %d", err, calls, spy.closes.Load(), tt.wantErr, tt.calls, tt.closes)
			}
			if err != nil {
				if nc != nil {
					t.Fatalf("failed handshake returned %T", nc)
				}
				return
			}
			if last, ok := spy.last(); !ok || !last.IsZero() {
				t.Fatalf("last deadline = %v (recorded %t), want an explicit clear", last, ok)
			}
			if tt.wss {
				s, ok := nc.(*tls.Conn)
				if !ok || !s.ConnectionState().HandshakeComplete || s.ConnectionState().ServerName != host {
					t.Fatalf("returned transport %T, want completed TLS to %s", nc, host)
				}
			} else if nc != spy {
				t.Fatalf("returned transport = %T, want caller's connection", nc)
			}
			if err := nc.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			roundTrip(t, gows.NewClientConn(nc, gows.WithHandshake(hs)), "caller connection")
		})
	}
}
