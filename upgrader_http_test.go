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
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zchee/gows"
)

// startUpgradeHTTPServer starts an httptest.Server whose handler calls
// u.UpgradeHTTP for every request, reporting the result via onResult.
// The server is not closed automatically; callers must defer srv.Close.
func startUpgradeHTTPServer(t *testing.T, u *gows.Upgrader, onResult func(net.Conn, gows.Handshake, error)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, hs, err := u.UpgradeHTTP(w, r)
		onResult(conn, hs, err)
	}))
}

func TestUpgradeHTTPSuccess(t *testing.T) {
	var gotHS gows.Handshake
	handlerErr := make(chan error, 1)
	srv := startUpgradeHTTPServer(t, &gows.Upgrader{}, func(conn net.Conn, hs gows.Handshake, err error) {
		gotHS = hs
		handlerErr <- err
		if conn != nil {
			conn.Close()
		}
	})
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	resp := dialAndExchange(t, addr, []byte(
		"GET /chat?x=1 HTTP/1.1\r\n"+
			"Host: "+addr+"\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
	))

	if !bytes.HasPrefix(resp, []byte("HTTP/1.1 101 Switching Protocols\r\n")) {
		t.Fatalf("response = %q, want 101 status line prefix", resp)
	}

	select {
	case err := <-handlerErr:
		if err != nil {
			t.Fatalf("UpgradeHTTP: unexpected error %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UpgradeHTTP result did not arrive in time")
	}
	if gotHS.Path != "/chat" || gotHS.Query != "x=1" {
		t.Errorf("Path/Query = %q/%q, want /chat / x=1", gotHS.Path, gotHS.Query)
	}
}

func TestUpgradeHTTPRejectionPaths(t *testing.T) {
	tests := map[string]struct {
		request        string
		wantErr        error
		wantStatusCode string
	}{
		"error: not GET": {
			request: "POST / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrNotUpgrade,
			wantStatusCode: "400",
		},
		"error: not an Upgrade request": {
			request: "GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrNotUpgrade,
			wantStatusCode: "400",
		},
		"error: bad version": {
			request: "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
			wantErr:        gows.ErrUnsupportedVersion,
			wantStatusCode: "426",
		},
		"error: missing key": {
			request: "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrMissingKey,
			wantStatusCode: "400",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			handlerErr := make(chan error, 1)
			srv := startUpgradeHTTPServer(t, &gows.Upgrader{}, func(conn net.Conn, hs gows.Handshake, err error) {
				handlerErr <- err
				if conn != nil {
					conn.Close()
				}
			})
			defer srv.Close()

			addr := srv.Listener.Addr().String()
			resp := dialAndExchange(t, addr, []byte(tt.request))
			if !bytes.Contains(resp, []byte(" "+tt.wantStatusCode+" ")) {
				t.Errorf("response = %q, want status %s", resp, tt.wantStatusCode)
			}

			select {
			case err := <-handlerErr:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("UpgradeHTTP: err = %v, want %v", err, tt.wantErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("UpgradeHTTP result did not arrive in time")
			}
		})
	}
}

func TestUpgradeHTTPPipelinedFrame(t *testing.T) {
	var gotHS gows.Handshake
	handlerErr := make(chan error, 1)
	srv := startUpgradeHTTPServer(t, &gows.Upgrader{}, func(conn net.Conn, hs gows.Handshake, err error) {
		gotHS = hs
		handlerErr <- err
		if conn != nil {
			conn.Close()
		}
	})
	defer srv.Close()

	pipelinedFrame := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	addr := srv.Listener.Addr().String()
	req := append([]byte(
		"GET / HTTP/1.1\r\n"+
			"Host: "+addr+"\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Version: 13\r\n\r\n",
	), pipelinedFrame...)
	dialAndExchange(t, addr, req)

	select {
	case err := <-handlerErr:
		if err != nil {
			t.Fatalf("UpgradeHTTP: unexpected error %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UpgradeHTTP result did not arrive in time")
	}
	if !bytes.Equal(gotHS.Buffered, pipelinedFrame) {
		t.Fatalf("Buffered = % x, want % x", gotHS.Buffered, pipelinedFrame)
	}
}

func TestUpgradeHTTPOriginCheck(t *testing.T) {
	u := &gows.Upgrader{
		OriginCheck: func(origin []byte) bool {
			return bytes.Equal(origin, []byte("https://allowed.example"))
		},
	}
	handlerErr := make(chan error, 1)
	srv := startUpgradeHTTPServer(t, u, func(conn net.Conn, hs gows.Handshake, err error) {
		handlerErr <- err
		if conn != nil {
			conn.Close()
		}
	})
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	req := "GET / HTTP/1.1\r\nHost: " + addr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Origin: https://evil.example\r\n\r\n"
	resp := dialAndExchange(t, addr, []byte(req))
	if !bytes.Contains(resp, []byte(" 403 ")) {
		t.Errorf("response = %q, want 403", resp)
	}

	select {
	case err := <-handlerErr:
		if !errors.Is(err, gows.ErrOriginRejected) {
			t.Fatalf("UpgradeHTTP: err = %v, want ErrOriginRejected", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UpgradeHTTP result did not arrive in time")
	}
}
