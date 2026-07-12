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

	wantResp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
	if string(resp) != wantResp {
		t.Fatalf("raw response mismatch\n got: %q\nwant: %q", resp, wantResp)
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

func TestUpgradeHTTPTrustedClientWindowBitsHint(t *testing.T) {
	result := make(chan gows.Handshake, 1)
	u := &gows.Upgrader{EnableCompression: true, TrustClientWindowBitsHint: true}
	srv := startUpgradeHTTPServer(t, u, func(conn net.Conn, hs gows.Handshake, err error) {
		if err != nil {
			t.Errorf("UpgradeHTTP: %v", err)
		}
		result <- hs
		if conn != nil {
			conn.Close()
		}
	})
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	resp := dialAndExchange(t, addr, []byte(
		"GET / HTTP/1.1\r\nHost: "+addr+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=9\r\n\r\n",
	))
	wantResp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n"
	if string(resp) != wantResp {
		t.Fatalf("raw trusted-hint response mismatch\n got: %q\nwant: %q", resp, wantResp)
	}
	select {
	case hs := <-result:
		if hs.CompressionParams.ClientMaxWindowBits != 0 || hs.CompressionParams.ClientMaxWindowBitsHint != 9 {
			t.Fatalf("wire/hint = %d/%d, want 0/9", hs.CompressionParams.ClientMaxWindowBits, hs.CompressionParams.ClientMaxWindowBitsHint)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UpgradeHTTP result did not arrive")
	}
}

func TestUpgradeDeflateResponseAndStateParity(t *testing.T) {
	const requestPrefix = "GET / HTTP/1.1\r\n" +
		"Host: example.invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
	const responsePrefix = "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover"

	tests := map[string]struct {
		u          gows.Upgrader
		extension  string
		wantSuffix string
		wantParams gows.CompressionParams
	}{
		"valued trusted no echo": {
			u:          gows.Upgrader{EnableCompression: true, TrustClientWindowBitsHint: true},
			extension:  "permessage-deflate; client_max_window_bits=9",
			wantSuffix: "\r\n\r\n",
			wantParams: gows.CompressionParams{ClientMaxWindowBitsHint: 9},
		},
		"bare emits configured value": {
			u:          gows.Upgrader{EnableCompression: true, ClientWindowBits: 10},
			extension:  "permessage-deflate; client_max_window_bits",
			wantSuffix: "; client_max_window_bits=10\r\n\r\n",
			wantParams: gows.CompressionParams{ClientMaxWindowBits: 10},
		},
		"parameter absent emits none": {
			u:          gows.Upgrader{EnableCompression: true, ClientWindowBits: 10, TrustClientWindowBitsHint: true},
			extension:  "permessage-deflate",
			wantSuffix: "\r\n\r\n",
		},
		"emitted min takes precedence": {
			u:          gows.Upgrader{EnableCompression: true, ClientWindowBits: 10, TrustClientWindowBitsHint: true},
			extension:  "permessage-deflate; client_max_window_bits=9",
			wantSuffix: "; client_max_window_bits=9\r\n\r\n",
			wantParams: gows.CompressionParams{ClientMaxWindowBits: 9},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			request := []byte(requestPrefix + "Sec-WebSocket-Extensions: " + tt.extension + "\r\n\r\n")
			wantResponse := responsePrefix + tt.wantSuffix

			directServer, directPeer := net.Pipe()
			directResult := make(chan externalUpgradeResult, 1)
			go func() {
				hs, err := tt.u.Upgrade(directServer)
				directResult <- externalUpgradeResult{conn: directServer, hs: hs, err: err}
			}()
			if _, err := directPeer.Write(request); err != nil {
				t.Fatalf("direct request write: %v", err)
			}
			directResponse := readRawHeaderBlock(t, directPeer)
			direct := <-directResult
			directPeer.Close()
			directServer.Close()
			if direct.err != nil {
				t.Fatalf("Upgrade: %v", direct.err)
			}

			httpResult := make(chan externalUpgradeResult, 1)
			srv := startUpgradeHTTPServer(t, &tt.u, func(conn net.Conn, hs gows.Handshake, err error) {
				httpResult <- externalUpgradeResult{conn: conn, hs: hs, err: err}
				if conn != nil {
					conn.Close()
				}
			})
			httpResponse := dialAndExchange(t, srv.Listener.Addr().String(), request)
			http := <-httpResult
			srv.Close()
			if http.err != nil {
				t.Fatalf("UpgradeHTTP: %v", http.err)
			}

			if got := string(directResponse); got != wantResponse {
				t.Fatalf("direct raw response mismatch\n got: %q\nwant: %q", got, wantResponse)
			}
			if got := string(httpResponse); got != wantResponse {
				t.Fatalf("HTTP raw response mismatch\n got: %q\nwant: %q", got, wantResponse)
			}
			if !bytes.Equal(directResponse, httpResponse) {
				t.Fatalf("direct/HTTP raw response differ: %q / %q", directResponse, httpResponse)
			}
			if direct.hs.CompressionParams != tt.wantParams || http.hs.CompressionParams != tt.wantParams {
				t.Fatalf("direct/HTTP params = %+v / %+v, want %+v", direct.hs.CompressionParams, http.hs.CompressionParams, tt.wantParams)
			}
		})
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
