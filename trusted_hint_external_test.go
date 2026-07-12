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
	"compress/flate"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zchee/gows"
)

const trustedHintRequest = "GET / HTTP/1.1\r\n" +
	"Host: example.invalid\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
	"Sec-WebSocket-Version: 13\r\n" +
	"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=10\r\n\r\n"

type externalUpgradeResult struct {
	conn net.Conn
	hs   gows.Handshake
	err  error
}

func establishTrustedHintConn(t *testing.T, httpUpgrade bool) (net.Conn, net.Conn, gows.Handshake) {
	t.Helper()
	u := &gows.Upgrader{EnableCompression: true, AllowContextTakeover: true, TrustClientWindowBitsHint: true}
	result := make(chan externalUpgradeResult, 1)
	var peer net.Conn
	if httpUpgrade {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, hs, err := u.UpgradeHTTP(w, r)
			result <- externalUpgradeResult{conn, hs, err}
		}))
		t.Cleanup(srv.Close)
		var err error
		peer, err = net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
	} else {
		server, client := net.Pipe()
		peer = client
		go func() {
			hs, err := u.Upgrade(server)
			result <- externalUpgradeResult{server, hs, err}
		}()
	}
	if _, err := peer.Write([]byte(trustedHintRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if resp := readRawHeaderBlock(t, peer); bytes.Contains(resp, []byte("client_max_window_bits")) {
		t.Fatalf("trusted hint changed response parameters: %q", resp)
	}
	r := <-result
	if r.err != nil {
		t.Fatalf("upgrade: %v", r.err)
	}
	if r.hs.CompressionParams.ClientMaxWindowBits != 0 || r.hs.CompressionParams.ClientMaxWindowBitsHint != 10 {
		t.Fatalf("exported wire/hint = %d/%d, want 0/10", r.hs.CompressionParams.ClientMaxWindowBits, r.hs.CompressionParams.ClientMaxWindowBitsHint)
	}
	t.Cleanup(func() { r.conn.Close(); peer.Close() })
	return r.conn, peer, r.hs
}

func independentTakeoverFrames(t *testing.T, first, second string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, 6)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	var wire []byte
	for _, msg := range []string{first, second} {
		compressed.Reset()
		if _, err := w.Write([]byte(msg)); err != nil {
			t.Fatalf("peer Write: %v", err)
		}
		if err := w.Flush(); err != nil {
			t.Fatalf("peer Flush: %v", err)
		}
		payload := append([]byte(nil), compressed.Bytes()...)
		payload = payload[:len(payload)-4] // RFC 7692 removes the sync-flush marker.
		const key = uint32(0x44332211)
		for i := range payload {
			payload[i] ^= byte(key >> (8 * (i & 3)))
		}
		wire = gows.AppendHeader(wire, gows.Header{Fin: true, Rsv: gows.RSV1, Opcode: gows.OpcodeBinary, Masked: true, MaskKey: key, Length: int64(len(payload))})
		wire = append(wire, payload...)
	}
	return wire
}

func TestTrustedClientWindowBitsHintPublicPipeline(t *testing.T) {
	for _, httpUpgrade := range []bool{false, true} {
		name := "Upgrade"
		if httpUpgrade {
			name = "UpgradeHTTP"
		}
		t.Run(name, func(t *testing.T) {
			const probe = "PUBLIC-HINT-CROSS-MESSAGE-PROBE-1234567890-"
			for _, risk := range []bool{false, true} {
				caseName := "conforming-within-hint"
				filler := strings.Repeat("near-", 100)
				if risk {
					caseName = "full-window-peer-exceeds-hint"
					filler = strings.Repeat("far-history-filler-", 180)
				}
				t.Run(caseName, func(t *testing.T) {
					server, peer, hs := establishTrustedHintConn(t, httpUpgrade)
					conn := gows.NewServerConn(server, gows.WithCompressionParams(hs.CompressionParams))
					wire := independentTakeoverFrames(t, probe+filler, probe)
					go func() {
						_, _ = peer.Write(wire)
						_, _ = io.Copy(io.Discard, peer)
					}()
					if _, first, err := conn.ReadMessage(); err != nil || string(first) != probe+filler {
						t.Fatalf("first ReadMessage: len=%d err=%v", len(first), err)
					}
					_, second, err := conn.ReadMessage()
					if risk {
						if err == nil {
							t.Fatalf("trusted 1KB hint accepted >1KB independent peer history: %q", second)
						}
					} else if err != nil || string(second) != probe {
						t.Fatalf("within-hint second ReadMessage = %q, %v", second, err)
					}
				})
			}
		})
	}
}
