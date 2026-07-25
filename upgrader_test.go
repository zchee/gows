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
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/httpx"
)

// upgradeResult carries the outcome of one server-side Upgrade call.
type upgradeResult struct {
	hs   gows.Handshake
	err  error
	conn net.Conn
}

// startUpgradeServer starts a TCP loopback listener that runs
// u.Upgrade on every accepted connection, sending each result on the
// returned channel. The listener is closed automatically at test end.
func startUpgradeServer(t *testing.T, u *gows.Upgrader) (addr string, results <-chan upgradeResult) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ch := make(chan upgradeResult, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				hs, err := u.Upgrade(conn)
				ch <- upgradeResult{hs: hs, err: err, conn: conn}
			}()
		}
	}()
	return ln.Addr().String(), ch
}

// dialAndExchange connects to addr, writes request, reads whatever
// response bytes arrive within a short deadline, and returns them
// alongside the connection (left open, closed via t.Cleanup).
func dialAndExchange(t *testing.T, addr string, request []byte) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 8192)
	n, _ := conn.Read(resp)
	return resp[:n]
}

const validUpgradeRequest = "GET /chat?room=1 HTTP/1.1\r\n" +
	"Host: example.com\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
	"Sec-WebSocket-Version: 13\r\n" +
	"\r\n"

func TestUpgradeSuccess(t *testing.T) {
	tests := map[string]struct {
		upgrader *gows.Upgrader
		request  string
		wantSub  string
	}{
		"no subprotocol offered": {
			upgrader: &gows.Upgrader{},
			request:  validUpgradeRequest,
			wantSub:  "",
		},
		"subprotocol negotiated": {
			upgrader: &gows.Upgrader{Subprotocols: []string{"chat", "superchat"}},
			request: "GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: keep-alive, Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"Sec-WebSocket-Protocol: superchat, other\r\n" +
				"\r\n",
			wantSub: "superchat",
		},
		"case-varied Upgrade/Connection headers": {
			upgrader: &gows.Upgrader{},
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"UPGRADE: WebSocket\r\n" +
				"Connection: upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"\r\n",
			wantSub: "",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr, results := startUpgradeServer(t, tt.upgrader)
			resp := dialAndExchange(t, addr, []byte(tt.request))

			if !bytes.HasPrefix(resp, []byte("HTTP/1.1 101 Switching Protocols\r\n")) {
				t.Fatalf("response = %q, want 101 status line prefix", resp)
			}
			wantAccept := mustAccept(t, "dGhlIHNhbXBsZSBub25jZQ==")
			if !bytes.Contains(resp, []byte("Sec-WebSocket-Accept: "+wantAccept+"\r\n")) {
				t.Errorf("response missing correct Sec-WebSocket-Accept: %q", resp)
			}
			if tt.wantSub != "" && !bytes.Contains(resp, []byte("Sec-WebSocket-Protocol: "+tt.wantSub+"\r\n")) {
				t.Errorf("response missing Sec-WebSocket-Protocol: %s: %q", tt.wantSub, resp)
			}

			select {
			case res := <-results:
				if res.err != nil {
					t.Fatalf("Upgrade: unexpected error %v", res.err)
				}
				if res.hs.Subprotocol != tt.wantSub {
					t.Errorf("Subprotocol = %q, want %q", res.hs.Subprotocol, tt.wantSub)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Upgrade result did not arrive in time")
			}
		})
	}
}

func TestUpgradePathAndQuery(t *testing.T) {
	addr, results := startUpgradeServer(t, &gows.Upgrader{})
	dialAndExchange(t, addr, []byte(validUpgradeRequest))

	res := <-results
	if res.err != nil {
		t.Fatalf("Upgrade: unexpected error %v", res.err)
	}
	if res.hs.Path != "/chat" {
		t.Errorf("Path = %q, want /chat", res.hs.Path)
	}
	if res.hs.Query != "room=1" {
		t.Errorf("Query = %q, want room=1", res.hs.Query)
	}
}

func TestUpgradeRawPath(t *testing.T) {
	addr, results := startUpgradeServer(t, &gows.Upgrader{RawPath: true})
	dialAndExchange(t, addr, []byte(validUpgradeRequest))

	res := <-results
	if res.err != nil {
		t.Fatalf("Upgrade: unexpected error %v", res.err)
	}
	if res.hs.Path != "" || res.hs.Query != "" {
		t.Errorf("with RawPath, Path/Query should stay empty, got %q/%q", res.hs.Path, res.hs.Query)
	}
	if string(res.hs.RawPath()) != "/chat" {
		t.Errorf("RawPath() = %q, want /chat", res.hs.RawPath())
	}
	if string(res.hs.RawQuery()) != "room=1" {
		t.Errorf("RawQuery() = %q, want room=1", res.hs.RawQuery())
	}
	res.hs.Release()
	if res.hs.RawPath() != nil || res.hs.RawQuery() != nil {
		t.Errorf("after Release, RawPath()/RawQuery() should be nil")
	}
	res.hs.Release() // must not panic when called twice
}

func TestUpgradeRejectionPaths(t *testing.T) {
	tests := map[string]struct {
		request        string
		wantErr        error
		wantStatusLine string
	}{
		"error: not GET": {
			request: "POST /chat HTTP/1.1\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        httpx.ErrNotGet,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
		"error: missing Host": {
			request: "GET /chat HTTP/1.1\r\n" +
				"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrMissingHost,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
		"error: not an Upgrade request": {
			request: "GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrNotUpgrade,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
		"error: Connection missing upgrade token": {
			request: "GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrNotConnectionUpgrade,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
		"error: missing Sec-WebSocket-Key": {
			request: "GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrMissingKey,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
		"error: wrong-length Sec-WebSocket-Key": {
			request: "GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dG9vc2hvcnQ=\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        gows.ErrMissingKey,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
		"error: bad version": {
			request: "GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
			wantErr:        gows.ErrUnsupportedVersion,
			wantStatusLine: "HTTP/1.1 426 Upgrade Required\r\n",
		},
		"error: missing version": {
			request: "GET /chat HTTP/1.1\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
			wantErr:        gows.ErrUnsupportedVersion,
			wantStatusLine: "HTTP/1.1 426 Upgrade Required\r\n",
		},
		"error: malformed request line": {
			request:        "GET /chat\r\n\r\n",
			wantErr:        httpx.ErrMalformedRequestLine,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
		"error: not HTTP/1.1": {
			request: "GET /chat HTTP/1.0\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantErr:        httpx.ErrNotHTTP11,
			wantStatusLine: "HTTP/1.1 400 Bad Request\r\n",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr, results := startUpgradeServer(t, &gows.Upgrader{})
			resp := dialAndExchange(t, addr, []byte(tt.request))

			if !bytes.HasPrefix(resp, []byte(tt.wantStatusLine)) {
				t.Errorf("response = %q, want prefix %q", resp, tt.wantStatusLine)
			}
			if tt.wantErr == gows.ErrUnsupportedVersion && !bytes.Contains(resp, []byte("Sec-WebSocket-Version: 13\r\n")) {
				t.Errorf("426 response missing Sec-WebSocket-Version: 13 header: %q", resp)
			}

			select {
			case res := <-results:
				if !errors.Is(res.err, tt.wantErr) {
					t.Fatalf("Upgrade: err = %v, want %v", res.err, tt.wantErr)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Upgrade result did not arrive in time")
			}
		})
	}
}

func TestUpgradeOriginCheck(t *testing.T) {
	u := &gows.Upgrader{
		OriginCheck: func(origin []byte) bool {
			return bytes.Equal(origin, []byte("https://allowed.example"))
		},
	}

	tests := map[string]struct {
		origin string
		wantOK bool
	}{
		"allowed origin":    {origin: "https://allowed.example", wantOK: true},
		"disallowed origin": {origin: "https://evil.example", wantOK: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr, results := startUpgradeServer(t, u)
			req := "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
				"Origin: " + tt.origin + "\r\n\r\n"
			resp := dialAndExchange(t, addr, []byte(req))

			res := <-results
			if tt.wantOK {
				if res.err != nil {
					t.Fatalf("Upgrade: unexpected error %v", res.err)
				}
				if !bytes.HasPrefix(resp, []byte("HTTP/1.1 101")) {
					t.Errorf("response = %q, want 101", resp)
				}
			} else {
				if !errors.Is(res.err, gows.ErrOriginRejected) {
					t.Fatalf("Upgrade: err = %v, want ErrOriginRejected", res.err)
				}
				if !bytes.HasPrefix(resp, []byte("HTTP/1.1 403")) {
					t.Errorf("response = %q, want 403", resp)
				}
			}
		})
	}
}

func TestUpgradeHeaderTooLarge(t *testing.T) {
	addr, results := startUpgradeServer(t, &gows.Upgrader{MaxHeaderBytes: 256})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// A request line plus a single header whose value never terminates
	// with a blank line, comfortably larger than the 256-byte limit. TCP
	// send buffers absorb this without blocking, unlike net.Pipe.
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Pad: " + string(bytes.Repeat([]byte("a"), 4096))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 4096)
	n, _ := conn.Read(resp)
	if !bytes.HasPrefix(resp[:n], []byte("HTTP/1.1 431 Request Header Fields Too Large\r\n")) {
		t.Errorf("response = %q, want 431 status line", resp[:n])
	}

	select {
	case res := <-results:
		if !errors.Is(res.err, gows.ErrHeaderTooLarge) {
			t.Fatalf("Upgrade: err = %v, want ErrHeaderTooLarge", res.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Upgrade result did not arrive in time")
	}
}

func TestUpgradeFragmentedHeaderArrival(t *testing.T) {
	addr, results := startUpgradeServer(t, &gows.Upgrader{})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	full := []byte(validUpgradeRequest)
	for _, b := range full {
		if _, err := conn.Write([]byte{b}); err != nil {
			t.Fatalf("write byte: %v", err)
		}
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp := make([]byte, 4096)
	n, _ := conn.Read(resp)
	if !bytes.HasPrefix(resp[:n], []byte("HTTP/1.1 101")) {
		t.Fatalf("response = %q, want 101", resp[:n])
	}

	select {
	case res := <-results:
		if res.err != nil {
			t.Fatalf("Upgrade: unexpected error %v", res.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Upgrade result did not arrive in time")
	}
}

func TestUpgradePipelinedFrame(t *testing.T) {
	addr, results := startUpgradeServer(t, &gows.Upgrader{})

	pipelinedFrame := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'} // a complete unmasked text frame
	req := append([]byte(validUpgradeRequest), pipelinedFrame...)
	dialAndExchange(t, addr, req)

	select {
	case res := <-results:
		if res.err != nil {
			t.Fatalf("Upgrade: unexpected error %v", res.err)
		}
		if !bytes.Equal(res.hs.Buffered, pipelinedFrame) {
			t.Fatalf("Buffered = % x, want % x", res.hs.Buffered, pipelinedFrame)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Upgrade result did not arrive in time")
	}
}

func TestUpgradeNoPipelinedDataLeavesBufferedNil(t *testing.T) {
	addr, results := startUpgradeServer(t, &gows.Upgrader{})
	dialAndExchange(t, addr, []byte(validUpgradeRequest))

	res := <-results
	if res.err != nil {
		t.Fatalf("Upgrade: unexpected error %v", res.err)
	}
	if res.hs.Buffered != nil {
		t.Errorf("Buffered = %v, want nil when nothing was pipelined", res.hs.Buffered)
	}
}

// mustAccept computes the expected Sec-WebSocket-Accept value for key
// using httpx directly, for assertions against a raw response.
func mustAccept(t *testing.T, key string) string {
	t.Helper()
	accept, err := httpx.Accept([]byte(key))
	if err != nil {
		t.Fatalf("httpx.Accept: %v", err)
	}
	return string(accept)
}

// fakeConn is a bytes-backed net.Conn for allocation/latency-sensitive
// benchmarking, avoiding the goroutine-scheduling and channel overhead
// of net.Pipe.
type fakeConn struct {
	readBuf  []byte
	readPos  int
	writeBuf []byte
}

func (c *fakeConn) Read(p []byte) (int, error) {
	n := copy(p, c.readBuf[c.readPos:])
	c.readPos += n
	return n, nil
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.writeBuf = append(c.writeBuf, p...)
	return len(p), nil
}

func (c *fakeConn) Close() error { return nil }

func (c *fakeConn) LocalAddr() net.Addr { return fakeAddr{} }

func (c *fakeConn) RemoteAddr() net.Addr { return fakeAddr{} }

func (c *fakeConn) SetDeadline(time.Time) error { return nil }

func (c *fakeConn) SetReadDeadline(time.Time) error { return nil }

func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }

func (fakeAddr) String() string { return "fake" }

func (c *fakeConn) reset() {
	c.readPos = 0
	c.writeBuf = c.writeBuf[:0]
}

func TestUpgradeAllocs(t *testing.T) {
	u := &gows.Upgrader{RawPath: true}
	c := &fakeConn{readBuf: []byte(validUpgradeRequest)}

	f := func() {
		c.reset()
		hs, err := u.Upgrade(c)
		if err != nil {
			t.Fatal(err)
		}
		hs.Release()
	}

	// Warm up more than testing.AllocsPerRun's single implicit warmup
	// call: each Upgrade+Release cycles two independent internal/pool
	// size classes (the request buffer and the response buffer) through
	// one shared wrapper pool, and under -race that combination measurably
	// needs a few more iterations to reach steady state than a single
	// class does (see internal/pool, whose single-class AllocsPerRun
	// tests are unaffected). This is a race-detector/GC-timing artifact,
	// not a real per-call allocation: the actual benchmark numbers come
	// from BenchmarkUpgrade run without -race, as is standard practice
	// for allocation-sensitive benchmarks.
	for range 10 {
		f()
	}

	avg := testing.AllocsPerRun(200, f)
	t.Logf("Upgrade (RawPath, Release'd) steady-state allocs/op: %.2f (race build: %v)", avg, gows.RaceEnabled)
	if avg != 0 && !gows.RaceEnabled {
		t.Errorf("Upgrade: %.2f allocs/op, want 0 (RawPath + Release)", avg)
	}
}

func BenchmarkUpgrade(b *testing.B) {
	tests := map[string]*gows.Upgrader{
		"default (Path/Query strings)": {},
		"RawPath":                      {RawPath: true},
	}
	for name, u := range tests {
		b.Run(name, func(b *testing.B) {
			c := &fakeConn{readBuf: []byte(validUpgradeRequest)}
			b.ReportAllocs()
			for b.Loop() {
				c.reset()
				hs, err := u.Upgrade(c)
				if err != nil {
					b.Fatal(err)
				}
				hs.Release()
			}
		})
	}
}

// --- Trusted window-hint public pipeline -------------------------------------

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
			// Go 1.27's rewritten flate emits a Flush with fewer than 128
			// pending bytes as a stored/Huffman-only block with no match
			// search at levels 1-6, so the second message must reach that
			// threshold for the peer encoder to emit the cross-message
			// back-reference these cases are about; the padding shares
			// nothing with the first message, keeping the probe's far
			// reference the only cross-message match available.
			secondMsg := probe + strings.Repeat("=", 128)
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
					wire := independentTakeoverFrames(t, probe+filler, secondMsg)
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
					} else if err != nil || string(second) != secondMsg {
						t.Fatalf("within-hint second ReadMessage = %q, %v", second, err)
					}
				})
			}
		})
	}
}

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
