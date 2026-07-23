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
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zchee/gows"
)

// dialViaPipe runs one Dial against an in-memory fake server that
// captures the raw handshake request and answers with a valid 101
// response, returning the captured request block. beforeDial, when
// non-nil, runs inside the NetDial callback -- after Dial has taken its
// header snapshot, sequenced on Dial's own goroutine -- so tests can
// model the caller reclaiming ownership of the source header map.
func dialViaPipe(t *testing.T, d *gows.Dialer, rawURL string, beforeDial func()) []byte {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	reqCh := make(chan []byte, 1)
	go func() {
		req := readRawHeaderBlock(t, serverConn)
		reqCh <- req
		accept := mustAcceptFromRequest(t, req)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		serverConn.Write([]byte(resp))
	}()

	d.NetDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if beforeDial != nil {
			beforeDial()
		}
		return clientConn, nil
	}
	conn, _, err := d.Dial(t.Context(), rawURL)
	if err != nil {
		t.Fatalf("Dial: unexpected error %v", err)
	}
	conn.Close()
	return <-reqCh
}

func TestDialExtraHeadersOnWire(t *testing.T) {
	d := &gows.Dialer{
		HTTPHeader: http.Header{
			"X-Custom":      {"v"},
			"Authorization": {"Bearer tok"},
			"Cookie":        {"a=1", "b=2"},
			"x-noncanon":    {"lower"},
		},
	}
	req := string(dialViaPipe(t, d, "ws://example.invalid/chat", nil))

	for _, line := range []string{
		"Authorization: Bearer tok\r\n",
		"Cookie: a=1\r\nCookie: b=2\r\n",
		"X-Custom: v\r\n",
		"x-noncanon: lower\r\n",
	} {
		if !strings.Contains(req, line) {
			t.Errorf("request missing %q:\n%s", line, req)
		}
	}
	authIdx := strings.Index(req, "Authorization:")
	cookieIdx := strings.Index(req, "Cookie:")
	customIdx := strings.Index(req, "X-Custom:")
	noncanonIdx := strings.Index(req, "x-noncanon:")
	if !(authIdx < cookieIdx && cookieIdx < customIdx && customIdx < noncanonIdx) {
		t.Errorf("extra headers not in sorted key order (offsets %d, %d, %d, %d):\n%s", authIdx, cookieIdx, customIdx, noncanonIdx, req)
	}
	if got := strings.Count(req, "\r\nHost: "); got != 1 {
		t.Errorf("Host line count = %d, want 1:\n%s", got, req)
	}
	if !strings.Contains(req, "Host: example.invalid\r\n") {
		t.Errorf("request missing URL-derived Host line:\n%s", req)
	}
}

// TestDialHeaderSnapshotIsolation pins the deep-copy contract: the
// snapshot is taken before any network I/O, so mutating the source map
// or a value slice afterwards (modeled inside NetDial, sequenced after
// the clone on Dial's own goroutine -- exactly when a caller regains
// ownership) never changes the emitted request.
func TestDialHeaderSnapshotIsolation(t *testing.T) {
	src := http.Header{
		"X-Snap": {"original"},
		"X-Del":  {"keep"},
	}
	vals := src["X-Snap"]
	d := &gows.Dialer{HTTPHeader: src}
	req := string(dialViaPipe(t, d, "ws://example.invalid/", func() {
		vals[0] = "slice-mutated"
		src.Set("X-Snap", "map-mutated")
		delete(src, "X-Del")
		src["X-Added"] = []string{"late"}
	}))

	if !strings.Contains(req, "X-Snap: original\r\n") {
		t.Errorf("request lost the snapshotted value:\n%s", req)
	}
	if !strings.Contains(req, "X-Del: keep\r\n") {
		t.Errorf("request lost the deleted-after-snapshot header:\n%s", req)
	}
	for _, leaked := range []string{"slice-mutated", "map-mutated", "X-Added"} {
		if strings.Contains(req, leaked) {
			t.Errorf("request observed post-snapshot mutation %q:\n%s", leaked, req)
		}
	}
}

func TestDialHeaderValidation(t *testing.T) {
	const secret = "SECRET-bearer-credential-XYZ"
	tests := map[string]struct {
		header  http.Header
		wantErr error
	}{
		"error: reserved Upgrade": {
			header:  http.Header{"Upgrade": {"h2c"}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: reserved Host": {
			header:  http.Header{"Host": {"virtual.example.com"}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: reserved Trailer": {
			header:  http.Header{"Trailer": {"X-T"}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: reserved TE": {
			header:  http.Header{"TE": {"trailers"}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: reserved Proxy-Authorization": {
			header:  http.Header{"Proxy-Authorization": {secret}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: reserved Keep-Alive": {
			header:  http.Header{"kEeP-aLiVe": {secret}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: reserved Proxy-Connection": {
			header:  http.Header{"pRoXy-CoNnEcTiOn": {secret}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: reserved Sec-WebSocket family member": {
			header:  http.Header{"sec-websocket-key": {"AAAA"}},
			wantErr: gows.ErrReservedHeader,
		},
		"error: header injection via value": {
			header:  http.Header{"X-Foo": {secret + "\r\nX-Injected: 1"}},
			wantErr: gows.ErrMalformedHeader,
		},
		"error: invalid name": {
			header:  http.Header{"X Foo": {secret}},
			wantErr: gows.ErrMalformedHeader,
		},
		"error: oversized headers": {
			header:  http.Header{"X-Big": {secret + strings.Repeat("a", 8192)}},
			wantErr: gows.ErrHeaderTooLarge,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dialed := false
			d := &gows.Dialer{
				HTTPHeader: tt.header,
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialed = true
					return nil, errors.New("must not be reached")
				},
			}
			_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Dial = %v, want errors.Is %v", err, tt.wantErr)
			}
			if dialed {
				t.Error("Dial performed network I/O despite invalid HTTPHeader")
			}
			for e := err; e != nil; e = errors.Unwrap(e) {
				if strings.Contains(e.Error(), secret) {
					t.Fatalf("error chain leaks a header value: %q", e)
				}
			}
		})
	}
}

// TestDialHeaderBoundary drives the exact serialized-size ceiling
// through the public API: one byte under the limit dials, one byte
// past it fails before any network I/O.
func TestDialHeaderBoundary(t *testing.T) {
	boundary := strings.Repeat("v", 8192-len("X-A")-len(": \r\n"))

	d := &gows.Dialer{HTTPHeader: http.Header{"X-A": {boundary}}}
	req := string(dialViaPipe(t, d, "ws://example.invalid/", nil))
	if !strings.Contains(req, "X-A: "+boundary+"\r\n") {
		t.Error("boundary-size header missing from the emitted request")
	}

	dialed := false
	over := &gows.Dialer{
		HTTPHeader: http.Header{"X-A": {boundary + "v"}},
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not be reached")
		},
	}
	_, _, err := over.Dial(t.Context(), "ws://example.invalid/")
	if !errors.Is(err, gows.ErrHeaderTooLarge) {
		t.Fatalf("Dial = %v, want errors.Is ErrHeaderTooLarge", err)
	}
	if dialed {
		t.Error("oversized header still performed network I/O")
	}
}

// TestDialRequestUnchangedWithoutHeader pins byte-compatibility: a
// zero-value Dialer produces a request with no extra header lines
// between Sec-WebSocket-Version and the terminating blank line.
func TestDialRequestUnchangedWithoutHeader(t *testing.T) {
	req := dialViaPipe(t, &gows.Dialer{}, "ws://example.invalid/", nil)
	if !bytes.HasSuffix(req, []byte("Sec-WebSocket-Version: 13\r\n\r\n")) {
		t.Errorf("headerless request does not end with the version line:\n%s", req)
	}
}

// deadlineRecorderConn records every SetDeadline call so a test can
// assert Dial cleared the guard deadline before returning the
// connection to the caller.
type deadlineRecorderConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecorderConn) SetDeadline(tm time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, tm)
	c.mu.Unlock()
	return c.Conn.SetDeadline(tm)
}

func (c *deadlineRecorderConn) last() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.deadlines) == 0 {
		return time.Time{}, false
	}
	return c.deadlines[len(c.deadlines)-1], true
}

// closeRecorderConn records whether Close was called, so failure-path
// tests can assert the raw connection was released.
type closeRecorderConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecorderConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}
