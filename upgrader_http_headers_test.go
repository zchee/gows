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
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows"
)

func TestUpgradeHTTPResponseHeaders(t *testing.T) {
	tests := map[string]struct{ forward bool }{
		"default ignores pending headers":             {},
		"opt in preserves cookies and buffered frame": {forward: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := make(chan error, 1)
			cookies := []string{"first=value; HttpOnly; SameSite=Strict", "second=value; Path=/"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header()["Set-Cookie"] = slices.Clone(cookies)
				w.Header().Set("X-Application", "ready")
				u := gows.Upgrader{ForwardResponseHeaders: tt.forward}
				conn, hs, err := u.UpgradeHTTP(w, r)
				if err != nil {
					result <- err
					return
				}
				ws := gows.NewServerConn(conn, gows.WithBuffered(hs.Buffered))
				defer ws.Abort()
				frame, err := ws.ReadFrame()
				if err == nil && (!frame.Header.Fin || frame.Header.Opcode != gows.OpcodeText || !bytes.Equal(frame.Payload, []byte("hello"))) {
					err = fmt.Errorf("first frame = %+v", frame)
				}
				result <- err
			}))
			defer server.Close()
			addr := server.Listener.Addr().String()
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			request := "GET / HTTP/1.1\r\nHost: " + addr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
			payload := append([]byte(request), 0x81, 0x85, 0, 0, 0, 0, 'h', 'e', 'l', 'l', 'o')
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), new(http.Request))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("status = %d", response.StatusCode)
			}
			wantCookies := cookies
			wantApplication := "ready"
			if !tt.forward {
				wantCookies = nil
				wantApplication = ""
			}
			if got := response.Header.Values("Set-Cookie"); !slices.Equal(got, wantCookies) {
				t.Fatalf("cookies = %q, want %q", got, wantCookies)
			}
			if got := response.Header.Get("X-Application"); got != wantApplication {
				t.Fatalf("application = %q, want %q", got, wantApplication)
			}
			for _, key := range []string{"Upgrade", "Connection", "Sec-WebSocket-Accept"} {
				if got := response.Header.Values(key); len(got) != 1 {
					t.Fatalf("reserved %s values = %q", key, got)
				}
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("first buffered frame was not delivered")
			}
		})
	}
}

func TestUpgradeHTTPResponseHeaderValidation(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		want    error
	}{
		"invalid name":    {http.Header{"Bad Name": {"value"}}, gows.ErrMalformedHeader},
		"empty name":      {http.Header{"": {"value"}}, gows.ErrMalformedHeader},
		"carriage return": {http.Header{"Set-Cookie": {"safe", "hidden\rvalue"}}, gows.ErrMalformedHeader},
		"line feed":       {http.Header{"Set-Cookie": {"hidden\nvalue"}}, gows.ErrMalformedHeader},
		"null byte":       {http.Header{"Set-Cookie": {"hidden\x00value"}}, gows.ErrMalformedHeader},
		"control byte":    {http.Header{"X-Application": {"hidden\x01value"}}, gows.ErrMalformedHeader},
		"delete byte":     {http.Header{"X-Application": {"hidden\x7fvalue"}}, gows.ErrMalformedHeader},
		"size limit":      {http.Header{"Set-Cookie": {cookieValueSerializingTo(gows.MaxExtraHeaderBytes + 1)}}, gows.ErrHeaderTooLarge},
	}
	for _, key := range []string{"Upgrade", "Connection", "Sec-WebSocket-Accept", "Sec-WebSocket-Protocol", "Sec-WebSocket-Extensions", "Sec-WebSocket-Version", "Sec-WebSocket-Key", "Host", "Content-Length", "Transfer-Encoding", "Trailer", "TE", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection"} {
		tests["reserved "+key] = struct {
			headers http.Header
			want    error
		}{http.Header{strings.ToLower(key): {"hidden-value"}}, gows.ErrReservedHeader}
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			maps.Copy(w.Header(), tt.headers)
			r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			r.Header = http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}}
			u := gows.Upgrader{ForwardResponseHeaders: true}
			conn, _, err := u.UpgradeHTTP(w, r)
			if conn != nil || !errors.Is(err, tt.want) {
				t.Fatalf("upgrade = %v, %v; want nil, %v", conn, err, tt.want)
			}
			if strings.Contains(err.Error(), "hidden") {
				t.Fatalf("error leaked header value: %v", err)
			}
			// The caller's documented pattern is a bare return on error, so
			// the rejection itself must have answered the request.
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
			}
			if w.Body.Len() == 0 {
				t.Fatal("rejection wrote an empty body")
			}
			if strings.Contains(w.Body.String(), "hidden") {
				t.Fatalf("response body leaked header value: %q", w.Body.String())
			}
		})
	}
}

// cookieValueSerializingTo returns a Set-Cookie value whose "Set-Cookie:
// <value>" CRLF line is exactly total bytes long, which is how the
// extra-header ceiling counts it.
func cookieValueSerializingTo(total int) string {
	return strings.Repeat("v", total-len("Set-Cookie")-len(": \r\n"))
}

// upgradeOverTCP serves handler on a real listener, sends one WebSocket
// upgrade request over a raw TCP connection, and parses the reply with
// http.ReadResponse. It returns the parsed response, its fully read body,
// and every byte the client received, so a failure can show the wire.
func upgradeOverTCP(t *testing.T, handler http.HandlerFunc) (*http.Response, []byte, []byte) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+addr+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	response, err := http.ReadResponse(bufio.NewReader(io.TeeReader(conn, &wire)), new(http.Request))
	if err != nil {
		t.Fatalf("read response: %v\nreceived:\n%q", err, wire.String())
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v\nreceived:\n%q", err, wire.String())
	}
	return response, body, wire.Bytes()
}

func TestUpgradeHTTPResponseHeaderRejectionOverTCP(t *testing.T) {
	tests := map[string]struct {
		headers  http.Header
		rejected string
		sentinel string
		kept     http.Header
		want     error
	}{
		"CRLF in a cookie value": {
			headers:  http.Header{"Set-Cookie": {"id=1\r\nX-Injected: hidden"}},
			rejected: "Set-Cookie",
			sentinel: "hidden",
			want:     gows.ErrMalformedHeader,
		},
		// net/http keeps a handler-staged non-identity Transfer-Encoding
		// and adds its own "chunked" beside it, which http.ReadResponse
		// refuses to parse, so the rejected header must be gone before the
		// 500 is written.
		"reserved Transfer-Encoding": {
			headers:  http.Header{"Transfer-Encoding": {"gzip"}},
			rejected: "Transfer-Encoding",
			sentinel: "gzip",
			want:     gows.ErrReservedHeader,
		},
		"reserved Sec-WebSocket-Accept beside a cookie": {
			headers:  http.Header{"Set-Cookie": {"session=ok; HttpOnly"}, "Sec-Websocket-Accept": {"hidden"}},
			rejected: "Sec-Websocket-Accept",
			sentinel: "hidden",
			kept:     http.Header{"Set-Cookie": {"session=ok; HttpOnly"}},
			want:     gows.ErrReservedHeader,
		},
		// Raw map keys bypass canonicalization, and net/http writes them
		// as spelled, so stripping has to match names case-insensitively
		// or a non-canonical reserved entry still reaches the wire.
		"reserved Transfer-Encoding under non-canonical keys": {
			headers:  http.Header{"transfer-encoding": {"hidden-lower"}, "TRANSFER-ENCODING": {"hidden-upper"}},
			rejected: "Transfer-Encoding",
			sentinel: "hidden",
			want:     gows.ErrReservedHeader,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := make(chan error, 1)
			response, body, wire := upgradeOverTCP(t, func(w http.ResponseWriter, r *http.Request) {
				maps.Copy(w.Header(), tt.headers)
				w.Header().Set("X-Application", "ready")
				u := gows.Upgrader{ForwardResponseHeaders: true}
				conn, _, err := u.UpgradeHTTP(w, r)
				if conn != nil {
					_ = conn.Close()
					result <- errors.New("rejected headers returned a live connection")
					return
				}
				result <- err
			})
			if err := <-result; !errors.Is(err, tt.want) {
				t.Fatalf("upgrade error = %v, want %v", err, tt.want)
			}
			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d\nreceived:\n%q", response.StatusCode, http.StatusInternalServerError, wire)
			}
			if len(body) == 0 {
				t.Fatalf("empty 500 body\nreceived:\n%q", wire)
			}
			if got := response.Header.Get("X-Application"); got != "ready" {
				t.Fatalf("X-Application = %q, want %q\nreceived:\n%q", got, "ready", wire)
			}
			for key, want := range tt.kept {
				if got := response.Header.Values(key); !slices.Equal(got, want) {
					t.Fatalf("%s = %q, want %q\nreceived:\n%q", key, got, want, wire)
				}
			}
			if got := response.Header.Values(tt.rejected); len(got) != 0 {
				t.Fatalf("rejected %s still sent: %q\nreceived:\n%q", tt.rejected, got, wire)
			}
			if bytes.Contains(wire, []byte(tt.sentinel)) {
				t.Fatalf("rejected value %q reached the client\nreceived:\n%q", tt.sentinel, wire)
			}
		})
	}
}

func TestUpgradeHTTPResponseHeaderSizeBoundary(t *testing.T) {
	cookie := cookieValueSerializingTo(gows.MaxExtraHeaderBytes)
	result := make(chan error, 1)
	response, _, _ := upgradeOverTCP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", cookie)
		u := gows.Upgrader{ForwardResponseHeaders: true}
		conn, _, err := u.UpgradeHTTP(w, r)
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	})
	if err := <-result; err != nil {
		t.Fatalf("upgrade at the exact ceiling: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusSwitchingProtocols)
	}
	if got := response.Header.Values("Set-Cookie"); len(got) != 1 || got[0] != cookie {
		t.Fatalf("Set-Cookie came back as %d values totalling %d bytes, want the one %d-byte value intact", len(got), len(strings.Join(got, "")), len(cookie))
	}
}

type headerWriteFailure struct {
	net.Conn
	short bool
}

func (c headerWriteFailure) Write(b []byte) (int, error) {
	if c.short {
		return c.Conn.Write(b[:len(b)/2])
	}
	return 0, io.ErrClosedPipe
}

type headerFailureWriter struct {
	http.ResponseWriter
	short bool
}

func (w headerFailureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return headerWriteFailure{Conn: conn, short: w.short}, rw, nil
}

func TestUpgradeHTTPResponseHeaderWriteFailure(t *testing.T) {
	tests := map[string]struct {
		short bool
		want  error
	}{
		"write error":   {want: io.ErrClosedPipe},
		"partial write": {short: true, want: io.ErrShortWrite},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Set-Cookie", "test=value")
				u := gows.Upgrader{ForwardResponseHeaders: true}
				conn, _, err := u.UpgradeHTTP(headerFailureWriter{ResponseWriter: w, short: tt.short}, r)
				if conn != nil {
					_ = conn.Close()
					result <- errors.New("failed write returned live connection")
					return
				}
				result <- err
			}))
			defer server.Close()
			conn, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(conn); err != nil {
				t.Fatalf("failed connection was not closed: %v", err)
			}
			if err := <-result; !errors.Is(err, tt.want) {
				t.Fatalf("write error = %v, want %v", err, tt.want)
			}
		})
	}
}
