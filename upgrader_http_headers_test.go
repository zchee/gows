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
		"size limit":      {http.Header{"Set-Cookie": {strings.Repeat("x", 8192)}}, gows.ErrHeaderTooLarge},
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
			if w.Body.Len() != 0 {
				t.Fatalf("validation wrote response: %q", w.Body.String())
			}
		})
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
