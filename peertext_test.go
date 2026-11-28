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
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/httpx"
)

// peerMark is a distinctive token placed in peer-controlled wire positions to
// verify that gows never echoes peer bytes into error text.
const peerMark = "PEERMARK-7f3a"

func TestPeerTextInCanonicalHeaderName(t *testing.T) {
	err := errors.New("unexpected header: X-Peermark-7f3a")
	if !containsPeerText(err.Error(), peerMark) {
		t.Fatalf("did not detect %q in %q", peerMark, err)
	}
}

// TestErrorsCarryNoPeerText places peerMark in peer-controlled handshake and
// frame inputs and verifies that every failing call reports the expected error
// class with peerMark absent from the entire error tree, and every succeeding
// handshake carries the expected fields cleanly.
func TestErrorsCarryNoPeerText(t *testing.T) {
	const refusedBody = "denied: " + peerMark
	const redirectHost = peerMark + ".invalid"
	redirect := func(*testing.T, []byte) string { return redirectResponse("ws://" + redirectHost) }
	dialFailure := errors.New("test dial failure")
	fail := func(string) error { return dialFailure }
	checkDialFailure := func(t *testing.T, err error) {
		if !errors.Is(err, dialFailure) {
			t.Fatalf("Dial err = %v, want the second hop's NetDial error", err)
		}
	}

	dialTests := map[string]struct {
		dialer   func(t *testing.T) *gows.Dialer
		viaProxy bool
		respond  func(t *testing.T, req []byte) string
		check    func(t *testing.T, err error)
	}{
		"native dial refused reason": {
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 403 Forbidden " + peerMark + "\r\nContent-Length: 0\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrUnexpectedStatus) {
					t.Fatalf("Dial err = %v, want errors.Is ErrUnexpectedStatus", err)
				}
				use, ok := errors.AsType[*gows.UnexpectedStatusError](err)
				if !ok || use.StatusCode != http.StatusForbidden || !strings.Contains(use.Reason, peerMark) {
					t.Fatalf("UnexpectedStatusError = %+v (ok=%v), want 403 with Reason containing %q", use, ok, peerMark)
				}
			},
		},
		"native dial refused header name": {
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 403 Forbidden\r\nX-" + peerMark + ": 1\r\nContent-Length: 0\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrUnexpectedStatus) {
					t.Fatalf("Dial err = %v, want errors.Is ErrUnexpectedStatus", err)
				}
				use, ok := errors.AsType[*gows.UnexpectedStatusError](err)
				if !ok || use.StatusCode != http.StatusForbidden || use.Header.Get("X-"+peerMark) != "1" {
					t.Fatalf("UnexpectedStatusError = %+v (ok=%v), want 403 with header X-%s=1", use, ok, peerMark)
				}
			},
		},
		"native dial refused header value": {
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 403 Forbidden\r\nX-Detail: " + peerMark + "\r\nContent-Length: 0\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrUnexpectedStatus) {
					t.Fatalf("Dial err = %v, want errors.Is ErrUnexpectedStatus", err)
				}
				use, ok := errors.AsType[*gows.UnexpectedStatusError](err)
				if !ok || use.StatusCode != http.StatusForbidden || use.Header.Get("X-Detail") != peerMark {
					t.Fatalf("UnexpectedStatusError = %+v (ok=%v), want 403 with X-Detail=%q", use, ok, peerMark)
				}
			},
		},
		"native dial refused body": {
			dialer: func(*testing.T) *gows.Dialer {
				return &gows.Dialer{MaxErrorBodyBytes: 4096}
			},
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 401 Unauthorized\r\nContent-Length: " + strconv.Itoa(len(refusedBody)) + "\r\n\r\n" + refusedBody
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrUnexpectedStatus) {
					t.Fatalf("Dial err = %v, want errors.Is ErrUnexpectedStatus", err)
				}
				use, ok := errors.AsType[*gows.UnexpectedStatusError](err)
				if !ok || use.StatusCode != http.StatusUnauthorized || string(use.Body) != refusedBody {
					t.Fatalf("UnexpectedStatusError = %+v (ok=%v), want 401 with Body=%q", use, ok, refusedBody)
				}
			},
		},
		"native dial malformed status line": {
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 " + peerMark + " Bad\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, httpx.ErrMalformedStatusLine) {
					t.Fatalf("Dial err = %v, want errors.Is httpx.ErrMalformedStatusLine", err)
				}
			},
		},
		"native dial bad accept": {
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + peerMark + "\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrAcceptMismatch) {
					t.Fatalf("Dial err = %v, want errors.Is ErrAcceptMismatch", err)
				}
			},
		},
		"native dial unoffered subprotocol": {
			dialer: func(*testing.T) *gows.Dialer {
				return &gows.Dialer{Subprotocols: []string{"chat"}}
			},
			respond: func(t *testing.T, req []byte) string {
				accept := mustAcceptFromRequest(t, req)
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + accept + "\r\n" +
					"Sec-WebSocket-Protocol: " + peerMark + "\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrUnrequestedSubprotocol) {
					t.Fatalf("Dial err = %v, want errors.Is ErrUnrequestedSubprotocol", err)
				}
			},
		},
		"native dial unoffered extension": {
			respond: func(t *testing.T, req []byte) string {
				accept := mustAcceptFromRequest(t, req)
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + accept + "\r\n" +
					"Sec-WebSocket-Extensions: " + peerMark + "\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrInvalidCompressionResponse) {
					t.Fatalf("Dial err = %v, want errors.Is ErrInvalidCompressionResponse", err)
				}
			},
		},
		"native dial redirect path query userinfo": {
			dialer: func(t *testing.T) *gows.Dialer {
				return &gows.Dialer{
					CheckRedirect: func(req *http.Request, _ []*http.Request) error {
						if req.URL.Path != "/p/"+peerMark || req.URL.RawQuery != "q="+peerMark || req.URL.User != nil {
							t.Errorf("CheckRedirect URL = %v (User=%v), want path=/p/%s query=q=%s nil userinfo", req.URL, req.URL.User, peerMark, peerMark)
						}
						return nil
					},
				}
			},
			respond: func(t *testing.T, _ []byte) string {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen dead hop: %v", err)
				}
				deadAddr := ln.Addr().String()
				_ = ln.Close()
				loc := "ws://u:" + peerMark + "@" + deadAddr + "/p/" + peerMark + "?q=" + peerMark
				return "HTTP/1.1 302 Found\r\nLocation: " + loc + "\r\nContent-Length: 0\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if _, ok := errors.AsType[*net.OpError](err); !ok || !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatalf("Dial err = %v, want a *net.OpError matching syscall.ECONNREFUSED", err)
				}
			},
		},
		"native dial redirect host": {
			dialer: func(*testing.T) *gows.Dialer {
				return &gows.Dialer{CheckRedirect: followAll, NetDial: failSecondDial(redirectHost+":80", fail)}
			},
			respond: redirect,
			check:   checkDialFailure,
		},
		"native dial redirect derived proxy": {
			dialer: func(*testing.T) *gows.Dialer {
				return &gows.Dialer{CheckRedirect: followAll, Proxy: proxyFromHost, NetDial: failSecondDial(redirectHost+":8080", fail)}
			},
			respond: redirect,
			check:   checkDialFailure,
		},
		"native dial proxy CONNECT reason": {
			viaProxy: true,
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 407 Proxy Authentication Required " + peerMark + "\r\nContent-Length: 0\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrProxyConnectFailed) || !errors.Is(err, gows.ErrUnexpectedStatus) {
					t.Fatalf("Dial err = %v, want errors.Is ErrProxyConnectFailed and ErrUnexpectedStatus", err)
				}
				use, ok := errors.AsType[*gows.UnexpectedStatusError](err)
				if !ok || use.StatusCode != http.StatusProxyAuthRequired || !strings.Contains(use.Reason, peerMark) {
					t.Fatalf("UnexpectedStatusError = %+v (ok=%v), want 407 with Reason containing %q", use, ok, peerMark)
				}
			},
		},
		"native dial proxy CONNECT header": {
			viaProxy: true,
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 403 Forbidden\r\nProxy-Authenticate: Basic realm=\"" + peerMark + "\"\r\nContent-Length: 0\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, gows.ErrProxyConnectFailed) || !errors.Is(err, gows.ErrUnexpectedStatus) {
					t.Fatalf("Dial err = %v, want errors.Is ErrProxyConnectFailed and ErrUnexpectedStatus", err)
				}
				use, ok := errors.AsType[*gows.UnexpectedStatusError](err)
				if !ok || use.StatusCode != http.StatusForbidden || use.Header != nil {
					t.Fatalf("UnexpectedStatusError = %+v (ok=%v), want 403 with nil Header", use, ok)
				}
			},
		},
		"native dial malformed CONNECT": {
			viaProxy: true,
			respond: func(*testing.T, []byte) string {
				return "HTTP/1.1 " + peerMark + " Forbidden\r\n\r\n"
			},
			check: func(t *testing.T, err error) {
				if !errors.Is(err, httpx.ErrMalformedStatusLine) {
					t.Fatalf("Dial err = %v, want errors.Is httpx.ErrMalformedStatusLine", err)
				}
			},
		},
	}

	for name, tt := range dialTests {
		t.Run(name, func(t *testing.T) {
			srv := startRawServer(t, func(req []byte) string { return tt.respond(t, req) })
			d := &gows.Dialer{}
			if tt.dialer != nil {
				d = tt.dialer(t)
			}
			target := srv.url
			if tt.viaProxy {
				d.Proxy = proxyFor(t, "http"+strings.TrimPrefix(srv.url, "ws"), nil)
				target = "wss://origin.test:443/"
			}
			conn, err := dialWithin(t, t.Context(), d, target, 5*time.Second)
			if conn != nil {
				_ = conn.Close()
				t.Fatalf("Dial conn = %v, want nil", conn)
			}
			if err == nil {
				t.Fatal("Dial err = nil, want non-nil")
			}
			tt.check(t, err)
			assertNoPeerText(t, err, peerMark)
			srv.awaitClosed(t)
		})
	}

	serverGroups := map[string]struct {
		run func(t *testing.T, u *gows.Upgrader, rawReq string) (gows.Handshake, error)
	}{
		"legacy Upgrade": {
			run: runLegacyUpgradePeerText,
		},
		"legacy UpgradeHTTP": {
			run: runLegacyUpgradeHTTPPeerText,
		},
	}
	for groupName, group := range serverGroups {
		t.Run(groupName, func(t *testing.T) {
			runServerPeerTextGroup(t, group.run)
		})
	}

	connTests := map[string]struct {
		run func(t *testing.T)
	}{
		"Conn retained write after peer Close": {
			run: func(t *testing.T) {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				raw, err := net.Dial("tcp4", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				peer, err := listener.(*net.TCPListener).AcceptTCP()
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				body := gows.AppendCloseBody(nil, gows.CloseNormalClosure, []byte(peerMark))
				frame := append([]byte{0x88, byte(len(body))}, body...)
				if _, err := peer.Write(frame); err != nil {
					t.Fatal(err)
				}
				if err := raw.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buffered := make([]byte, len(frame))
				if _, err := io.ReadFull(raw, buffered); err != nil {
					t.Fatal(err)
				}
				if err := peer.SetLinger(0); err != nil {
					t.Fatal(err)
				}
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := raw.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
					t.Fatalf("peer reset = %v", err)
				}
				ws := gows.NewClientConn(raw, gows.WithBuffered(buffered))
				_, _, readErr := ws.ReadMessage()
				if ce, ok := errors.AsType[*gows.CloseError](readErr); !ok || ce.Reason != peerMark || ce.Sent {
					t.Fatalf("received Close = %v", readErr)
				}
				writeErr := ws.WriteMessage(gows.OpcodeText, nil)
				if !errors.Is(writeErr, net.ErrClosed) || !errors.Is(writeErr, syscall.EPIPE) || ws.WriteMessage(gows.OpcodeText, nil) != writeErr {
					t.Fatalf("retained Close reply failure = %v", writeErr)
				}
				assertNoPeerText(t, writeErr, peerMark)
			},
		},
		"Conn frame protocol violation": {
			run: func(t *testing.T) {
				serverConn, clientConn := net.Pipe()
				t.Cleanup(func() {
					_ = clientConn.Close()
					_ = serverConn.Close()
				})
				ws := gows.NewClientConn(clientConn)
				t.Cleanup(func() { _ = ws.CloseNow() })

				payload := append([]byte(peerMark), 0xff)
				frame := append([]byte{0x81, byte(len(payload))}, payload...)
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					_, _ = serverConn.Write(frame)
					_, _ = io.Copy(io.Discard, serverConn)
				}()

				_, _, err := ws.ReadMessage()
				if err == nil {
					t.Fatal("ReadMessage err = nil, want protocol violation")
				}
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ReadMessage err = %v, want errors.Is net.ErrClosed", err)
				}
				ce, ok := errors.AsType[*gows.CloseError](err)
				if !ok || !ce.Sent || ce.Code != gows.CloseInvalidFramePayloadData {
					t.Fatalf("CloseError = %+v (ok=%v), want Sent=true Code=%d", ce, ok, gows.CloseInvalidFramePayloadData)
				}
				assertNoPeerText(t, err, peerMark)

				_ = serverConn.Close()
				<-serverDone
			},
		},
		"Conn received Close reason": {
			run: func(t *testing.T) {
				serverConn, clientConn := net.Pipe()
				t.Cleanup(func() {
					_ = clientConn.Close()
					_ = serverConn.Close()
				})
				ws := gows.NewClientConn(clientConn)
				t.Cleanup(func() { _ = ws.CloseNow() })

				payload := append([]byte{0x03, 0xe8}, peerMark...)
				frame := append([]byte{0x88, byte(len(payload))}, payload...)
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					_, _ = serverConn.Write(frame)
					_, _ = io.Copy(io.Discard, serverConn)
				}()

				_, _, err := ws.ReadMessage()
				if err == nil {
					t.Fatal("ReadMessage err = nil, want *CloseError")
				}
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("ReadMessage err = %v, want errors.Is net.ErrClosed", err)
				}
				ce, ok := errors.AsType[*gows.CloseError](err)
				if !ok || ce.Sent || ce.Code != gows.CloseNormalClosure || ce.Reason != peerMark {
					t.Fatalf("CloseError = %+v (ok=%v), want Sent=false Code=%d Reason=%q", ce, ok, gows.CloseNormalClosure, peerMark)
				}
				assertNoPeerText(t, err, peerMark)

				_ = serverConn.Close()
				<-serverDone
			},
		},
		"ParseClose received reason": {
			run: func(t *testing.T) {
				payload := append([]byte{0x03, 0xe8}, peerMark...)
				ce, err := gows.ParseClose(payload)
				if err != nil {
					t.Fatalf("ParseClose err = %v, want nil", err)
				}
				if ce.Sent || ce.Code != gows.CloseNormalClosure || ce.Reason != peerMark {
					t.Fatalf("ParseClose = %+v, want Sent=false Code=%d Reason=%q", ce, gows.CloseNormalClosure, peerMark)
				}
				if containsPeerText(ce.Error(), peerMark) {
					t.Fatalf("CloseError.Error() = %q, must not contain %q", ce.Error(), peerMark)
				}
				assertNoPeerText(t, &ce, peerMark)
			},
		},
	}
	for name, tt := range connTests {
		t.Run(name, tt.run)
	}
}

func runLegacyUpgradePeerText(t *testing.T, u *gows.Upgrader, rawReq string) (gows.Handshake, error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		_, _ = clientConn.Write([]byte(rawReq))
		_, _ = io.Copy(io.Discard, clientConn)
	}()
	hs, err := u.Upgrade(serverConn)
	_ = serverConn.Close()
	_ = clientConn.Close()
	<-clientDone
	return hs, err
}

func runLegacyUpgradeHTTPPeerText(t *testing.T, u *gows.Upgrader, rawReq string) (gows.Handshake, error) {
	t.Helper()
	type outcome struct {
		hs      gows.Handshake
		err     error
		hasConn bool
	}
	resCh := make(chan outcome, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, hs, err := u.UpgradeHTTP(w, r)
		hasConn := conn != nil
		if conn != nil {
			_ = conn.Close()
		}
		resCh <- outcome{hs: hs, err: err, hasConn: hasConn}
	}))
	srv.Config.SetKeepAlivesEnabled(false)
	srv.Start()
	t.Cleanup(srv.Close)

	clientConn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial httptest server: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		_, _ = clientConn.Write([]byte(rawReq))
		_, _ = io.Copy(io.Discard, clientConn)
	}()

	var res outcome
	select {
	case res = <-resCh:
	case <-time.After(5 * time.Second):
		t.Fatal("UpgradeHTTP handler did not finish within 5s")
	}
	_ = clientConn.Close()
	<-clientDone

	if (res.err == nil) != res.hasConn {
		t.Fatalf("UpgradeHTTP err = %v, hasConn = %v; want conn iff err == nil", res.err, res.hasConn)
	}
	return res.hs, res.err
}

func runServerPeerTextGroup(t *testing.T, run func(t *testing.T, u *gows.Upgrader, rawReq string) (gows.Handshake, error)) {
	t.Helper()
	const wsKey = "dGhlIHNhbXBsZSBub25jZQ=="

	tests := map[string]struct {
		upgrader func(t *testing.T) (*gows.Upgrader, func(t *testing.T))
		request  string
		wantErr  error
		checkVal func(t *testing.T, hs gows.Handshake)
	}{
		"bad Upgrade": {
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: " + peerMark + "\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + wsKey + "\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n",
			wantErr: gows.ErrNotUpgrade,
		},
		"bad Connection": {
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: " + peerMark + "\r\n" +
				"Sec-WebSocket-Key: " + wsKey + "\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n",
			wantErr: gows.ErrNotConnectionUpgrade,
		},
		"bad Sec-WebSocket-Key": {
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + peerMark + "\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n",
			wantErr: gows.ErrMissingKey,
		},
		"bad Sec-WebSocket-Version": {
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + wsKey + "\r\n" +
				"Sec-WebSocket-Version: " + peerMark + "\r\n\r\n",
			wantErr: gows.ErrUnsupportedVersion,
		},
		"rejected Origin": {
			upgrader: func(*testing.T) (*gows.Upgrader, func(t *testing.T)) {
				var saw atomic.Value
				u := &gows.Upgrader{
					OriginCheck: func(origin []byte) bool {
						saw.Store(string(origin))
						return false
					},
				}
				return u, func(t *testing.T) {
					if got, _ := saw.Load().(string); got != "https://"+peerMark+".example" {
						t.Fatalf("OriginCheck saw %q, want %q", got, "https://"+peerMark+".example")
					}
				}
			},
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + wsKey + "\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"Origin: https://" + peerMark + ".example\r\n\r\n",
			wantErr: gows.ErrOriginRejected,
		},
		"value path and query": {
			request: "GET /p/" + peerMark + "?q=" + peerMark + " HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + wsKey + "\r\n" +
				"Sec-WebSocket-Version: 13\r\n\r\n",
			checkVal: func(t *testing.T, hs gows.Handshake) {
				if hs.Path != "/p/"+peerMark || hs.Query != "q="+peerMark {
					t.Fatalf("Handshake Path=%q Query=%q, want %q and %q", hs.Path, hs.Query, "/p/"+peerMark, "q="+peerMark)
				}
			},
		},
		"value declined extension": {
			upgrader: func(*testing.T) (*gows.Upgrader, func(t *testing.T)) {
				return &gows.Upgrader{EnableCompression: true}, nil
			},
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + wsKey + "\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"Sec-WebSocket-Extensions: " + peerMark + "\r\n\r\n",
			checkVal: func(t *testing.T, hs gows.Handshake) {
				if hs.Compressed || hs.CompressionParams != (gows.CompressionParams{}) {
					t.Fatalf("Handshake Compressed=%v Params=%+v, want declined compression", hs.Compressed, hs.CompressionParams)
				}
			},
		},
		"value unselected subprotocol": {
			upgrader: func(*testing.T) (*gows.Upgrader, func(t *testing.T)) {
				return &gows.Upgrader{Subprotocols: []string{"chat"}}, nil
			},
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Key: " + wsKey + "\r\n" +
				"Sec-WebSocket-Version: 13\r\n" +
				"Sec-WebSocket-Protocol: " + peerMark + "\r\n\r\n",
			checkVal: func(t *testing.T, hs gows.Handshake) {
				if hs.Subprotocol != "" {
					t.Fatalf("Handshake Subprotocol=%q, want empty", hs.Subprotocol)
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			u := &gows.Upgrader{}
			var postCheck func(t *testing.T)
			if tt.upgrader != nil {
				u, postCheck = tt.upgrader(t)
			}
			hs, err := run(t, u, tt.request)
			if postCheck != nil {
				postCheck(t)
			}
			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("err = nil, want errors.Is %v", tt.wantErr)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want errors.Is %v", err, tt.wantErr)
				}
				assertNoPeerText(t, err, peerMark)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.checkVal(t, hs)
		})
	}
}
