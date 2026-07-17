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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zchee/gows"
)

// hopRecord captures one accepted connection on a hop server: the raw
// request block (valid once ready is closed) and whether the client
// closed the connection afterwards (closed).
type hopRecord struct {
	req    []byte
	ready  chan struct{}
	closed chan struct{}
}

// awaitClosed asserts the client closed this hop's connection.
func (r *hopRecord) awaitClosed(t *testing.T, what string) {
	t.Helper()
	select {
	case <-r.closed:
	case <-time.After(3 * time.Second):
		t.Errorf("%s: connection was not closed by the client", what)
	}
}

// startHopServer starts a loopback listener whose respond callback maps
// (connection index, raw request block) to raw response bytes. When
// tlsCert is non-nil each accepted connection is wrapped in TLS first.
// It returns the listener address and an accessor for the per-
// connection records.
func startHopServer(t *testing.T, tlsCert *tls.Certificate, respond func(n int, req []byte) string) (string, func(i int) *hopRecord) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var recs []*hopRecord
	go func() {
		for n := 0; ; n++ {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			rec := &hopRecord{ready: make(chan struct{}), closed: make(chan struct{})}
			mu.Lock()
			recs = append(recs, rec)
			mu.Unlock()
			go func(n int, conn net.Conn) {
				defer conn.Close()
				if tlsCert != nil {
					conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*tlsCert}})
				}
				rec.req = readRawHeaderBlock(t, conn)
				close(rec.ready)
				if _, werr := conn.Write([]byte(respond(n, rec.req))); werr != nil {
					return
				}
				// A closing client surfaces as EOF (or a TLS close) here;
				// the deadline expiring instead means the client kept the
				// connection open, which must NOT count as closed.
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, rerr := conn.Read(make([]byte, 1)); rerr != nil && !errors.Is(rerr, os.ErrDeadlineExceeded) {
					close(rec.closed)
				}
			}(n, conn)
		}
	}()

	return ln.Addr().String(), func(i int) *hopRecord {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			mu.Lock()
			var rec *hopRecord
			if i < len(recs) {
				rec = recs[i]
			}
			mu.Unlock()
			if rec != nil {
				select {
				case <-rec.ready:
				case <-time.After(3 * time.Second):
					t.Fatalf("hop connection %d never completed its request", i)
				}
				return rec
			}
			if time.Now().After(deadline) {
				t.Fatalf("hop server never saw connection %d", i)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func redirectResponse(location string) string {
	return "HTTP/1.1 302 Found\r\nLocation: " + location + "\r\n\r\n"
}

func upgradeResponse(t *testing.T, req []byte) string {
	t.Helper()
	return "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\n\r\n"
}

// followAll is the minimal opt-in policy: follow every redirect.
func followAll(*http.Request, []*http.Request) error { return nil }

func TestDialRedirectRelative(t *testing.T) {
	var recorded []*http.Request
	var vias [][]*http.Request
	addr, rec := startHopServer(t, nil, func(n int, req []byte) string {
		if n == 0 {
			return redirectResponse("/next")
		}
		return upgradeResponse(t, req)
	})

	d := &gows.Dialer{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			recorded = append(recorded, req)
			vias = append(vias, via)
			return nil
		},
	}
	conn, _, err := d.Dial(t.Context(), "ws://"+addr+"/start?q=1")
	if err != nil {
		t.Fatalf("Dial with relative redirect: %v", err)
	}
	conn.Close()

	if got := string(rec(0).req); !strings.HasPrefix(got, "GET /start?q=1 HTTP/1.1\r\n") {
		t.Errorf("first hop request line wrong:\n%s", got)
	}
	if got := string(rec(1).req); !strings.HasPrefix(got, "GET /next HTTP/1.1\r\n") {
		t.Errorf("redirected hop did not resolve the relative Location:\n%s", got)
	}
	rec(0).awaitClosed(t, "intermediate hop")

	if len(recorded) != 1 || len(vias) != 1 {
		t.Fatalf("CheckRedirect called %d times, want 1", len(recorded))
	}
	if recorded[0].URL.Path != "/next" || recorded[0].URL.Scheme != "ws" {
		t.Errorf("CheckRedirect req URL = %v, want ws .../next", recorded[0].URL)
	}
	if len(vias[0]) != 1 || vias[0][0].URL.Path != "/start" {
		t.Errorf("CheckRedirect via = %v, want the initial request", vias[0])
	}
}

func TestDialRedirectSameOriginKeepsCredentials(t *testing.T) {
	// The redirect target is this same listener (same scheme, host, and
	// effective port), published to the handler through a channel.
	targetReady := make(chan struct{})
	var sameOriginTarget string
	addr2, rec2 := startHopServer(t, nil, func(n int, req []byte) string {
		if n == 0 {
			<-targetReady
			return redirectResponse(sameOriginTarget)
		}
		return upgradeResponse(t, req)
	})
	sameOriginTarget = "ws://" + addr2 + "/authed"
	close(targetReady)

	d := &gows.Dialer{
		HTTPHeader: http.Header{
			"Authorization": {"Bearer keep-me"},
			"Cookie":        {"session=1"},
		},
		CheckRedirect: followAll,
	}
	conn, _, err := d.Dial(t.Context(), "ws://"+addr2+"/start")
	if err != nil {
		t.Fatalf("Dial with same-origin redirect: %v", err)
	}
	conn.Close()

	second := string(rec2(1).req)
	if !strings.Contains(second, "Authorization: Bearer keep-me\r\n") {
		t.Errorf("same-origin redirect dropped Authorization:\n%s", second)
	}
	if !strings.Contains(second, "Cookie: session=1\r\n") {
		t.Errorf("same-origin redirect dropped Cookie:\n%s", second)
	}
}

func TestDialRedirectCrossOriginStripsCredentials(t *testing.T) {
	targetAddr, targetRec := startHopServer(t, nil, func(n int, req []byte) string {
		return upgradeResponse(t, req)
	})
	// A second listener is a different effective port, hence a
	// different origin even on the same host.
	srcAddr, srcRec := startHopServer(t, nil, func(n int, req []byte) string {
		return redirectResponse("ws://" + targetAddr + "/elsewhere")
	})

	d := &gows.Dialer{
		HTTPHeader: http.Header{
			"Authorization": {"Bearer strip-me"},
			"cookie":        {"session=1"}, // non-canonical spelling must strip too
			"X-Custom":      {"survives"},
		},
		CheckRedirect: followAll,
	}
	conn, _, err := d.Dial(t.Context(), "ws://"+srcAddr+"/start")
	if err != nil {
		t.Fatalf("Dial with cross-origin redirect: %v", err)
	}
	conn.Close()

	first := string(srcRec(0).req)
	if !strings.Contains(first, "Authorization: Bearer strip-me\r\n") || !strings.Contains(first, "cookie: session=1\r\n") {
		t.Fatalf("first hop lost the caller credentials:\n%s", first)
	}
	second := string(targetRec(0).req)
	for _, forbidden := range []string{"Authorization", "authorization", "Cookie", "cookie", "strip-me", "session=1"} {
		if strings.Contains(second, forbidden) {
			t.Errorf("cross-origin hop still carries %q:\n%s", forbidden, second)
		}
	}
	if !strings.Contains(second, "X-Custom: survives\r\n") {
		t.Errorf("cross-origin hop dropped a non-credential header:\n%s", second)
	}
	srcRec(0).awaitClosed(t, "cross-origin intermediate hop")
}

func TestDialRedirectDowngradeStripsCredentials(t *testing.T) {
	cert, der := generateSelfSignedCert(t, "127.0.0.1")
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool.AddCert(leaf)

	plainAddr, plainRec := startHopServer(t, nil, func(n int, req []byte) string {
		return upgradeResponse(t, req)
	})
	// The http-scheme Location also pins the http->ws mapping.
	tlsAddr, tlsRec := startHopServer(t, &cert, func(n int, req []byte) string {
		return redirectResponse("http://" + plainAddr + "/downgraded")
	})

	d := &gows.Dialer{
		HTTPHeader:    http.Header{"Authorization": {"Bearer strip-on-downgrade"}},
		TLSConfig:     &tls.Config{RootCAs: pool},
		CheckRedirect: followAll,
	}
	conn, _, err := d.Dial(t.Context(), "wss://"+tlsAddr+"/secure")
	if err != nil {
		t.Fatalf("Dial with wss->ws downgrade redirect: %v", err)
	}
	conn.Close()

	if got := string(tlsRec(0).req); !strings.Contains(got, "Authorization: Bearer strip-on-downgrade\r\n") {
		t.Fatalf("wss hop lost the credential:\n%s", got)
	}
	second := string(plainRec(0).req)
	if strings.Contains(second, "strip-on-downgrade") {
		t.Errorf("downgrade hop still carries the credential:\n%s", second)
	}
	if !strings.HasPrefix(second, "GET /downgraded HTTP/1.1\r\n") {
		t.Errorf("http Location did not map onto a ws dial:\n%s", second)
	}
}

func TestDialRedirectLoop(t *testing.T) {
	var loopTarget string
	addr, rec := startHopServer(t, nil, func(n int, req []byte) string {
		return redirectResponse(loopTarget)
	})
	loopTarget = "ws://" + addr + "/loop"

	d := &gows.Dialer{CheckRedirect: followAll}
	_, _, err := d.Dial(t.Context(), "ws://"+addr+"/loop")
	if !errors.Is(err, gows.ErrTooManyRedirects) {
		t.Fatalf("Dial = %v, want errors.Is ErrTooManyRedirects", err)
	}
	// The initial request plus exactly maxRedirects follows were
	// issued, and every one of those connections was closed.
	for i := range 11 {
		rec(i).awaitClosed(t, "loop hop")
	}
}

func TestDialRedirectCheckRedirectStops(t *testing.T) {
	stop := errors.New("stop right there")
	var addr string
	addrSet := make(chan struct{})
	addrVal, rec := startHopServer(t, nil, func(n int, req []byte) string {
		<-addrSet
		return redirectResponse("ws://" + addr + "/next")
	})
	addr = addrVal
	close(addrSet)

	d := &gows.Dialer{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return stop },
	}
	_, _, err := d.Dial(t.Context(), "ws://"+addr+"/start")
	if !errors.Is(err, stop) {
		t.Fatalf("Dial = %v, want the CheckRedirect error", err)
	}
	rec(0).awaitClosed(t, "policy-stopped hop")
}

func TestDialRedirectSanitizedFailures(t *testing.T) {
	const secret = "SECRET-token-value"
	tests := map[string]struct {
		location string
		wantErr  error
	}{
		"error: unparseable Location keeps the secret out": {
			location: "\x01://bad\x7f?token=" + secret,
			wantErr:  gows.ErrMalformedLocation,
		},
		"error: non-websocket scheme keeps the secret out": {
			location: "ftp://host/?token=" + secret,
			wantErr:  gows.ErrNotWebSocketScheme,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr, _ := startHopServer(t, nil, func(n int, req []byte) string {
				return redirectResponse(tt.location)
			})
			d := &gows.Dialer{CheckRedirect: followAll}
			_, _, err := d.Dial(t.Context(), "ws://"+addr+"/start")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Dial = %v, want errors.Is %v", err, tt.wantErr)
			}
			for e := err; e != nil; e = errors.Unwrap(e) {
				if strings.Contains(e.Error(), secret) {
					t.Fatalf("error chain leaks the Location secret: %q", e)
				}
			}
		})
	}
}

func TestDialRedirectDropsLocationUserinfo(t *testing.T) {
	const secret = "PW-SECRET-userinfo"
	targetAddr, targetRec := startHopServer(t, nil, func(n int, req []byte) string {
		return upgradeResponse(t, req)
	})
	var seen *http.Request
	srcAddr, _ := startHopServer(t, nil, func(n int, req []byte) string {
		return redirectResponse("ws://user:" + secret + "@" + targetAddr + "/x")
	})

	d := &gows.Dialer{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			seen = req
			return nil
		},
	}
	conn, _, err := d.Dial(t.Context(), "ws://"+srcAddr+"/start")
	if err != nil {
		t.Fatalf("Dial with userinfo Location: %v", err)
	}
	conn.Close()

	if seen == nil || seen.URL.User != nil {
		t.Errorf("CheckRedirect saw userinfo %v, want it dropped", seen.URL)
	}
	if got := string(targetRec(0).req); strings.Contains(got, secret) {
		t.Errorf("redirected request carries Location userinfo:\n%s", got)
	}
}

// TestDialRedirectFinalHopBuffered pins that only the final hop's
// pipelined bytes are surfaced: the 101 and the first WebSocket frame
// arrive in one write, and the frame reaches the Conn intact.
func TestDialRedirectFinalHopBuffered(t *testing.T) {
	// An unmasked server Text frame "early", crafted byte-for-byte.
	frame := append([]byte{0x81, 0x05}, []byte("early")...)
	var addr string
	addrSet := make(chan struct{})
	addrVal, rec := startHopServer(t, nil, func(n int, req []byte) string {
		if n == 0 {
			<-addrSet
			return redirectResponse("ws://" + addr + "/final")
		}
		return upgradeResponse(t, req) + string(frame)
	})
	addr = addrVal
	close(addrSet)

	d := &gows.Dialer{CheckRedirect: followAll}
	conn, hs, err := d.Dial(t.Context(), "ws://"+addr+"/start")
	if err != nil {
		t.Fatalf("Dial with pipelined final hop: %v", err)
	}
	defer conn.Close()
	rec(0).awaitClosed(t, "redirecting hop")

	if string(hs.Buffered) != string(frame) {
		t.Fatalf("Handshake.Buffered = %x, want the pipelined frame %x", hs.Buffered, frame)
	}
	c := gows.NewClientConn(conn, gows.WithBuffered(hs.Buffered))
	op, p, rerr := c.ReadMessage()
	if rerr != nil || op != gows.OpcodeText || string(p) != "early" {
		t.Fatalf("ReadMessage = (%v, %q, %v), want the pipelined Text \"early\"", op, p, rerr)
	}
}
