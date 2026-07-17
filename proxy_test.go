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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows"
)

// proxyFor returns a Dialer.Proxy hook that always selects rawURL,
// recording the synthesized request it received.
func proxyFor(t *testing.T, rawURL string, sawReq **http.Request) func(*http.Request) (*url.URL, error) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return func(r *http.Request) (*url.URL, error) {
		if sawReq != nil {
			*sawReq = r
		}
		return u, nil
	}
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestDialWSViaProxyAbsoluteForm(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	reqCh := make(chan []byte, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		req := readRawHeaderBlock(t, conn)
		reqCh <- req
		accept := mustAcceptFromRequest(t, req)
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"))
	}()

	var sawReq *http.Request
	d := &gows.Dialer{
		HTTPHeader: http.Header{
			"Authorization": {"Bearer app-token"},
			"X-Custom":      {"v"},
		},
		Proxy: proxyFor(t, "http://alice:proxy-pass@"+ln.Addr().String(), &sawReq),
	}
	conn, _, err := d.Dial(t.Context(), "ws://origin.example:8123/chat?x=1")
	if err != nil {
		t.Fatalf("Dial through proxy: %v", err)
	}
	conn.Close()

	req := string(<-reqCh)
	if !strings.HasPrefix(req, "GET http://origin.example:8123/chat?x=1 HTTP/1.1\r\n") {
		t.Errorf("proxied request is not absolute-form:\n%s", req)
	}
	if !strings.Contains(req, "Host: origin.example:8123\r\n") {
		t.Errorf("Host is not the origin authority:\n%s", req)
	}
	if got := strings.Count(req, "Proxy-Authorization: "); got != 1 {
		t.Errorf("Proxy-Authorization count = %d, want exactly 1:\n%s", got, req)
	}
	if !strings.Contains(req, "Proxy-Authorization: "+basicAuth("alice", "proxy-pass")+"\r\n") {
		t.Errorf("proxy credentials did not reach the proxy leg:\n%s", req)
	}
	// The origin Authorization stays a distinct header and never feeds
	// the proxy credential, in either direction.
	if !strings.Contains(req, "Authorization: Bearer app-token\r\n") {
		t.Errorf("origin Authorization missing:\n%s", req)
	}
	if strings.Contains(req, "Proxy-Authorization: Bearer app-token") {
		t.Errorf("origin Authorization leaked into Proxy-Authorization:\n%s", req)
	}
	if !strings.Contains(req, "X-Custom: v\r\n") {
		t.Errorf("extra header missing from proxied request:\n%s", req)
	}

	// The Proxy hook saw the net/http-compatible synthesized request:
	// scheme translated so http.ProxyFromEnvironment works unchanged.
	if sawReq == nil || sawReq.URL.String() != "http://origin.example:8123/chat?x=1" {
		t.Errorf("Proxy hook request URL = %v, want the http-scheme origin URL", sawReq.URL)
	}
	if sawReq.Header.Get("X-Custom") != "v" {
		t.Errorf("Proxy hook request lacks the header snapshot: %v", sawReq.Header)
	}
}

func TestDialWSSViaProxyConnect(t *testing.T) {
	cert, der := generateSelfSignedCert(t, "origin.test")
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool.AddCert(leaf)

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin Listen: %v", err)
	}
	t.Cleanup(func() { originLn.Close() })
	originReq := make(chan []byte, 1)
	go func() {
		conn, aerr := originLn.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		tconn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		req := readRawHeaderBlock(t, tconn)
		originReq <- req
		accept := mustAcceptFromRequest(t, req)
		tconn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"))
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy Listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })
	connectReq := make(chan []byte, 1)
	go func() {
		conn, aerr := proxyLn.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		req := readRawHeaderBlock(t, conn)
		connectReq <- req
		upstream, derr := net.Dial("tcp", originLn.Addr().String())
		if derr != nil {
			return
		}
		defer upstream.Close()
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go io.Copy(upstream, conn)
		io.Copy(conn, upstream)
	}()

	_, originPort, _ := net.SplitHostPort(originLn.Addr().String())
	var sawReq *http.Request
	d := &gows.Dialer{
		HTTPHeader: http.Header{"Authorization": {"Bearer app-token"}, "X-Custom": {"v"}},
		TLSConfig:  &tls.Config{RootCAs: pool},
		Proxy:      proxyFor(t, "http://alice:proxy-pass@"+proxyLn.Addr().String(), &sawReq),
	}
	conn, _, err := d.Dial(t.Context(), "wss://origin.test:"+originPort+"/chat")
	if err != nil {
		t.Fatalf("Dial wss through CONNECT proxy: %v", err)
	}
	conn.Close()

	connect := string(<-connectReq)
	wantTarget := "origin.test:" + originPort
	if !strings.HasPrefix(connect, "CONNECT "+wantTarget+" HTTP/1.1\r\n") {
		t.Errorf("CONNECT request line wrong:\n%s", connect)
	}
	if !strings.Contains(connect, "Host: "+wantTarget+"\r\n") {
		t.Errorf("CONNECT Host wrong:\n%s", connect)
	}
	if !strings.Contains(connect, "Proxy-Authorization: "+basicAuth("alice", "proxy-pass")+"\r\n") {
		t.Errorf("CONNECT lacks the proxy credentials:\n%s", connect)
	}
	for _, forbidden := range []string{"Bearer app-token", "X-Custom", "Upgrade: websocket", "Sec-WebSocket"} {
		if strings.Contains(connect, forbidden) {
			t.Errorf("CONNECT leaked origin material %q:\n%s", forbidden, connect)
		}
	}

	origin := string(<-originReq)
	if !strings.HasPrefix(origin, "GET /chat HTTP/1.1\r\n") {
		t.Errorf("origin request is not origin-form:\n%s", origin)
	}
	if strings.Contains(origin, "Proxy-Authorization") {
		t.Errorf("proxy credentials reached the origin:\n%s", origin)
	}
	if !strings.Contains(origin, "Authorization: Bearer app-token\r\n") || !strings.Contains(origin, "X-Custom: v\r\n") {
		t.Errorf("origin request lost the caller headers:\n%s", origin)
	}
	if sawReq == nil || sawReq.URL.Scheme != "https" {
		t.Errorf("Proxy hook URL scheme = %v, want https for a wss dial", sawReq.URL)
	}
}

func TestDialWSSViaProxyConnectRefused(t *testing.T) {
	const proxySecret = "proxy-SECRET-pw"
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })
	go func() {
		conn, aerr := proxyLn.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		readRawHeaderBlock(t, conn)
		// Reflect the credential into the reason phrase; it must not
		// surface through the error chain.
		conn.Write([]byte("HTTP/1.1 407 denied " + proxySecret + "\r\n\r\n"))
	}()

	d := &gows.Dialer{
		Proxy: proxyFor(t, "http://alice:"+proxySecret+"@"+proxyLn.Addr().String(), nil),
	}
	_, _, err = d.Dial(t.Context(), "wss://origin.test:443/")
	if !errors.Is(err, gows.ErrProxyConnectFailed) {
		t.Fatalf("Dial = %v, want errors.Is ErrProxyConnectFailed", err)
	}
	if !errors.Is(err, gows.ErrUnexpectedStatus) {
		t.Fatalf("Dial = %v, want errors.Is ErrUnexpectedStatus", err)
	}
	var use *gows.UnexpectedStatusError
	if !errors.As(err, &use) || use.StatusCode != 407 {
		t.Fatalf("Dial = %v, want *UnexpectedStatusError with status 407", err)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), proxySecret) {
			t.Fatalf("error chain leaks the proxy credential: %q", e)
		}
	}
}

func TestDialWSSViaProxyUntrustedOriginTLS(t *testing.T) {
	cert, _ := generateSelfSignedCert(t, "origin.test")
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin Listen: %v", err)
	}
	t.Cleanup(func() { originLn.Close() })
	go func() {
		conn, aerr := originLn.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		tconn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tconn.Handshake()
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy Listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })
	go func() {
		conn, aerr := proxyLn.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		readRawHeaderBlock(t, conn)
		upstream, derr := net.Dial("tcp", originLn.Addr().String())
		if derr != nil {
			return
		}
		defer upstream.Close()
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go io.Copy(upstream, conn)
		io.Copy(conn, upstream)
	}()

	_, originPort, _ := net.SplitHostPort(originLn.Addr().String())
	d := &gows.Dialer{
		// An empty root pool: the origin's self-signed certificate must
		// be rejected inside the tunnel exactly as on a direct dial.
		TLSConfig: &tls.Config{RootCAs: x509.NewCertPool()},
		Proxy:     proxyFor(t, "http://"+proxyLn.Addr().String(), nil),
	}
	_, _, err = d.Dial(t.Context(), "wss://origin.test:"+originPort+"/")
	if err == nil {
		t.Fatal("Dial = nil, want certificate verification failure inside the tunnel")
	}
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
		t.Fatalf("Dial = %v, want x509.UnknownAuthorityError", err)
	}
}

func TestDialProxyResolverError(t *testing.T) {
	boom := errors.New("proxy resolver exploded")
	dialed := false
	d := &gows.Dialer{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, boom },
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not be reached")
		},
	}
	_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
	if !errors.Is(err, boom) {
		t.Fatalf("Dial = %v, want the resolver error", err)
	}
	if dialed {
		t.Error("Dial performed network I/O despite a proxy resolver failure")
	}
}

func TestDialProxyUnsupportedScheme(t *testing.T) {
	dialed := false
	d := &gows.Dialer{
		Proxy: proxyFor(t, "socks5://127.0.0.1:1080", nil),
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not be reached")
		},
	}
	_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
	if !errors.Is(err, gows.ErrProxyUnsupportedScheme) {
		t.Fatalf("Dial = %v, want errors.Is ErrProxyUnsupportedScheme", err)
	}
	if dialed {
		t.Error("Dial performed network I/O despite an unsupported proxy scheme")
	}
}

func TestDialContextCanceledDuringProxyConnect(t *testing.T) {
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })

	sawConnect := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, aerr := proxyLn.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		readRawHeaderBlock(t, conn)
		close(sawConnect)
		<-release // never answer the CONNECT
	}()

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-sawConnect
		cancel()
	}()

	d := &gows.Dialer{
		Proxy: proxyFor(t, "http://"+proxyLn.Addr().String(), nil),
	}
	start := time.Now()
	_, _, err = d.Dial(ctx, "wss://origin.test:443/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want errors.Is context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Dial took %v to observe cancellation during CONNECT", elapsed)
	}
}
