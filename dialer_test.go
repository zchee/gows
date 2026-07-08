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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/httpx"
)

// readRawHeaderBlock reads from c until it has a complete CRLFCRLF
// terminated block, returning everything read (which may extend past
// the terminator). It is the fake-server-side counterpart to gows's own
// internal header reader, used here to inspect or ignore a real
// handshake request without depending on gows's own request parsing.
func readRawHeaderBlock(t *testing.T, c net.Conn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buf []byte
	tmp := make([]byte, 4096)
	for !bytes.Contains(buf, []byte("\r\n\r\n")) {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			t.Fatalf("readRawHeaderBlock: %v", err)
		}
	}
	return buf
}

// TestDialSuccessPipe exercises Dial against Upgrade over an in-memory
// net.Pipe, using Dialer.NetDial to substitute the pipe for a real
// network dial -- the same handshake code path a real TCP dial uses.
func TestDialSuccessPipe(t *testing.T) {
	tests := map[string]struct {
		dialerSub   []string
		upgraderSub []string
		wantSub     string
	}{
		"no subprotocols": {},
		"subprotocol negotiated": {
			dialerSub:   []string{"chat", "superchat"},
			upgraderSub: []string{"superchat"},
			wantSub:     "superchat",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()

			serverDone := make(chan gows.Handshake, 1)
			serverErr := make(chan error, 1)
			go func() {
				u := &gows.Upgrader{Subprotocols: tt.upgraderSub}
				hs, err := u.Upgrade(serverConn)
				serverErr <- err
				serverDone <- hs
			}()

			d := &gows.Dialer{
				Subprotocols: tt.dialerSub,
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return clientConn, nil
				},
			}
			conn, hs, err := d.Dial(t.Context(), "ws://example.invalid/chat?x=1")
			if err != nil {
				t.Fatalf("Dial: unexpected error %v", err)
			}
			defer conn.Close()

			if hs.Subprotocol != tt.wantSub {
				t.Errorf("client Subprotocol = %q, want %q", hs.Subprotocol, tt.wantSub)
			}

			if err := <-serverErr; err != nil {
				t.Fatalf("Upgrade: unexpected error %v", err)
			}
			shs := <-serverDone
			if shs.Path != "/chat" || shs.Query != "x=1" {
				t.Errorf("server Path/Query = %q/%q, want /chat / x=1", shs.Path, shs.Query)
			}
			if shs.Subprotocol != tt.wantSub {
				t.Errorf("server Subprotocol = %q, want %q", shs.Subprotocol, tt.wantSub)
			}
		})
	}
}

// TestDialSuccessTCP exercises Dial against Upgrade over a real TCP
// loopback listener, i.e. Dial's default net.Dialer path with no
// NetDial override.
func TestDialSuccessTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		u := &gows.Upgrader{}
		_, err = u.Upgrade(conn)
		serverErr <- err
	}()

	d := &gows.Dialer{}
	conn, hs, err := d.Dial(t.Context(), "ws://"+ln.Addr().String()+"/")
	if err != nil {
		t.Fatalf("Dial: unexpected error %v", err)
	}
	defer conn.Close()

	if hs.Subprotocol != "" {
		t.Errorf("Subprotocol = %q, want empty", hs.Subprotocol)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("Upgrade: unexpected error %v", err)
	}
}

func TestDialBadScheme(t *testing.T) {
	d := &gows.Dialer{}
	_, _, err := d.Dial(t.Context(), "http://example.com/")
	if !errors.Is(err, gows.ErrNotWebSocketScheme) {
		t.Fatalf("Dial: err = %v, want ErrNotWebSocketScheme", err)
	}
}

// TestDialFakeServerRejections tampers with a handcrafted handshake
// response, verifying the client detects each specific violation.
func TestDialFakeServerRejections(t *testing.T) {
	tests := map[string]struct {
		respond func(t *testing.T, key string) string
		wantErr error
	}{
		"wrong status code": {
			respond: func(t *testing.T, key string) string {
				return "HTTP/1.1 400 Bad Request\r\n\r\n"
			},
			wantErr: gows.ErrUnexpectedStatus,
		},
		"missing Upgrade header": {
			respond: func(t *testing.T, key string) string {
				accept := mustAccept(t, key)
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
			},
			wantErr: gows.ErrNotUpgrade,
		},
		"missing Connection header": {
			respond: func(t *testing.T, key string) string {
				accept := mustAccept(t, key)
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
			},
			wantErr: gows.ErrNotConnectionUpgrade,
		},
		"tampered Sec-WebSocket-Accept": {
			respond: func(t *testing.T, key string) string {
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: dGhpc2lzd3Jvbmc9PQ==\r\n\r\n"
			},
			wantErr: gows.ErrAcceptMismatch,
		},
		"unrequested subprotocol": {
			respond: func(t *testing.T, key string) string {
				accept := mustAccept(t, key)
				return "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + accept + "\r\n" +
					"Sec-WebSocket-Protocol: not-offered\r\n\r\n"
			},
			wantErr: gows.ErrUnrequestedSubprotocol,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()

			go func() {
				req := readRawHeaderBlock(t, serverConn)
				sc := httpx.NewHeaderScanner(bytes.SplitAfterN(req, []byte("\r\n"), 2)[1])
				var key string
				for sc.Next() {
					if httpx.EqualFold(sc.Key(), "sec-websocket-key") {
						key = string(sc.Value())
					}
				}
				serverConn.Write([]byte(tt.respond(t, key)))
			}()

			d := &gows.Dialer{
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return clientConn, nil
				},
			}
			_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Dial: err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDialPipelinedFrame(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	pipelinedFrame := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	go func() {
		req := readRawHeaderBlock(t, serverConn)
		sc := httpx.NewHeaderScanner(bytes.SplitAfterN(req, []byte("\r\n"), 2)[1])
		var key string
		for sc.Next() {
			if httpx.EqualFold(sc.Key(), "sec-websocket-key") {
				key = string(sc.Value())
			}
		}
		accept := mustAccept(t, key)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		serverConn.Write(append([]byte(resp), pipelinedFrame...))
	}()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	conn, hs, err := d.Dial(t.Context(), "ws://example.invalid/")
	if err != nil {
		t.Fatalf("Dial: unexpected error %v", err)
	}
	defer conn.Close()

	if !bytes.Equal(hs.Buffered, pipelinedFrame) {
		t.Fatalf("Buffered = % x, want % x", hs.Buffered, pipelinedFrame)
	}
}

// TestDialWSS exercises Dial against Upgrade over TLS, using a
// self-signed certificate generated in-test (crypto/x509, stdlib only).
func TestDialWSS(t *testing.T) {
	cert, der := generateSelfSignedCert(t, "127.0.0.1")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	serverErr := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		u := &gows.Upgrader{}
		_, err = u.Upgrade(conn)
		serverErr <- err
	}()

	rootCAs := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	rootCAs.AddCert(leaf)

	d := &gows.Dialer{TLSConfig: &tls.Config{RootCAs: rootCAs}}
	conn, _, err := d.Dial(t.Context(), "wss://"+ln.Addr().String()+"/")
	if err != nil {
		t.Fatalf("Dial: unexpected error %v", err)
	}
	defer conn.Close()

	if _, ok := conn.(*tls.Conn); !ok {
		t.Errorf("Dial returned %T, want *tls.Conn for a wss:// URL", conn)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("Upgrade: unexpected error %v", err)
	}
}

func TestDialWSSCertificateRejected(t *testing.T) {
	cert, _ := generateSelfSignedCert(t, "127.0.0.1")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})

	go func() {
		conn, err := tlsLn.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	// No RootCAs configured: the self-signed cert must not verify.
	d := &gows.Dialer{}
	_, _, err = d.Dial(t.Context(), "wss://"+ln.Addr().String()+"/")
	if err == nil {
		t.Fatal("Dial: expected a TLS verification error, got nil")
	}
}

// generateSelfSignedCert returns a fresh self-signed ECDSA certificate
// valid for the given hosts (IP literals or DNS names), along with its
// DER bytes.
func generateSelfSignedCert(t *testing.T, hosts ...string) (tls.Certificate, []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, der
}

func TestDialHeaderTooLarge(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		readRawHeaderBlock(t, conn)
		// Respond with a status line that never terminates with a blank
		// line, comfortably larger than the client's default 8KB limit.
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nX-Pad: "))
		conn.Write(bytes.Repeat([]byte("a"), 16384))
	}()

	d := &gows.Dialer{}
	_, _, err = d.Dial(t.Context(), "ws://"+ln.Addr().String()+"/")
	if !errors.Is(err, gows.ErrHeaderTooLarge) {
		t.Fatalf("Dial: err = %v, want ErrHeaderTooLarge", err)
	}
}

// TestUpgradeHTTPAgainstDial exercises Dial against UpgradeHTTP served
// by a real net/http server (httptest.Server), rather than Upgrade.
// startUpgradeHTTPServer is defined in upgrader_http_test.go.
func TestUpgradeHTTPAgainstDial(t *testing.T) {
	var gotHS gows.Handshake
	handlerErr := make(chan error, 1)
	srv := startUpgradeHTTPServer(t, &gows.Upgrader{Subprotocols: []string{"chat"}}, func(conn net.Conn, hs gows.Handshake, err error) {
		gotHS = hs
		handlerErr <- err
		if conn != nil {
			conn.Close()
		}
	})
	defer srv.Close()

	wsURL := "ws" + srv.URL[len("http"):] + "/room?x=1"
	d := &gows.Dialer{Subprotocols: []string{"chat"}}
	conn, hs, err := d.Dial(t.Context(), wsURL)
	if err != nil {
		t.Fatalf("Dial: unexpected error %v", err)
	}
	defer conn.Close()

	if hs.Subprotocol != "chat" {
		t.Errorf("client Subprotocol = %q, want chat", hs.Subprotocol)
	}
	if err := <-handlerErr; err != nil {
		t.Fatalf("UpgradeHTTP: unexpected error %v", err)
	}
	if gotHS.Path != "/room" || gotHS.Query != "x=1" {
		t.Errorf("server Path/Query = %q/%q, want /room / x=1", gotHS.Path, gotHS.Query)
	}
}
