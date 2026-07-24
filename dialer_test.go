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
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

func TestDialRejectsHostlessOriginBeforeNetworkIO(t *testing.T) {
	const secret = "SECRET-origin-userinfo-query"
	tests := map[string]string{
		"error: empty authority":             "ws:///socket?token=" + secret,
		"error: port without hostname":       "wss://:443/socket?token=" + secret,
		"error: userinfo without a hostname": "ws://user:" + secret + "@/socket?token=" + secret,
	}
	for name, rawURL := range tests {
		t.Run(name, func(t *testing.T) {
			dialed := false
			d := &gows.Dialer{
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialed = true
					return nil, errors.New("must not be reached")
				},
			}
			_, _, err := d.Dial(t.Context(), rawURL)
			if _, ok := errors.AsType[net.InvalidAddrError](err); !ok {
				t.Fatalf("Dial = %v, want net.InvalidAddrError", err)
			}
			if dialed {
				t.Error("Dial performed network I/O for a hostless origin")
			}
			for e := err; e != nil; e = errors.Unwrap(e) {
				if strings.Contains(e.Error(), secret) {
					t.Fatalf("error chain leaks origin URL material: %q", e)
				}
			}
		})
	}
}

func TestDialSanitizesMalformedOriginURL(t *testing.T) {
	const secret = "SECRET-origin-parse"
	tests := map[string]string{
		"error: invalid explicit port": "ws://user:" + secret + "@example.com:notaport/socket?token=" + secret,
		"error: missing IPv6 bracket":  "wss://user:" + secret + "@[::1/socket?token=" + secret,
		"error: invalid path escape":   "ws://example.com/%zz?token=" + secret,
	}
	for name, rawURL := range tests {
		t.Run(name, func(t *testing.T) {
			dialed := false
			d := &gows.Dialer{
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialed = true
					return nil, errors.New("must not be reached")
				},
			}
			_, _, err := d.Dial(t.Context(), rawURL)
			if _, ok := errors.AsType[net.InvalidAddrError](err); !ok {
				t.Fatalf("Dial = %v, want net.InvalidAddrError", err)
			}
			if dialed {
				t.Error("Dial performed network I/O for a malformed origin URL")
			}
			for e := err; e != nil; e = errors.Unwrap(e) {
				if strings.Contains(e.Error(), secret) {
					t.Fatalf("error chain leaks origin URL material: %q", e)
				}
			}
		})
	}
}

func TestDialValidOriginAuthorityFormation(t *testing.T) {
	boom := errors.New("stop after address capture")
	tests := map[string]struct {
		rawURL   string
		wantAddr string
	}{
		"success: hostname with default port": {rawURL: "ws://example.test/socket", wantAddr: "example.test:80"},
		"success: IPv6 with explicit port":    {rawURL: "ws://[::1]:8080/socket", wantAddr: "[::1]:8080"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var gotAddr string
			d := &gows.Dialer{
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					gotAddr = addr
					return nil, boom
				},
			}
			_, _, err := d.Dial(t.Context(), tt.rawURL)
			if !errors.Is(err, boom) {
				t.Fatalf("Dial = %v, want address-capture error", err)
			}
			if gotAddr != tt.wantAddr {
				t.Errorf("NetDial address = %q, want %q", gotAddr, tt.wantAddr)
			}
		})
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
			peerClosed := make(chan error, 1)

			go func() {
				req := readRawHeaderBlock(t, serverConn)
				sc := httpx.NewHeaderScanner(bytes.SplitAfterN(req, []byte("\r\n"), 2)[1])
				var key string
				for sc.Next() {
					if httpx.EqualFold(sc.Key(), "sec-websocket-key") {
						key = string(sc.Value())
					}
				}
				_, _ = serverConn.Write([]byte(tt.respond(t, key)))
				_ = serverConn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, err := serverConn.Read(make([]byte, 1))
				peerClosed <- err
			}()

			d := &gows.Dialer{
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return clientConn, nil
				},
			}
			conn, _, err := d.Dial(t.Context(), "ws://example.invalid/")
			if conn != nil {
				t.Fatalf("Dial conn = %v, want nil on validation failure", conn)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Dial: err = %v, want %v", err, tt.wantErr)
			}
			select {
			case closeErr := <-peerClosed:
				if closeErr == nil {
					t.Fatal("peer read succeeded, want client-side close")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("peer did not observe client-side close")
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
// startUpgradeHTTPServer is defined in upgrader_test.go.
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

// --- ServerWindowBits / unsupported window bits ----------------------------

// TestDialServerWindowBitsOffer confirms Dialer.ServerWindowBits is
// emitted in the offer and that a response echoing a smaller value
// populates CompressionParams.ServerMaxWindowBits; a response echoing
// larger fails with the existing too-large sentinel.
func TestDialServerWindowBitsOffer(t *testing.T) {
	tests := map[string]struct {
		echoBits   int // 0 = omit server_max_window_bits from response
		wantServer int
		wantErr    error
	}{
		"success: response echoes 9": {
			echoBits:   9,
			wantServer: 9,
		},
		"error: response echoes 11 above offer": {
			echoBits: 11,
			wantErr:  gows.ErrInvalidCompressionResponse,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			reqCh := make(chan []byte, 1)
			peerClosed := make(chan error, 1)
			go func() {
				req := readRawHeaderBlock(t, serverConn)
				reqCh <- req
				accept := mustAcceptFromRequest(t, req)
				ext := "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
				if tt.echoBits != 0 {
					ext += "; server_max_window_bits=" + strconv.Itoa(tt.echoBits)
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + accept + "\r\n" +
					"Sec-WebSocket-Extensions: " + ext + "\r\n\r\n"
				_, _ = serverConn.Write([]byte(resp))
				if tt.wantErr != nil {
					_ = serverConn.SetReadDeadline(time.Now().Add(3 * time.Second))
					_, err := serverConn.Read(make([]byte, 1))
					peerClosed <- err
				}
			}()

			d := &gows.Dialer{
				EnableCompression: true,
				ServerWindowBits:  10,
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return clientConn, nil
				},
			}
			conn, hs, err := d.Dial(t.Context(), "ws://example.invalid/")
			if tt.wantErr != nil {
				if conn != nil {
					t.Fatalf("Dial conn = %v, want nil", conn)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Dial err = %v, want %v", err, tt.wantErr)
				}
				// Also assert the more specific wrapped sentinel when too-large.
				if tt.echoBits == 11 {
					// ErrDeflateServerMaxWindowBitsTooLarge is internal;
					// the public wrapper is ErrInvalidCompressionResponse.
					if !errors.Is(err, gows.ErrInvalidCompressionResponse) {
						t.Fatalf("want ErrInvalidCompressionResponse wrap, got %v", err)
					}
				}
				select {
				case closeErr := <-peerClosed:
					if closeErr == nil {
						t.Fatal("peer read succeeded, want client-side close")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("peer did not observe client-side close")
				}
				return
			}
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()

			req := <-reqCh
			if !bytes.Contains(req, []byte("server_max_window_bits=10")) {
				t.Fatalf("request missing server_max_window_bits=10: %q", req)
			}
			if hs.CompressionParams.ServerMaxWindowBits != tt.wantServer {
				t.Fatalf("ServerMaxWindowBits = %d, want %d", hs.CompressionParams.ServerMaxWindowBits, tt.wantServer)
			}
		})
	}
}

// TestDialInvalidServerWindowBits confirms out-of-range ServerWindowBits
// fails before dialing.
func TestDialInvalidServerWindowBits(t *testing.T) {
	for name, bits := range map[string]int{"too low": 7, "too high": 16} {
		t.Run(name, func(t *testing.T) {
			d := &gows.Dialer{
				EnableCompression: true,
				ServerWindowBits:  bits,
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					t.Fatal("NetDial must not be called for invalid ServerWindowBits")
					return nil, nil
				},
			}
			_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
			if !errors.Is(err, gows.ErrInvalidWindowBits) {
				t.Fatalf("Dial err = %v, want ErrInvalidWindowBits", err)
			}
		})
	}
}

// TestDialUnsupportedWindowBitsBeforeDial confirms WindowBits=10 with the
// default stdlib backend fails with ErrUnsupportedWindowBits before any
// network I/O.
func TestDialUnsupportedWindowBitsBeforeDial(t *testing.T) {
	d := &gows.Dialer{
		EnableCompression: true,
		WindowBits:        10,
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			t.Fatal("NetDial must not be called when WindowBits is unsupported by the active backend")
			return nil, nil
		},
	}
	_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
	if !errors.Is(err, gows.ErrUnsupportedWindowBits) {
		t.Fatalf("Dial err = %v, want ErrUnsupportedWindowBits", err)
	}
}

func TestDialConflictingClientWindowBitsBeforeAnything(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		d := &gows.Dialer{
			EnableCompression: enabled, WindowBits: 15, OfferClientMaxWindowBits: true,
			NetDial: func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("NetDial called")
				return nil, nil
			},
		}
		_, _, err := d.Dial(t.Context(), ":// malformed")
		if !errors.Is(err, gows.ErrConflictingClientWindowBits) {
			t.Fatalf("compression=%v err=%v, want conflict", enabled, err)
		}
	}
}

func TestDialBareClientMaxWindowBits(t *testing.T) {
	for _, responseBits := range []int{0, 15} {
		t.Run(strconv.Itoa(responseBits), func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			reqCh := make(chan []byte, 1)
			go func() {
				req := readRawHeaderBlock(t, serverConn)
				reqCh <- req
				ext := "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
				if responseBits != 0 {
					ext += "; client_max_window_bits=" + strconv.Itoa(responseBits)
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\nSec-WebSocket-Extensions: " + ext + "\r\n\r\n"
				_, _ = serverConn.Write([]byte(resp))
			}()
			d := &gows.Dialer{EnableCompression: true, OfferClientMaxWindowBits: true, NetDial: func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }}
			conn, hs, err := d.Dial(t.Context(), "ws://example.invalid/")
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()
			req := <-reqCh
			if got := bytes.Count(req, []byte("client_max_window_bits")); got != 1 || bytes.Contains(req, []byte("client_max_window_bits=")) {
				t.Fatalf("bare request count/form invalid: %q", req)
			}
			if hs.CompressionParams.ClientMaxWindowBits != responseBits {
				t.Fatalf("ClientMaxWindowBits=%d, want %d", hs.CompressionParams.ClientMaxWindowBits, responseBits)
			}
		})
	}
}

func TestDialBareClientMaxWindowBitsResponseFailuresClose(t *testing.T) {
	for name, responseParam := range map[string]string{
		"bare response":        "; client_max_window_bits",
		"invalid low response": "; client_max_window_bits=7",
		"unsupported response": "; client_max_window_bits=9",
	} {
		t.Run(name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			closed := make(chan error, 1)
			go func() {
				req := readRawHeaderBlock(t, serverConn)
				resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + mustAcceptFromRequest(t, req) + "\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover" + responseParam + "\r\n\r\n"
				_, _ = serverConn.Write([]byte(resp))
				one := make([]byte, 1)
				_, err := serverConn.Read(one)
				closed <- err
			}()
			d := &gows.Dialer{EnableCompression: true, OfferClientMaxWindowBits: true, NetDial: func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }}
			conn, _, err := d.Dial(t.Context(), "ws://example.invalid/")
			if conn != nil || err == nil {
				t.Fatalf("Dial = %v, %v, want nil conn/error", conn, err)
			}
			want := gows.ErrInvalidCompressionResponse
			if name == "unsupported response" {
				want = gows.ErrUnsupportedWindowBits
			}
			if !errors.Is(err, want) {
				t.Fatalf("err=%v, want %v", err, want)
			}
			select {
			case closeErr := <-closed:
				if closeErr == nil {
					t.Fatal("peer read succeeded, want closed connection")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("established connection was not closed")
			}
		})
	}
}

// mustAcceptFromRequest extracts Sec-WebSocket-Key from a raw request and
// returns the expected Accept value.
func mustAcceptFromRequest(t *testing.T, req []byte) string {
	t.Helper()
	sc := httpx.NewHeaderScanner(bytes.SplitAfterN(req, []byte("\r\n"), 2)[1])
	var key string
	for sc.Next() {
		if httpx.EqualFold(sc.Key(), "sec-websocket-key") {
			key = string(sc.Value())
		}
	}
	if key == "" {
		t.Fatal("request missing Sec-WebSocket-Key")
	}
	return mustAccept(t, key)
}

func TestDialContextAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	dialed := false
	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not be reached")
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ctx.Err()) {
		t.Fatalf("Dial = %v, want errors.Is ctx.Err (context.Canceled)", err)
	}
	if dialed {
		t.Error("Dial performed network I/O with an already-canceled context")
	}
}

func TestDialContextCanceledDuringNetDial(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	entered := make(chan struct{})
	go func() {
		<-entered
		cancel()
	}()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want errors.Is context.Canceled", err)
	}
}

func TestDialContextCancelCauseDuringNetDialMatchesErrAndCause(t *testing.T) {
	cause := errors.New("dial canceled during NetDial")
	ctx, cancel := context.WithCancelCause(t.Context())
	entered := make(chan struct{})
	go func() {
		<-entered
		cancel(cause)
	}()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("Dial = %v, want errors.Is ctx.Err (%v)", err, ctx.Err())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("Dial = %v, want errors.Is cancel cause", err)
	}
}

// writeSignalConn closes ch just before the first Write starts, so a
// test can cancel while the handshake request write is in flight.
type writeSignalConn struct {
	net.Conn
	once sync.Once
	ch   chan struct{}
}

func (c *writeSignalConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.ch) })
	return c.Conn.Write(p)
}

// cancelOnStopContext deterministically ends itself from the stop
// function returned to context.AfterFunc. This models the success-boundary
// race where ctx becomes done after the exchange completes but before the
// callback goroutine starts.
type cancelOnStopContext struct {
	context.Context
	done chan struct{}
	once sync.Once
	err  error
}

func newCancelOnStopContext(parent context.Context) *cancelOnStopContext {
	return &cancelOnStopContext{Context: parent, done: make(chan struct{})}
}

func (c *cancelOnStopContext) Done() <-chan struct{} { return c.done }

func (c *cancelOnStopContext) Err() error { return c.err }

func (c *cancelOnStopContext) AfterFunc(func()) func() bool {
	return func() bool {
		c.once.Do(func() {
			c.err = context.Canceled
			close(c.done)
		})
		return true
	}
}

type deadlineFailConn struct {
	net.Conn
	armErr   error
	clearErr error
	writeErr error
	closed   bool
}

func (c *deadlineFailConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(p)
}

func (c *deadlineFailConn) SetDeadline(tm time.Time) error {
	if tm.IsZero() && c.clearErr != nil {
		return c.clearErr
	}
	if !tm.IsZero() && c.armErr != nil {
		return c.armErr
	}
	return c.Conn.SetDeadline(tm)
}

func (c *deadlineFailConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func TestDialContextCanceledDuringRequestWrite(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	// The server never reads: net.Pipe is unbuffered, so the request
	// write blocks until cancellation force-closes the connection.
	writing := make(chan struct{})
	rec := &closeRecorderConn{Conn: &writeSignalConn{Conn: clientConn, ch: writing}}

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-writing
		cancel()
	}()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want errors.Is context.Canceled", err)
	}
	if !rec.closed.Load() {
		t.Error("Dial left the raw connection open after a canceled request write")
	}
}

func TestDialContextCanceledDuringResponseRead(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	gotRequest := make(chan struct{})
	go func() {
		readRawHeaderBlock(t, serverConn)
		close(gotRequest)
		// Never respond: only the cancellation interrupt can unblock.
	}()

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-gotRequest
		cancel()
	}()

	rec := &closeRecorderConn{Conn: clientConn}
	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	start := time.Now()
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ctx.Err()) {
		t.Fatalf("Dial = %v, want errors.Is ctx.Err (context.Canceled)", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Dial took %v to observe cancellation", elapsed)
	}
	if !rec.closed.Load() {
		t.Error("Dial left the raw connection open after a canceled response read")
	}
}

func TestDialContextCanceledDuringTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	sawHello := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		one := make([]byte, 1)
		if _, rerr := conn.Read(one); rerr == nil {
			close(sawHello)
		}
		<-release // stall mid-TLS-handshake until the test ends
	}()

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-sawHello
		cancel()
	}()

	var d gows.Dialer
	start := time.Now()
	_, _, err = d.Dial(ctx, "wss://"+ln.Addr().String()+"/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want errors.Is context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Dial took %v to observe cancellation during TLS", elapsed)
	}
}

func TestDialContextDeadlineExceeded(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		readRawHeaderBlock(t, serverConn) // consume, never respond
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	start := time.Now()
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial = %v, want errors.Is context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Dial took %v to observe the deadline", elapsed)
	}
}

func TestDialContextCancelCauseMatchesErrAndCause(t *testing.T) {
	cause := errors.New("dial canceled by caller")
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(cause)

	dialed := false
	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not be reached")
		},
	}
	_, _, err := d.Dial(ctx, "ws://example.invalid/")
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("Dial = %v, want errors.Is ctx.Err (%v)", err, ctx.Err())
	}
	if !errors.Is(err, cause) {
		t.Fatalf("Dial = %v, want errors.Is cancel cause", err)
	}
	if dialed {
		t.Error("Dial performed network I/O with an already-canceled context")
	}
}

func TestDialDeadlineArmFailureClosesConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	armErr := errors.New("cannot arm deadline")
	rec := &deadlineFailConn{Conn: clientConn, armErr: armErr, writeErr: errors.New("write should not be reached")}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	conn, _, err := d.Dial(ctx, "ws://example.invalid/")
	if conn != nil {
		conn.Close()
		t.Fatal("Dial returned a connection after SetDeadline failed")
	}
	if !errors.Is(err, armErr) {
		t.Fatalf("Dial = %v, want errors.Is arm failure", err)
	}
	if !rec.closed {
		t.Error("Dial left the raw connection open after SetDeadline failed")
	}
}

func TestDialDeadlineClearFailureClosesConnection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		req := readRawHeaderBlock(t, serverConn)
		accept := mustAcceptFromRequest(t, req)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		serverConn.Write([]byte(resp))
	}()

	clearErr := errors.New("cannot clear deadline")
	rec := &deadlineFailConn{Conn: clientConn, clearErr: clearErr}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	conn, _, err := d.Dial(ctx, "ws://example.invalid/")
	if conn != nil {
		conn.Close()
		t.Fatal("Dial returned a connection with an uncleared deadline")
	}
	if !errors.Is(err, clearErr) {
		t.Fatalf("Dial = %v, want errors.Is clear failure", err)
	}
	if !rec.closed {
		t.Error("Dial left the raw connection open after clearing the deadline failed")
	}
}

// TestDialSuccessClearsDeadlines pins the ownership handoff: the guard
// deadline derived from ctx is reset to the zero time on success, and
// the returned connection carries live traffic unbounded by it.
func TestDialSuccessClearsDeadlines(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	go func() {
		req := readRawHeaderBlock(t, serverConn)
		accept := mustAcceptFromRequest(t, req)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		serverConn.Write([]byte(resp))
	}()

	rec := &deadlineRecorderConn{Conn: clientConn}
	ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancel()

	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	conn, _, err := d.Dial(ctx, "ws://example.invalid/")
	if err != nil {
		t.Fatalf("Dial: unexpected error %v", err)
	}

	last, ok := rec.last()
	if !ok {
		t.Fatal("Dial never set the ctx-derived handshake deadline")
	}
	if !last.IsZero() {
		t.Errorf("last SetDeadline = %v, want the zero time (deadline cleared on success)", last)
	}

	// Live traffic after the ctx deadline has passed proves neither the
	// deadline nor a late callback poisoned the connection.
	server := gows.NewServerConn(serverConn)
	client := gows.NewClientConn(conn)
	serverErr := make(chan error, 1)
	go func() {
		op, p, rerr := server.ReadMessage()
		if rerr == nil {
			rerr = server.WriteMessage(op, p)
		}
		serverErr <- rerr
	}()
	time.Sleep(300 * time.Millisecond) // outlive the original ctx deadline
	if err := client.WriteMessage(gows.OpcodeText, []byte("post-deadline")); err != nil {
		t.Fatalf("WriteMessage after Dial: %v", err)
	}
	if _, p, err := client.ReadMessage(); err != nil || string(p) != "post-deadline" {
		t.Fatalf("ReadMessage after Dial = (%q, %v), want the echo", p, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server echo: %v", err)
	}
	// The server goroutine has stopped reading, so a closing handshake
	// would block on the unbuffered pipe; release the raw transports.
	conn.Close()
	serverConn.Close()
}

func TestDialCancelAtSuccessBoundary(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	ctx := newCancelOnStopContext(t.Context())
	go func() {
		req := readRawHeaderBlock(t, serverConn)
		accept := mustAcceptFromRequest(t, req)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		serverConn.Write([]byte(resp))
	}()

	rec := &closeRecorderConn{Conn: clientConn}
	d := &gows.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return rec, nil
		},
	}
	conn, _, err := d.Dial(ctx, "ws://example.invalid/")
	if conn != nil {
		conn.Close()
		t.Fatal("Dial returned a connection after ctx became done at the success boundary")
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ctx.Err()) {
		t.Fatalf("Dial = %v, want errors.Is ctx.Err (context.Canceled)", err)
	}
	if !rec.closed.Load() {
		t.Error("Dial left the raw connection open after success-boundary cancellation")
	}
}

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

// dialWithRawResponse runs one Dial whose fake server answers with the
// given raw response bytes, returning Dial's error.
func dialWithRawResponse(t *testing.T, d *gows.Dialer, response string) error {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		readRawHeaderBlock(t, serverConn)
		serverConn.Write([]byte(response))
	}()
	d.NetDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return clientConn, nil
	}
	_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
	if err == nil {
		t.Fatal("Dial = nil error, want failure")
	}
	return err
}

func TestDialUnexpectedStatus(t *testing.T) {
	tests := map[string]struct {
		response   string
		wantStatus int
		wantReason string
	}{
		"error: 403 with reason": {
			response:   "HTTP/1.1 403 Forbidden\r\n\r\n",
			wantStatus: 403,
			wantReason: "Forbidden",
		},
		"error: 500 empty reason": {
			response:   "HTTP/1.1 500 \r\n\r\n",
			wantStatus: 500,
			wantReason: "",
		},
		"error: redirect status without opt-in stays a status error": {
			response:   "HTTP/1.1 302 Found\r\nLocation: ws://elsewhere.invalid/\r\n\r\n",
			wantStatus: 302,
			wantReason: "Found",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := dialWithRawResponse(t, &gows.Dialer{}, tt.response)
			if !errors.Is(err, gows.ErrUnexpectedStatus) {
				t.Fatalf("Dial = %v, want errors.Is ErrUnexpectedStatus", err)
			}
			var use *gows.UnexpectedStatusError
			if !errors.As(err, &use) {
				t.Fatalf("Dial = %v, want a *UnexpectedStatusError in the chain", err)
			}
			if use.StatusCode != tt.wantStatus || use.Reason != tt.wantReason {
				t.Fatalf("UnexpectedStatusError = (%d, %q), want (%d, %q)", use.StatusCode, use.Reason, tt.wantStatus, tt.wantReason)
			}
		})
	}
}

// TestDialMalformedStatus pins that a status-code field that is not
// exactly three ASCII digits is a malformed status line, never a typed
// unexpected-status result.
func TestDialMalformedStatus(t *testing.T) {
	for name, response := range map[string]string{
		"error: alphabetic code": "HTTP/1.1 ABC Nope\r\n\r\n",
		"error: four-digit code": "HTTP/1.1 4033 Nope\r\n\r\n",
		"error: two-digit code":  "HTTP/1.1 42 Nope\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := dialWithRawResponse(t, &gows.Dialer{}, response)
			if errors.Is(err, gows.ErrUnexpectedStatus) {
				t.Fatalf("Dial = %v, want a malformed-status error, not ErrUnexpectedStatus", err)
			}
			if !errors.Is(err, httpx.ErrMalformedStatusLine) {
				t.Fatalf("Dial = %v, want errors.Is httpx.ErrMalformedStatusLine", err)
			}
		})
	}
}

// TestDialStatusReasonRedaction reflects a recognizable bearer secret
// back in the peer's reason phrase and asserts it never surfaces in
// Error() output anywhere in the chain -- only in the explicitly
// documented Reason field.
func TestDialStatusReasonRedaction(t *testing.T) {
	const secret = "SECRET-BEARER-TOKEN-XYZ"
	d := &gows.Dialer{HTTPHeader: http.Header{"Authorization": {"Bearer " + secret}}}
	err := dialWithRawResponse(t, d, "HTTP/1.1 401 denied "+secret+"\r\n\r\n")

	if !errors.Is(err, gows.ErrUnexpectedStatus) {
		t.Fatalf("Dial = %v, want errors.Is ErrUnexpectedStatus", err)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), secret) {
			t.Fatalf("error chain leaks the reflected secret: %q", e)
		}
	}
	var use *gows.UnexpectedStatusError
	if !errors.As(err, &use) {
		t.Fatalf("Dial = %v, want a *UnexpectedStatusError", err)
	}
	if use.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", use.StatusCode)
	}
	// The field carries the verbatim reason for callers that opt in to
	// inspecting it; only Error() text must stay clean.
	if !strings.Contains(use.Reason, secret) {
		t.Errorf("Reason field = %q, want the verbatim peer reason", use.Reason)
	}
}
