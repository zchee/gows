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
	"strconv"
	"strings"
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
			var invalidAddr net.InvalidAddrError
			if !errors.As(err, &invalidAddr) {
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
			var invalidAddr net.InvalidAddrError
			if !errors.As(err, &invalidAddr) {
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
		"success: IPv4 with explicit port":    {rawURL: "wss://127.0.0.1:9443/socket", wantAddr: "127.0.0.1:9443"},
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
