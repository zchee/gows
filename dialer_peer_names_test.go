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
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows"
)

func proxyFromHost(req *http.Request) (*url.URL, error) {
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(req.URL.Hostname(), cmp.Or(req.URL.Port(), "8080"))}, nil
}

// failSecondDial connects to the loopback redirect server, then fails the dial
// to wantAddr without resolving its test hostname.
func failSecondDial(wantAddr string, fail func(string) error) func(context.Context, string, string) (net.Conn, error) {
	first := true
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if first {
			first = false
			if host != "127.0.0.1" && host != "::1" {
				return nil, fmt.Errorf("first dial address = %q, want loopback", addr)
			}
			return new(net.Dialer).DialContext(ctx, network, addr)
		}
		if addr != wantAddr {
			return nil, fmt.Errorf("second dial address = %q, want %q", addr, wantAddr)
		}
		return nil, fail(host)
	}
}

func TestPeerChosenNamesOnlyInNetworkErrors(t *testing.T) {
	marker := strings.ToLower(peerMark)
	host := marker + ".invalid"
	redirect := httptest.NewServer(http.RedirectHandler("http://"+host+"/", http.StatusFound))
	t.Cleanup(redirect.Close)

	cert, _ := generateSelfSignedCert(t, marker+".example")
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		httpClient bool
		tls        bool
		proxy      bool
	}{
		"native redirect DNS error":             {},
		"native redirect through derived proxy": {proxy: true},
		"native TLS certificate name":           {tls: true},
		"HTTPClient TLS certificate name":       {httpClient: true, tls: true},
		"HTTPClient DialContext DNS error":      {httpClient: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d := &gows.Dialer{}
			target := wsURL(redirect, "/")
			if tt.tls {
				// With an IP literal x509 reports missing IP SANs, not the certificate's DNS name.
				target = "wss://" + net.JoinHostPort("localhost", port) + "/"
				if tt.httpClient {
					d.HTTPClient = server.Client()
				} else {
					d.TLSConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				}
			} else {
				addr := host + ":80"
				if tt.proxy {
					d.Proxy = proxyFromHost
					addr = host + ":8080"
				}
				dial := failSecondDial(addr, func(host string) error {
					return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
				})
				if tt.httpClient {
					d.HTTPClient = newHTTPClient(t)
					d.HTTPClient.Transport.(*http.Transport).DialContext = dial
				} else {
					d.CheckRedirect, d.NetDial = followAll, dial
				}
			}
			_, err := dialWithin(t, t.Context(), d, target, 5*time.Second)
			if tt.tls {
				if _, ok := errors.AsType[x509.HostnameError](err); !ok {
					t.Fatalf("Dial err = %v, want x509.HostnameError", err)
				}
			} else if de, ok := errors.AsType[*net.DNSError](err); !ok || de.Name != host || !de.IsNotFound {
				t.Fatalf("Dial err = %v, want *net.DNSError for %s", err, host)
			}
			assertPeerTextOnlyInAllowedLinks(t, err, marker)
		})
	}
}

func TestRedirectHopTextThroughProxy(t *testing.T) {
	marker := strings.ToLower(peerMark)
	host := marker + ".invalid"
	server := httptest.NewServer(http.RedirectHandler("http://"+host+"/", http.StatusFound))
	t.Cleanup(server.Close)
	firstAddr := server.Listener.Addr().String()
	dialFailure := errors.New("test dial failure")

	tests := map[string]struct {
		proxy        func(*http.Request) (*url.URL, error)
		target       string
		secondAddr   string
		cancelBefore bool
	}{
		"no proxy":                             {target: wsURL(server, "/"), secondAddr: host + ":80"},
		"proxy from a fixed address":           {target: "ws://caller.test/", proxy: proxyFor(t, server.URL, nil), secondAddr: firstAddr},
		"proxy derived from the redirect host": {target: wsURL(server, "/"), proxy: proxyFromHost, secondAddr: host + ":8080"},
		"ctx ended before the second hop":      {target: wsURL(server, "/"), secondAddr: host + ":80", cancelBefore: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, redirected := range []bool{false, true} {
				for _, cancelDuring := range []bool{false, true} {
					if tt.cancelBefore && cancelDuring {
						continue
					}
					ctx, cancel := context.WithCancel(t.Context())
					fail := func(string) error {
						if tt.cancelBefore {
							t.Error("NetDial called after context cancellation")
						}
						if cancelDuring {
							cancel()
						}
						return dialFailure
					}
					d := &gows.Dialer{Proxy: tt.proxy, CheckRedirect: followAll}
					label := firstAddr
					if redirected {
						label = "redirect target"
						d.NetDial = failSecondDial(tt.secondAddr, fail)
						if tt.cancelBefore {
							d.CheckRedirect = func(*http.Request, []*http.Request) error { cancel(); return nil }
						}
					} else {
						d.NetDial = func(_ context.Context, _, addr string) (net.Conn, error) { return nil, fail(addr) }
						if tt.cancelBefore {
							cancel()
						}
					}
					_, err := dialWithin(t, ctx, d, tt.target, 5*time.Second)
					cancel()
					if errors.Is(err, context.Canceled) != (tt.cancelBefore || cancelDuring) || errors.Is(err, dialFailure) != !tt.cancelBefore {
						t.Fatalf("redirected=%t cancelDuring=%t: wrong causes in %v", redirected, cancelDuring, err)
					}
					want := "gows: dial " + label + ": "
					if cancelDuring {
						want += ": " // Separator between the two wrapped errors.
					}
					if got := ownText(err); got != want {
						t.Fatalf("ownText = %q, want %q (err: %v)", got, want, err)
					}
					assertNoPeerText(t, err, marker)
				}
			}
		})
	}
}
