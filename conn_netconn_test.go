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
	"net"
	"net/http"
	"net/http/httptrace"
	"testing"

	"github.com/zchee/gows"
)

func TestConnNetConn(t *testing.T) {
	tests := map[string]struct{ useTLS bool }{
		"native ws":  {},
		"native wss": {useTLS: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			srv := startHTTPUpgradeServer(t, tt.useTLS, &gows.Upgrader{}, echoServe)
			var raw net.Conn
			d := gows.Dialer{NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
				raw = conn
				return conn, err
			}}
			if tt.useTLS {
				d.TLSConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
			}
			c, _, err := d.Dial(t.Context(), wsURL(srv.Server, "/"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()
			got := c.NetConn()
			if tt.useTLS {
				tc, ok := got.(*tls.Conn)
				if !ok {
					t.Fatalf("NetConn() = %T, want *tls.Conn", got)
				}
				if !tc.ConnectionState().HandshakeComplete {
					t.Fatal("NetConn() returned a TLS connection without a completed handshake")
				}
				got = tc.NetConn()
			}
			if raw == nil || got != raw {
				t.Fatal("transport does not use the connection returned by NetDial")
			}
		})
	}

	t.Run("HTTPClient", func(t *testing.T) {
		srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, echoServe)
		traced := make(chan net.Conn, 1)
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { traced <- info.Conn },
		})
		d := gows.Dialer{HTTPClient: newHTTPClient(t)}
		c, _, err := d.Dial(ctx, wsURL(srv.Server, "/"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.CloseNow()
		select {
		case raw := <-traced:
			transport := c.NetConn()
			if transport == raw {
				t.Fatal("NetConn() exposed the traced socket instead of the HTTP upgrade body wrapper")
			}
			if got, want := transport.RemoteAddr(), raw.RemoteAddr(); got.Network() != want.Network() || got.String() != want.String() {
				t.Errorf("RemoteAddr() = %v, want traced peer %v", got, want)
			}
		default:
			t.Fatal("HTTP transport did not report a connection to the trace")
		}
	})
}
