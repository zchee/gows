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

package gows

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/zchee/gows/internal/httpx"
)

func TestParseCompression(t *testing.T) {
	tests := map[string]struct {
		offer, response     []string
		want                CompressionParams
		negotiated, invalid bool
	}{
		"no extensions":                       {},
		"server declined":                     {offer: []string{"permessage-deflate"}},
		"default windows":                     {offer: []string{"permessage-deflate"}, response: []string{"permessage-deflate"}, want: CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}, negotiated: true},
		"different windows and context flags": {offer: []string{"permessage-deflate; server_max_window_bits=12; client_max_window_bits=10"}, response: []string{"permessage-deflate; server_max_window_bits=9; client_max_window_bits=12; server_no_context_takeover"}, want: CompressionParams{ServerMaxWindowBits: 9, ClientMaxWindowBits: 12, ClientContextTakeover: true}, negotiated: true},
		"repeated offer header lines":         {offer: []string{"unsupported", "permessage-deflate; client_max_window_bits"}, response: []string{"permessage-deflate; client_max_window_bits=9"}, want: CompressionParams{ClientMaxWindowBits: 9, ServerContextTakeover: true, ClientContextTakeover: true}, negotiated: true},
		"later compatible choice":             {offer: []string{"permessage-deflate; server_max_window_bits=9, permessage-deflate; server_max_window_bits=12"}, response: []string{"permessage-deflate; server_max_window_bits=10"}, want: CompressionParams{ServerMaxWindowBits: 10, ServerContextTakeover: true, ClientContextTakeover: true}, negotiated: true},
		"quoted window":                       {offer: []string{"permessage-deflate; client_max_window_bits"}, response: []string{"permessage-deflate; client_max_window_bits=\"10\""}, want: CompressionParams{ClientMaxWindowBits: 10, ServerContextTakeover: true, ClientContextTakeover: true}, negotiated: true},
		"unsolicited compression":             {response: []string{"permessage-deflate"}, invalid: true},
		"unsupported response":                {offer: []string{"unsupported"}, response: []string{"unsupported"}, invalid: true},
		"unsupported alongside compression":   {offer: []string{"permessage-deflate"}, response: []string{"permessage-deflate, unsupported"}, invalid: true},
		"duplicate response lines":            {offer: []string{"permessage-deflate"}, response: []string{"permessage-deflate", "permessage-deflate"}, invalid: true},
		"duplicate parameter":                 {offer: []string{"permessage-deflate"}, response: []string{"permessage-deflate; server_no_context_takeover; server_no_context_takeover"}, invalid: true},
		"out of range":                        {offer: []string{"permessage-deflate"}, response: []string{"permessage-deflate; server_max_window_bits=16"}, invalid: true},
		"bare response bits":                  {offer: []string{"permessage-deflate; client_max_window_bits"}, response: []string{"permessage-deflate; client_max_window_bits"}, invalid: true},
		"unoffered client window":             {offer: []string{"permessage-deflate"}, response: []string{"permessage-deflate; client_max_window_bits=10"}, invalid: true},
		"excessive server window":             {offer: []string{"permessage-deflate; server_max_window_bits=9"}, response: []string{"permessage-deflate; server_max_window_bits=10"}, invalid: true},
		"omitted server window":               {offer: []string{"permessage-deflate; server_max_window_bits=9"}, response: []string{"permessage-deflate"}, invalid: true},
		"omitted server no context":           {offer: []string{"permessage-deflate; server_no_context_takeover"}, response: []string{"permessage-deflate"}, invalid: true},
		"invalid offer":                       {offer: []string{"permessage-deflate; unknown"}, response: []string{"permessage-deflate"}, invalid: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, negotiated, err := ParseCompression(tt.offer, tt.response)
			if tt.invalid {
				if !errors.Is(err, ErrInvalidCompressionResponse) || negotiated || got != (CompressionParams{}) {
					t.Fatalf("invalid response: params=%+v negotiated=%v err=%v", got, negotiated, err)
				}
				return
			}
			if err != nil || got != tt.want || negotiated != tt.negotiated {
				t.Fatalf("params=%+v negotiated=%v err=%v; want %+v negotiated=%v", got, negotiated, err, tt.want, tt.negotiated)
			}
		})
	}
}

func TestDialRejectsUnsolicitedExtensions(t *testing.T) {
	tests := map[string]struct {
		enable   bool
		response string
		invalid  bool
	}{
		"compression disabled":         {response: "permessage-deflate", invalid: true},
		"unknown extension":            {response: "unsupported", invalid: true},
		"unknown with compression":     {enable: true, response: "permessage-deflate; server_no_context_takeover; client_no_context_takeover, unsupported", invalid: true},
		"duplicate extension lines":    {enable: true, response: "permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\nSec-WebSocket-Extensions: permessage-deflate", invalid: true},
		"valid negotiated compression": {enable: true, response: "permessage-deflate; server_no_context_takeover; client_no_context_takeover"},
		"declined compression":         {enable: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
			_ = server.SetDeadline(time.Now().Add(30 * time.Second))
			done := make(chan error, 1)
			go func() {
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					done <- err
					return
				}
				accept := httpx.AppendAccept(nil, []byte(req.Header.Get("Sec-WebSocket-Key")))
				header := ""
				if tt.response != "" {
					header = "Sec-WebSocket-Extensions: " + tt.response + "\r\n"
				}
				_, err = fmt.Fprintf(server, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n%s\r\n", accept, header)
				done <- err
			}()
			d := Dialer{EnableCompression: tt.enable, NetDial: func(context.Context, string, string) (net.Conn, error) { return client, nil }}
			conn, hs, err := d.Dial(t.Context(), "ws://example.invalid/")
			if conn != nil {
				_ = conn.Close()
			}
			if serverErr := <-done; serverErr != nil {
				t.Fatalf("response: %v", serverErr)
			}
			if tt.invalid {
				if !errors.Is(err, ErrInvalidCompressionResponse) || conn != nil {
					t.Fatalf("conn=%v handshake=%+v err=%v", conn, hs, err)
				}
			} else if err != nil || hs.Compressed != (tt.response != "") {
				t.Fatalf("handshake=%+v err=%v", hs, err)
			}
		})
	}
}
