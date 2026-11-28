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
	"compress/flate"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/zchee/gows"
)

func TestDialDeliversPipelinedFrame(t *testing.T) {
	for name, configure := range dialPaths {
		t.Run(name, func(t *testing.T) {
			srv := startRawServer(t, func(req []byte) string { return upgradeResponse(t, req) + "\x81\x02hi" })
			var d gows.Dialer
			configure(t, &d)
			dial := d.Dial
			if d.HTTPClient == nil {
				dial = gows.Dial
			}
			c, hs, err := dial(t.Context(), srv.url)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()
			if hs.Buffered != nil {
				t.Fatalf("Dial returned Buffered = %x, want nil", hs.Buffered)
			}
			if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			op, p, err := c.ReadMessage()
			if err != nil || op != gows.OpcodeText || string(p) != "hi" {
				t.Fatalf("first frame = (%v, %q, %v), want text hi", op, p, err)
			}
		})
	}
}

// dialFramePeer keeps the upgraded server transport available for wire checks.
func dialFramePeer(t *testing.T, d *gows.Dialer, u *gows.Upgrader, opts ...gows.ConnOption) (*gows.Conn, net.Conn) {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	srv := startHTTPUpgradeServer(t, false, u, func(nc net.Conn, _ gows.Handshake) {
		accepted <- nc
		<-done
	})
	t.Cleanup(func() { close(done) })
	c, _, err := d.Dial(t.Context(), wsURL(srv.Server, "/"), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	nc := <-accepted
	deadline := time.Now().Add(5 * time.Second)
	if err := nc.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return c, nc
}

func inflateDialFrame(payload, dict []byte) ([]byte, error) {
	// Restore the omitted sync flush and terminate the stream for ReadAll.
	r := flate.NewReaderDict(io.MultiReader(bytes.NewReader(payload), bytes.NewReader([]byte{0, 0, 0xff, 0xff, 1, 0, 0, 0xff, 0xff})), dict)
	defer r.Close()
	return io.ReadAll(r)
}

func TestDialNegotiatedFactsWin(t *testing.T) {
	opts := make([]gows.ConnOption, 5, 8)
	opts[0] = gows.WithHandshake(gows.Handshake{})
	opts[1] = gows.WithCompressionParams(gows.CompressionParams{})
	opts[2] = gows.WithCompression(false)
	opts[3] = gows.WithBuffered([]byte("\x81\x04junk"))
	opts[4] = gows.WithReadLimit(4096)
	opts[:6][5] = gows.WithBuffered([]byte("\x81\x08sentinel"))

	t.Run("concurrent dials", func(t *testing.T) {
		for name, configure := range dialPaths {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				d := gows.Dialer{EnableCompression: true, AllowContextTakeover: true}
				configure(t, &d)
				c, raw := dialFramePeer(t, &d, &gows.Upgrader{EnableCompression: true, AllowContextTakeover: true}, opts...)
				peer := gows.NewServerConn(raw, gows.WithCompression(true))
				msg := bytes.Repeat([]byte("use the previous message's dictionary; "), 40)
				var dict []byte
				for i := range 2 {
					if err := c.WriteMessage(gows.OpcodeBinary, msg); err != nil {
						t.Fatal(err)
					}
					f, err := peer.ReadFrame()
					if err != nil || f.Header.Rsv != gows.RSV1 || f.Header.Opcode != gows.OpcodeBinary {
						t.Fatalf("client frame %d: header=%+v err=%v", i, f.Header, err)
					}
					if i == 1 {
						if _, err := inflateDialFrame(f.Payload, nil); err == nil {
							t.Fatal("second frame inflated without the first message's dictionary")
						}
					}
					plain, err := inflateDialFrame(f.Payload, dict)
					if err != nil || !bytes.Equal(plain, msg) {
						t.Fatalf("inflate client frame %d: got %d bytes, err=%v", i, len(plain), err)
					}
					dict = plain
					// Echo the captured compressed bytes, not a freshly compressed message:
					// the client must resolve the same cross-message reference on its read side.
					h := gows.Header{Fin: true, Rsv: gows.RSV1, Opcode: gows.OpcodeBinary, Length: int64(len(f.Payload))}
					if _, err := raw.Write(append(gows.AppendHeader(nil, h), f.Payload...)); err != nil {
						t.Fatal(err)
					}
					op, got, err := c.ReadMessage()
					if err != nil || op != gows.OpcodeBinary || !bytes.Equal(got, msg) {
						t.Fatalf("ReadMessage %d: op=%v len=%d err=%v", i, op, len(got), err)
					}
				}
				if err := peer.WriteFrame(gows.OpcodeBinary, true, make([]byte, 5000), false); err != nil {
					t.Fatal(err)
				}
				_, _, err := c.ReadMessage()
				if ce, ok := errors.AsType[*gows.CloseError](err); !ok || !ce.Sent || ce.Code != gows.CloseMessageTooBig {
					t.Fatalf("5000-byte message: got %v, want sent Close 1009", err)
				}
			})
		}
	})
	probe := gows.NewClientConn(&fakeConn{readBuf: []byte("\x81\x00")}, opts[:6][5])
	defer probe.CloseNow()
	if _, p, err := probe.ReadMessage(); err != nil || string(p) != "sentinel" {
		t.Fatalf("option in spare capacity was overwritten: payload=%q err=%v", p, err)
	}
}

func TestDialDeclinedCompression(t *testing.T) {
	for name, configure := range dialPaths {
		t.Run(name, func(t *testing.T) {
			d := gows.Dialer{EnableCompression: true}
			configure(t, &d)
			c, raw := dialFramePeer(t, &d, &gows.Upgrader{}, gows.WithCompression(true))
			peer := gows.NewServerConn(raw)
			msg := bytes.Repeat([]byte("x"), 4096)
			if err := c.WriteMessage(gows.OpcodeText, msg); err != nil {
				t.Fatal(err)
			}
			f, err := peer.ReadFrame()
			if err != nil || f.Header.Rsv != 0 || f.Header.Opcode != gows.OpcodeText || !bytes.Equal(f.Payload, msg) {
				t.Fatalf("wire frame: header=%+v len=%d err=%v; want uncompressed text", f.Header, len(f.Payload), err)
			}
		})
	}
}

func TestDialContextAfterSuccess(t *testing.T) {
	for name, configure := range dialPaths {
		t.Run(name, func(t *testing.T) {
			srv := startHTTPUpgradeServer(t, false, &gows.Upgrader{}, echoServe)
			var d gows.Dialer
			configure(t, &d)
			ctx, cancel := context.WithCancel(t.Context())
			c, _, err := d.Dial(ctx, wsURL(srv.Server, "/"))
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()
			if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			roundTrip(t, c, "after cancellation")
		})
	}
}

func TestDialFailureBuildsNoConn(t *testing.T) {
	for name, configure := range dialPaths {
		t.Run(name, func(t *testing.T) {
			srv := startRawServer(t, func([]byte) string { return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n" })
			var d gows.Dialer
			configure(t, &d)
			c, _, err := d.Dial(t.Context(), srv.url)
			if c != nil {
				_ = c.CloseNow()
				t.Fatal("refusal returned a Conn")
			}
			if status, ok := errors.AsType[*gows.UnexpectedStatusError](err); !ok || status.StatusCode != http.StatusForbidden {
				t.Fatalf("Dial error = %v, want UnexpectedStatusError for 403", err)
			}
			if d.HTTPClient == nil {
				select {
				case err := <-srv.closed:
					if !errors.Is(err, io.EOF) {
						t.Fatalf("server read after refusal = %v, want EOF", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("server did not observe EOF after refusal")
				}
			}
		})
	}
}

func TestDialHandshakeMetadata(t *testing.T) {
	for name, configure := range dialPaths {
		t.Run(name, func(t *testing.T) {
			addr, _ := startHopServer(t, nil, func(_ int, req []byte) string {
				return upgradeResponseWith(t, req, "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=12; client_max_window_bits=15\r\n")
			})
			d := gows.Dialer{Subprotocols: []string{"chat"}, EnableCompression: true, AllowContextTakeover: true, WindowBits: 15, ServerWindowBits: 12}
			configure(t, &d)
			url := "ws://" + addr
			nc, low, err := d.DialNetConn(t.Context(), url)
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			c, hs, err := d.Dial(t.Context(), url)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()
			want := gows.CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true, ServerMaxWindowBits: 12, ClientMaxWindowBits: 15}
			if hs.Subprotocol != "chat" || !hs.Compressed || hs.CompressionParams != want {
				t.Fatalf("Dial metadata: protocol=%q compressed=%t params=%+v", hs.Subprotocol, hs.Compressed, hs.CompressionParams)
			}
			if hs.Subprotocol != low.Subprotocol || hs.Compressed != low.Compressed || hs.CompressionParams != low.CompressionParams {
				t.Fatalf("Dial metadata differs from DialNetConn: high=%+v low=%+v", hs, low)
			}
		})
	}
}
