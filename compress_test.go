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
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows/internal/extension"
	"github.com/zchee/gows/internal/httpx"
)

// --- negotiation: server side (negotiateDeflate, Upgrade) ------------------

func TestNegotiateDeflate(t *testing.T) {
	tests := map[string]struct {
		extensions           string
		negotiateWindowBits  bool
		allowContextTakeover bool
		wantOK               bool
		want                 extension.DeflateParams
	}{
		"simplest offer": {
			extensions: "permessage-deflate",
			wantOK:     true,
			want:       extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
		},
		"decline sub-15 falls back to next valid offer": {
			extensions: "permessage-deflate; server_max_window_bits=10, permessage-deflate",
			wantOK:     true,
			want:       extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
		},
		"server_max_window_bits=15 explicitly is fine": {
			extensions: "permessage-deflate; server_max_window_bits=15",
			wantOK:     true,
			want:       extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
		},
		"bare client_max_window_bits accepted": {
			extensions: "permessage-deflate; client_max_window_bits",
			wantOK:     true,
			want:       extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
		},
		"valued client_max_window_bits accepted regardless of value": {
			extensions: "permessage-deflate; client_max_window_bits=10",
			wantOK:     true,
			want:       extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
		},
		"duplicate parameter makes that offer invalid, falls back": {
			extensions: "permessage-deflate; server_no_context_takeover; server_no_context_takeover, " +
				"permessage-deflate",
			wantOK: true,
			want:   extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
		},
		"all offers decline sub-15, none fall back": {
			extensions: "permessage-deflate; server_max_window_bits=8",
			wantOK:     false,
		},
		"unrelated extension only": {
			extensions: "permessage-foo",
			wantOK:     false,
		},
		"empty": {
			extensions: "",
			wantOK:     false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := negotiateDeflate([]byte(tt.extensions), deflateNegotiatePolicy{
				negotiateWindowBits:  tt.negotiateWindowBits,
				allowContextTakeover: tt.allowContextTakeover,
			})
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got=%+v)", ok, tt.wantOK, got)
			}
			if ok && got != tt.want {
				t.Fatalf("params = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// --- negotiation: windows-capable backend (SetDeflateBackend) --------------

// fakeWindowedBackend reports capability for the full RFC 7692 window
// range (8-15) so negotiateDeflate's accept/decline/echo logic can be
// exercised, but its NewWriter/NewReader ignore windowBits and always
// compress at the full stdlib compress/flate window: this test only
// exercises negotiation policy (does the handshake accept and correctly
// echo a sub-15 offer), not real window-restricted compression --
// flatekp's own module tests that.
var fakeWindowedBackend = &DeflateBackend{
	Name: "fake-windowed",
	NewWriter: func(level, windowBits int) (DeflateWriter, error) {
		return flate.NewWriter(io.Discard, level)
	},
	NewReader: func(windowBits int) DeflateReader {
		return flate.NewReader(bytes.NewReader(nil)).(DeflateReader)
	},
	MinLevel: flate.HuffmanOnly, MaxLevel: flate.BestCompression,
	MinWindowBits: 8, MaxWindowBits: 15,
}

// withDeflateBackend installs b at level/windowBits for the duration of
// t, restoring whatever was active beforehand once t completes. It must
// not be used from a t.Parallel() test: Go's test runner always finishes
// every non-parallel top-level test (cleanup included) before any
// t.Parallel() test in the same package starts running, which is what
// keeps this process-global mutation from racing the package's other,
// t.Parallel()-marked compression tests.
func withDeflateBackend(t *testing.T, b *DeflateBackend, level, windowBits int) {
	t.Helper()
	prev := activeDeflate.Load()
	if err := SetDeflateBackend(b, level, windowBits); err != nil {
		t.Fatalf("SetDeflateBackend: %v", err)
	}
	t.Cleanup(func() { activeDeflate.Store(prev) })
}

func TestSetDeflateBackendValidation(t *testing.T) {
	tests := map[string]struct {
		backend    *DeflateBackend
		level      int
		windowBits int
		wantErr    bool
	}{
		"valid":                                  {fakeWindowedBackend, 1, 10, false},
		"nil backend":                            {nil, 1, 15, true},
		"level too low":                          {fakeWindowedBackend, flate.HuffmanOnly - 1, 15, true},
		"level too high":                         {fakeWindowedBackend, flate.BestCompression + 1, 15, true},
		"window bits too low":                    {fakeWindowedBackend, 1, 7, true},
		"window bits too high":                   {fakeWindowedBackend, 1, 16, true},
		"stdlib backend, sub-15 window rejected": {defaultDeflateBackend, 1, 10, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			prev := activeDeflate.Load()
			defer activeDeflate.Store(prev)

			err := SetDeflateBackend(tt.backend, tt.level, tt.windowBits)
			if (err != nil) != tt.wantErr {
				t.Fatalf("SetDeflateBackend err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && activeDeflate.Load() != prev {
				t.Fatalf("SetDeflateBackend must leave the previous backend active on error")
			}
		})
	}
}

func TestNegotiateDeflateWindowBits(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, 10)

	tests := map[string]struct {
		extensions          string
		negotiateWindowBits bool
		wantOK              bool
		want                extension.DeflateParams
	}{
		"negotiation off: sub-15 still declined despite capable backend": {
			extensions:          "permessage-deflate; server_max_window_bits=10",
			negotiateWindowBits: false,
			wantOK:              false,
		},
		"negotiation on: offer equal to active bits accepted and echoed": {
			extensions:          "permessage-deflate; server_max_window_bits=10",
			negotiateWindowBits: true,
			wantOK:              true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
				ServerMaxWindowBits: 10,
			},
		},
		"negotiation on: offer above active bits accepted, echoes active bits (less than ceiling)": {
			extensions:          "permessage-deflate; server_max_window_bits=15",
			negotiateWindowBits: true,
			wantOK:              true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
				ServerMaxWindowBits: 10,
			},
		},
		"negotiation on: offer below active bits declined, no fallback": {
			extensions:          "permessage-deflate; server_max_window_bits=8",
			negotiateWindowBits: true,
			wantOK:              false,
		},
		"negotiation on: offer below active bits declined, falls back to next offer": {
			extensions:          "permessage-deflate; server_max_window_bits=8, permessage-deflate",
			negotiateWindowBits: true,
			wantOK:              true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
				ServerMaxWindowBits: 10,
			},
		},
		"negotiation on: no window-bits parameter at all still echoes active bits": {
			extensions:          "permessage-deflate",
			negotiateWindowBits: true,
			wantOK:              true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
				ServerMaxWindowBits: 10,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := negotiateDeflate([]byte(tt.extensions), deflateNegotiatePolicy{
				negotiateWindowBits: tt.negotiateWindowBits,
			})
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got=%+v)", ok, tt.wantOK, got)
			}
			if ok && got != tt.want {
				t.Fatalf("params = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestUpgradeCompressionNegotiationWindowBits drives the full Upgrade()
// handshake with a windows-capable backend active, asserting the wire
// response actually echoes the negotiated server_max_window_bits (RFC
// 7692 §7.1.2.1), not just negotiateDeflate's return value in isolation.
func TestUpgradeCompressionNegotiationWindowBits(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, 10)

	const base = "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=12\r\n" +
		"\r\n"

	sc := &scriptConn{in: []byte(base)}
	u := &Upgrader{EnableCompression: true, NegotiateWindowBits: true}
	hs, err := u.Upgrade(sc)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !hs.Compressed {
		t.Fatalf("Compressed = false, want true")
	}
	resp := sc.out.String()
	const want = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; " +
		"client_no_context_takeover; server_max_window_bits=10\r\n"
	if !strings.Contains(resp, want) {
		t.Errorf("response missing echoed window bits %q: %q", want, resp)
	}
}

func TestUpgradeCompressionNegotiation(t *testing.T) {
	const base = "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n"

	tests := map[string]struct {
		enableServer      bool
		extHeader         string // "" omits the header entirely
		wantCompressed    bool
		wantExtInResponse string // "" means no Sec-WebSocket-Extensions in the response
	}{
		"accept simplest offer": {
			enableServer:      true,
			extHeader:         "permessage-deflate",
			wantCompressed:    true,
			wantExtInResponse: "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
		},
		"non-negotiated peer: client sends no offer": {
			enableServer:   true,
			wantCompressed: false,
		},
		"non-negotiated peer: server has EnableCompression off": {
			enableServer:   false,
			extHeader:      "permessage-deflate",
			wantCompressed: false,
		},
		"decline sub-15 falls back to next offer": {
			enableServer:      true,
			extHeader:         "permessage-deflate; server_max_window_bits=10, permessage-deflate",
			wantCompressed:    true,
			wantExtInResponse: "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
		},
		"bare client_max_window_bits accepted": {
			enableServer:      true,
			extHeader:         "permessage-deflate; client_max_window_bits",
			wantCompressed:    true,
			wantExtInResponse: "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
		},
		"duplicate param makes that offer invalid, falls back": {
			enableServer: true,
			extHeader: "permessage-deflate; server_no_context_takeover; server_no_context_takeover, " +
				"permessage-deflate",
			wantCompressed:    true,
			wantExtInResponse: "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := base
			if tt.extHeader != "" {
				req += "Sec-WebSocket-Extensions: " + tt.extHeader + "\r\n"
			}
			req += "\r\n"

			sc := &scriptConn{in: []byte(req)}
			u := &Upgrader{EnableCompression: tt.enableServer}
			hs, err := u.Upgrade(sc)
			if err != nil {
				t.Fatalf("Upgrade: %v", err)
			}
			if hs.Compressed != tt.wantCompressed {
				t.Errorf("Compressed = %v, want %v", hs.Compressed, tt.wantCompressed)
			}
			resp := sc.out.String()
			if tt.wantExtInResponse == "" {
				if strings.Contains(resp, "Sec-WebSocket-Extensions") {
					t.Errorf("response unexpectedly contains Sec-WebSocket-Extensions: %q", resp)
				}
				return
			}
			if !strings.Contains(resp, "Sec-WebSocket-Extensions: "+tt.wantExtInResponse+"\r\n") {
				t.Errorf("response missing extensions header %q: %q", tt.wantExtInResponse, resp)
			}
		})
	}
}

// --- negotiation: client side (Dial) ----------------------------------------

// readRawHeaderBlockCompress is a local copy of dialer_test.go's identical
// helper (unavailable here: that one lives in the gows_test black-box
// package).
func readRawHeaderBlockCompress(t *testing.T, c net.Conn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var buf []byte
	tmp := make([]byte, 4096)
	for !bytes.Contains(buf, []byte("\r\n\r\n")) {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			t.Fatalf("readRawHeaderBlockCompress: %v", err)
		}
	}
	return buf
}

// acceptFromRawRequest extracts Sec-WebSocket-Key from a raw handshake
// request and computes the matching Sec-WebSocket-Accept value.
func acceptFromRawRequest(t *testing.T, req []byte) string {
	t.Helper()
	sc := httpx.NewHeaderScanner(bytes.SplitAfterN(req, []byte("\r\n"), 2)[1])
	var key []byte
	for sc.Next() {
		if httpx.EqualFold(sc.Key(), "sec-websocket-key") {
			key = sc.Value()
		}
	}
	return string(httpx.AppendAccept(nil, key))
}

func TestDialCompressionNegotiation(t *testing.T) {
	tests := map[string]struct {
		enableClient    bool
		serverExtHeader string // "" omits the header entirely
		wantCompressed  bool
		wantErr         error
	}{
		"server declines by omitting extensions": {
			enableClient: true,
		},
		"server response names unrelated extension only": {
			enableClient:    true,
			serverExtHeader: "x-foo",
		},
		"server accepts": {
			enableClient:    true,
			serverExtHeader: "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
			wantCompressed:  true,
		},
		"server response malformed permessage-deflate": {
			enableClient:    true,
			serverExtHeader: "permessage-deflate; not_a_real_param",
			wantErr:         ErrInvalidCompressionResponse,
		},
		"server response bare client max": {
			enableClient:    true,
			serverExtHeader: "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits",
			wantErr:         ErrInvalidCompressionResponse,
		},
		"server response unsolicited valued client max": {
			enableClient:    true,
			serverExtHeader: "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=15",
			wantErr:         ErrInvalidCompressionResponse,
		},
		"client never offered: EnableCompression off": {
			enableClient:    false,
			serverExtHeader: "permessage-deflate",
			wantCompressed:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			peerClosed := make(chan error, 1)

			go func() {
				req := readRawHeaderBlockCompress(t, serverConn)
				resp := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + acceptFromRawRequest(t, req) + "\r\n"
				if tt.serverExtHeader != "" {
					resp += "Sec-WebSocket-Extensions: " + tt.serverExtHeader + "\r\n"
				}
				resp += "\r\n"
				_, _ = serverConn.Write([]byte(resp))
				if tt.wantErr != nil {
					_ = serverConn.SetReadDeadline(time.Now().Add(3 * time.Second))
					_, err := serverConn.Read(make([]byte, 1))
					peerClosed <- err
				}
			}()

			d := &Dialer{
				EnableCompression: tt.enableClient,
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
				t.Fatalf("Dial: unexpected error %v", err)
			}
			defer conn.Close()
			if hs.Compressed != tt.wantCompressed {
				t.Errorf("Compressed = %v, want %v", hs.Compressed, tt.wantCompressed)
			}
		})
	}
}

// TestDialWindowBitsOffer confirms Dialer.WindowBits controls whether
// (and with what value) the handshake request's Sec-WebSocket-Extensions
// offer includes client_max_window_bits, without needing a windows-
// capable backend at all: offering a restriction on the Dialer's own
// outgoing compression is a request-side concern, independent of
// [SetDeflateBackend].
func TestDialWindowBitsOffer(t *testing.T) {
	tests := map[string]struct {
		windowBits int
		bare       bool
		wantOffer  string
	}{
		"zero value: no window-bits restriction offered": {
			windowBits: 0,
			wantOffer:  "permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n",
		},
		"explicit window bits offered": {
			windowBits: 10,
			wantOffer: "permessage-deflate; server_no_context_takeover; client_no_context_takeover; " +
				"client_max_window_bits=10\r\n",
		},
		"bare window bits offered": {
			bare:      true,
			wantOffer: "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits\r\n",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// WindowBits < 15 requires a backend whose MinWindowBits is at most
			// the offered ceiling; otherwise Dial fails with
			// ErrUnsupportedWindowBits before dialing (deliberate fail-fast).
			if tt.windowBits != 0 && tt.windowBits < deflateWindowBits {
				withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, tt.windowBits)
			}
			serverConn, clientConn := net.Pipe()
			reqCh := make(chan []byte, 1)
			go func() {
				req := readRawHeaderBlockCompress(t, serverConn)
				reqCh <- req
				resp := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: " + acceptFromRawRequest(t, req) + "\r\n\r\n"
				serverConn.Write([]byte(resp))
			}()

			d := &Dialer{
				EnableCompression:        true,
				WindowBits:               tt.windowBits,
				OfferClientMaxWindowBits: tt.bare,
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return clientConn, nil
				},
			}
			conn, _, err := d.Dial(t.Context(), "ws://example.invalid/")
			if err != nil {
				t.Fatalf("Dial: unexpected error %v", err)
			}
			defer conn.Close()

			req := <-reqCh
			wantLine := []byte("Sec-WebSocket-Extensions: " + tt.wantOffer)
			if bytes.Count(req, wantLine) != 1 {
				t.Errorf("request exact offer line count = %d, want 1; line=%q request=%q", bytes.Count(req, wantLine), wantLine, req)
			}
		})
	}
}

// TestDialInvalidWindowBits confirms Dial rejects an out-of-range
// Dialer.WindowBits before dialing anything at all (NetDial must never
// be called).
func TestDialInvalidWindowBits(t *testing.T) {
	tests := map[string]int{
		"too low (below 8)":   7,
		"too high (above 15)": 16,
	}
	for name, windowBits := range tests {
		t.Run(name, func(t *testing.T) {
			d := &Dialer{
				EnableCompression: true,
				WindowBits:        windowBits,
				NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					t.Fatal("NetDial must not be called for an invalid WindowBits")
					return nil, nil
				},
			}
			_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
			if !errors.Is(err, ErrInvalidWindowBits) {
				t.Fatalf("Dial err = %v, want %v", err, ErrInvalidWindowBits)
			}
		})
	}
}

// --- write path: compression threshold --------------------------------------

func TestWriteMessageCompressionThreshold(t *testing.T) {
	tests := map[string]struct {
		size     int
		wantRSV1 bool
	}{
		"511 bytes: below threshold, not compressed": {size: 511, wantRSV1: false},
		"512 bytes: at threshold, compressed":        {size: 512, wantRSV1: true},
		"513 bytes: above threshold, compressed":     {size: 513, wantRSV1: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sc := &scriptConn{}
			c := NewServerConn(sc, WithCompression(true))
			payload := bytes.Repeat([]byte{'z'}, tt.size)
			if err := c.WriteMessage(OpcodeText, payload); err != nil {
				t.Fatalf("WriteMessage: %v", err)
			}
			frames := parseFrames(t, sc.out.Bytes())
			if len(frames) != 1 {
				t.Fatalf("wrote %d frames, want 1", len(frames))
			}
			if got := frames[0].h.Rsv == RSV1; got != tt.wantRSV1 {
				t.Errorf("RSV1 set = %v, want %v", got, tt.wantRSV1)
			}
		})
	}
}

// TestWriteMessageNeverCompressesControlFrames confirms control frames are
// never compressed even when compression is negotiated and the payload
// (impossible in practice, since control frames are capped at 125 bytes,
// but exercised here directly via writeControl) would otherwise qualify.
func TestWriteMessageNeverCompressesControlFrames(t *testing.T) {
	sc := &scriptConn{}
	c := NewServerConn(sc, WithCompression(true))
	if err := c.writeControl(OpcodePing, []byte("ping")); err != nil {
		t.Fatalf("writeControl: %v", err)
	}
	frames := parseFrames(t, sc.out.Bytes())
	if len(frames) != 1 || frames[0].h.Rsv != 0 {
		t.Fatalf("control frame RSV = %#x, want 0", frames[0].h.Rsv)
	}
}

// --- read path: round trips, fragmentation, RFC interop ---------------------

// buildCompressedFrame compresses plain with the package's own
// compressPayload and wraps it in a single client-role (masked) wire frame
// with RSV1 set.
func buildCompressedFrame(t *testing.T, fin bool, op Opcode, plain []byte) []byte {
	t.Helper()
	compressed, err := compressPayload(nil, plain)
	if err != nil {
		t.Fatalf("compressPayload: %v", err)
	}
	return frameBytes(fin, op, RSV1, true, testKey, compressed)
}

func TestCompressionEchoRoundTrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		op Opcode
		p  []byte
	}{
		"text below threshold":                   {OpcodeText, []byte("hi")},
		"text above threshold":                   {OpcodeText, []byte(strings.Repeat("hello world compressible ", 40))},
		"binary above threshold, incompressible": {OpcodeBinary, pseudoRandomBytes(2048)},
		"unicode text above threshold":           {OpcodeText, []byte(strings.Repeat("日本語 mixed ascii ✓ ", 40))},
	}

	run := func(t *testing.T, srvConn, cliConn net.Conn) {
		t.Helper()
		srv := NewServerConn(srvConn, WithCompression(true))
		cli := NewClientConn(cliConn, WithCompression(true))

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Loop until ReadMessage errors (the client's closing Close
			// frame, reported as a *CloseError, ends this the same way
			// conn_io_test.go's runEcho does) so the peer's Close
			// handshake is always answered -- a fixed iteration count
			// would return before the client's Close frame arrives and
			// deadlock cli.Close's net.Pipe write waiting for a reader.
			for {
				op, p, err := srv.ReadMessage()
				if err != nil {
					return
				}
				if err := srv.WriteMessage(op, p); err != nil {
					return
				}
			}
		}()

		for name, tt := range tests {
			if err := cli.WriteMessage(tt.op, tt.p); err != nil {
				t.Fatalf("%s: write: %v", name, err)
			}
			op, got, err := cli.ReadMessage()
			if err != nil {
				t.Fatalf("%s: read: %v", name, err)
			}
			if op != tt.op || !bytes.Equal(got, tt.p) {
				t.Fatalf("%s: echo mismatch: op=%v len(got)=%d len(want)=%d", name, op, len(got), len(tt.p))
			}
		}
		_ = cli.Close(CloseNormalClosure, "bye")
		<-done
	}

	t.Run("pipe", func(t *testing.T) {
		t.Parallel()
		a, b := net.Pipe()
		run(t, a, b)
	})
	t.Run("tcp", func(t *testing.T) {
		t.Parallel()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		ch := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			ch <- c
		}()
		cliConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		srvConn := <-ch
		run(t, srvConn, cliConn)
	})
}

func TestReadMessageFragmentedCompressed(t *testing.T) {
	t.Parallel()

	plain := []byte(strings.Repeat("fragmented compressed message content ", 50))
	compressed, err := compressPayload(nil, plain)
	if err != nil {
		t.Fatalf("compressPayload: %v", err)
	}

	third := len(compressed) / 3
	f1 := frameBytes(false, OpcodeBinary, RSV1, true, testKey, compressed[:third])
	f2 := frameBytes(false, OpcodeContinuation, 0, true, testKey, compressed[third:2*third])
	f3 := frameBytes(true, OpcodeContinuation, 0, true, testKey, compressed[2*third:])
	in := append(append(append([]byte{}, f1...), f2...), f3...)

	c := NewServerConn(&scriptConn{in: in}, WithCompression(true))
	op, got, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if op != OpcodeBinary || !bytes.Equal(got, plain) {
		t.Fatalf("got op=%v len=%d, want OpcodeBinary len=%d", op, len(got), len(plain))
	}
}

// TestDecompressRFC7692HelloExample is an interop-by-construction test: the
// raw octets are RFC 7692 §7.2.3.1's worked example for compressing the
// 5-byte ASCII string "Hello" (verified directly against stdlib
// compress/flate: compressing "Hello" at any level and stripping the
// trailing 4-byte sync-flush marker yields exactly rfc7692HelloFirst's 7
// octets), fed to [Conn.ReadMessage] as hand-built wire frames rather than
// produced by this package's own compressPayload.
func TestDecompressRFC7692HelloExample(t *testing.T) {
	t.Parallel()

	t.Run("single frame", func(t *testing.T) {
		frame := frameBytes(true, OpcodeText, RSV1, true, testKey, rfc7692HelloFirst)
		c := NewServerConn(&scriptConn{in: frame}, WithCompression(true))
		op, p, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if op != OpcodeText || string(p) != "Hello" {
			t.Fatalf("got op=%v payload=%q, want OpcodeText %q", op, p, "Hello")
		}
	})

	t.Run("split across two frames per RFC worked example", func(t *testing.T) {
		// First frame: RSV1 set, FIN=0, opcode=binary, 3 octets.
		first := frameBytes(false, OpcodeBinary, RSV1, true, testKey, rfc7692HelloFirst[:3])
		// Second frame: RSV1 unset, FIN=1, opcode=continuation, 4 octets.
		second := frameBytes(true, OpcodeContinuation, 0, true, testKey, rfc7692HelloFirst[3:])
		in := append(append([]byte{}, first...), second...)

		c := NewServerConn(&scriptConn{in: in}, WithCompression(true))
		op, p, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if op != OpcodeBinary || string(p) != "Hello" {
			t.Fatalf("got op=%v payload=%q, want OpcodeBinary %q", op, p, "Hello")
		}
	})
}

// --- RSV1 validation table ---------------------------------------------------

func TestReadMessageRSV1Violations(t *testing.T) {
	t.Parallel()

	validCompressed, err := compressPayload(nil, []byte("payload"))
	if err != nil {
		t.Fatalf("compressPayload: %v", err)
	}

	tests := map[string]struct {
		compression bool
		frame       []byte
		wantErr     bool
	}{
		"RSV1 without negotiation": {
			compression: false,
			frame:       frameBytes(true, OpcodeBinary, RSV1, true, testKey, validCompressed),
			wantErr:     true,
		},
		"RSV1 on control frame (Ping)": {
			compression: true,
			frame:       frameBytes(true, OpcodePing, RSV1, true, testKey, []byte("ping")),
			wantErr:     true,
		},
		"RSV1 on continuation frame": {
			compression: true,
			frame: append(
				frameBytes(false, OpcodeBinary, RSV1, true, testKey, validCompressed[:2]),
				frameBytes(true, OpcodeContinuation, RSV1, true, testKey, validCompressed[2:])...,
			),
			wantErr: true,
		},
		"RSV2 set alone": {
			compression: true,
			frame:       frameBytes(true, OpcodeBinary, RSV2, true, testKey, []byte("hi")),
			wantErr:     true,
		},
		"RSV1 and RSV2 together": {
			compression: true,
			frame:       frameBytes(true, OpcodeBinary, RSV1|RSV2, true, testKey, validCompressed),
			wantErr:     true,
		},
		"RSV1 on first frame when negotiated is legal": {
			compression: true,
			frame:       frameBytes(true, OpcodeBinary, RSV1, true, testKey, validCompressed),
			wantErr:     false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := NewServerConn(&scriptConn{in: tt.frame}, WithCompression(tt.compression))
			_, _, err := c.ReadMessage()
			if tt.wantErr {
				var ce *CloseError
				if !errors.As(err, &ce) || ce.Code != CloseProtocolError {
					t.Fatalf("ReadMessage error = %v, want CloseError{Code: CloseProtocolError}", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadMessage: unexpected error %v", err)
			}
		})
	}
}

// --- decompression bomb defense ---------------------------------------------

func TestReadMessageDecompressionBomb(t *testing.T) {
	t.Parallel()

	huge := bytes.Repeat([]byte{'A'}, 200_000)
	frame := buildCompressedFrame(t, true, OpcodeBinary, huge)

	c := NewServerConn(&scriptConn{in: frame}, WithCompression(true), WithReadLimit(1024))
	_, _, err := c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseMessageTooBig {
		t.Fatalf("ReadMessage error = %v, want CloseError{Code: CloseMessageTooBig}", err)
	}
}

// --- UTF-8 validation runs post-inflate --------------------------------------

func TestReadMessageInvalidUTF8PostInflate(t *testing.T) {
	t.Parallel()

	// A lone continuation byte (0x80) is invalid UTF-8 on its own. Sending
	// it compressed proves the violation is only caught after
	// decompression (RFC 6455 §8.1), not mistaken for compressed-bytes
	// garbage or silently skipped because the wire bytes are not UTF-8.
	invalid := []byte("valid text ending in a lone continuation byte: \x80")
	frame := buildCompressedFrame(t, true, OpcodeText, invalid)

	c := NewServerConn(&scriptConn{in: frame}, WithCompression(true))
	_, _, err := c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseInvalidFramePayloadData {
		t.Fatalf("ReadMessage error = %v, want CloseError{Code: CloseInvalidFramePayloadData}", err)
	}
}

// --- pooled writer/reader reuse: no cross-message state leak ----------------

// TestCompressionPooledReuseNoStateLeak round-trips many distinct messages
// across several independent connection pairs concurrently, forcing the
// shared deflateWriterPool/deflateReaderPool to interleave across
// connections and messages. If Reset ever failed to establish a fresh,
// empty window per message (no-context-takeover), a pooled writer/reader
// reused between messages of different content would corrupt output.
func TestCompressionPooledReuseNoStateLeak(t *testing.T) {
	t.Parallel()

	run := func(payloads [][]byte) error {
		srvConn, cliConn := net.Pipe()
		srv := NewServerConn(srvConn, WithCompression(true))
		cli := NewClientConn(cliConn, WithCompression(true))

		done := make(chan struct{})
		go func() {
			defer close(done)
			// See the identical comment in TestCompressionEchoRoundTrip:
			// loop until error (the client's Close frame), not a fixed
			// count, or cli.Close's net.Pipe write deadlocks waiting for
			// a reader that already exited.
			for {
				op, p, err := srv.ReadMessage()
				if err != nil {
					return
				}
				if err := srv.WriteMessage(op, p); err != nil {
					return
				}
			}
		}()

		var retErr error
		for i, p := range payloads {
			if err := cli.WriteMessage(OpcodeBinary, p); err != nil {
				retErr = fmt.Errorf("write %d: %w", i, err)
				break
			}
			_, got, err := cli.ReadMessage()
			if err != nil {
				retErr = fmt.Errorf("read %d: %w", i, err)
				break
			}
			if !bytes.Equal(got, p) {
				retErr = fmt.Errorf("round trip %d mismatch: got %d bytes, want %d bytes", i, len(got), len(p))
				break
			}
		}
		_ = cli.Close(CloseNormalClosure, "")
		<-done
		return retErr
	}

	const numConns = 4
	errs := make(chan error, numConns)
	for i := range numConns {
		go func(i int) {
			payloads := make([][]byte, 20)
			for j := range payloads {
				payloads[j] = bytes.Repeat([]byte{byte('A' + i), byte('a' + j%26)}, 300)
			}
			errs <- run(payloads)
		}(i)
	}
	for range numConns {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

// pseudoRandomBytes returns n deterministic, effectively-incompressible
// bytes (xorshift32), avoiding both a math/rand import and any dependence
// on real entropy for a reproducible test fixture.
func pseudoRandomBytes(n int) []byte {
	b := make([]byte, n)
	x := uint32(0x2545f491)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

// --- compression benchmarks (compare against BenchmarkConnReadMessage /
// BenchmarkConnWriteMessage in conn_io_test.go, which measure the
// compression-off hot path) ---------------------------------------------

func BenchmarkConnReadMessageCompressed(b *testing.B) {
	payload := bytes.Repeat([]byte("compressible benchmark payload "), 32) // 1024 bytes
	compressed, err := compressPayload(nil, payload)
	if err != nil {
		b.Fatalf("compressPayload: %v", err)
	}
	frame := frameBytes(true, OpcodeBinary, RSV1, true, testKey, compressed)
	c := NewServerConn(&loopConn{frame: frame}, WithCompression(true))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := c.ReadMessage(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnWriteMessageCompressed(b *testing.B) {
	c := NewServerConn(&loopConn{frame: []byte{0x00}}, WithCompression(true))
	payload := bytes.Repeat([]byte("compressible benchmark payload "), 32) // 1024 bytes
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// --- client_max_window_bits emission (Upgrader.ClientWindowBits) ----------

// TestNegotiateDeflateClientWindowBits exercises negotiateDeflate's
// client_max_window_bits emission policy: emit only when the offer
// included the parameter and ClientWindowBits is set; min with a valued
// offer; never emit above a valued offer; never emit when the offer
// lacks the parameter; never use a valued offer as a dict-size hint when
// ClientWindowBits is zero.
func TestNegotiateDeflateClientWindowBits(t *testing.T) {
	tests := map[string]struct {
		extensions       string
		clientWindowBits int
		wantOK           bool
		want             extension.DeflateParams
	}{
		"success: bare offer emits ClientWindowBits": {
			extensions:       "permessage-deflate; client_max_window_bits",
			clientWindowBits: 10,
			wantOK:           true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
				ClientMaxWindowBits: 10,
			},
		},
		"success: valued offer below ClientWindowBits uses min": {
			extensions:       "permessage-deflate; client_max_window_bits=8",
			clientWindowBits: 10,
			wantOK:           true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
				ClientMaxWindowBits: 8,
			},
		},
		"success: valued offer above ClientWindowBits uses ClientWindowBits": {
			extensions:       "permessage-deflate; client_max_window_bits=12",
			clientWindowBits: 10,
			wantOK:           true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
				ClientMaxWindowBits: 10,
			},
		},
		"success: offer without param emits nothing despite ClientWindowBits": {
			extensions:       "permessage-deflate",
			clientWindowBits: 10,
			wantOK:           true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
			},
		},
		"success: ClientWindowBits zero leaves valued offer unused (hint deliberately unused)": {
			extensions:       "permessage-deflate; client_max_window_bits=10",
			clientWindowBits: 0,
			wantOK:           true,
			want: extension.DeflateParams{
				ServerNoContextTakeover: true, ClientNoContextTakeover: true,
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := negotiateDeflate([]byte(tt.extensions), deflateNegotiatePolicy{
				clientWindowBits: tt.clientWindowBits,
			})
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got=%+v)", ok, tt.wantOK, got)
			}
			if ok && got != tt.want {
				t.Fatalf("params = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestUpgradeClientWindowBits drives full Upgrade handshakes asserting
// wire emission of client_max_window_bits and Handshake.CompressionParams
// population, plus fail-fast for out-of-range ClientWindowBits.
func TestUpgradeClientWindowBits(t *testing.T) {
	const base = "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n"

	tests := map[string]struct {
		clientWindowBits int
		extHeader        string
		wantExt          string // substring of response Extensions header, "" = absent
		wantClientBits   int
		wantErr          error
	}{
		"success: bare offer emits 10": {
			clientWindowBits: 10,
			extHeader:        "permessage-deflate; client_max_window_bits",
			wantExt:          "client_max_window_bits=10",
			wantClientBits:   10,
		},
		"success: valued offer 8 min rule": {
			clientWindowBits: 10,
			extHeader:        "permessage-deflate; client_max_window_bits=8",
			wantExt:          "client_max_window_bits=8",
			wantClientBits:   8,
		},
		"success: valued offer 12 capped at 10": {
			clientWindowBits: 10,
			extHeader:        "permessage-deflate; client_max_window_bits=12",
			wantExt:          "client_max_window_bits=10",
			wantClientBits:   10,
		},
		"success: offer without param emits nothing": {
			clientWindowBits: 10,
			extHeader:        "permessage-deflate",
			wantExt:          "",
			wantClientBits:   0,
		},
		"success: ClientWindowBits zero ignores valued offer": {
			clientWindowBits: 0,
			extHeader:        "permessage-deflate; client_max_window_bits=10",
			wantExt:          "",
			wantClientBits:   0,
		},
		"error: ClientWindowBits too low": {
			clientWindowBits: 7,
			wantErr:          ErrInvalidWindowBits,
		},
		"error: ClientWindowBits too high": {
			clientWindowBits: 16,
			wantErr:          ErrInvalidWindowBits,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			u := &Upgrader{EnableCompression: true, ClientWindowBits: tt.clientWindowBits}
			if tt.wantErr != nil {
				sc := &scriptConn{in: []byte(base + "\r\n")}
				_, err := u.Upgrade(sc)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Upgrade err = %v, want %v", err, tt.wantErr)
				}
				if sc.pos != 0 {
					t.Fatalf("Upgrade consumed %d bytes of the conn before failing; want 0 (config bug before read)", sc.pos)
				}
				return
			}
			req := base + "Sec-WebSocket-Extensions: " + tt.extHeader + "\r\n\r\n"
			sc := &scriptConn{in: []byte(req)}
			hs, err := u.Upgrade(sc)
			if err != nil {
				t.Fatalf("Upgrade: %v", err)
			}
			if !hs.Compressed {
				t.Fatalf("Compressed = false, want true")
			}
			if hs.CompressionParams.ClientMaxWindowBits != tt.wantClientBits {
				t.Fatalf("ClientMaxWindowBits = %d, want %d", hs.CompressionParams.ClientMaxWindowBits, tt.wantClientBits)
			}
			resp := sc.out.String()
			if tt.wantExt == "" {
				if strings.Contains(resp, "client_max_window_bits") {
					t.Fatalf("response unexpectedly contains client_max_window_bits: %q", resp)
				}
			} else if !strings.Contains(resp, tt.wantExt) {
				t.Fatalf("response missing %q: %q", tt.wantExt, resp)
			}
		})
	}
}

func TestUpgradeTrustedClientWindowBitsHint(t *testing.T) {
	const base = "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n"
	tests := map[string]struct {
		trust, takeover bool
		clientBits      int
		ext             string
		wantWire        int
		wantHint        int
		wantIncoming    int
		wantDict        bool
	}{
		"opt out valued":            {ext: "permessage-deflate; client_max_window_bits=9", takeover: true, wantIncoming: 15, wantDict: true},
		"trusted valued":            {trust: true, ext: "permessage-deflate; client_max_window_bits=9", takeover: true, wantHint: 9, wantIncoming: 9, wantDict: true},
		"trusted bare":              {trust: true, ext: "permessage-deflate; client_max_window_bits", takeover: true, wantIncoming: 15, wantDict: true},
		"trusted absent":            {trust: true, ext: "permessage-deflate", takeover: true, wantIncoming: 15, wantDict: true},
		"emitted wins":              {trust: true, ext: "permessage-deflate; client_max_window_bits=9", takeover: true, clientBits: 8, wantWire: 8, wantIncoming: 8, wantDict: true},
		"no takeover no allocation": {trust: true, ext: "permessage-deflate; client_max_window_bits=9", wantHint: 9},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := base + "Sec-WebSocket-Extensions: " + tt.ext + "\r\n\r\n"
			sc := &scriptConn{in: []byte(req)}
			u := &Upgrader{EnableCompression: true, AllowContextTakeover: tt.takeover, ClientWindowBits: tt.clientBits, TrustClientWindowBitsHint: tt.trust}
			hs, err := u.Upgrade(sc)
			if err != nil {
				t.Fatalf("Upgrade: %v", err)
			}
			if hs.CompressionParams.ClientMaxWindowBits != tt.wantWire || hs.CompressionParams.ClientMaxWindowBitsHint != tt.wantHint {
				t.Fatalf("params wire/hint = %d/%d, want %d/%d", hs.CompressionParams.ClientMaxWindowBits, hs.CompressionParams.ClientMaxWindowBitsHint, tt.wantWire, tt.wantHint)
			}
			if tt.wantWire == 0 && strings.Contains(sc.out.String(), "client_max_window_bits=") {
				t.Fatalf("trusted hint changed response bytes: %q", sc.out.String())
			}
			c := NewServerConn(&scriptConn{}, WithCompressionParams(hs.CompressionParams))
			if !tt.wantDict {
				if c.deflate != nil {
					t.Fatalf("deflate = %+v, want nil", c.deflate)
				}
				return
			}
			if c.deflate == nil || c.deflate.incomingDict == nil || c.deflate.incomingWindowBits != tt.wantIncoming || cap(c.deflate.incomingDict) != 1<<tt.wantIncoming {
				t.Fatalf("incoming state = %+v, want bits/cap %d/%d", c.deflate, tt.wantIncoming, 1<<tt.wantIncoming)
			}
		})
	}
}

func TestUpgradeResponseBytesFrozen(t *testing.T) {
	const base = "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
	const prefix = "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
	for name, tt := range map[string]struct {
		u    Upgrader
		ext  string
		want string
	}{
		"zero default": {want: prefix + "\r\n"},
		"trusted valued hint no echo": {
			u:    Upgrader{EnableCompression: true, TrustClientWindowBitsHint: true},
			ext:  "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=9\r\n",
			want: prefix + "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n\r\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			sc := &scriptConn{in: []byte(base + tt.ext + "\r\n")}
			if _, err := tt.u.Upgrade(sc); err != nil {
				t.Fatalf("Upgrade: %v", err)
			}
			if got := sc.out.String(); got != tt.want {
				t.Fatalf("raw response mismatch\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestUpgradeServerMaxWindowBitsPopulatesParams confirms that when the
// response echoes server_max_window_bits, Handshake.CompressionParams
// carries it (plumbing added with the window-bits fields).
func TestUpgradeServerMaxWindowBitsPopulatesParams(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, 10)
	const req = "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=12\r\n" +
		"\r\n"
	sc := &scriptConn{in: []byte(req)}
	u := &Upgrader{EnableCompression: true, NegotiateWindowBits: true}
	hs, err := u.Upgrade(sc)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if hs.CompressionParams.ServerMaxWindowBits != 10 {
		t.Fatalf("ServerMaxWindowBits = %d, want 10 (active bits echoed)", hs.CompressionParams.ServerMaxWindowBits)
	}
}

// TestDialClientMaxWindowBitsMinOfOfferAndResponse confirms that with a
// capable backend, WindowBits=10 plus a server response of
// client_max_window_bits=9 yields CompressionParams.ClientMaxWindowBits==9
// (min of offer and response).
func TestDialClientMaxWindowBitsMinOfOfferAndResponse(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, 15)

	serverConn, clientConn := net.Pipe()
	go func() {
		req := readRawHeaderBlockCompress(t, serverConn)
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptFromRawRequest(t, req) + "\r\n" +
			"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; " +
			"client_no_context_takeover; client_max_window_bits=9\r\n\r\n"
		serverConn.Write([]byte(resp))
	}()

	d := &Dialer{
		EnableCompression: true,
		WindowBits:        10,
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientConn, nil
		},
	}
	conn, hs, err := d.Dial(t.Context(), "ws://example.invalid/")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if hs.CompressionParams.ClientMaxWindowBits != 9 {
		t.Fatalf("ClientMaxWindowBits = %d, want 9 (min of offer 10 and response 9)", hs.CompressionParams.ClientMaxWindowBits)
	}
}

// --- Context takeover --------------------------------------------------------

// --- RFC 7692 §7.2.3 context-takeover worked example -----------------------
//
// Verbatim from RFC 7692 §7.2.3.1/§7.2.3.2 (verified directly against the
// RFC text, not from memory): compressing "Hello" once yields
// 0xf2 0x48 0xcd 0xc9 0xc9 0x07 0x00 regardless of context takeover; a
// second, identical "Hello" compresses to the much shorter
// 0xf2 0x00 0x11 0x00 0x00 (referencing the first message's history in the
// LZ77 sliding window) only when context takeover is in effect for that
// direction, and to the identical 7-byte form again otherwise.
var (
	rfc7692HelloFirst           = []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}
	rfc7692HelloSecondTakeover  = []byte{0xf2, 0x00, 0x11, 0x00, 0x00}
	rfc7692HelloSecondNoContext = []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}
)

// TestContextTakeoverRFC7692DecodeExample is a decode-interop test using
// the RFC's own worked bytes verbatim (compress.go's own compressor is
// not involved at all here -- see TestContextTakeoverCompressorShrinksRepeatedMessage
// below for that, using gows's own compressor's output instead, since a
// different DEFLATE encoder is not required to reproduce another
// implementation's exact compressed bytes for the same input, only to
// decode correctly). It confirms gows's decompressor, using
// [CompressionParams]-driven context takeover, decodes the RFC's second,
// shorter "Hello" using the sliding window built from the first, and
// that without context takeover the repeated (non-shortened) form
// decodes correctly too.
func TestContextTakeoverRFC7692DecodeExample(t *testing.T) {
	t.Parallel()

	t.Run("with context takeover: shorter second message decodes via the sliding window", func(t *testing.T) {
		t.Parallel()
		// Server role, ClientContextTakeover: incoming (the peer/client's
		// outgoing) direction uses context takeover -- see newDeflateState's
		// direction mapping.
		c := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ClientContextTakeover: true}))

		got1, err := c.decompressMessage(rfc7692HelloFirst)
		if err != nil {
			t.Fatalf("decompressMessage(first): %v", err)
		}
		if string(got1) != "Hello" {
			t.Fatalf("first = %q, want %q", got1, "Hello")
		}

		got2, err := c.decompressMessage(rfc7692HelloSecondTakeover)
		if err != nil {
			t.Fatalf("decompressMessage(second, with takeover): %v", err)
		}
		if string(got2) != "Hello" {
			t.Fatalf("second = %q, want %q", got2, "Hello")
		}
	})

	t.Run("without context takeover: repeated (non-shortened) message decodes independently", func(t *testing.T) {
		t.Parallel()
		c := NewServerConn(&scriptConn{}, WithCompression(true))

		got1, err := c.decompressMessage(rfc7692HelloFirst)
		if err != nil {
			t.Fatalf("decompressMessage(first): %v", err)
		}
		if string(got1) != "Hello" {
			t.Fatalf("first = %q, want %q", got1, "Hello")
		}

		got2, err := c.decompressMessage(rfc7692HelloSecondNoContext)
		if err != nil {
			t.Fatalf("decompressMessage(second, no context): %v", err)
		}
		if string(got2) != "Hello" {
			t.Fatalf("second = %q, want %q", got2, "Hello")
		}
	})
}

// TestContextTakeoverCompressorShrinksRepeatedMessage exercises gows's
// own compressor (not the RFC's literal bytes) to confirm the qualitative
// claim the RFC's example illustrates: compressing the same short message
// twice in a row produces a strictly shorter second encoding with context
// takeover, and an identical-length second encoding without it. The
// payload and level are chosen for where stdlib compress/flate can
// exhibit the effect at all, across every supported toolchain: level 1
// finds no match for a short message even within a single call (verified
// directly on Go 1.26: it emits a raw stored block for "Hello"
// regardless of history), so this uses level 6 -- and Go 1.27's
// rewritten flate gives levels 1-6 per-level fast encoders whose Flush
// with fewer than 128 pending bytes takes a small-size path
// (deflateFast in deflate.go) that emits the chunk as a stored or
// Huffman-only block and resets the fast encoder's window history, so a
// sub-128-byte message can never carry a cross-message back-reference
// there. The payload therefore stays comfortably above 128 bytes,
// which also matches production reality: [Conn.WriteMessage] never
// compresses a payload under defaultCompressMinSize (512) in the first
// place. Level 6 with this payload is empirically confirmed to shrink
// on go1.26.5, go1.27rc2, and tip.
func TestContextTakeoverCompressorShrinksRepeatedMessage(t *testing.T) {
	withDeflateBackend(t, DefaultDeflateBackend(), 6, deflateWindowBits)

	payload := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 5))

	t.Run("with context takeover", func(t *testing.T) {
		srv := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
		first, _, err := srv.compressMessage(nil, payload)
		if err != nil {
			t.Fatalf("compressMessage(first): %v", err)
		}
		second, _, err := srv.compressMessage(nil, payload)
		if err != nil {
			t.Fatalf("compressMessage(second): %v", err)
		}
		if len(second) >= len(first) {
			t.Fatalf("second compressed length %d, want < first %d bytes (context takeover should shrink a repeated message, per RFC 7692 §7.2.3.2)",
				len(second), len(first))
		}

		// Round-trip both through a matching context-takeover decompressor.
		cli := NewClientConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
		if got, err := cli.decompressMessage(first); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("decompress(first) = %d bytes, %v, want %d bytes, nil", len(got), err, len(payload))
		}
		if got, err := cli.decompressMessage(second); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("decompress(second) = %d bytes, %v, want %d bytes, nil", len(got), err, len(payload))
		}
	})

	t.Run("without context takeover", func(t *testing.T) {
		srv := NewServerConn(&scriptConn{}, WithCompression(true))
		first, _, err := srv.compressMessage(nil, payload)
		if err != nil {
			t.Fatalf("compressMessage(first): %v", err)
		}
		second, _, err := srv.compressMessage(nil, payload)
		if err != nil {
			t.Fatalf("compressMessage(second): %v", err)
		}
		if len(first) != len(second) {
			t.Fatalf("compressed lengths differ (%d vs %d) without context takeover; a fresh window each time should compress identically", len(first), len(second))
		}
	})
}

// --- cross-message window continuity, both directions ----------------------

// runContextTakeoverEchoLoop mirrors flatekp_test.go's identical helper
// (unavailable here in a different module): answers every message srv
// receives with an identical echo until ReadMessage errors, so the
// eventual cli.Close's Close frame is always drained rather than
// deadlocking net.Pipe's unbuffered Write.
func runContextTakeoverEchoLoop(srv *Conn) (done chan struct{}) {
	done = make(chan struct{})
	go func() {
		defer close(done)
		for {
			op, p, err := srv.ReadMessage()
			if err != nil {
				return
			}
			if err := srv.WriteMessage(op, p); err != nil {
				return
			}
		}
	}()
	return done
}

// TestContextTakeoverWindowContinuityBothDirections drives a full,
// negotiated-shape handshake pair (built directly via CompressionParams,
// not through Upgrader/Dialer -- see TestUpgraderDialerContextTakeoverIntegration
// for the negotiation-to-Conn pipeline) with context takeover enabled for
// BOTH directions, sends the same repeated-content message several times
// each way, and confirms: (a) every echo round-trips correctly, and (b)
// each direction's *wire* frame payload strictly shrinks after the first
// occurrence -- proof the LZ77 window is actually carrying over between
// messages, not just that decompression happens to still work.
func TestContextTakeoverWindowContinuityBothDirections(t *testing.T) {
	t.Parallel()

	srvConn, cliConn := net.Pipe()
	params := CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}
	srv := NewServerConn(srvConn, WithCompressionParams(params))
	cli := NewClientConn(cliConn, WithCompressionParams(params))
	done := runContextTakeoverEchoLoop(srv)

	payload := []byte(strings.Repeat("context takeover window continuity payload ", 20))
	const rounds = 4
	for range rounds {
		if err := cli.WriteMessage(OpcodeBinary, payload); err != nil {
			t.Fatalf("client WriteMessage: %v", err)
		}
		_, got, err := cli.ReadMessage()
		if err != nil {
			t.Fatalf("client ReadMessage: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
		}
	}
	_ = cli.Close(CloseNormalClosure, "bye")
	<-done

	// Wire-level shrink check, both directions: compress the same payload
	// directly through each role's own persistent compressor (mirroring
	// what the loop above just did on the wire) and confirm messages 2-4
	// are each no larger than message 1, with at least one strictly
	// smaller -- the only direct evidence the window is really shared
	// across calls rather than the echo merely happening to still be
	// correct.
	tests := map[string]struct {
		newConn func(net.Conn, ...ConnOption) *Conn
		params  CompressionParams
	}{
		"server's own outgoing direction": {NewServerConn, CompressionParams{ServerContextTakeover: true}},
		"client's own outgoing direction": {NewClientConn, CompressionParams{ClientContextTakeover: true}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := tt.newConn(&scriptConn{}, WithCompressionParams(tt.params))
			sizes := make([]int, rounds)
			for i := range rounds {
				out, _, err := c.compressMessage(nil, payload)
				if err != nil {
					t.Fatalf("compressMessage[%d]: %v", i, err)
				}
				sizes[i] = len(out)
			}
			shrank := false
			for i := 1; i < rounds; i++ {
				if sizes[i] > sizes[0] {
					t.Fatalf("message %d compressed to %d bytes, larger than message 1's %d", i, sizes[i], sizes[0])
				}
				if sizes[i] < sizes[0] {
					shrank = true
				}
			}
			if !shrank {
				t.Fatalf("no message after the first was strictly smaller than the first (sizes=%v); context takeover should shrink a repeated payload", sizes)
			}
		})
	}
}

// --- mixed negotiation: all 4 per-direction combinations --------------------

// TestNegotiateDeflateContextTakeoverAllCombinations confirms
// negotiateDeflate, with AllowContextTakeover on, independently derives
// each direction's agreed context-takeover state purely from what a
// given offer contains -- covering all 4 combinations named in the task
// ("server accepts client's ctx-takeover but keeps its own no-ctx and
// vice versa").
func TestNegotiateDeflateContextTakeoverAllCombinations(t *testing.T) {
	tests := map[string]struct {
		extensions string
		want       extension.DeflateParams
	}{
		"both context takeover: offer has neither no-context-takeover flag": {
			extensions: "permessage-deflate",
			want:       extension.DeflateParams{},
		},
		"server no-ctx, client ctx: offer requires server_no_context_takeover only": {
			extensions: "permessage-deflate; server_no_context_takeover",
			want:       extension.DeflateParams{ServerNoContextTakeover: true},
		},
		"server ctx, client no-ctx: offer hints client_no_context_takeover only": {
			extensions: "permessage-deflate; client_no_context_takeover",
			want:       extension.DeflateParams{ClientNoContextTakeover: true},
		},
		"both no-ctx: offer requires both flags (== today's default outcome)": {
			extensions: "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
			want:       extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := negotiateDeflate([]byte(tt.extensions), deflateNegotiatePolicy{
				allowContextTakeover: true,
			})
			if !ok {
				t.Fatalf("negotiateDeflate: ok = false, want true")
			}
			if got != tt.want {
				t.Fatalf("params = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestNegotiateDeflateContextTakeoverOff confirms AllowContextTakeover's
// zero value (false) preserves this package's original behavior exactly,
// even for an offer that would otherwise allow context takeover on both
// directions.
func TestNegotiateDeflateContextTakeoverOff(t *testing.T) {
	got, ok := negotiateDeflate([]byte("permessage-deflate"), deflateNegotiatePolicy{})
	if !ok {
		t.Fatalf("negotiateDeflate: ok = false, want true")
	}
	want := extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true}
	if got != want {
		t.Fatalf("params = %+v, want %+v (AllowContextTakeover off must force no-context-takeover)", got, want)
	}
}

// --- interop: context-takeover Conn <-> no-context-takeover Conn -----------

// TestContextTakeoverInteropWithNoContextPeer confirms a context-takeover
// Conn on one side and a no-context-takeover Conn on the other -- each
// correctly reflecting what was actually negotiated for its own
// direction, which real negotiation always ensures the two peers agree
// on, but this test constructs directly to isolate the wire-compatibility
// claim -- still echo correctly: RFC 7692's RSV1/frame-level wire format
// is identical either way, only whether the *sender's* window resets
// between messages differs, and that is purely a sender-side/receiver-side
// pairing concern already covered by TestContextTakeoverWindowContinuityBothDirections.
// Here, the server uses context takeover for its own (outgoing) direction
// while the client -- correctly reflecting that same negotiated
// direction -- decompresses with context takeover too; the reverse
// (client to server) direction in this same pair uses no-context-takeover
// on both ends, exercising the mixed-negotiation shape end-to-end.
func TestContextTakeoverInteropWithNoContextPeer(t *testing.T) {
	t.Parallel()

	srvConn, cliConn := net.Pipe()
	// Server's own outgoing direction (ServerContextTakeover) uses context
	// takeover; client's own outgoing direction does not (ClientContextTakeover
	// left false on both ends) -- an asymmetric, but valid, negotiated shape.
	srvParams := CompressionParams{ServerContextTakeover: true}
	cliParams := CompressionParams{ServerContextTakeover: true} // client's *incoming* direction must match.
	srv := NewServerConn(srvConn, WithCompressionParams(srvParams))
	cli := NewClientConn(cliConn, WithCompressionParams(cliParams))
	done := runContextTakeoverEchoLoop(srv)

	payload := []byte(strings.Repeat("mixed direction interop payload ", 20))
	for range 3 {
		if err := cli.WriteMessage(OpcodeText, payload); err != nil {
			t.Fatalf("client WriteMessage: %v", err)
		}
		_, got, err := cli.ReadMessage()
		if err != nil {
			t.Fatalf("client ReadMessage: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
		}
	}
	_ = cli.Close(CloseNormalClosure, "")
	<-done
}

// --- teardown releases state -------------------------------------------

// TestContextTakeoverTeardownReleasesState confirms Close drops c.deflate
// (and, transitively, its persistent compressor and dictionary) rather
// than leaving it referencing memory the Conn no longer needs --
// deflateState values are never pooled (see deflateState's doc: they are
// owned solely by one Conn), so dropping the reference is the entire
// cleanup contract.
func TestContextTakeoverTeardownReleasesState(t *testing.T) {
	t.Parallel()

	srvConn, cliConn := net.Pipe()
	params := CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}
	srv := NewServerConn(srvConn, WithCompressionParams(params))
	cli := NewClientConn(cliConn, WithCompressionParams(params))

	if srv.deflate == nil || srv.deflate.outgoing == nil || srv.deflate.incomingDict == nil {
		t.Fatalf("srv.deflate not fully populated before Close: %+v", srv.deflate)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		cli.ReadMessage() // drains the server's Close frame so srv.Close doesn't block.
	}()
	if err := srv.Close(CloseNormalClosure, ""); err != nil {
		t.Fatalf("srv.Close: %v", err)
	}
	<-done

	if srv.deflate != nil {
		t.Fatalf("srv.deflate = %+v, want nil after Close", srv.deflate)
	}
}

// --- backend pinning: SetDeflateBackend after construction is a no-op for a live Conn --

// TestContextTakeoverBackendPinning confirms a context-takeover Conn's
// persistent compressor, once built, is unaffected by a later
// SetDeflateBackend call -- the agreed decision from this package's T2
// report: a Conn using persistent compressor state pins its backend at
// construction time.
func TestContextTakeoverBackendPinning(t *testing.T) {
	withDeflateBackend(t, DefaultDeflateBackend(), 6, deflateWindowBits)

	c := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
	outgoingBefore := c.deflate.outgoing

	// Install a different backend/level process-wide after construction.
	if err := SetDeflateBackend(fakeWindowedBackend, 1, 10); err != nil {
		t.Fatalf("SetDeflateBackend: %v", err)
	}

	if c.deflate.outgoing != outgoingBefore {
		t.Fatalf("c.deflate.outgoing changed identity after a later SetDeflateBackend call; a context-takeover Conn must pin its backend at construction")
	}

	// The Conn must keep working correctly (still the original backend's
	// behavior, e.g. outgoingWindowBits pinned at construction time), not
	// the newly active one.
	if c.deflate.outgoingWindowBits != deflateWindowBits {
		t.Fatalf("c.deflate.outgoingWindowBits = %d, want %d (pinned at construction)", c.deflate.outgoingWindowBits, deflateWindowBits)
	}
	if _, _, err := c.compressMessage(nil, []byte("still usable after SetDeflateBackend")); err != nil {
		t.Fatalf("compressMessage after SetDeflateBackend: %v", err)
	}
}

// --- regression: incoming dict must not be bound by the outgoing window ---

// TestContextTakeoverIncomingDictNotBoundToOutgoingWindowBits is a
// regression test for a reviewer-caught bug: an earlier revision capped
// the incoming context-takeover sliding dict at 1<<outgoingWindowBits --
// the process-wide *outgoing* compressor's window (from
// [SetDeflateBackend]) -- even though gows negotiates no bound at all on
// what window the *peer* actually compresses with (neither
// negotiateDeflate nor Dialer.deflateOffer ever emits
// client_max_window_bits/server_max_window_bits to restrict the peer's
// own compressor; see [deflateState]'s doc). A fully RFC-7692-compliant
// peer using the full 32KB default window can legitimately emit a
// cross-message back-reference the wrongly truncated dict can no longer
// resolve, corrupting decode ("flate: corrupt input") for an innocent,
// conformant peer.
//
// This is deliberately reproduced with a real, independent
// compress/flate.Writer standing in for "the peer" -- not gows's own
// compressMessage -- since the whole point is that the peer is not, and
// was never meant to be, bound by this process's own backend/windowBits.
func TestContextTakeoverIncomingDictNotBoundToOutgoingWindowBits(t *testing.T) {
	// Our own outgoing window: 1KB (2^10) -- deliberately small, and
	// deliberately irrelevant to the peer's own (unbounded) window. Before
	// the fix, this value alone determined the incoming dict's capacity,
	// which is the bug.
	withDeflateBackend(t, fakeWindowedBackend, 1, 10)

	var buf bytes.Buffer
	peer, err := flate.NewWriter(&buf, 6)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	compressMsg := func(p string) []byte {
		buf.Reset()
		if _, err := peer.Write([]byte(p)); err != nil {
			t.Fatalf("peer Write: %v", err)
		}
		if err := peer.Flush(); err != nil {
			t.Fatalf("peer Flush: %v", err)
		}
		out := buf.Bytes()
		out = out[:len(out)-len(deflateFlushTail)] // Strip the 4-byte sync-flush marker, matching wire framing.
		// Copy out of buf's backing array: the next compressMsg call
		// Resets and reuses the same array, which would otherwise
		// overwrite this result before it's used (buf.Bytes() aliases,
		// it does not copy).
		return append([]byte(nil), out...)
	}

	const sharedBlock = "CROSS-MESSAGE-BACK-REFERENCE-PROBE-1234567890-"
	// message1 puts sharedBlock at its very start, followed by >1KB of
	// filler, so message2's back-reference into it lands at a distance
	// comfortably past a 1KB cap but well within the real 32KB window.
	message1 := sharedBlock + strings.Repeat("filler-", 300)
	message2 := sharedBlock
	if len(message1) <= 1<<10 {
		t.Fatalf("test setup bug: message1 (%d bytes) must exceed 1KB for this regression to be meaningful", len(message1))
	}

	compressed1 := compressMsg(message1)
	compressed2 := compressMsg(message2)

	c := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ClientContextTakeover: true}))
	got1, err := c.decompressMessage(compressed1)
	if err != nil {
		t.Fatalf("decompressMessage(message1): %v", err)
	}
	if string(got1) != message1 {
		t.Fatalf("message1 mismatch: got %d bytes, want %d", len(got1), len(message1))
	}

	got2, err := c.decompressMessage(compressed2)
	if err != nil {
		t.Fatalf("decompressMessage(message2): %v -- a small process-wide outgoing windowBits must not truncate the incoming sliding dict", err)
	}
	if string(got2) != message2 {
		t.Fatalf("message2 mismatch: got %q, want %q", got2, message2)
	}
}

// TestTrustedClientWindowBitsHintRejectsLargerConformingHistory documents
// the opt-in risk: with no binding response parameter, the same full-window
// peer stream is RFC-conforming and succeeds by default, but may fail when
// the server trusts a smaller offer-side hint.
func TestTrustedClientWindowBitsHintRejectsLargerConformingHistory(t *testing.T) {
	var buf bytes.Buffer
	peer, err := flate.NewWriter(&buf, 6)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	compressMsg := func(p string) []byte {
		buf.Reset()
		if _, err := peer.Write([]byte(p)); err != nil {
			t.Fatalf("peer Write: %v", err)
		}
		if err := peer.Flush(); err != nil {
			t.Fatalf("peer Flush: %v", err)
		}
		out := buf.Bytes()
		return append([]byte(nil), out[:len(out)-len(deflateFlushTail)]...)
	}
	const probe = "TRUSTED-HINT-DISTANCE-PROBE-1234567890-"
	first := probe + strings.Repeat("independent-filler-", 180)
	// Go 1.27's rewritten flate emits a Flush with fewer than 128 pending
	// bytes as a stored/Huffman-only block with no match search at levels
	// 1-6 (and resets the fast encoder's history), so the second message
	// must reach that threshold for the peer encoder to emit the far
	// cross-message back-reference this test is about. The padding shares
	// nothing with first, so the probe's far reference stays the only
	// cross-message match available; verified to be emitted on go1.26.5,
	// go1.27rc2, and tip.
	second := probe + strings.Repeat("=", 128)
	if len(first) <= 1<<10 {
		t.Fatalf("setup: first message %d must exceed hinted 1KB", len(first))
	}
	c1, c2 := compressMsg(first), compressMsg(second)

	decode := func(hint int) error {
		c := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{
			ClientContextTakeover:   true,
			ClientMaxWindowBitsHint: hint,
		}))
		if got, err := c.decompressMessage(c1); err != nil || string(got) != first {
			t.Fatalf("first decode hint=%d: len=%d err=%v", hint, len(got), err)
		}
		got, err := c.decompressMessage(c2)
		if err == nil && string(got) != second {
			t.Fatalf("second decode hint=%d: got %d bytes, want %d", hint, len(got), len(second))
		}
		return err
	}
	if err := decode(0); err != nil {
		t.Fatalf("default 32KB dictionary rejected conforming stream: %v", err)
	}
	if err := decode(10); err == nil {
		t.Fatal("trusted 1KB hint unexpectedly accepted a >1KB back-reference")
	}
}

// --- zero-value regression: WithCompressionParams's zero value ------------

// TestCompressionParamsZeroValueMatchesWithCompression confirms the zero
// [CompressionParams] value behaves identically to [WithCompression](true)
// alone: no per-Conn deflateState at all.
func TestCompressionParamsZeroValueMatchesWithCompression(t *testing.T) {
	c := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{}))
	if c.deflate != nil {
		t.Fatalf("c.deflate = %+v, want nil for the zero CompressionParams value", c.deflate)
	}
	if !c.compression {
		t.Fatalf("c.compression = false, want true (WithCompressionParams must still enable compression)")
	}
}

// --- decompression bomb defense still applies under context takeover ------

// TestContextTakeoverDecompressionBombStillBounded confirms c.readLimit
// still bounds decompressed output size when the incoming direction uses
// context takeover -- decompressMessage's dict handling is additive to
// the existing bomb-defense loop, not a replacement for it.
func TestContextTakeoverDecompressionBombStillBounded(t *testing.T) {
	t.Parallel()

	huge := bytes.Repeat([]byte{'A'}, 200_000)
	// Compress via a context-takeover-shaped compressor so the wire bytes
	// are representative, then feed them to a matching context-takeover
	// decompressor with a small read limit.
	srv := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
	compressed, _, err := srv.compressMessage(nil, huge)
	if err != nil {
		t.Fatalf("compressMessage: %v", err)
	}

	frame := frameBytes(true, OpcodeBinary, RSV1, true, testKey, compressed)
	c := NewServerConn(&scriptConn{in: frame}, WithCompressionParams(CompressionParams{ClientContextTakeover: true}), WithReadLimit(1024))
	_, _, err = c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseMessageTooBig {
		t.Fatalf("ReadMessage error = %v, want CloseError{Code: CloseMessageTooBig}", err)
	}
}

// --- full negotiation-to-Conn pipeline: Upgrader/Dialer AllowContextTakeover --

// TestUpgraderDialerContextTakeoverIntegration drives a real handshake
// (Upgrader.Upgrade / Dialer.Dial, not CompressionParams constructed
// directly) with AllowContextTakeover set on both sides, confirms both
// ends' Handshake.CompressionParams agree, and confirms Conns built from
// those handshakes via WithCompressionParams actually exchange messages
// correctly -- exercising the whole pipeline named in the task
// (negotiation -> Handshake -> WithCompressionParams -> live Conn), not
// just its individual pieces in isolation.
func TestUpgraderDialerContextTakeoverIntegration(t *testing.T) {
	t.Parallel()

	srvConn, cliConn := net.Pipe()
	serverErr := make(chan error, 1)
	serverHS := make(chan Handshake, 1)
	go func() {
		u := &Upgrader{EnableCompression: true, AllowContextTakeover: true}
		hs, err := u.Upgrade(srvConn)
		serverErr <- err
		serverHS <- hs
	}()

	d := &Dialer{
		EnableCompression:    true,
		AllowContextTakeover: true,
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cliConn, nil
		},
	}
	conn, clientHS, err := d.Dial(t.Context(), "ws://example.invalid/")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	serverHandshake := <-serverHS

	if !serverHandshake.Compressed || !clientHS.Compressed {
		t.Fatalf("Compressed = server:%v client:%v, want both true", serverHandshake.Compressed, clientHS.Compressed)
	}
	wantParams := CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}
	if serverHandshake.CompressionParams != wantParams {
		t.Fatalf("server CompressionParams = %+v, want %+v", serverHandshake.CompressionParams, wantParams)
	}
	if clientHS.CompressionParams != wantParams {
		t.Fatalf("client CompressionParams = %+v, want %+v", clientHS.CompressionParams, wantParams)
	}

	srv := NewServerConn(srvConn, WithCompressionParams(serverHandshake.CompressionParams))
	cli := NewClientConn(conn, WithCompressionParams(clientHS.CompressionParams))
	done := runContextTakeoverEchoLoop(srv)

	payload := []byte(strings.Repeat("full negotiation pipeline payload ", 20))
	for range 3 {
		if err := cli.WriteMessage(OpcodeBinary, payload); err != nil {
			t.Fatalf("client WriteMessage: %v", err)
		}
		_, got, err := cli.ReadMessage()
		if err != nil {
			t.Fatalf("client ReadMessage: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
		}
	}
	_ = cli.Close(CloseNormalClosure, "")
	<-done
}

// --- per-direction window bits plumbing ------------------------------------

// TestContextTakeoverIncomingDictUsesNegotiatedClientMaxWindowBits confirms
// a server-role Conn with negotiated ClientMaxWindowBits=9 allocates
// incomingDict with capacity 1<<9 rather than the RFC default 32KB.
func TestContextTakeoverIncomingDictUsesNegotiatedClientMaxWindowBits(t *testing.T) {
	c := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{
		ClientContextTakeover: true,
		ClientMaxWindowBits:   9,
	}))
	if c.deflate == nil || c.deflate.incomingDict == nil {
		t.Fatalf("deflate/incomingDict = nil, want allocated")
	}
	want := 1 << 9
	if cap(c.deflate.incomingDict) != want {
		t.Fatalf("cap(incomingDict) = %d, want %d", cap(c.deflate.incomingDict), want)
	}
	if c.deflate.incomingWindowBits != 9 {
		t.Fatalf("incomingWindowBits = %d, want 9", c.deflate.incomingWindowBits)
	}
}

func TestClientMaxWindowBitsHintPrecedenceAndRole(t *testing.T) {
	tests := []struct {
		name   string
		client bool
		params CompressionParams
		want   int
	}{
		{"server valid hint", false, CompressionParams{ClientContextTakeover: true, ClientMaxWindowBitsHint: 9}, 9},
		{"server emitted wins", false, CompressionParams{ClientContextTakeover: true, ClientMaxWindowBits: 10, ClientMaxWindowBitsHint: 9}, 10},
		{"server invalid low absent", false, CompressionParams{ClientContextTakeover: true, ClientMaxWindowBitsHint: 7}, 15},
		{"server invalid high absent", false, CompressionParams{ClientContextTakeover: true, ClientMaxWindowBitsHint: 16}, 15},
		{"client ignores hint", true, CompressionParams{ServerContextTakeover: true, ClientMaxWindowBitsHint: 9}, 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c *Conn
			if tt.client {
				c = NewClientConn(&scriptConn{}, WithCompressionParams(tt.params))
			} else {
				c = NewServerConn(&scriptConn{}, WithCompressionParams(tt.params))
			}
			if c.deflate == nil || c.deflate.incomingWindowBits != tt.want || cap(c.deflate.incomingDict) != 1<<tt.want {
				t.Fatalf("deflate = %+v, want incoming bits %d", c.deflate, tt.want)
			}
		})
	}
}

// TestSubCeilingOutgoingNoTakeover confirms a negotiated outgoing ceiling
// below the process-global windowBits allocates a per-Conn writer with
// outgoingTakeover=false, resets the window per message (identical
// compressed lengths for identical payloads), and decodes correctly.
func TestSubCeilingOutgoingNoTakeover(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, 6, 15)

	params := CompressionParams{ClientMaxWindowBits: 9}
	cli := NewClientConn(&scriptConn{}, WithCompressionParams(params))
	if cli.deflate == nil {
		t.Fatalf("deflate = nil, want allocated for sub-ceiling")
	}
	if cli.deflate.outgoingTakeover {
		t.Fatalf("outgoingTakeover = true, want false for no-takeover sub-ceiling")
	}
	if cli.deflate.outgoing == nil {
		t.Fatalf("outgoing = nil, want per-Conn sub-ceiling writer")
	}
	if cli.outgoingWindowCeil != 9 {
		t.Fatalf("outgoingWindowCeil = %d, want 9", cli.outgoingWindowCeil)
	}

	payload := []byte("HelloHelloHello")
	first, _, err := cli.compressMessage(nil, payload)
	if err != nil {
		t.Fatalf("compressMessage(first): %v", err)
	}
	second, _, err := cli.compressMessage(nil, payload)
	if err != nil {
		t.Fatalf("compressMessage(second): %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("compressed lengths differ (%d vs %d); sub-ceiling no-takeover must Reset per message", len(first), len(second))
	}

	// Peer is a server with matching client_max_window_bits=9 for its incoming.
	srv := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ClientMaxWindowBits: 9}))
	for i, msg := range [][]byte{first, second} {
		got, err := srv.decompressMessage(msg)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("decompress[%d] = %q, %v, want %q, nil", i, got, err, payload)
		}
	}
}

// TestSubCeilingOutgoingWithTakeover confirms a sub-ceiling writer with
// context takeover preserves the window: the second identical message
// compresses strictly shorter.
func TestSubCeilingOutgoingWithTakeover(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, 6, 15)

	params := CompressionParams{ClientContextTakeover: true, ClientMaxWindowBits: 9}
	cli := NewClientConn(&scriptConn{}, WithCompressionParams(params))
	if cli.deflate == nil || !cli.deflate.outgoingTakeover || cli.deflate.outgoing == nil {
		t.Fatalf("want takeover sub-ceiling writer, got deflate=%+v", cli.deflate)
	}

	// >=128 bytes: see TestContextTakeoverCompressorShrinksRepeatedMessage's
	// doc for the Go 1.27 fast-encoder small-flush regime this must clear.
	payload := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 5))
	first, _, err := cli.compressMessage(nil, payload)
	if err != nil {
		t.Fatalf("compressMessage(first): %v", err)
	}
	second, _, err := cli.compressMessage(nil, payload)
	if err != nil {
		t.Fatalf("compressMessage(second): %v", err)
	}
	if len(second) >= len(first) {
		t.Fatalf("second compressed length %d, want < first %d (takeover at sub-ceiling)", len(second), len(first))
	}
}

// TestOutgoingDisabledOnBackendRace forces a construction-time race:
// negotiate a ceiling of 9 under a capable backend, then swap to stdlib
// (MinWindowBits=15) before Conn construction so outgoingDisabled is set.
// Messages go out uncompressed (RSV1 clear); incoming compressed still
// decodes.
func TestOutgoingDisabledOnBackendRace(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, 9)

	params := CompressionParams{ServerMaxWindowBits: 9, ServerContextTakeover: true}
	// Race: swap to stdlib after "negotiation" (params already fixed).
	if err := SetDeflateBackend(DefaultDeflateBackend(), defaultDeflateLevel, deflateWindowBits); err != nil {
		t.Fatalf("SetDeflateBackend(stdlib): %v", err)
	}

	sc := &scriptConn{}
	// Server role so the wire frame is unmasked and easy to inspect.
	c := NewServerConn(sc, WithCompressionParams(params))
	if c.deflate == nil || !c.deflate.outgoingDisabled {
		t.Fatalf("want outgoingDisabled=true after race, got deflate=%+v", c.deflate)
	}
	if c.deflate.outgoing != nil {
		t.Fatalf("outgoing must be nil when outgoingDisabled")
	}

	payload := bytes.Repeat([]byte{'x'}, defaultCompressMinSize)
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	h, n, err := DecodeHeader(sc.out.Bytes())
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.Rsv&RSV1 != 0 {
		t.Fatalf("RSV1 set on wire, want clear (uncompressed fallback)")
	}
	if !bytes.Equal(sc.out.Bytes()[n:], payload) {
		t.Fatalf("plain payload mismatch")
	}

	// Incoming still works with context takeover under stdlib.
	// (Re-install a usable backend for decompression pool; stdlib is fine.)
	srv := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{
		ClientContextTakeover: true,
		ClientMaxWindowBits:   9,
	}))
	// Server's incoming is independent of its own outgoingDisabled.
	if srv.deflate == nil || srv.deflate.incomingDict == nil {
		t.Fatalf("server incomingDict nil")
	}
	// Compress with a peer stand-in (stdlib full window) and decode.
	peerCompressed, err := compressPayload(nil, []byte("peer-hello"))
	if err != nil {
		t.Fatalf("compressPayload: %v", err)
	}
	got, err := srv.decompressMessage(peerCompressed)
	if err != nil || string(got) != "peer-hello" {
		t.Fatalf("decompress = %q, %v", got, err)
	}
}

// TestPerEmissionCeilingGuard confirms a pooled-path Conn with ceiling 9
// under a small backend compresses, then after SetDeflateBackend to
// stdlib (windowBits 15) a WriteMessage goes out uncompressed, and
// swapping back resumes compression.
func TestPerEmissionCeilingGuard(t *testing.T) {
	withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, 9)

	// Pooled path: no takeover, ceiling 9, process windowBits also 9 →
	// needSubCeilWriter is false (outCeil == cfg.windowBits), so deflate
	// is nil and the pooled path + per-emission guard applies.
	params := CompressionParams{ServerMaxWindowBits: 9}
	sc := &scriptConn{}
	// Server role so wire frames are unmasked for RSV1 inspection.
	c := NewServerConn(sc, WithCompressionParams(params))
	if c.deflate != nil {
		t.Fatalf("deflate = %+v, want nil (pooled path: ceiling equals active bits)", c.deflate)
	}
	if c.outgoingWindowCeil != 9 {
		t.Fatalf("outgoingWindowCeil = %d, want 9", c.outgoingWindowCeil)
	}

	payload := bytes.Repeat([]byte{'y'}, defaultCompressMinSize)
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage (small backend): %v", err)
	}
	h, _, err := DecodeHeader(sc.out.Bytes())
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.Rsv&RSV1 == 0 {
		t.Fatalf("want RSV1 set under small backend")
	}

	// Swap to stdlib (windowBits 15 > ceiling 9) → per-emission guard.
	sc.out.Reset()
	if err := SetDeflateBackend(DefaultDeflateBackend(), defaultDeflateLevel, deflateWindowBits); err != nil {
		t.Fatalf("SetDeflateBackend(stdlib): %v", err)
	}
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage (stdlib): %v", err)
	}
	h, _, err = DecodeHeader(sc.out.Bytes())
	if err != nil {
		t.Fatalf("DecodeHeader after swap: %v", err)
	}
	if h.Rsv&RSV1 != 0 {
		t.Fatalf("RSV1 set after stdlib swap, want clear (per-emission guard)")
	}

	// Swap back → compression resumes.
	sc.out.Reset()
	if err := SetDeflateBackend(fakeWindowedBackend, defaultDeflateLevel, 9); err != nil {
		t.Fatalf("SetDeflateBackend(fake): %v", err)
	}
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage (fake again): %v", err)
	}
	h, _, err = DecodeHeader(sc.out.Bytes())
	if err != nil {
		t.Fatalf("DecodeHeader after restore: %v", err)
	}
	if h.Rsv&RSV1 == 0 {
		t.Fatalf("want RSV1 set after restoring small backend")
	}
}

// failOnceConn is a net.Conn whose Write fails once after writing n bytes
// of the first Write, then succeeds for subsequent Writes. Used to
// exercise outgoingDisabled on takeover emit failure.
type failOnceConn struct {
	scriptConn
	failAfter int
	failed    bool
}

func (f *failOnceConn) Write(p []byte) (int, error) {
	if !f.failed {
		f.failed = true
		n := min(f.failAfter, len(p))
		if n > 0 {
			f.out.Write(p[:n])
		}
		return n, errors.New("simulated write failure")
	}
	return f.scriptConn.Write(p)
}

// TestOutgoingDisabledOnTakeoverEmitFailure confirms that a failed
// WriteMessage on a context-takeover Conn sets outgoingDisabled, so a
// subsequent WriteMessage over a healthy conn goes out uncompressed.
func TestOutgoingDisabledOnTakeoverEmitFailure(t *testing.T) {
	withDeflateBackend(t, DefaultDeflateBackend(), 6, deflateWindowBits)

	fc := &failOnceConn{failAfter: 2} // fail mid-frame after a couple of header bytes
	c := NewServerConn(fc, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
	payload := bytes.Repeat([]byte{'z'}, defaultCompressMinSize)
	err := c.WriteMessage(OpcodeBinary, payload)
	if err == nil {
		t.Fatalf("WriteMessage: want error from failOnceConn")
	}
	if c.deflate == nil || !c.deflate.outgoingDisabled {
		t.Fatalf("want outgoingDisabled after emit failure, got deflate=%+v", c.deflate)
	}

	// Subsequent write over the now-healthy path must go uncompressed.
	fc.out.Reset()
	if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
		t.Fatalf("WriteMessage after disable: %v", err)
	}
	h, n, err := DecodeHeader(fc.out.Bytes())
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.Rsv&RSV1 != 0 {
		t.Fatalf("RSV1 set after outgoingDisabled, want clear")
	}
	if !bytes.Equal(fc.out.Bytes()[n:], payload) {
		t.Fatalf("payload mismatch after outgoingDisabled")
	}
}
