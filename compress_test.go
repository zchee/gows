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
			got, ok := negotiateDeflate([]byte(tt.extensions), tt.negotiateWindowBits, tt.allowContextTakeover, 0)
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
			got, ok := negotiateDeflate([]byte(tt.extensions), tt.negotiateWindowBits, false, 0)
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
// trailing 4-byte sync-flush marker yields exactly these 7 octets), fed to
// [Conn.ReadMessage] as hand-built wire frames rather than produced by this
// package's own compressPayload.
func TestDecompressRFC7692HelloExample(t *testing.T) {
	t.Parallel()

	stripped := []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}

	t.Run("single frame", func(t *testing.T) {
		frame := frameBytes(true, OpcodeText, RSV1, true, testKey, stripped)
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
		first := frameBytes(false, OpcodeBinary, RSV1, true, testKey, stripped[:3])
		// Second frame: RSV1 unset, FIN=1, opcode=continuation, 4 octets.
		second := frameBytes(true, OpcodeContinuation, 0, true, testKey, stripped[3:])
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
			got, ok := negotiateDeflate([]byte(tt.extensions), false, false, tt.clientWindowBits)
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
