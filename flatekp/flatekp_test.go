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

package flatekp_test

import (
	"bytes"
	"compress/flate"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/zchee/gows"
	"github.com/zchee/gows/flatekp"
)

// --- RFC 7692 §7.2.1/§7.2.2 framing helpers, reimplemented locally --------
//
// flatekp is a separate module from gows and cannot reach gows's
// unexported compress.go helpers (compressPayload, decompressMessage,
// deflateFlushTail, deflateReadTail), so this test reproduces the exact
// framing directly against the [gows.DeflateWriter]/[gows.DeflateReader]
// interfaces: Flush, strip the trailing 4-byte sync-flush marker on the
// way out; re-append it (plus the 5-byte final-empty-block trailer) on
// the way in. See compress.go's identical comments for why.

var deflateFlushTail = [4]byte{0x00, 0x00, 0xff, 0xff}

var deflateReadTail = [9]byte{0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff}

func compressVia(t *testing.T, w gows.DeflateWriter, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w.Reset(&buf)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	out := buf.Bytes()
	if len(out) < len(deflateFlushTail) {
		t.Fatalf("compressed output (%d bytes) shorter than the sync-flush marker", len(out))
	}
	return out[:len(out)-len(deflateFlushTail)]
}

func decompressVia(t *testing.T, r gows.DeflateReader, compressed []byte) []byte {
	t.Helper()
	src := append(append([]byte(nil), compressed...), deflateReadTail[:]...)
	if err := r.Reset(bytes.NewReader(src), nil); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return out
}

func stdlibWriter(t *testing.T, level int) gows.DeflateWriter {
	t.Helper()
	w, err := flate.NewWriter(io.Discard, level)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	return w
}

func stdlibReader() gows.DeflateReader {
	return flate.NewReader(bytes.NewReader(nil)).(gows.DeflateReader)
}

// --- deterministic payload fixtures (no external entropy, reproducible) ---

func jsonlikePayload(n int) []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, `{"id":%d,"type":"update","user":"user_%d","value":%d.%d},`, i, i%37, (i*7)%997, i%100)
	}
	return b.Bytes()[:n]
}

func repetitivePayload(n int) []byte {
	const pattern = "the quick brown fox jumps over the lazy dog. "
	return bytes.Repeat([]byte(pattern), n/len(pattern)+1)[:n]
}

// randomPayload returns n deterministic, effectively-incompressible bytes
// (xorshift32) -- a local copy of gows's own compress_test.go fixture of
// the same name/algorithm, avoiding both a math/rand import and real
// entropy for a reproducible fixture.
func randomPayload(n int) []byte {
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

func payloadFixtures() map[string][]byte {
	const size = 2048
	return map[string][]byte{
		"jsonlike":   jsonlikePayload(size),
		"random":     randomPayload(size),
		"repetitive": repetitivePayload(size),
	}
}

// --- round trip: klauspost compress / stdlib decompress, and back ---------

// TestRoundTripCrossBackend proves flatekp's compressed bytes are
// standard, interoperable DEFLATE output (decodable by stdlib
// compress/flate, not just by itself) across every level x window-bits
// combination this backend advertises, and the reverse (stdlib-compressed
// bytes decode via flatekp). For windowBits < 15, level has no effect on
// flatekp's output (see the package doc and TestWindowedWriterIgnoresLevel
// below) -- this still exercises every requested combination, it just
// doesn't produce 3 distinct outputs per window size in that case.
func TestRoundTripCrossBackend(t *testing.T) {
	backend := flatekp.Backend()
	levels := []int{1, 6, 9}
	windowBitsList := []int{8, 10, 15}
	payloads := payloadFixtures()

	for _, level := range levels {
		for _, wb := range windowBitsList {
			for kind, payload := range payloads {
				t.Run(fmt.Sprintf("level=%d/windowBits=%d/%s", level, wb, kind), func(t *testing.T) {
					kw, err := backend.NewWriter(level, wb)
					if err != nil {
						t.Fatalf("backend.NewWriter(%d, %d): %v", level, wb, err)
					}
					kCompressed := compressVia(t, kw, payload)
					if got := decompressVia(t, stdlibReader(), kCompressed); !bytes.Equal(got, payload) {
						t.Fatalf("klauspost-compressed bytes did not decode via stdlib flate (got %d bytes, want %d)",
							len(got), len(payload))
					}

					// stdlib has no windowed mode at all (see the
					// package doc); its half of the matrix only varies
					// by level, always at the full window.
					sCompressed := compressVia(t, stdlibWriter(t, level), payload)
					if got := decompressVia(t, backend.NewReader(wb), sCompressed); !bytes.Equal(got, payload) {
						t.Fatalf("stdlib-compressed bytes did not decode via klauspost flate (got %d bytes, want %d)",
							len(got), len(payload))
					}
				})
			}
		}
	}
}

// TestWindowedWriterIgnoresLevel confirms, positively (not just by
// documentation), the package doc's claim that a windowed
// (windowBits < 15) writer's output is identical regardless of the level
// requested -- klauspost/compress/flate's NewWriterWindow has no level
// parameter of its own.
func TestWindowedWriterIgnoresLevel(t *testing.T) {
	backend := flatekp.Backend()
	payload := repetitivePayload(4096)

	var first []byte
	for i, level := range []int{1, 6, 9} {
		w, err := backend.NewWriter(level, 10)
		if err != nil {
			t.Fatalf("backend.NewWriter(%d, 10): %v", level, err)
		}
		out := compressVia(t, w, payload)
		if i == 0 {
			first = out
			continue
		}
		if !bytes.Equal(out, first) {
			t.Fatalf("level %d produced different windowed output than level 1; expected level to be ignored for windowBits < 15", level)
		}
	}
}

// TestWindowedWriterResetPreservesWindow confirms Reset on a writer
// constructed via NewWriterWindow keeps compressing at the same custom
// window afterward, rather than reverting to the full 32KB window --
// compress.go's pooling contract (Get, Reset, use, Put) depends on this.
func TestWindowedWriterResetPreservesWindow(t *testing.T) {
	backend := flatekp.Backend()
	payload := repetitivePayload(4096)

	w, err := backend.NewWriter(1, 10)
	if err != nil {
		t.Fatalf("backend.NewWriter: %v", err)
	}
	first := compressVia(t, w, payload)
	second := compressVia(t, w, payload) // Reset happens inside compressVia.
	if !bytes.Equal(first, second) {
		t.Fatalf("Reset did not reproduce identical output for identical input at the same window")
	}
	if got := decompressVia(t, backend.NewReader(10), second); !bytes.Equal(got, payload) {
		t.Fatalf("post-Reset windowed compression did not round-trip correctly")
	}
}

func TestNewWriterWindowBitsValidation(t *testing.T) {
	backend := flatekp.Backend()
	tests := map[string]struct {
		windowBits int
		wantErr    bool
	}{
		"below minimum":    {7, true},
		"minimum accepted": {8, false},
		"maximum accepted": {15, false},
		"above maximum":    {16, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := backend.NewWriter(1, tt.windowBits)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewWriter(1, %d) err = %v, wantErr %v", tt.windowBits, err, tt.wantErr)
			}
		})
	}
}

// TestDecompressRFC7692HelloExample is an interop-by-construction test:
// the raw octets are RFC 7692 §7.2.3.1's worked example for compressing
// the 5-byte ASCII string "Hello" (produced by, and verified against,
// stdlib compress/flate directly -- see gows's own compress_test.go,
// which shares this fixture). It must decode identically through
// flatekp's decompressor.
func TestDecompressRFC7692HelloExample(t *testing.T) {
	stripped := []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}
	got := decompressVia(t, flatekp.Backend().NewReader(15), stripped)
	if string(got) != "Hello" {
		t.Fatalf("got %q, want %q", got, "Hello")
	}
}

// --- capability report ------------------------------------------------

func TestBackendCapability(t *testing.T) {
	b := flatekp.Backend()
	if b.MinWindowBits != 8 || b.MaxWindowBits != 15 {
		t.Fatalf("window bits range = [%d, %d], want [8, 15]", b.MinWindowBits, b.MaxWindowBits)
	}
	if b.MinLevel != flate.HuffmanOnly || b.MaxLevel != flate.BestCompression {
		t.Fatalf("level range = [%d, %d], want [%d, %d]", b.MinLevel, b.MaxLevel, flate.HuffmanOnly, flate.BestCompression)
	}
	if b.NewWriter == nil || b.NewReader == nil {
		t.Fatal("NewWriter/NewReader must not be nil")
	}
}

// --- full gows integration: live Conn<->Conn traffic -----------------------

// withGowsDeflateBackend installs b at level/windowBits for the duration
// of t (gows.SetDeflateBackend is process-wide; see its doc), restoring
// gows's built-in stdlib backend once t completes. It must not be used
// from a t.Parallel() test -- see compress_test.go's identical
// withDeflateBackend helper in the parent module for why serializing
// against the package's other tests is what keeps this safe.
func withGowsDeflateBackend(t *testing.T, b *gows.DeflateBackend, level, windowBits int) {
	t.Helper()
	if err := gows.SetDeflateBackend(b, level, windowBits); err != nil {
		t.Fatalf("SetDeflateBackend: %v", err)
	}
	t.Cleanup(func() {
		if err := gows.SetDeflateBackend(gows.DefaultDeflateBackend(), 1, 15); err != nil {
			t.Fatalf("restore SetDeflateBackend: %v", err)
		}
	})
}

// runServerEchoLoop answers every message srv receives with an identical
// echo until ReadMessage errors (the client's closing Close frame,
// mirroring gows's own compress_test.go TestCompressionEchoRoundTrip), and
// closes done once it returns. A fixed per-message goroutine (started and
// exited once per echoRoundTrip call instead of once for the whole test)
// would stop reading after the last expected message and deadlock the
// eventual cli.Close's net.Pipe write, which blocks forever waiting for a
// peer that is no longer reading at all -- this is why the loop, not
// echoRoundTrip itself, owns the server-side goroutine's lifetime.
func runServerEchoLoop(srv *gows.Conn) (done chan struct{}) {
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

// echoRoundTrip writes p as one message on cli and confirms it comes
// back unchanged, driving a real permessage-deflate compress/decompress
// cycle through whatever backend gows.SetDeflateBackend currently has
// active. The server side answering it is [runServerEchoLoop], started
// once for the whole test.
func echoRoundTrip(t *testing.T, cli *gows.Conn, op gows.Opcode, p []byte) {
	t.Helper()
	if err := cli.WriteMessage(op, p); err != nil {
		t.Fatalf("client WriteMessage: %v", err)
	}
	gotOp, got, err := cli.ReadMessage()
	if err != nil {
		t.Fatalf("client ReadMessage: %v", err)
	}
	if gotOp != op || !bytes.Equal(got, p) {
		t.Fatalf("echo mismatch: op=%v len(got)=%d len(want)=%d", gotOp, len(got), len(p))
	}
}

// TestIntegrationEchoFlatekpBothEnds drives a full gows handshake and
// message echo with the flatekp/klauspost backend active process-wide
// and a negotiated sub-15 window on both the Upgrader (server,
// NegotiateWindowBits) and Dialer (client, WindowBits) sides -- proving
// the whole stack (negotiation through compress.go's pools) works
// end-to-end with this backend, not just its compressor/decompressor in
// isolation.
func TestIntegrationEchoFlatekpBothEnds(t *testing.T) {
	withGowsDeflateBackend(t, flatekp.Backend(), 6, 10)

	srvConn, cliConn := net.Pipe()
	serverErr := make(chan error, 1)
	serverHS := make(chan gows.Handshake, 1)
	go func() {
		u := &gows.Upgrader{EnableCompression: true, NegotiateWindowBits: true}
		hs, err := u.Upgrade(srvConn)
		serverErr <- err
		serverHS <- hs
	}()

	d := &gows.Dialer{
		EnableCompression: true,
		WindowBits:        10,
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
	hs := <-serverHS
	if !hs.Compressed || !clientHS.Compressed {
		t.Fatalf("Compressed = server:%v client:%v, want both true", hs.Compressed, clientHS.Compressed)
	}

	srv := gows.NewServerConn(srvConn, gows.WithCompression(true))
	cli := gows.NewClientConn(conn, gows.WithCompression(true))
	done := runServerEchoLoop(srv)

	payloads := payloadFixtures()
	for kind, p := range payloads {
		t.Run(kind, func(t *testing.T) {
			echoRoundTrip(t, cli, gows.OpcodeBinary, p)
		})
	}
	_ = cli.Close(gows.CloseNormalClosure, "bye")
	<-done
}

// TestMixedBackendWireCompatibility is this task's "mixed
// (flatekp server <-> stdlib-default client)" scenario, at the level
// the claim actually needs proving at: gows.SetDeflateBackend is a
// process-wide switch (see its doc) -- a single process cannot run a
// server-role Conn on klauspost and a client-role Conn on stdlib
// simultaneously, since both share the one active backend. What "mixed"
// is really asserting -- that either peer's compressed bytes are
// ordinary, standards-compliant DEFLATE the *other* backend can decode
// regardless of which one produced them -- is exactly
// TestRoundTripCrossBackend's cross-decode assertions, run again here
// framed explicitly as "server compresses with flatekp, client
// decompresses with stdlib" and vice versa, so the scenario named in the
// task is traceable to a concrete test by name.
func TestMixedBackendWireCompatibility(t *testing.T) {
	backend := flatekp.Backend()
	payload := jsonlikePayload(2048)

	t.Run("flatekp server compresses, stdlib client decompresses", func(t *testing.T) {
		w, err := backend.NewWriter(6, 15)
		if err != nil {
			t.Fatalf("backend.NewWriter: %v", err)
		}
		compressed := compressVia(t, w, payload)
		if got := decompressVia(t, stdlibReader(), compressed); !bytes.Equal(got, payload) {
			t.Fatalf("stdlib client could not decode flatekp server's output")
		}
	})

	t.Run("stdlib server compresses, flatekp client decompresses", func(t *testing.T) {
		compressed := compressVia(t, stdlibWriter(t, 1), payload)
		if got := decompressVia(t, backend.NewReader(15), compressed); !bytes.Equal(got, payload) {
			t.Fatalf("flatekp client could not decode stdlib server's output")
		}
	})
}

// TestIntegrationEchoMixedNegotiation drives a live handshake where the
// server has flatekp installed and negotiates a sub-15 window, while the
// client's own Dialer never sets WindowBits (the zero-value, "no
// restriction" offer any stdlib-only client would send) -- confirming a
// windows-capable server still interoperates with an otherwise-default
// client offer.
func TestIntegrationEchoMixedNegotiation(t *testing.T) {
	withGowsDeflateBackend(t, flatekp.Backend(), 6, 10)

	srvConn, cliConn := net.Pipe()
	serverErr := make(chan error, 1)
	serverHS := make(chan gows.Handshake, 1)
	go func() {
		u := &gows.Upgrader{EnableCompression: true, NegotiateWindowBits: true}
		hs, err := u.Upgrade(srvConn)
		serverErr <- err
		serverHS <- hs
	}()

	d := &gows.Dialer{
		EnableCompression: true, // WindowBits left at its zero value.
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
	hs := <-serverHS
	if !hs.Compressed || !clientHS.Compressed {
		t.Fatalf("Compressed = server:%v client:%v, want both true", hs.Compressed, clientHS.Compressed)
	}

	srv := gows.NewServerConn(srvConn, gows.WithCompression(true))
	cli := gows.NewClientConn(conn, gows.WithCompression(true))
	done := runServerEchoLoop(srv)
	echoRoundTrip(t, cli, gows.OpcodeText, []byte(strings.Repeat("mixed negotiation echo payload ", 40)))
	_ = cli.Close(gows.CloseNormalClosure, "")
	<-done
}

// --- benchmark: Reset cost flat across levels (deflate-study.md's claim) --

// BenchmarkWriterResetLevel1 and BenchmarkWriterResetLevel6 are a quick
// regression check on .omc/research/deflate-study.md's headline finding
// (klauspost's pooled-Writer Reset cost is flat and negligible across
// levels, unlike stdlib compress/flate's ~2,700x level-6-vs-level-1
// blowup) -- not a full restudy, just enough to catch a regression.
func BenchmarkWriterResetLevel1(b *testing.B) {
	benchmarkWriterReset(b, 1)
}

func BenchmarkWriterResetLevel6(b *testing.B) {
	benchmarkWriterReset(b, 6)
}

func benchmarkWriterReset(b *testing.B, level int) {
	backend := flatekp.Backend()
	w, err := backend.NewWriter(level, 15)
	if err != nil {
		b.Fatalf("backend.NewWriter: %v", err)
	}
	b.ReportAllocs()
	for b.Loop() {
		w.Reset(io.Discard)
	}
}

// --- benchmark: NewWriter memory cost does not shrink with window bits ---

// BenchmarkNewWriterMemoryWindowBits8/15 back up the package doc's
// "measured directly" claim with a reproducible number: -benchmem's B/op
// here is each construction's allocation size, and it is expected to
// come out essentially identical at windowBits 8 and 15 -- klauspost's
// windowed encoder allocates a fixed-size internal buffer regardless of
// how far back a match may reference, so a smaller negotiated window
// does not shrink this backend's own persistent-compressor memory cost
// (gows's WithCompressionParams doc explains why that memory
// distinction matters for permessage-deflate context takeover).
func BenchmarkNewWriterMemoryWindowBits8(b *testing.B) {
	benchmarkNewWriterMemory(b, 8)
}

func BenchmarkNewWriterMemoryWindowBits15(b *testing.B) {
	benchmarkNewWriterMemory(b, 15)
}

func benchmarkNewWriterMemory(b *testing.B, windowBits int) {
	backend := flatekp.Backend()
	b.ReportAllocs()
	for b.Loop() {
		w, err := backend.NewWriter(1, windowBits)
		if err != nil {
			b.Fatalf("backend.NewWriter: %v", err)
		}
		_ = w
	}
}
