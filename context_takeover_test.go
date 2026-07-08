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
	"net"
	"strings"
	"testing"

	"github.com/zchee/gows/internal/extension"
)

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
// takeover, and an identical-length second encoding without it. "Hello" is
// too short for stdlib compress/flate's level 1 (this package's default)
// to find any match at all even within a single call (verified directly:
// level 1 emits a raw stored block for "Hello" regardless of history), so
// this uses level 6 specifically -- still stdlib compress/flate, just a
// level empirically confirmed to exhibit the effect for this input.
func TestContextTakeoverCompressorShrinksRepeatedMessage(t *testing.T) {
	withDeflateBackend(t, DefaultDeflateBackend(), 6, deflateWindowBits)

	payload := []byte("Hello")

	t.Run("with context takeover", func(t *testing.T) {
		srv := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
		first, err := srv.compressMessage(nil, payload)
		if err != nil {
			t.Fatalf("compressMessage(first): %v", err)
		}
		second, err := srv.compressMessage(nil, payload)
		if err != nil {
			t.Fatalf("compressMessage(second): %v", err)
		}
		if len(second) >= len(first) {
			t.Fatalf("second compressed length %d, want < first %d bytes (context takeover should shrink a repeated message, per RFC 7692 §7.2.3.2)",
				len(second), len(first))
		}

		// Round-trip both through a matching context-takeover decompressor.
		cli := NewClientConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
		if got, err := cli.decompressMessage(first); err != nil || string(got) != "Hello" {
			t.Fatalf("decompress(first) = %q, %v, want %q, nil", got, err, "Hello")
		}
		if got, err := cli.decompressMessage(second); err != nil || string(got) != "Hello" {
			t.Fatalf("decompress(second) = %q, %v, want %q, nil", got, err, "Hello")
		}
	})

	t.Run("without context takeover", func(t *testing.T) {
		srv := NewServerConn(&scriptConn{}, WithCompression(true))
		first, err := srv.compressMessage(nil, payload)
		if err != nil {
			t.Fatalf("compressMessage(first): %v", err)
		}
		second, err := srv.compressMessage(nil, payload)
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
				out, err := c.compressMessage(nil, payload)
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
			got, ok := negotiateDeflate([]byte(tt.extensions), false, true)
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
	got, ok := negotiateDeflate([]byte("permessage-deflate"), false, false)
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
	if _, err := c.compressMessage(nil, []byte("still usable after SetDeflateBackend")); err != nil {
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
	compressed, err := srv.compressMessage(nil, huge)
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
