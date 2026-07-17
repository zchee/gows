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

// Package flatekp adapts github.com/klauspost/compress/flate into a
// [gows.DeflateBackend], for callers that want to swap gows's default
// permessage-deflate backend (stdlib compress/flate) via
// [gows.SetDeflateBackend].
//
// klauspost/compress/flate is kept out of the core gows module's own
// go.mod (github.com/zchee/gows's zero-dependency invariant) by living
// in this separate submodule instead; import it only from a program's
// own main module, never from gows itself.
//
// # When to use this backend
//
// gows's own bench/ deflate study measured stdlib compress/flate's
// pooled Writer.Reset cost at level 6
// (compress.go's no-context-takeover model calls Reset once per
// message) at roughly 11.6µs on darwin/arm64 and 13.5µs on
// linux/amd64 -- about 2,700x more than stdlib's own level-1 Reset cost,
// and about 1,700-2,700x more than klauspost/compress/flate's Reset at
// the *same* level 6 (which costs the same ~4-8ns regardless of level).
// Concretely: at level 1 (gows's zero-value default), the two backends
// are close (klauspost 1.1-2x faster encode/decode); at level 6 or
// above, klauspost wins decisively because stdlib's Reset tax alone
// would dominate the cost of compressing anything smaller than several
// KB. Use this backend whenever a program wants compression levels
// above gows's zero-value default of 1, or wants to negotiate a window
// smaller than the RFC 7692 default 32KB (see "Window-bits negotiation"
// below, which stdlib compress/flate cannot do at all).
//
// # Window-bits negotiation
//
// klauspost/compress/flate additionally exposes NewWriterWindow, which
// stdlib compress/flate has no equivalent of at all -- stdlib can only
// ever compress at the full 32KB window. Installing this backend with
// [gows.SetDeflateBackend] at a windowBits below 15 lets
// [gows.Upgrader.NegotiateWindowBits] (server role) and
// [gows.Dialer.WindowBits] (client role) actually negotiate and honor a
// smaller permessage-deflate window with peers, instead of declining
// every offer that asks for one.
//
// One real constraint of the underlying library carries through here
// honestly rather than being papered over: klauspost's NewWriterWindow
// has no level parameter of its own -- a custom (sub-32KB) window
// always uses klauspost's internal fast, level-5-equivalent encoder.
// [Backend]'s NewWriter therefore only honors the level argument when
// windowBits is 15 (the default, full window); for windowBits 8-14, the
// level argument is accepted (so callers configuring
// [gows.SetDeflateBackend] don't need to special-case it) but ignored.
//
// # Memory cost does not shrink with window bits (measured)
//
// A caller combining this backend with gows's permessage-deflate context
// takeover (a persistent per-Conn compressor; see gows's
// WithCompressionParams doc for the full cost breakdown) might expect a
// smaller negotiated window to shrink that persistent compressor's
// memory footprint proportionally. Measured directly against this
// backend, it does not: klauspost's windowed encoder
// (fastEncL5Window, the type NewWriterWindow constructs) allocates a
// fixed-size internal buffer independent of windowBits --
// NewWriterWindow at 8, 10, 12, and 15 bits (256B, 1KB, 4KB, and 32KB
// windows) all measured at ~730KB per instance, versus ~475KB for the
// unwindowed NewWriter(level=1) path. windowBits only bounds how far
// back a match may reference, a cheap int32 comparison, not how large
// the encoder's own working set is.
//
// This fixed writer allocation is distinct from gows's incoming-side
// sliding dictionary (see [gows.WithCompressionParams]). Installing this
// backend at a smaller windowBits does not itself shrink that dictionary:
// the peer-direction max-window-bits value actually emitted in the
// handshake response can set a smaller binding cap, and a server may
// separately opt into [gows.Upgrader.TrustClientWindowBitsHint] to use a
// valued offer as a non-negotiated local cap. The latter can reject an
// otherwise conforming peer that uses history beyond the hint when the
// response omitted client_max_window_bits. Thus the backend writer's
// working set remains fixed, while gows's incoming dictionary can shrink
// only through response negotiation or that explicit trust policy.
package flatekp

import (
	"bytes"
	"fmt"
	"io"

	kflate "github.com/klauspost/compress/flate"

	"github.com/zchee/gows"
)

// Window-bits bounds this backend advertises via [Backend]'s
// MinWindowBits/MaxWindowBits, matching RFC 7692 §7.1.2's own range.
// klauspost/compress/flate itself permits window sizes from
// [kflate.MinCustomWindowSize] (32 bytes) up to [kflate.MaxCustomWindowSize]
// (32KB), a wider range than RFC 7692 ever negotiates; this package only
// exposes the RFC-meaningful 8-15 bits (256B-32KB) subset of it.
const (
	minWindowBits = 8
	maxWindowBits = 15
)

// Backend returns a [gows.DeflateBackend] backed by
// github.com/klauspost/compress/flate, for use with
// [gows.SetDeflateBackend]. It advertises the same compression-level
// range as stdlib compress/flate (klauspost/compress/flate is a
// drop-in-compatible fork) and RFC 7692's full window-bits range,
// 8-15 -- see the package doc for the one real caveat (level is only
// honored at windowBits == 15).
func Backend() *gows.DeflateBackend {
	return &gows.DeflateBackend{
		Name:          "klauspost/compress/flate",
		NewWriter:     newWriter,
		NewReader:     newReader,
		MinLevel:      kflate.HuffmanOnly,
		MaxLevel:      kflate.BestCompression,
		MinWindowBits: minWindowBits,
		MaxWindowBits: maxWindowBits,
	}
}

// newWriter implements the compressor half of [Backend]. For the
// RFC 7692 default window (windowBits == 15) it delegates to
// kflate.NewWriter, honoring level exactly as stdlib compress/flate
// would. For a smaller negotiated window it delegates to
// kflate.NewWriterWindow, which -- per the package doc -- has no level
// parameter of its own; level is accepted but not passed through in
// that case, since klauspost's windowed mode always uses its internal
// fast (~level 5) encoder regardless of what is asked for.
func newWriter(level, windowBits int) (gows.DeflateWriter, error) {
	if windowBits < minWindowBits || windowBits > maxWindowBits {
		return nil, fmt.Errorf("flatekp: window bits %d outside [%d, %d]", windowBits, minWindowBits, maxWindowBits)
	}
	if windowBits == maxWindowBits {
		w, err := kflate.NewWriter(io.Discard, level)
		if err != nil {
			return nil, fmt.Errorf("flatekp: new writer at level %d: %w", level, err)
		}
		return w, nil
	}
	w, err := kflate.NewWriterWindow(io.Discard, 1<<windowBits)
	if err != nil {
		return nil, fmt.Errorf("flatekp: new windowed writer at %d bits: %w", windowBits, err)
	}
	return w, nil
}

// newReader implements the decompressor half of [Backend]. windowBits
// is unused: like stdlib compress/flate, klauspost's decompressor needs
// no window-size configuration in advance -- DEFLATE back-reference
// distances are self-describing in the compressed stream itself, so any
// decompressor with a buffer at least as large as the compressor's
// window (klauspost's is always the RFC 7692 maximum, 32KB, regardless
// of what window the peer's compressor used) decodes correctly.
func newReader(windowBits int) gows.DeflateReader {
	// kflate.NewReader's returned io.ReadCloser also implements
	// kflate.Resetter (Reset(io.Reader, []byte) error), the same stable
	// guarantee compress.go's stdlib backend relies on.
	return kflate.NewReader(bytes.NewReader(nil)).(gows.DeflateReader)
}
