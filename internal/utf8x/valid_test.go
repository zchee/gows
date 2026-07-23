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

package utf8x_test

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/zchee/gows/internal/utf8x"
)

// newRNG returns a deterministically-seeded RNG so failures reproduce.
func newRNG() *rand.Rand {
	return rand.New(rand.NewPCG(0x1234567890abcdef, 0xfedcba0987654321))
}

// encodeBits packs the low bits of v into an n-byte UTF-8-shaped
// sequence using the raw RFC 3629 bit layout, without enforcing the
// shortest-form rule. It is used to construct deliberately overlong,
// surrogate, and out-of-range test vectors that [utf8.AppendRune] would
// never produce, since AppendRune only ever emits canonical encodings.
func encodeBits(v uint32, n int) []byte {
	switch n {
	case 2:
		return []byte{
			0xC0 | byte(v>>6),
			0x80 | byte(v&0x3F),
		}
	case 3:
		return []byte{
			0xE0 | byte(v>>12),
			0x80 | byte((v>>6)&0x3F),
			0x80 | byte(v&0x3F),
		}
	case 4:
		return []byte{
			0xF0 | byte(v>>18),
			0x80 | byte((v>>12)&0x3F),
			0x80 | byte((v>>6)&0x3F),
			0x80 | byte(v&0x3F),
		}
	default:
		panic("encodeBits: n must be 2, 3, or 4")
	}
}

// TestEncodeBitsKnownVectors pins encodeBits against the well-known
// UTF-8 stress-test vectors (Markus Kuhn's decoder stress test and the
// RFC 3629 worked examples) before the rest of this file leans on it to
// build overlong, surrogate, and out-of-range inputs.
func TestEncodeBitsKnownVectors(t *testing.T) {
	tests := map[string]struct {
		v    uint32
		n    int
		want []byte
	}{
		"overlong NUL, 2 bytes":                {v: 0x0000, n: 2, want: []byte{0xC0, 0x80}},
		"overlong NUL, 3 bytes":                {v: 0x0000, n: 3, want: []byte{0xE0, 0x80, 0x80}},
		"overlong NUL, 4 bytes":                {v: 0x0000, n: 4, want: []byte{0xF0, 0x80, 0x80, 0x80}},
		"overlong max 1-byte value (U+007F)":   {v: 0x007F, n: 2, want: []byte{0xC1, 0xBF}},
		"overlong max 2-byte value (U+07FF)":   {v: 0x07FF, n: 3, want: []byte{0xE0, 0x9F, 0xBF}},
		"overlong max 3-byte value (U+FFFF)":   {v: 0xFFFF, n: 4, want: []byte{0xF0, 0x8F, 0xBF, 0xBF}},
		"surrogate U+D800 (low surrogate lo)":  {v: 0xD800, n: 3, want: []byte{0xED, 0xA0, 0x80}},
		"surrogate U+DFFF (high surrogate hi)": {v: 0xDFFF, n: 3, want: []byte{0xED, 0xBF, 0xBF}},
		"valid U+10FFFF (max scalar value)":    {v: 0x10FFFF, n: 4, want: []byte{0xF4, 0x8F, 0xBF, 0xBF}},
		"out of range U+110000 (max+1)":        {v: 0x110000, n: 4, want: []byte{0xF4, 0x90, 0x80, 0x80}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := encodeBits(tt.v, tt.n)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("encodeBits(%#x, %d) = % X, want % X", tt.v, tt.n, got, tt.want)
			}
		})
	}
}

// boundaryRunes are the code points named by the task at the edge of
// every UTF-8 encoding length class and the surrogate gap.
var boundaryRunes = []rune{
	0x007F,   // max 1-byte
	0x0080,   // min 2-byte
	0x07FF,   // max 2-byte
	0x0800,   // min 3-byte
	0xD7FF,   // last scalar value before the surrogate gap
	0xE000,   // first scalar value after the surrogate gap
	0xFFFF,   // max 3-byte
	0x10000,  // min 4-byte
	0x10FFFF, // max scalar value
}

// TestValidBoundaryCodePoints checks that the canonical encoding of every
// boundary code point is accepted by both utf8.Valid and utf8x.Valid,
// individually and concatenated into one buffer.
func TestValidBoundaryCodePoints(t *testing.T) {
	var all []byte
	for _, r := range boundaryRunes {
		b := utf8.AppendRune(nil, r)
		t.Run(runeName(r), func(t *testing.T) {
			if !utf8.Valid(b) {
				t.Fatalf("utf8.Valid(%U canonical encoding) = false, want true (test bug)", r)
			}
			if got := utf8x.Valid(b); got != true {
				t.Errorf("Valid(%U canonical encoding % X) = %v, want true", r, b, got)
			}
		})
		all = append(all, b...)
	}

	t.Run("all boundary runes concatenated", func(t *testing.T) {
		if want := utf8.Valid(all); utf8x.Valid(all) != want {
			t.Errorf("Valid(concatenated boundary runes) = %v, want %v", utf8x.Valid(all), want)
		}
	})
}

// TestValidRejectsOverlongEncodings checks every overlong re-encoding of
// each length-class boundary value, at every excess byte count RFC 3629
// forbids.
func TestValidRejectsOverlongEncodings(t *testing.T) {
	tests := map[string][]byte{
		"NUL as overlong 2-byte":            encodeBits(0x0000, 2),
		"NUL as overlong 3-byte":            encodeBits(0x0000, 3),
		"NUL as overlong 4-byte":            encodeBits(0x0000, 4),
		"U+007F (max 1-byte) as 2-byte":     encodeBits(0x007F, 2),
		"U+007F (max 1-byte) as 3-byte":     encodeBits(0x007F, 3),
		"U+007F (max 1-byte) as 4-byte":     encodeBits(0x007F, 4),
		"U+07FF (max 2-byte) as overlong 3": encodeBits(0x07FF, 3),
		"U+07FF (max 2-byte) as overlong 4": encodeBits(0x07FF, 4),
		"U+0800 (min 3-byte) as overlong 4": encodeBits(0x0800, 4),
		"U+FFFF (max 3-byte) as overlong 4": encodeBits(0xFFFF, 4),
	}

	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if utf8.Valid(b) {
				t.Fatalf("utf8.Valid(% X) = true, want false (test bug: not actually overlong)", b)
			}
			if utf8x.Valid(b) {
				t.Errorf("Valid(% X) = true, want false (overlong encoding must be rejected)", b)
			}
		})
	}
}

// TestValidRejectsSurrogates checks that every encoded UTF-16 surrogate
// code point (U+D800-U+DFFF) is rejected, across the low- and
// high-surrogate sub-ranges and their boundaries.
func TestValidRejectsSurrogates(t *testing.T) {
	tests := map[string]uint32{
		"U+D800 (low surrogate start)":  0xD800,
		"U+DB7F (low surrogate mid)":    0xDB7F,
		"U+DBFF (low surrogate end)":    0xDBFF,
		"U+DC00 (high surrogate start)": 0xDC00,
		"U+DEFF (high surrogate mid)":   0xDEFF,
		"U+DFFF (high surrogate end)":   0xDFFF,
	}

	for name, v := range tests {
		t.Run(name, func(t *testing.T) {
			b := encodeBits(v, 3)
			if utf8.Valid(b) {
				t.Fatalf("utf8.Valid(% X) = true, want false (test bug: not actually a surrogate encoding)", b)
			}
			if utf8x.Valid(b) {
				t.Errorf("Valid(% X) = true, want false (surrogate encoding must be rejected)", b)
			}
		})
	}
}

// TestValidRejectsOutOfRange checks that code points beyond U+10FFFF,
// the maximum Unicode scalar value, are rejected even though they fit
// the raw 4-byte bit-packing.
func TestValidRejectsOutOfRange(t *testing.T) {
	tests := map[string]uint32{
		"U+110000 (max+1)":                        0x110000,
		"U+1FFFFF (max representable in 4 bytes)": 0x1FFFFF,
	}

	for name, v := range tests {
		t.Run(name, func(t *testing.T) {
			b := encodeBits(v, 4)
			if utf8.Valid(b) {
				t.Fatalf("utf8.Valid(% X) = true, want false (test bug)", b)
			}
			if utf8x.Valid(b) {
				t.Errorf("Valid(% X) = true, want false (code point exceeds U+10FFFF)", b)
			}
		})
	}
}

// TestExhaustiveOneAndTwoByteSequences differentially tests every
// possible 1-byte input (256) and every possible 2-byte input (65536)
// against stdlib, fully exhausting the smallest two length classes
// rather than relying on curated samples.
func TestExhaustiveOneAndTwoByteSequences(t *testing.T) {
	for b0 := range 256 {
		b := []byte{byte(b0)}
		if want, got := utf8.Valid(b), utf8x.Valid(b); got != want {
			t.Fatalf("Valid(% X) = %v, want %v", b, got, want)
		}
	}

	for b0 := range 256 {
		for b1 := range 256 {
			b := []byte{byte(b0), byte(b1)}
			if want, got := utf8.Valid(b), utf8x.Valid(b); got != want {
				t.Fatalf("Valid(% X) = %v, want %v", b, got, want)
			}
		}
	}
}

// TestExhaustiveLeadingBytePairs differentially tests every possible
// (leading byte, second byte) pair for the 3- and 4-byte length classes
// against stdlib, with the remaining continuation byte(s) held fixed at
// a valid filler (0x80) and then at an invalid one (0xFF). This is where
// RFC 3629's overlong/surrogate/out-of-range restrictions actually live
// (see the [dfaState] doc comment), so exhausting the leading pair here
// is far more valuable than exhausting the trailing, purely-generic
// continuation bytes.
func TestExhaustiveLeadingBytePairs(t *testing.T) {
	for _, filler := range []byte{0x80, 0xFF} {
		t.Run(fmt.Sprintf("3-byte, filler=%#02x", filler), func(t *testing.T) {
			for b0 := range 256 {
				for b1 := range 256 {
					b := []byte{byte(b0), byte(b1), filler}
					if want, got := utf8.Valid(b), utf8x.Valid(b); got != want {
						t.Fatalf("Valid(% X) = %v, want %v", b, got, want)
					}
				}
			}
		})

		t.Run(fmt.Sprintf("4-byte, filler=%#02x", filler), func(t *testing.T) {
			for b0 := range 256 {
				for b1 := range 256 {
					b := []byte{byte(b0), byte(b1), filler, filler}
					if want, got := utf8.Valid(b), utf8x.Valid(b); got != want {
						t.Fatalf("Valid(% X) = %v, want %v", b, got, want)
					}
				}
			}
		})
	}
}

// TestValidRejectsInvalidContinuations exercises malformed leading and
// continuation bytes in the 3- and 4-byte length classes plus a
// multi-sequence stream, none of which the overlong/surrogate/
// out-of-range categories above cover; 1- and 2-byte malformations are
// exhausted by TestExhaustiveOneAndTwoByteSequences.
func TestValidRejectsInvalidContinuations(t *testing.T) {
	tests := map[string][]byte{
		"invalid leading byte 0xF5":        {0xF5, 0x80, 0x80, 0x80},
		"3-byte lead, bad 2nd byte":        {0xE1, 0xFF, 0x80},
		"3-byte lead, bad 3rd byte":        {0xE1, 0x80, 0xFF},
		"4-byte lead, bad 2nd byte":        {0xF1, 0xFF, 0x80, 0x80},
		"4-byte lead, bad 4th byte":        {0xF1, 0x80, 0x80, 0xFF},
		"valid rune followed by lone 0x80": append([]byte("ok"), 0x80),
	}

	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if want := utf8.Valid(b); want {
				t.Fatalf("utf8.Valid(% X) = true, want false (test bug)", b)
			}
			if utf8x.Valid(b) {
				t.Errorf("Valid(% X) = true, want false", b)
			}
		})
	}
}

// TestValidTruncations checks, for every boundary code point's canonical
// encoding, that every proper prefix is reported as an incomplete (not
// yet disproven) sequence by Feed/Done individually, while the one-shot
// Valid helper agrees with utf8.Valid that the truncated buffer taken
// alone is not valid UTF-8.
func TestValidTruncations(t *testing.T) {
	for _, r := range boundaryRunes {
		full := utf8.AppendRune(nil, r)
		if len(full) == 1 {
			continue // No proper non-empty prefix to truncate.
		}
		for n := 1; n < len(full); n++ {
			prefix := full[:n]
			t.Run(fmt.Sprintf("%s/prefix-len-%d", runeName(r), n), func(t *testing.T) {
				var v utf8x.Validator
				if !v.Feed(prefix) {
					t.Fatalf("Feed(%U truncated to %d bytes % X) = false, want true (incomplete, not yet invalid)", r, n, prefix)
				}
				if v.Done() {
					t.Fatalf("Done() = true after feeding only %d/%d bytes of %U, want false (sequence incomplete)", n, len(full), r)
				}

				if want := utf8.Valid(prefix); utf8x.Valid(prefix) != want {
					t.Errorf("Valid(%U truncated to %d bytes % X) = %v, want %v (matching utf8.Valid one-shot semantics)",
						r, n, prefix, utf8x.Valid(prefix), want)
				}
			})
		}
	}
}

// TestDoneSemantics directly pins the Feed/Done split required for
// streaming validation across WebSocket fragments (RFC 6455 §8.1): a
// prefix that ends mid-sequence is not yet disproven (Feed true) but is
// not complete either (Done false), while a fully valid, complete
// message is both.
func TestDoneSemantics(t *testing.T) {
	t.Run("valid prefix ending mid-sequence", func(t *testing.T) {
		var v utf8x.Validator
		// 0xE2 0x82 begins the 3-byte encoding of U+20AC (EURO SIGN,
		// 0xE2 0x82 0xAC); withholding the final byte leaves the
		// sequence incomplete.
		if !v.Feed([]byte{0xE2, 0x82}) {
			t.Fatal("Feed(partial 3-byte sequence) = false, want true")
		}
		if v.Done() {
			t.Fatal("Done() = true after a partial 3-byte sequence, want false")
		}
	})

	t.Run("complete valid message", func(t *testing.T) {
		var v utf8x.Validator
		if !v.Feed([]byte("hello, \xe2\x82\xac!")) {
			t.Fatal("Feed(complete valid message) = false, want true")
		}
		if !v.Done() {
			t.Fatal("Done() = false after a complete valid message, want true")
		}
	})

	t.Run("sequence completed across a second Feed call", func(t *testing.T) {
		var v utf8x.Validator
		if !v.Feed([]byte{0xE2, 0x82}) {
			t.Fatal("Feed(first chunk) = false, want true")
		}
		if v.Done() {
			t.Fatal("Done() = true mid-sequence, want false")
		}
		if !v.Feed([]byte{0xAC}) {
			t.Fatal("Feed(closing chunk) = false, want true")
		}
		if !v.Done() {
			t.Fatal("Done() = false after the sequence was completed, want true")
		}
	})
}

// TestFeedStickyInvalid checks that once Feed reports an error, every
// later call keeps reporting an error regardless of its own input, until
// Reset.
func TestFeedStickyInvalid(t *testing.T) {
	var v utf8x.Validator
	if v.Feed([]byte{0x80}) {
		t.Fatal("Feed(invalid lone continuation byte) = true, want false")
	}

	tests := map[string][]byte{
		"empty input":       {},
		"nil input":         nil,
		"valid ASCII input": []byte("hello"),
		"another invalid":   {0x80},
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if v.Feed(b) {
				t.Errorf("Feed(%q) = true after a prior rejection, want sticky false", b)
			}
			if v.Done() {
				t.Error("Done() = true on a rejected Validator, want false")
			}
		})
	}

	v.Reset()
	if !v.Feed([]byte("hello")) {
		t.Fatal("Feed(valid input) = false after Reset, want true")
	}
	if !v.Done() {
		t.Fatal("Done() = false after Reset and a complete valid message, want true")
	}
}

// streamingCorpus holds both valid and deliberately invalid strings,
// including Autobahn 6.x-style mixed-script payloads and hand-corrupted
// continuation-byte patterns, used to check that chunking never changes
// the verdict.
var streamingCorpus = []struct {
	name string
	b    []byte
}{
	{"empty", nil},
	{"pure ASCII sentence", []byte("The quick brown fox jumps over the lazy dog.")},
	{"autobahn-style mixed script", []byte("Hello-µ@ßöäüàá-UTF-8!!")},
	{"autobahn-style mixed script repeated", bytes.Repeat([]byte("Hello-µ@ßöäüàá-UTF-8!!"), 17)},
	{"dense multibyte (CJK)", bytes.Repeat([]byte("日本語のテスト"), 11)},
	{"dense 4-byte (emoji)", bytes.Repeat([]byte("\U0001F600\U0001F601\U0001F602"), 13)},
	{"boundary runes concatenated", boundaryRunesBytes()},
	{
		"mixed script with truncated tail",
		[]byte("Hello-µ@ßöäüàá-UTF-8!!\xe2\x82"), // trailing incomplete EURO SIGN
	},
	{"mixed script with embedded lone continuation byte", splice("Hello-µ@ß", []byte{0x80}, "öäüàá-UTF-8!!")},
	{"mixed script with embedded overlong encoding", splice("Hello-µ@ß", encodeBits(0x0000, 2), "öäüàá-UTF-8!!")},
	{"mixed script with embedded surrogate", splice("Hello-µ@ß", encodeBits(0xD800, 3), "öäüàá-UTF-8!!")},
	{"mixed script with invalid leading byte", splice("Hello-µ@ß", []byte{0xFF}, "öäüàá-UTF-8!!")},
}

func boundaryRunesBytes() []byte {
	var b []byte
	for _, r := range boundaryRunes {
		b = utf8.AppendRune(b, r)
	}
	return b
}

// verdict feeds b to a fresh Validator in the given chunks and reports
// the overall one-shot-equivalent verdict: every Feed call must return
// true, and Done must return true at the end.
func verdict(chunks [][]byte) bool {
	var v utf8x.Validator
	for _, c := range chunks {
		if !v.Feed(c) {
			return false
		}
	}
	return v.Done()
}

// splitAt splits b into two chunks at byte offset i (0 <= i <= len(b)).
func splitAt(b []byte, i int) [][]byte {
	return [][]byte{b[:i], b[i:]}
}

// randomChunks splits b into a random number of contiguous pieces using
// rng, covering the full range from "all in one Feed call" to
// "one byte per Feed call".
func randomChunks(b []byte, rng *rand.Rand) [][]byte {
	if len(b) <= 1 {
		return [][]byte{b}
	}

	cutSet := make(map[int]bool)
	for range rng.IntN(len(b)) {
		cutSet[1+rng.IntN(len(b)-1)] = true // Interior cut points: 1..len(b)-1.
	}
	cuts := make([]int, 0, len(cutSet)+2)
	cuts = append(cuts, 0, len(b))
	for c := range cutSet {
		cuts = append(cuts, c)
	}
	slices.Sort(cuts)

	chunks := make([][]byte, 0, len(cuts)-1)
	for i := 1; i < len(cuts); i++ {
		if cuts[i] > cuts[i-1] {
			chunks = append(chunks, b[cuts[i-1]:cuts[i]])
		}
	}
	return chunks
}

// TestStreamingChunkingMatchesOneShot checks that, for every corpus
// entry, every single two-way split point and a sweep of random
// multi-way chunkings produce the same verdict as validating the whole
// buffer in one call.
func TestStreamingChunkingMatchesOneShot(t *testing.T) {
	rng := newRNG()

	for _, tc := range streamingCorpus {
		t.Run(tc.name, func(t *testing.T) {
			want := utf8x.Valid(tc.b)
			if stdWant := utf8.Valid(tc.b); stdWant != want {
				t.Fatalf("utf8x.Valid(one-shot) = %v but utf8.Valid = %v (test bug: implementation disagrees with stdlib before chunking is even involved)", want, stdWant)
			}

			for i := 0; i <= len(tc.b); i++ {
				if got := verdict(splitAt(tc.b, i)); got != want {
					t.Errorf("split at %d/%d: verdict = %v, want %v (one-shot)", i, len(tc.b), got, want)
				}
			}

			const sweeps = 200
			for range sweeps {
				chunks := randomChunks(tc.b, rng)
				if got := verdict(chunks); got != want {
					t.Errorf("random chunking %v: verdict = %v, want %v (one-shot)", chunkLens(chunks), got, want)
				}
			}
		})
	}
}

func chunkLens(chunks [][]byte) []int {
	lens := make([]int, len(chunks))
	for i, c := range chunks {
		lens[i] = len(c)
	}
	return lens
}

// TestRandomBuffersDifferential compares Valid against utf8.Valid on
// purely random byte buffers (almost always invalid) and on buffers
// assembled from random valid runes (always valid), across a range of
// sizes.
func TestRandomBuffersDifferential(t *testing.T) {
	rng := newRNG()

	t.Run("random bytes", func(t *testing.T) {
		for _, size := range []int{0, 1, 2, 3, 4, 5, 8, 16, 64, 256, 4096} {
			for range 50 {
				b := make([]byte, size)
				for i := range b {
					b[i] = byte(rng.Uint32())
				}
				if want, got := utf8.Valid(b), utf8x.Valid(b); got != want {
					t.Fatalf("Valid(% X) = %v, want %v (utf8.Valid)", b, got, want)
				}
			}
		}
	})

	t.Run("random valid rune sequences", func(t *testing.T) {
		for _, numRunes := range []int{0, 1, 2, 8, 64, 1024} {
			var b []byte
			for range numRunes {
				r := rune(rng.IntN(utf8.MaxRune + 1))
				if r >= 0xD800 && r <= 0xDFFF {
					r = 0x41 // Dodge the surrogate gap: AppendRune substitutes RuneError there.
				}
				b = utf8.AppendRune(b, r)
			}
			if want, got := utf8.Valid(b), utf8x.Valid(b); got != want || !want {
				t.Fatalf("Valid(%d random valid runes) = %v, want %v", numRunes, got, want)
			}
		}
	})
}

// TestFeedAllocs checks that Feed performs no heap allocations on a
// realistic mixed-content buffer.
func TestFeedAllocs(t *testing.T) {
	buf := make([]byte, 0, 4096)
	for len(buf) < 4096 {
		buf = append(buf, "The quick brown fox: Hello-µ@ßöäüàá-UTF-8!! 日本語"...)
	}
	buf = buf[:4096]

	avg := testing.AllocsPerRun(100, func() {
		var v utf8x.Validator
		if !v.Feed(buf) {
			t.Fatal("Feed(valid buffer) = false, want true")
		}
	})
	if avg != 0 {
		t.Fatalf("Feed: %.2f allocs/op, want 0", avg)
	}
}

// runeName formats r the way the rest of this file's subtest names do.
func runeName(r rune) string {
	return fmt.Sprintf("U+%04X", uint32(r))
}

// splice concatenates prefix, middle, and suffix into one buffer, for
// building corpus entries that embed a specific byte pattern inside
// otherwise-valid surrounding text.
func splice(prefix string, middle []byte, suffix string) []byte {
	b := make([]byte, 0, len(prefix)+len(middle)+len(suffix))
	b = append(b, prefix...)
	b = append(b, middle...)
	b = append(b, suffix...)
	return b
}
