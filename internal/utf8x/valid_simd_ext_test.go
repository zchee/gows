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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/zchee/gows/internal/utf8x"
)

// simdDensityUnits are repeated to build buffers large enough to engage the
// SIMD bulk path (>= the entry threshold) at several multibyte densities.
var simdDensityUnits = map[string]string{
	"ascii":  "The quick brown fox jumps over the lazy dog. ",
	"2-byte": "µßöäüàá£çñ",
	"3-byte": "日本語のテスト文字",
	"4-byte": "🎉😀😁🎊🥳🚀",
	"mixed":  "Hello-µ@ßöäüàá 日本語 🎉 UTF-8!! ",
}

// TestSIMDIntegrationDifferential drives the public Valid (hence Feed's SIMD
// bulk path) against stdlib for every length 0..2048 and start offsets 0..7,
// per density. Slicing valid content this way regularly starts or ends
// mid-sequence, so the SIMD/scalar hand-off at both ends is what is under test.
func TestSIMDIntegrationDifferential(t *testing.T) {
	for name, unit := range simdDensityUnits {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			big := []byte(strings.Repeat(unit, 2048/len(unit)+8))
			for off := 0; off <= 7; off++ {
				for n := 0; off+n <= len(big) && n <= 2048; n++ {
					b := big[off : off+n]
					if want, got := utf8.Valid(b), utf8x.Valid(b); got != want {
						t.Fatalf("off=%d n=%d: Valid=%v want=%v\n% X", off, n, got, want, b)
					}
				}
			}
		})
	}
}

// TestSIMDSplitSweep splits SIMD-sized buffers (valid, invalid, and truncated)
// at every byte boundary and confirms the streaming verdict always equals the
// one-shot verdict. With buffers well over the SIMD threshold, split points
// routinely land inside a vector block mid-multibyte-sequence (plan §10
// scenario 2).
func TestSIMDSplitSweep(t *testing.T) {
	surrogate := []byte{0xED, 0xA0, 0x80} // encoded U+D800, invalid
	inputs := map[string][]byte{
		"dense 3-byte valid":        []byte(strings.Repeat("日本語のテスト", 20)),
		"dense 4-byte valid":        []byte(strings.Repeat("🎉😀", 40)),
		"mixed valid":               []byte(strings.Repeat("Hello-µ@ß 日本 🎉 ", 20)),
		"dense with embedded error": splice(strings.Repeat("日本語", 30), surrogate, strings.Repeat("テスト", 30)),
		"dense truncated tail":      []byte(strings.Repeat("日本語", 40) + "\xe6\x97"),
	}

	for name, b := range inputs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			want := utf8.Valid(b)
			if got := utf8x.Valid(b); got != want {
				t.Fatalf("one-shot Valid = %v, want %v (stdlib)", got, want)
			}
			for i := 0; i <= len(b); i++ {
				if got := verdict(splitAt(b, i)); got != want {
					t.Errorf("split at %d/%d: verdict = %v, want %v", i, len(b), got, want)
				}
			}
		})
	}
}
