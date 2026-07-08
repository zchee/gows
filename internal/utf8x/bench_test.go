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
	"strconv"
	"testing"

	"github.com/zchee/gows/internal/utf8x"
)

// benchBuffer returns a buffer of exactly size bytes built by repeating
// unit, so every benchmarked size exercises the same byte pattern.
func benchBuffer(unit string, size int) []byte {
	b := bytes.Repeat([]byte(unit), size/len(unit)+1)
	return b[:size]
}

// benchSizes spans a small control-frame-sized payload through a large
// data-frame payload.
var benchSizes = []int{64, 1024, 65536}

func benchFeed(b *testing.B, unit string) {
	for _, size := range benchSizes {
		buf := benchBuffer(unit, size)
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				var v utf8x.Validator
				if !v.Feed(buf) {
					b.Fatal("Feed: unexpected rejection")
				}
			}
		})
	}
}

// BenchmarkValidatorFeedASCII measures the ASCII word fast path in
// isolation: this is the case the scalar baseline should already be
// close to memory-bandwidth-bound on, since it never leaves the accept
// state.
func BenchmarkValidatorFeedASCII(b *testing.B) {
	benchFeed(b, "The quick brown fox jumps over the lazy dog. ")
}

// BenchmarkValidatorFeedMixed measures a realistic i18n workload: mostly
// ASCII punctuation and spacing with scattered 2- and 3-byte runes, the
// same shape as the Autobahn 6.x-style corpus used in the correctness
// tests.
func BenchmarkValidatorFeedMixed(b *testing.B) {
	benchFeed(b, "Hello-µ@ßöäüàá-UTF-8!! ")
}

// BenchmarkValidatorFeedDenseMultibyte measures the worst case for this
// scalar implementation: every byte is part of a multi-byte sequence, so
// the ASCII fast path never triggers and every byte goes through step.
// This is the number Phase 3's SIMD interior loop most needs to beat.
func BenchmarkValidatorFeedDenseMultibyte(b *testing.B) {
	benchFeed(b, "日本語のテスト文字列です")
}
