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
	"math/rand/v2"
	"testing"
	"unicode/utf8"

	"github.com/zchee/gows/internal/utf8x"
)

// FuzzValidator differentially fuzzes [utf8x.Valid] and the streaming
// Feed/Done contract against [unicode/utf8.Valid]. chunkSeed derives how
// data is split across Feed calls (via the same randomChunks helper
// TestStreamingChunkingMatchesOneShot uses), so the fuzzer can discover
// chunk-boundary bugs over an open-ended input space rather than only
// the fixed corpus that test covers.
func FuzzValidator(f *testing.F) {
	seeds := [][]byte{
		nil,
		{},
		[]byte("hello, world"),
		[]byte("Hello-µ@ßöäüàá-UTF-8!!"),
		{0x80},
		{0xBF},
		{0xC0, 0x80},
		{0xC2, 0x80},
		{0xE0, 0x80, 0x80},
		{0xED, 0xA0, 0x80},
		{0xED, 0xBF, 0xBF},
		{0xF0, 0x80, 0x80, 0x80},
		{0xF4, 0x8F, 0xBF, 0xBF},
		{0xF4, 0x90, 0x80, 0x80},
		{0xE2, 0x82}, // Truncated EURO SIGN.
		{0xF0, 0x9F},
		[]byte("日本語のテスト"),
		[]byte("\U0001F600\U0001F601\U0001F602"),
	}
	for _, s := range seeds {
		for _, seed := range []uint64{0, 1, 12345} {
			f.Add(s, seed)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte, chunkSeed uint64) {
		want := utf8.Valid(data)

		if got := utf8x.Valid(data); got != want {
			t.Fatalf("Valid(one-shot, % X) = %v, want %v", data, got, want)
		}

		rng := rand.New(rand.NewPCG(chunkSeed, chunkSeed^0x9e3779b97f4a7c15))
		chunks := randomChunks(data, rng)

		streamed := verdict(chunks)
		if streamed != want {
			t.Fatalf("streamed verdict (data=% X, chunks=%v) = %v, want %v", data, chunkLens(chunks), streamed, want)
		}
	})
}
