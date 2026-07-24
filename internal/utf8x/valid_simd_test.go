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

//go:build (amd64 || arm64) && !purego

package utf8x

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// The arch-specific test files bind these to the platform's SIMD kernel so the
// differential logic below is written once. bulkKernel requires len(b) to be a
// positive multiple of kernelBlock.
var (
	bulkKernel    func(b []byte) bool
	kernelBlock   int
	kernelPresent bool
	kernelName    string
)

// scalarStructural is the independent, pure-scalar reference for the SIMD
// kernel's contract: whether b contains no *structural* UTF-8 error, treating a
// trailing incomplete sequence as not-yet-an-error. It runs the DFA transition
// byte by byte with no ASCII fast path and no SIMD, so it cannot share a bug
// with the kernel.
func scalarStructural(b []byte) bool {
	st := accept
	for _, c := range b {
		st = step(st, c)
		if st == reject {
			return false
		}
	}
	return true
}

// densityUnits are repeated to build buffers of a given multibyte density.
var densityUnits = map[string]string{
	"ascii":  "The quick brown fox jumps! ",
	"2-byte": "µßöäüàá£çñ",
	"3-byte": "日本語のテスト文字",
	"4-byte": "🎉😀😁🎊🥳🚀",
	"mixed":  "Hello-µ@ßöäüàá 日本語 🎉 UTF-8!! ",
}

// TestKernelDifferential checks the SIMD kernel against the pure-scalar
// structural reference for every block-aligned length up to 4096 and every
// start offset spanning a full block (varying both the multibyte phase and
// vector alignment) across several densities. Slicing valid content at
// arbitrary offsets/lengths routinely starts or ends mid-sequence, exercising
// the kernel's boundary behaviour, which must match bit for bit.
func TestKernelDifferential(t *testing.T) {
	if !kernelPresent {
		t.Skipf("%s kernel not available", kernelName)
	}

	for name, unit := range densityUnits {
		t.Run(name, func(t *testing.T) {
			big := []byte(strings.Repeat(unit, 4096/len(unit)+2*kernelBlock))
			for off := range kernelBlock {
				for n := kernelBlock; off+n <= len(big) && n <= 4096; n += kernelBlock {
					b := big[off : off+n]
					got := bulkKernel(b)
					want := scalarStructural(b)
					if got != want {
						t.Fatalf("off=%d n=%d: %s=%v want=%v\n% X", off, n, kernelName, got, want, b)
					}
				}
			}
		})
	}
}

// TestKernelRejectsCorruption injects each invalid lead/continuation byte at
// every position (up to the trailing block boundary) of an otherwise-valid
// dense buffer and confirms the kernel and the scalar reference agree.
func TestKernelRejectsCorruption(t *testing.T) {
	if !kernelPresent {
		t.Skipf("%s kernel not available", kernelName)
	}

	base := []byte(strings.Repeat("日本語のテスト🎉µ", 40))
	base = base[:len(base)/kernelBlock*kernelBlock]
	bad := []byte{0x80, 0xBF, 0xC0, 0xC1, 0xF5, 0xFF, 0xED, 0xA0}

	// Inject only up to len-4: a single invalid lead byte in the last 1-3
	// positions is deliberately deferred by the kernel to the scalar tail
	// (covered by the integration tests), so it would not match the
	// whole-buffer scalar reference here.
	for _, bb := range bad {
		for pos := 0; pos <= len(base)-4; pos++ {
			b := append([]byte(nil), base...)
			b[pos] = bb
			if got, want := bulkKernel(b), scalarStructural(b); got != want {
				t.Fatalf("byte %#02x at pos %d: %s=%v want=%v", bb, pos, kernelName, got, want)
			}
		}
	}
}

// TestBoundaryBackoff pins the pure-Go backoff helper: adv must land on the
// start of the trailing (possibly incomplete) sequence so the scalar DFA
// resumes at a boundary.
func TestBoundaryBackoff(t *testing.T) {
	tests := map[string]struct {
		tail []byte
		want int // adv relative to m
	}{
		"ends on ascii":              {[]byte("abcd"), 0},
		"complete 3-byte at end":     {[]byte("ab日"), -3},
		"incomplete 3-byte (2 of 3)": {[]byte("abc\xe6\x97"), -2},
		"incomplete 3-byte (1 of 3)": {[]byte("abcd\xe6"), -1},
		"incomplete 4-byte (2 of 4)": {[]byte("ab\xf0\x9f"), -2},
		"incomplete 4-byte (3 of 4)": {[]byte("a\xf0\x9f\x8e"), -3},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			b := append(bytes.Repeat([]byte("x"), 16), tt.tail...)
			m := len(b)
			if adv := boundaryBackoff(b, m); adv != m+tt.want {
				t.Errorf("boundaryBackoff = %d, want %d (m=%d)", adv, m+tt.want, m)
			} else {
				st := accept
				for _, c := range b[:adv] {
					st = step(st, c)
				}
				if st != accept {
					t.Errorf("b[:adv] does not end on a boundary (state=%d)", st)
				}
			}
		})
	}
}

// calibSizes straddle the scalar-DFA<->SIMD-kernel crossover that fixes
// simdThreshold. They start at the kernel block size (below it the kernel
// cannot engage) and step through the small-payload band where the kernel's
// fixed table-load setup competes with the byte-at-a-time DFA.
var calibSizes = []int{16, 24, 32, 48, 64, 96, 128}

// calibDensities are the multibyte shapes that actually reach the kernel:
// simdBulk is only called from a sequence boundary after the ASCII word fast
// path, so the remaining buffer always leads with a non-ASCII byte. Pure ASCII
// never engages the kernel and so is not a calibration input.
var calibDensities = map[string]string{
	"2-byte": "µßöäüàá£çñ",
	"3-byte": "日本語のテスト文字",
	"mixed":  "Hello-µ@ß 日本 UTF-8!! ",
}

// calibBuffer builds a size-byte buffer of the given density; slicing at an
// arbitrary size routinely ends mid-sequence, exactly as Feed sees it.
func calibBuffer(unit string, size int) []byte {
	return []byte(strings.Repeat(unit, size/len(unit)+1))[:size]
}

// BenchmarkThresholdScalar measures the pure-scalar DFA cost of validating a
// small multibyte buffer — the work Feed performs below simdThreshold.
func BenchmarkThresholdScalar(b *testing.B) {
	for name, unit := range calibDensities {
		b.Run(name, func(b *testing.B) {
			for _, size := range calibSizes {
				buf := calibBuffer(unit, size)
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					b.SetBytes(int64(size))
					for b.Loop() {
						if !scalarStructural(buf) {
							b.Fatal("unexpected structural error")
						}
					}
				})
			}
		})
	}
}

// kernelCorpus are whole-buffer inputs fed straight to the SIMD kernel to
// measure the 64-byte ASCII fast-skip in isolation. "ascii" is the skip's best
// case, "multibyte" its worst (the screen never fires, so it is the regression
// guard), and "mixed" the realistic middle. Buffers are built at multiples of
// 64 so both the 16-byte block and the 64-byte screen align.
var kernelCorpus = map[string]string{
	"ascii":     "The quick brown fox jumps over the lazy dog. ",
	"mixed":     "Hello-µ@ß 日本 UTF-8!! ",
	"multibyte": "日本語のテスト文字",
}

var kernelCorpusSizes = []int{64, 1024, 65536}

// BenchmarkKernelCorpus measures the raw kernel throughput per corpus so the
// ASCII fast-skip can be evaluated with benchstat: adopt only if "ascii"
// improves substantially without regressing "multibyte".
func BenchmarkKernelCorpus(b *testing.B) {
	if !kernelPresent {
		b.Skipf("%s kernel not available", kernelName)
	}
	for name, unit := range kernelCorpus {
		b.Run(name, func(b *testing.B) {
			for _, size := range kernelCorpusSizes {
				m := size / kernelBlock * kernelBlock
				buf := calibBuffer(unit, m)
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					b.SetBytes(int64(m))
					for b.Loop() {
						if !bulkKernel(buf) {
							b.Fatal("unexpected structural error")
						}
					}
				})
			}
		})
	}
}

// BenchmarkThresholdSIMD measures the SIMD dispatch cost at the same sizes: the
// kernel over the largest block-aligned prefix plus the scalar DFA over the
// boundary-backoff remainder — the work Feed performs at or above the
// threshold. Comparing the two curves with benchstat fixes simdThreshold at the
// smallest size where the kernel path wins.
func BenchmarkThresholdSIMD(b *testing.B) {
	if !kernelPresent {
		b.Skipf("%s kernel not available", kernelName)
	}
	for name, unit := range calibDensities {
		b.Run(name, func(b *testing.B) {
			for _, size := range calibSizes {
				buf := calibBuffer(unit, size)
				m := size / kernelBlock * kernelBlock
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					b.SetBytes(int64(size))
					for b.Loop() {
						if m > 0 && !bulkKernel(buf[:m]) {
							b.Fatal("unexpected structural error")
						}
						adv := m
						if m > 0 {
							adv = boundaryBackoff(buf, m)
						}
						st := accept
						for _, c := range buf[adv:] {
							st = step(st, c)
						}
						if st == reject {
							b.Fatal("unexpected reject")
						}
					}
				})
			}
		})
	}
}
