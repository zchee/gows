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
	"strconv"
	"strings"
	"testing"
)

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
