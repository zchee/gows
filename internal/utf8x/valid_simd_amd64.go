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

//go:build amd64 && !purego

package utf8x

import "github.com/zchee/gows/internal/cpu"

// simdThreshold is the smallest remaining payload for which the AVX2 kernel is
// engaged; below it the scalar DFA (with its ASCII word fast path) is cheaper.
// Placeholder pending benchstat calibration (see utf8-simd-calibration.md).
const simdThreshold = 32

// avx2Validated gates whether the production Feed path uses the AVX2 kernel.
// It was held false until the exhaustive differential suite (TestKernelDifferential,
// which invokes utf8ValidAVX2 directly) ran on real AVX2 hardware. That
// validation passed on an Intel Xeon 8481C (Sapphire Rapids) — every density ×
// block-aligned length 0..4096 × offset, plus the corruption sweep and the full
// Feed/Valid streaming and fuzz suites — so the AVX2 path is now enabled.
const avx2Validated = true

// utf8ValidAVX2 reports whether the n bytes at p contain no structural UTF-8
// error, treating the buffer as if it may continue past its end (a trailing
// incomplete sequence is NOT an error — the caller's scalar DFA owns the
// boundary). n must be a positive multiple of 32.
//
//go:noescape
func utf8ValidAVX2(p *byte, n int) bool

// simdBulk validates the largest 32-byte-aligned prefix of b with the AVX2
// kernel and returns how many bytes Feed may advance while remaining on a
// code-point boundary, -1 on a structural error, or 0 if it does not engage.
//
// A CPU without AVX2 (which the internal/cpu detector gates, along with the
// GOWS_SIMD kill switch) falls through to 0, so Feed runs the pure-scalar path.
func simdBulk(b []byte) int {
	if !avx2Validated || len(b) < simdThreshold || !cpu.X86.HasAVX2 {
		return 0
	}
	m := len(b) &^ 31
	if m == 0 {
		return 0
	}
	if !utf8ValidAVX2(&b[0], m) {
		return -1
	}
	return boundaryBackoff(b, m)
}
