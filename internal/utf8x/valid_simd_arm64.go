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

//go:build arm64 && !purego

package utf8x

import "github.com/zchee/gows/internal/cpu"

// simdThreshold is the smallest remaining payload for which the NEON kernel is
// engaged; below it the scalar DFA (with its ASCII word fast path) is cheaper.
// Calibrated by benchstat (BenchmarkThresholdScalar vs BenchmarkThresholdSIMD,
// n=10, GOMAXPROCS=1) on an Apple M3 Max, go1.26.5 darwin/arm64, 2026-07-14
// (light host contention, load1 ~4.5-5; benchstat variance ±0-3%). For
// multibyte content -- the only kind that reaches the kernel, since Feed's
// ASCII word path consumes ASCII runs first -- the NEON kernel plus boundary
// backoff beats the scalar DFA at every size from 16 B up: 16 B 5.7 vs
// 31-37 ns (3.7-6.4x), 32 B ~8 vs 63-75 ns (7-11x), 64 B 9-11 vs 117-148 ns
// (11-17x). 16 is the smallest size at which the kernel can engage
// (m = len&^15 >= 16), lowered from the previous placeholder of 32. See
// .omc/research/neon-vnext-calibration.md.
const simdThreshold = 16

// utf8ValidNEON reports whether the n bytes at p contain no structural UTF-8
// error, treating the buffer as if it may continue past its end (a trailing
// incomplete sequence is NOT an error — the caller's scalar DFA owns the
// boundary). n must be a positive multiple of 16.
//
//go:noescape
func utf8ValidNEON(p *byte, n int) bool

// simdBulk validates the largest 16-byte-aligned prefix of b with the NEON
// kernel and returns how many bytes Feed may advance while remaining on a
// code-point boundary, or -1 if a structural error is found, or 0 if the
// kernel does not engage.
func simdBulk(b []byte) int {
	if !cpu.HasNEON || len(b) < simdThreshold {
		return 0
	}
	m := len(b) &^ 15
	if m == 0 {
		return 0
	}
	if !utf8ValidNEON(&b[0], m) {
		return -1
	}
	return boundaryBackoff(b, m)
}
