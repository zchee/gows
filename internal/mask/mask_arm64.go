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

package mask

import "github.com/zchee/gows/internal/cpu"

// thresholdSIMD is the payload size below which the pure-Go word loop beats the
// NEON kernel. Calibrated by benchstat (BenchmarkKernelCalib, n=10,
// GOMAXPROCS=1, median GB/s) on an Apple M3 Max, go1.26.5 darwin/arm64,
// 2026-07-14 (light host contention, load1 ~4.5-5; benchstat variance ±0-3%).
// The generic<->NEON crossover sits between 24 B and 32 B: at 24 B the word loop
// wins (generic 8.2 vs NEON 5.8 GB/s) but at 32 B NEON overtakes it (7.5 vs
// 6.4 GB/s, 1.18x) and the margin widens (48 B 1.05x, 64 B 1.52x, 128 B 1.9x).
// 32 is the smallest measured size where NEON wins, lowered from the previous
// placeholder of 64 (benchstat n=10, Apple M3 Max, 2026-07-14).
const thresholdSIMD = 32

// maskNEON masks b (n bytes) with key using 64-byte EOR blocks over 128-bit V
// registers and returns the resumable rotated key.
//
//go:noescape
func maskNEON(b *byte, n int, key uint32) uint32

// Mask XORs b in place with the little-endian 4-byte key and returns the key
// rotated for resuming a chunked payload; see the package documentation for
// the exact contract.
//
// It uses the NEON kernel for payloads of at least thresholdSIMD bytes and the
// pure-Go word loop otherwise.
func Mask(b []byte, key uint32) uint32 {
	if n := len(b); n >= thresholdSIMD && cpu.HasNEON {
		return maskNEON(&b[0], n, key)
	}
	return maskGeneric(b, key)
}
