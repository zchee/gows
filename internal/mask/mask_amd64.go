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

package mask

import "github.com/zchee/gows/internal/cpu"

// Size thresholds selecting the masking kernel, calibrated by benchstat
// (n=10, median GB/s) on an Intel Xeon 8481C (Sapphire Rapids).
//
//   - thresholdSIMD: below 64 B the pure-Go word loop beats an SSE2 setup
//     (16 B: generic 3.6 vs SSE2 2.7 GB/s); at 64 B SSE2 wins 1.6x.
//   - thresholdYMM: AVX2 overtakes SSE2 at 128 B (20.2 vs 17.0 GB/s, 1.19x)
//     and widens to 1.36x by 256 B.
//   - thresholdZMM..thresholdZMMMax: AVX-512 beats AVX2 only in an L1-resident
//     window. It wins from 4 KB (154 vs 106 GB/s, 1.45x) through 48 KB
//     (159 vs 100 GB/s, 1.59x), but once the payload exceeds the 48 KB L1d the
//     workload is memory-bandwidth-bound and ZMM regresses (64 KB: 43 vs
//     49 GB/s). Payloads at or above thresholdZMMMax therefore fall through to
//     AVX2 rather than pay the ZMM penalty for no gain.
const (
	thresholdSIMD   = 64
	thresholdYMM    = 128
	thresholdZMM    = 4096
	thresholdZMMMax = 65536
)

// maskSSE2 masks b (n bytes) with key using 64-byte PXOR blocks and returns the
// resumable rotated key. It is safe on every amd64 CPU (SSE2 is baseline).
//
//go:noescape
func maskSSE2(b *byte, n int, key uint32) uint32

// maskAVX2 masks b (n bytes) with key using 128-byte VPXOR (YMM) blocks and
// returns the resumable rotated key. The caller must ensure AVX2 is available.
//
//go:noescape
func maskAVX2(b *byte, n int, key uint32) uint32

// maskAVX512 masks b (n bytes) with key using 256-byte VPXORQ (ZMM) blocks and
// returns the resumable rotated key. The caller must ensure AVX-512 F+BW+VL are
// available and enabled by the OS.
//
//go:noescape
func maskAVX512(b *byte, n int, key uint32) uint32

// Mask XORs b in place with the little-endian 4-byte key and returns the key
// rotated for resuming a chunked payload; see the package documentation for
// the exact contract.
//
// It dispatches by payload size and detected CPU features: the pure-Go word
// loop for small payloads, then SSE2/AVX2/AVX-512 as the payload grows.
func Mask(b []byte, key uint32) uint32 {
	n := len(b)
	switch {
	case n < thresholdSIMD:
		return maskGeneric(b, key)
	case cpu.X86.HasAVX512 && n >= thresholdZMM && n < thresholdZMMMax:
		return maskAVX512(&b[0], n, key)
	case cpu.X86.HasAVX2 && n >= thresholdYMM:
		return maskAVX2(&b[0], n, key)
	default:
		return maskSSE2(&b[0], n, key)
	}
}
