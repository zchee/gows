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

package mask

import (
	"strconv"
	"testing"
)

// benchSizes spans small control frames through large data frames so the
// size-threshold crossovers between kernels are visible in the curves.
var benchSizes = []int{16, 64, 256, 1024, 4096, 16384, 65536, 262144}

func benchMask(b *testing.B, fn func([]byte, uint32) uint32, size int) {
	buf := make([]byte, size)
	fillRand(buf, newRNG())
	key := uint32(0x9e3779b1)
	b.SetBytes(int64(size))
	for b.Loop() {
		key = fn(buf, key)
	}
	_ = key
}

// BenchmarkMask measures the production size-dispatching entry point.
func BenchmarkMask(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			benchMask(b, Mask, size)
		})
	}
}

// BenchmarkKernel measures each available kernel individually so the per-kernel
// throughput curves (used to calibrate the dispatch thresholds, AC4) can be
// compared directly.
func BenchmarkKernel(b *testing.B) {
	for _, kern := range Kernels() {
		b.Run(kern.Name, func(b *testing.B) {
			for _, size := range benchSizes {
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					benchMask(b, kern.Fn, size)
				})
			}
		})
	}
}
