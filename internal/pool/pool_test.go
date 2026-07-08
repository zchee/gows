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

package pool_test

import (
	"fmt"
	"math/bits"
	"sync"
	"testing"

	"github.com/zchee/gows/internal/pool"
)

// expectedClassSize returns the pooled class size that Get(n) must draw
// from, or 0 if n exceeds the pooled range (n > 256KB).
func expectedClassSize(n int) int {
	const (
		minClassSize = 1 << 7
		maxClassSize = 1 << 18
	)
	if n > maxClassSize {
		return 0
	}
	if n <= minClassSize {
		return minClassSize
	}
	shift := bits.Len(uint(n - 1))
	return 1 << shift
}

func TestGetClassBoundaries(t *testing.T) {
	const maxClassSize = 1 << 18

	sizes := []int{}
	for _, base := range []int{1 << 7, 1 << 8, 1 << 9, 1 << 10, 1 << 16, 1 << 17, maxClassSize} {
		sizes = append(sizes, base-1, base, base+1)
	}
	sizes = append(sizes, 1, maxClassSize+1, maxClassSize+1024)

	for _, n := range sizes {
		t.Run("", func(t *testing.T) {
			b := pool.Get(n)
			if len(b) != 0 {
				t.Fatalf("Get(%d): len = %d, want 0", n, len(b))
			}
			if cap(b) < n {
				t.Fatalf("Get(%d): cap = %d, want >= %d", n, cap(b), n)
			}
			want := expectedClassSize(n)
			switch want {
			case 0:
				// Outside the pooled range: exact make(n), not rounded to a class.
				if cap(b) != n {
					t.Fatalf("Get(%d): cap = %d, want exact %d (unpooled)", n, cap(b), n)
				}
			default:
				if cap(b) != want {
					t.Fatalf("Get(%d): cap = %d, want class size %d", n, cap(b), want)
				}
			}
		})
	}
}

func TestGetPutRoundTripReuse(t *testing.T) {
	const size = 1024

	b := pool.Get(size)
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0xAB
	}
	pool.Put(b)

	b2 := pool.Get(size)
	b2 = b2[:cap(b2)]
	if b2[0] != 0xAB {
		t.Fatalf("Get after Put: b2[0] = %#x, want 0xAB (pool did not reuse the backing array)", b2[0])
	}
}

func TestPutDropsNonClassCaps(t *testing.T) {
	tests := map[string]struct {
		cap int
	}{
		"too small, power of two":   {cap: 64},
		"too large, power of two":   {cap: 1 << 19},
		"non-power-of-two in range": {cap: 1000},
		"zero capacity":             {cap: 0},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// A Put of a non-class-matching buffer must not panic and must
			// not be observable via a subsequent Get of the same class
			// (there is no way to assert "not pooled" directly, so this
			// test only guards against a panic or invariant violation).
			b := make([]byte, 0, tt.cap)
			pool.Put(b)
		})
	}
}

func TestGetCapLenInvariants(t *testing.T) {
	for n := range 4098 {
		b := pool.Get(n)
		if len(b) != 0 {
			t.Fatalf("Get(%d): len = %d, want 0", n, len(b))
		}
		if cap(b) < n {
			t.Fatalf("Get(%d): cap = %d, want >= %d", n, cap(b), n)
		}
		pool.Put(b)
	}
}

func TestConcurrentGetPut(t *testing.T) {
	const goroutines = 32
	const iterations = 2000

	sizes := []int{16, 127, 128, 129, 1024, 65536, 1 << 18, 1<<18 + 1}

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := range iterations {
				n := sizes[(seed+i)%len(sizes)]
				b := pool.Get(n)
				if len(b) != 0 || cap(b) < n {
					panic("invariant violated under concurrency")
				}
				b = append(b, byte(i))
				pool.Put(b)
			}
		}(g)
	}
	wg.Wait()
}

func TestGetPutSteadyStateAllocs(t *testing.T) {
	// sync.Pool items can be dropped by the garbage collector between
	// runs (victim-cache eviction after two consecutive GC cycles with no
	// intervening Get), which can occasionally surface as a non-zero
	// AllocsPerRun result under heavy GC pressure (e.g. -race, or a test
	// run alongside other allocation-heavy tests). This test is expected
	// to be stable in isolation; treat a rare non-zero result as a
	// scheduling/GC flake rather than a pooling bug before investigating
	// further.
	const size = 1024

	f := func() {
		b := pool.Get(size)
		pool.Put(b)
	}

	avg := testing.AllocsPerRun(100, f)
	if avg != 0 {
		t.Fatalf("Get(%d)+Put: %.2f allocs/op, want 0", size, avg)
	}
}

func BenchmarkGetPut(b *testing.B) {
	sizes := []int{16, 64, 256, 1024, 4096, 16384, 65536, 262144}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				buf := pool.Get(size)
				pool.Put(buf)
			}
		})
	}
}
