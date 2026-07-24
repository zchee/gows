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
	"bytes"
	"encoding/binary"
	"math/bits"
	"math/rand/v2"
	"strconv"
	"testing"
)

// maskRef is the trivial, obviously-correct reference: it XORs each byte with
// the key byte for its position and rotates the key by the number of bytes
// consumed. Every kernel must reproduce its output and its returned key
// exactly. Written out longhand here (not delegating to maskGeneric) so a bug
// shared with the production reference cannot hide.
func maskRef(b []byte, key uint32) uint32 {
	k := [4]byte{byte(key), byte(key >> 8), byte(key >> 16), byte(key >> 24)}
	for i := range b {
		b[i] ^= k[i&3]
	}
	return bits.RotateLeft32(key, -8*(len(b)&3))
}

// fillRand deterministically fills b with pseudo-random bytes from rng.
func fillRand(b []byte, rng *rand.Rand) {
	i := 0
	for ; i+8 <= len(b); i += 8 {
		binary.LittleEndian.PutUint64(b[i:], rng.Uint64())
	}
	for ; i < len(b); i++ {
		b[i] = byte(rng.Uint64())
	}
}

func newRNG() *rand.Rand {
	return rand.New(rand.NewPCG(0x1234567890abcdef, 0xfedcba0987654321))
}

// TestMaskConvention pins the resumable-key rotation convention against
// hand-computed expectations before the differential sweep leans on maskRef.
func TestMaskConvention(t *testing.T) {
	t.Parallel()

	// key bytes little-endian: k0=0x01, k1=0x02, k2=0x03, k3=0x04.
	const key = 0x04030201

	tests := map[string]struct {
		n       int
		wantOut []byte
		wantKey uint32
	}{
		"empty: key unchanged": {
			n:       0,
			wantOut: []byte{},
			wantKey: 0x04030201,
		},
		"one byte: rotate by 1": {
			n:       1,
			wantOut: []byte{0x01},
			wantKey: bits.RotateLeft32(key, -8),
		},
		"four bytes: full cycle, key unchanged": {
			n:       4,
			wantOut: []byte{0x01, 0x02, 0x03, 0x04},
			wantKey: key,
		},
		"five bytes: wraps to k0 again, rotate by 1": {
			n:       5,
			wantOut: []byte{0x01, 0x02, 0x03, 0x04, 0x01},
			wantKey: bits.RotateLeft32(key, -8),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := make([]byte, tt.n) // all zeros, so XOR yields the key bytes
			gotKey := maskRef(b, key)
			if !bytes.Equal(b, tt.wantOut) {
				t.Errorf("maskRef output = % x, want % x", b, tt.wantOut)
			}
			if gotKey != tt.wantKey {
				t.Errorf("maskRef key = %#08x, want %#08x", gotKey, tt.wantKey)
			}
		})
	}
}

// maxDiffLen is the largest payload length exercised by the differential
// sweep. 4097 forces the AVX-512 256-byte loop plus a partial trailing block.
const maxDiffLen = 4097

// offsetsFor returns the slice start offsets the differential sweep should try.
// The full 0..63 range covers every alignment relative to a 64-byte boundary;
// short mode keeps only representative offsets so -race -short stays quick.
func offsetsFor(short bool) []int {
	if short {
		return []int{0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63}
	}
	offs := make([]int, 64)
	for i := range offs {
		offs[i] = i
	}
	return offs
}

// TestKernelsDifferential masks the same input with every available kernel and
// the reference at every length 0..4097 and every start offset 0..63, then
// checks that both the transformed bytes and the returned key match. This is
// the primary defense against tail/alignment/key-phase bugs in the assembly.
func TestKernelsDifferential(t *testing.T) {
	t.Parallel()

	const key = 0x9e3779b1 // a non-trivial key exercising all four lanes
	offsets := offsetsFor(testing.Short())

	rng := newRNG()
	src := make([]byte, maxDiffLen+64)
	fillRand(src, rng)

	wantBuf := make([]byte, maxDiffLen)
	gotBuf := make([]byte, maxDiffLen)

	for _, kern := range Kernels() {
		for _, off := range offsets {
			for n := 0; n <= maxDiffLen; n++ {
				in := src[off : off+n]

				want := wantBuf[:n]
				copy(want, in)
				wantKey := maskRef(want, key)

				got := gotBuf[:n]
				copy(got, in)
				gotKey := kern.Fn(got, key)

				if gotKey != wantKey || !bytes.Equal(got, want) {
					t.Fatalf("kernel %s: off=%d n=%d\n got=% x key=%#08x\nwant=% x key=%#08x",
						kern.Name, off, n, got, gotKey, want, wantKey)
				}
			}
		}
	}
}

// TestKernelsKeys sweeps a set of keys (including edge values) at
// boundary-adjacent lengths to catch any key-dependent defect the single-key
// differential sweep would miss.
func TestKernelsKeys(t *testing.T) {
	t.Parallel()

	keys := []uint32{
		0x00000000, 0xffffffff, 0x000000ff, 0xff000000,
		0x01020304, 0x04030201, 0xdeadbeef, 0x9e3779b1, 0x80000001,
	}
	lengths := []int{
		0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33,
		63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 257,
		511, 512, 513, 1023, 1024, 4095, 4096, 4097,
	}

	rng := newRNG()
	src := make([]byte, 4097)
	fillRand(src, rng)

	for _, kern := range Kernels() {
		for _, key := range keys {
			for _, n := range lengths {
				want := append([]byte(nil), src[:n]...)
				wantKey := maskRef(want, key)

				got := append([]byte(nil), src[:n]...)
				gotKey := kern.Fn(got, key)

				if gotKey != wantKey || !bytes.Equal(got, want) {
					t.Fatalf("kernel %s: key=%#08x n=%d\n got=% x key=%#08x\nwant=% x key=%#08x",
						kern.Name, key, n, got, gotKey, want, wantKey)
				}
			}
		}
	}
}

// TestChunkResume verifies the resumable-key contract: masking a buffer in a
// random sequence of chunks, carrying the returned key from one to the next,
// must equal masking the whole buffer at once. Checked for every kernel and
// for the size-dispatching Mask entry point.
func TestChunkResume(t *testing.T) {
	t.Parallel()

	rng := newRNG()

	maskers := append([]NamedKernel{{Name: "dispatch", Fn: Mask}}, Kernels()...)

	for _, m := range maskers {
		for trial := range 2000 {
			n := int(rng.Uint64() % 5000)
			key := rng.Uint32()

			base := make([]byte, n)
			fillRand(base, rng)

			oneShot := append([]byte(nil), base...)
			m.Fn(oneShot, key)

			chunked := append([]byte(nil), base...)
			chunkKey := key
			rest := chunked
			// Split into 1-8 chunks at random boundaries.
			splits := 1 + int(rng.Uint64()%8)
			for s := 0; s < splits && len(rest) > 0; s++ {
				var take int
				if s == splits-1 {
					take = len(rest)
				} else {
					take = int(rng.Uint64() % uint64(len(rest)+1))
				}
				chunkKey = m.Fn(rest[:take], chunkKey)
				rest = rest[take:]
			}

			if !bytes.Equal(chunked, oneShot) {
				t.Fatalf("kernel %s: trial=%d n=%d key=%#08x chunked != one-shot\n chunked=% x\n oneShot=% x",
					m.Name, trial, n, key, chunked, oneShot)
			}
		}
	}
}

// TestMaskDispatch checks the production Mask entry point (which selects a
// kernel by size and CPU features) against the reference across sizes that
// straddle the dispatch thresholds.
func TestMaskDispatch(t *testing.T) {
	t.Parallel()

	rng := newRNG()
	lengths := []int{
		0, 1, 8, 63, 64, 65, 100, 511, 512, 513, 1000,
		4095, 4096, 4097, 8192, 16384, 65537, 100000,
	}

	for _, n := range lengths {
		base := make([]byte, n)
		fillRand(base, rng)
		key := rng.Uint32()

		want := append([]byte(nil), base...)
		wantKey := maskRef(want, key)

		got := append([]byte(nil), base...)
		gotKey := Mask(got, key)

		if gotKey != wantKey || !bytes.Equal(got, want) {
			t.Fatalf("Mask n=%d key=%#08x: got key=%#08x want key=%#08x, bytes equal=%v",
				n, key, gotKey, wantKey, bytes.Equal(got, want))
		}
	}
}

// TestMaskGenericMatchesRef guards the production reference implementation
// itself (the one every kernel is compared to indirectly at the dispatch
// boundary) against the longhand reference.
func TestMaskGenericMatchesRef(t *testing.T) {
	t.Parallel()

	rng := newRNG()
	for n := 0; n <= 600; n++ {
		base := make([]byte, n)
		fillRand(base, rng)
		key := rng.Uint32()

		want := append([]byte(nil), base...)
		wantKey := maskRef(want, key)

		got := append([]byte(nil), base...)
		gotKey := maskGeneric(got, key)

		if gotKey != wantKey || !bytes.Equal(got, want) {
			t.Fatalf("maskGeneric n=%d: mismatch with reference", n)
		}
	}
}

// NamedKernel pairs a masking kernel with a human-readable name so tests and
// benchmarks can drive each implementation individually.
type NamedKernel struct {
	// Name identifies the kernel, e.g. "generic", "sse2", "avx512", "neon".
	Name string
	// Fn masks b in place and returns the resumable rotated key.
	Fn func(b []byte, key uint32) uint32
}

// genericKernel returns the always-present pure-Go reference kernel.
func genericKernel() NamedKernel {
	return NamedKernel{Name: "generic", Fn: maskGeneric}
}

// FuzzMask differentially fuzzes the size-dispatching Mask entry point and
// every available kernel against the longhand reference. Any payload/key that
// produces a differing transform or returned key is a crash.
func FuzzMask(f *testing.F) {
	seeds := []struct {
		b   []byte
		key uint32
	}{
		{nil, 0},
		{[]byte{}, 0xffffffff},
		{[]byte("h"), 0x01020304},
		{[]byte("hello, websocket"), 0x9e3779b1},
		{bytes.Repeat([]byte{0xa5}, 63), 0xdeadbeef},
		{bytes.Repeat([]byte{0x00}, 64), 0x80000001},
		{bytes.Repeat([]byte{0xff}, 255), 0x12345678},
		{bytes.Repeat([]byte{0x5a}, 4097), 0xcafebabe},
	}
	for _, s := range seeds {
		f.Add(s.b, s.key)
	}

	f.Fuzz(func(t *testing.T, b []byte, key uint32) {
		want := append([]byte(nil), b...)
		wantKey := maskRef(want, key)

		maskers := append([]NamedKernel{{Name: "dispatch", Fn: Mask}}, Kernels()...)
		for _, m := range maskers {
			got := append([]byte(nil), b...)
			gotKey := m.Fn(got, key)
			if gotKey != wantKey || !bytes.Equal(got, want) {
				t.Fatalf("kernel %s: len=%d key=%#08x mismatch\n got=% x key=%#08x\nwant=% x key=%#08x",
					m.Name, len(b), key, got, gotKey, want, wantKey)
			}
		}
	})
}

// benchSizes spans small control frames through large data frames so the
// size-threshold crossovers between kernels are visible in the curves.
var benchSizes = []int{16, 64, 256, 1024, 4096, 16384, 65536, 262144}

// benchCalibSizes are fine-grained sizes straddling the generic<->NEON
// crossover. BenchmarkKernelCalib sweeps them so thresholdSIMD can be read off
// the point where NEON first beats the generic word loop.
var benchCalibSizes = []int{8, 16, 24, 32, 48, 64, 96, 128}

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
// throughput curves used to calibrate the dispatch thresholds can be compared
// directly.
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

// BenchmarkKernelCalib sweeps each kernel across benchCalibSizes so the
// generic<->NEON crossover that fixes thresholdSIMD can be read directly off
// the throughput curves at fine granularity.
func BenchmarkKernelCalib(b *testing.B) {
	for _, kern := range Kernels() {
		b.Run(kern.Name, func(b *testing.B) {
			for _, size := range benchCalibSizes {
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					benchMask(b, kern.Fn, size)
				})
			}
		})
	}
}
