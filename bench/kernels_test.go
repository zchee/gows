// Package bench holds mask-kernel comparison benchmarks against vendored
// competitor kernels: gorilla maskBytes, coder maskGo, gws MaskXOR, and
// gobwas Cipher, under internal/thirdparty with attribution (see that
// package's doc comments) rather than go:linkname'd, for build stability
// across upstream refactors. BenchmarkMaskGoWS calls gows's own
// internal/mask.Mask directly (not vendored -- gows is a real dependency
// of this module via the local replace in go.mod), exercising its actual
// runtime CPU-feature dispatch (AVX2/AVX-512/NEON/scalar) rather than one
// fixed kernel, same as production traffic would hit.
//
// Run with: go test -bench=BenchmarkMask -benchmem -count=10 ./...
package bench

import (
	"strconv"
	"testing"

	"github.com/zchee/gows/internal/mask"

	tpcoder "github.com/zchee/gows/bench/internal/thirdparty/coder"
	tpgobwas "github.com/zchee/gows/bench/internal/thirdparty/gobwas"
	tpgorilla "github.com/zchee/gows/bench/internal/thirdparty/gorilla"
	tpgws "github.com/zchee/gows/bench/internal/thirdparty/gws"
)

// sizes matches the standard kernel-benchmark size sweep.
var sizes = []int{64, 256, 1024, 4096, 16384, 65536}

var maskKey = [4]byte{0x12, 0x34, 0x56, 0x78}

func BenchmarkMaskGorilla(b *testing.B) {
	for _, n := range sizes {
		b.Run(sizeName(n), func(b *testing.B) {
			buf := make([]byte, n)
			b.SetBytes(int64(n))
			for b.Loop() {
				tpgorilla.MaskBytes(maskKey, 0, buf)
			}
		})
	}
}

func BenchmarkMaskCoder(b *testing.B) {
	for _, n := range sizes {
		b.Run(sizeName(n), func(b *testing.B) {
			buf := make([]byte, n)
			key := uint32(0x78563412)
			b.SetBytes(int64(n))
			for b.Loop() {
				key = tpcoder.MaskGo(buf, key)
			}
		})
	}
}

func BenchmarkMaskGWS(b *testing.B) {
	for _, n := range sizes {
		b.Run(sizeName(n), func(b *testing.B) {
			buf := make([]byte, n)
			key := maskKey[:]
			b.SetBytes(int64(n))
			for b.Loop() {
				tpgws.MaskXOR(buf, key)
			}
		})
	}
}

func BenchmarkMaskGobwas(b *testing.B) {
	for _, n := range sizes {
		b.Run(sizeName(n), func(b *testing.B) {
			buf := make([]byte, n)
			b.SetBytes(int64(n))
			for b.Loop() {
				tpgobwas.Cipher(buf, maskKey, 0)
			}
		})
	}
}

// BenchmarkMaskGoWS exercises gows's own internal/mask.Mask, i.e. the exact
// kernel dispatch [Conn.ReadMessage]/[Conn.WriteMessage] use in production
// (see internal/mask's per-architecture calibration godocs for the numbers
// this benchmark cross-checks on linux/amd64).
func BenchmarkMaskGoWS(b *testing.B) {
	for _, n := range sizes {
		b.Run(sizeName(n), func(b *testing.B) {
			buf := make([]byte, n)
			key := uint32(0x78563412)
			b.SetBytes(int64(n))
			for b.Loop() {
				key = mask.Mask(buf, key)
			}
		})
	}
}

func sizeName(n int) string {
	if n < 1024 {
		return strconv.Itoa(n) + "B"
	}
	return strconv.Itoa(n/1024) + "KB"
}
