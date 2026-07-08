// Package gws vendors lxzan/gws's unexported masking kernel for benchmark
// comparison purposes (bench/kernels_test.go).
//
// Source: github.com/lxzan/gws@v1.9.1, internal/utils.go, func MaskXOR.
// License: Apache-2.0 (lxzan).
// https://github.com/lxzan/gws/blob/v1.9.1/LICENSE
package gws

import "encoding/binary"

// MaskXOR is a verbatim copy of lxzan/gws's internal.MaskXOR, kept under its
// original (exported-within-gws) name. Unlike gorilla/coder, it masks the
// full buffer in one call rather than returning a rotated key for chunked
// resumption.
func MaskXOR(b []byte, key []byte) {
	var maskKey = binary.LittleEndian.Uint32(key)
	var key64 = uint64(maskKey)<<32 + uint64(maskKey)

	for len(b) >= 64 {
		v := binary.LittleEndian.Uint64(b)
		binary.LittleEndian.PutUint64(b, v^key64)
		v = binary.LittleEndian.Uint64(b[8:16])
		binary.LittleEndian.PutUint64(b[8:16], v^key64)
		v = binary.LittleEndian.Uint64(b[16:24])
		binary.LittleEndian.PutUint64(b[16:24], v^key64)
		v = binary.LittleEndian.Uint64(b[24:32])
		binary.LittleEndian.PutUint64(b[24:32], v^key64)
		v = binary.LittleEndian.Uint64(b[32:40])
		binary.LittleEndian.PutUint64(b[32:40], v^key64)
		v = binary.LittleEndian.Uint64(b[40:48])
		binary.LittleEndian.PutUint64(b[40:48], v^key64)
		v = binary.LittleEndian.Uint64(b[48:56])
		binary.LittleEndian.PutUint64(b[48:56], v^key64)
		v = binary.LittleEndian.Uint64(b[56:64])
		binary.LittleEndian.PutUint64(b[56:64], v^key64)
		b = b[64:]
	}

	for len(b) >= 8 {
		v := binary.LittleEndian.Uint64(b[:8])
		binary.LittleEndian.PutUint64(b[:8], v^key64)
		b = b[8:]
	}

	var n = len(b)
	for i := 0; i < n; i++ {
		idx := i & 3
		b[i] ^= key[idx]
	}
}
