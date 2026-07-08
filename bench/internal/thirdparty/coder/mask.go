// Package coder vendors coder/websocket's unexported pure-Go masking kernel
// for benchmark comparison purposes (bench/kernels_test.go). This is the
// path coder/websocket actually ships on amd64/arm64: its asm masker
// (mask_amd64.s) is present in the source tree but disabled at the call site
// ("TODO: Will enable in v1.9.0", see mask_asm.go) pending a rewrite, so
// maskGo is what every current release executes.
//
// Source: github.com/coder/websocket@v1.8.15, mask.go, func maskGo.
// License: ISC (coder/websocket, formerly nhooyr.io/websocket).
// https://github.com/coder/websocket/blob/v1.8.15/LICENSE.txt
package coder

import (
	"encoding/binary"
	"math/bits"
)

// MaskGo is a verbatim copy of coder/websocket's unexported maskGo, renamed
// for exported use. It applies the WebSocket masking algorithm to b with the
// given key and returns the correctly rotated key so callers can resume
// masking a subsequent chunk.
func MaskGo(b []byte, key uint32) uint32 {
	if len(b) >= 8 {
		key64 := uint64(key)<<32 | uint64(key)

		for len(b) >= 128 {
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
			v = binary.LittleEndian.Uint64(b[64:72])
			binary.LittleEndian.PutUint64(b[64:72], v^key64)
			v = binary.LittleEndian.Uint64(b[72:80])
			binary.LittleEndian.PutUint64(b[72:80], v^key64)
			v = binary.LittleEndian.Uint64(b[80:88])
			binary.LittleEndian.PutUint64(b[80:88], v^key64)
			v = binary.LittleEndian.Uint64(b[88:96])
			binary.LittleEndian.PutUint64(b[88:96], v^key64)
			v = binary.LittleEndian.Uint64(b[96:104])
			binary.LittleEndian.PutUint64(b[96:104], v^key64)
			v = binary.LittleEndian.Uint64(b[104:112])
			binary.LittleEndian.PutUint64(b[104:112], v^key64)
			v = binary.LittleEndian.Uint64(b[112:120])
			binary.LittleEndian.PutUint64(b[112:120], v^key64)
			v = binary.LittleEndian.Uint64(b[120:128])
			binary.LittleEndian.PutUint64(b[120:128], v^key64)
			b = b[128:]
		}

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

		for len(b) >= 32 {
			v := binary.LittleEndian.Uint64(b)
			binary.LittleEndian.PutUint64(b, v^key64)
			v = binary.LittleEndian.Uint64(b[8:16])
			binary.LittleEndian.PutUint64(b[8:16], v^key64)
			v = binary.LittleEndian.Uint64(b[16:24])
			binary.LittleEndian.PutUint64(b[16:24], v^key64)
			v = binary.LittleEndian.Uint64(b[24:32])
			binary.LittleEndian.PutUint64(b[24:32], v^key64)
			b = b[32:]
		}

		for len(b) >= 16 {
			v := binary.LittleEndian.Uint64(b)
			binary.LittleEndian.PutUint64(b, v^key64)
			v = binary.LittleEndian.Uint64(b[8:16])
			binary.LittleEndian.PutUint64(b[8:16], v^key64)
			b = b[16:]
		}

		for len(b) >= 8 {
			v := binary.LittleEndian.Uint64(b)
			binary.LittleEndian.PutUint64(b, v^key64)
			b = b[8:]
		}
	}

	for len(b) >= 4 {
		v := binary.LittleEndian.Uint32(b)
		binary.LittleEndian.PutUint32(b, v^key)
		b = b[4:]
	}

	for i := range b {
		b[i] ^= byte(key)
		key = bits.RotateLeft32(key, -8)
	}

	return key
}
