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

// Package mask implements the RFC 6455 §5.3 payload transformation (masking),
// which XORs a payload with a repeating 4-byte key.
//
// The key is interpreted little-endian: byte i of the payload is XORed with
// byte i%4 of the key, i.e. byte(key >> (8*(i%4))). Mask processes a byte
// slice in place and returns the key rotated so that masking a subsequent
// chunk with the returned key is identical to masking the concatenation of
// both chunks with the original key. This resumable-key contract (matching
// coder/websocket) lets a caller mask a logically contiguous payload that
// arrives in several reads without buffering it whole.
//
// A pure-Go word-loop implementation is always available and serves as both
// the correctness reference and the fallback for platforms and build
// configurations without an assembly kernel. On amd64 and arm64 (without the
// purego build tag) Mask dispatches by payload size to SSE2/AVX2/AVX-512 or
// NEON kernels.
package mask

import (
	"encoding/binary"
	"math/bits"
)

// maskGeneric XORs b in place with the little-endian key and returns the key
// rotated right by 8*(len(b) mod 4) bits, so it can resume a chunked payload.
//
// It is the portable reference implementation: an unrolled 128-byte word loop
// followed by descending 64/32/16/8-byte blocks and a per-byte tail. Every
// block below the tail consumes a multiple of four bytes, so the key phase is
// preserved until the final 0–3 bytes, which rotate the key per byte.
func maskGeneric(b []byte, key uint32) uint32 {
	if len(b) >= 8 {
		key64 := uint64(key) | uint64(key)<<32

		for len(b) >= 128 {
			for off := 0; off < 128; off += 8 {
				v := binary.LittleEndian.Uint64(b[off:])
				binary.LittleEndian.PutUint64(b[off:], v^key64)
			}
			b = b[128:]
		}
		if len(b) >= 64 {
			for off := 0; off < 64; off += 8 {
				v := binary.LittleEndian.Uint64(b[off:])
				binary.LittleEndian.PutUint64(b[off:], v^key64)
			}
			b = b[64:]
		}
		if len(b) >= 32 {
			for off := 0; off < 32; off += 8 {
				v := binary.LittleEndian.Uint64(b[off:])
				binary.LittleEndian.PutUint64(b[off:], v^key64)
			}
			b = b[32:]
		}
		if len(b) >= 16 {
			v0 := binary.LittleEndian.Uint64(b[0:])
			v1 := binary.LittleEndian.Uint64(b[8:])
			binary.LittleEndian.PutUint64(b[0:], v0^key64)
			binary.LittleEndian.PutUint64(b[8:], v1^key64)
			b = b[16:]
		}
		if len(b) >= 8 {
			v := binary.LittleEndian.Uint64(b)
			binary.LittleEndian.PutUint64(b, v^key64)
			b = b[8:]
		}
	}

	for i := range b {
		b[i] ^= byte(key)
		key = bits.RotateLeft32(key, -8)
	}
	return key
}
