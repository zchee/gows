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

// thresholdSIMD is the payload size below which the pure-Go word loop beats a
// NEON setup. It is a placeholder pending benchstat calibration (plan §5.3).
const thresholdSIMD = 64

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
