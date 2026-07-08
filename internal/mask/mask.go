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

//go:build purego || (!amd64 && !arm64)

package mask

// Mask XORs b in place with the little-endian 4-byte key and returns the key
// rotated for resuming a chunked payload; see the package documentation for
// the exact contract.
//
// This build has no assembly kernel (the purego tag or an architecture without
// a gows SIMD implementation), so it always uses the pure-Go word loop.
func Mask(b []byte, key uint32) uint32 {
	return maskGeneric(b, key)
}
