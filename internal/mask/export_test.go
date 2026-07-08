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
