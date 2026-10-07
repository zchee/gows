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

//go:build amd64 && !purego

package mask

import "github.com/zchee/gows/internal/cpu"

func maskSSE2Slice(b []byte, key uint32) uint32 {
	if len(b) == 0 {
		return key
	}
	return maskSSE2(&b[0], len(b), key)
}

func maskAVX2Slice(b []byte, key uint32) uint32 {
	if len(b) == 0 {
		return key
	}
	return maskAVX2(&b[0], len(b), key)
}

func maskAVX512Slice(b []byte, key uint32) uint32 {
	if len(b) == 0 {
		return key
	}
	return maskAVX512(&b[0], len(b), key)
}

// Kernels returns every masking kernel available on the current amd64 CPU.
// SSE2 is always present; AVX2 and AVX-512 are included only when detected so
// that running them can never fault on an unsupported machine.
func Kernels() []NamedKernel {
	ks := []NamedKernel{
		genericKernel(),
		{Name: "sse2", Fn: maskSSE2Slice},
	}
	if cpu.X86.HasAVX2 {
		ks = append(ks, NamedKernel{Name: "avx2", Fn: maskAVX2Slice})
	}
	if cpu.X86.HasAVX512 {
		ks = append(ks, NamedKernel{Name: "avx512", Fn: maskAVX512Slice})
	}
	return ks
}
