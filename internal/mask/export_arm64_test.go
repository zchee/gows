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

func maskNEONSlice(b []byte, key uint32) uint32 {
	if len(b) == 0 {
		return key
	}
	return maskNEON(&b[0], len(b), key)
}

// Kernels returns every masking kernel available on the current arm64 CPU: the
// pure-Go reference and, unless disabled via GOWS_SIMD, the NEON kernel.
func Kernels() []NamedKernel {
	ks := []NamedKernel{genericKernel()}
	if cpu.HasNEON {
		ks = append(ks, NamedKernel{Name: "neon", Fn: maskNEONSlice})
	}
	return ks
}
