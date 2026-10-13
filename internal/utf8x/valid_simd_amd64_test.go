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

package utf8x

import "github.com/zchee/gows/internal/cpu"

// Bind the shared kernel differential tests (valid_simd_test.go) to the
// AVX2 kernel.
func init() {
	kernelName = "avx2"
	kernelBlock = 32
	kernelPresent = cpu.X86.HasAVX2
	bulkKernel = func(b []byte) bool { return utf8ValidAVX2(&b[0], len(b)) }
}
