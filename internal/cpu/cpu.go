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

// Package cpu performs zero-dependency runtime detection of the SIMD CPU
// features used by the gows masking and UTF-8 kernels.
//
// Detection runs once at package initialization. The GOWS_SIMD environment
// variable is a kill switch read at that time: "off" disables all SIMD,
// "sse2" caps the amd64 dispatch at SSE2, "avx2" caps it at AVX2, and
// "avx512" (or an empty/unknown value) imposes no cap. On arm64, "off"
// disables NEON. The switch is provided as an escape hatch for environments
// where a SIMD path misbehaves (see plan §9 risk table).
package cpu

import (
	"os"
	"strings"
)

// simdCap is the normalized value of the GOWS_SIMD kill switch, read once at
// package initialization and consulted by the architecture-specific detectors.
var simdCap = strings.ToLower(strings.TrimSpace(os.Getenv("GOWS_SIMD")))

// x86Features reports the x86-64 SIMD features that gows can dispatch on.
type x86Features struct {
	// HasAVX2 reports whether AVX2 is present and enabled by the OS.
	HasAVX2 bool
	// HasAVX512 reports whether AVX-512 F+BW+VL are present, the OS has
	// enabled the opmask and ZMM register state, and the kill switch permits it.
	HasAVX512 bool
}

// X86 holds the detected x86-64 SIMD features. On non-amd64 platforms every
// field is false.
var X86 x86Features

// HasNEON reports whether ARM NEON (Advanced SIMD) is available. It is true on
// arm64 unless disabled via GOWS_SIMD=off, and false on every other platform.
var HasNEON bool
