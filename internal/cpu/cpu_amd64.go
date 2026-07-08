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

//go:build amd64

package cpu

// cpuid executes the CPUID instruction with the given EAX (leaf) and ECX
// (subleaf) inputs and returns the resulting EAX, EBX, ECX, and EDX registers.
//
//go:noescape
func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// xgetbv executes XGETBV with ECX=0 and returns the low 32 bits of XCR0. The
// caller must confirm CPUID leaf 1 reported OSXSAVE before invoking it, since
// XGETBV faults when CR4.OSXSAVE is clear.
//
//go:noescape
func xgetbv() uint32

func init() {
	if simdCap == "off" {
		return
	}

	maxLeaf, _, _, _ := cpuid(0, 0)
	if maxLeaf < 1 {
		return
	}

	const (
		bitOSXSAVE = 1 << 27 // CPUID.1:ECX.OSXSAVE
		bitAVX     = 1 << 28 // CPUID.1:ECX.AVX
	)
	_, _, ecx1, _ := cpuid(1, 0)
	if ecx1&bitOSXSAVE == 0 || ecx1&bitAVX == 0 {
		// Without OSXSAVE the OS has not enabled XSAVE-managed vector state,
		// so no AVX-family path (which all assume YMM/ZMM state) is usable.
		return
	}

	xcr0 := xgetbv()
	const xcr0XMMYMM = 0x6 // XCR0 bits 1 (XMM) and 2 (YMM).
	if xcr0&xcr0XMMYMM != xcr0XMMYMM {
		return
	}

	if maxLeaf < 7 {
		return
	}
	_, ebx7, _, _ := cpuid(7, 0)

	const (
		bitAVX2     = 1 << 5
		bitAVX512F  = 1 << 16
		bitAVX512BW = 1 << 30
		bitAVX512VL = 1 << 31
	)

	hasAVX2 := ebx7&bitAVX2 != 0

	// AVX-512 additionally requires the OS to have enabled the opmask (bit 5),
	// ZMM_Hi256 (bit 6), and Hi16_ZMM (bit 7) state components. Using ZMM
	// without this check risks SIGILL on kernels/VMs that do not save that
	// state (plan §10 XCR0 risk).
	const xcr0AVX512 = 0xe0
	zmmEnabled := xcr0&xcr0AVX512 == xcr0AVX512
	hasAVX512 := zmmEnabled &&
		ebx7&bitAVX512F != 0 &&
		ebx7&bitAVX512BW != 0 &&
		ebx7&bitAVX512VL != 0

	switch simdCap {
	case "sse2":
		hasAVX2, hasAVX512 = false, false
	case "avx2":
		hasAVX512 = false
	}

	X86.HasAVX2 = hasAVX2
	X86.HasAVX512 = hasAVX512
}
