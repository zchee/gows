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

#include "textflag.h"

// UTF-8 validation via the Keiser-Lemire "range" algorithm (simdutf), AVX2
// port. Same classification as the NEON kernel (see valid_arm64.s), over
// 32-byte blocks. The cross-block byte shifts prev<1..3> are built with
// VPERM2I128 (to bridge the two 128-bit lanes) followed by VPALIGNR. Each
// lookup table is stored twice so a single per-lane VPSHUFB indexes both lanes.
// A trailing incomplete sequence is intentionally NOT flagged.

DATA tbl1high<>+0(SB)/8, $0x0202020202020202
DATA tbl1high<>+8(SB)/8, $0x4915012180808080
DATA tbl1high<>+16(SB)/8, $0x0202020202020202
DATA tbl1high<>+24(SB)/8, $0x4915012180808080
GLOBL tbl1high<>(SB), RODATA|NOPTR, $32

DATA tbl1low<>+0(SB)/8, $0xCBCBCB8B8383A3E7
DATA tbl1low<>+8(SB)/8, $0xCBCBDBCBCBCBCBCB
DATA tbl1low<>+16(SB)/8, $0xCBCBCB8B8383A3E7
DATA tbl1low<>+24(SB)/8, $0xCBCBDBCBCBCBCBCB
GLOBL tbl1low<>(SB), RODATA|NOPTR, $32

DATA tbl2high<>+0(SB)/8, $0x0101010101010101
DATA tbl2high<>+8(SB)/8, $0x01010101BABAAEE6
DATA tbl2high<>+16(SB)/8, $0x0101010101010101
DATA tbl2high<>+24(SB)/8, $0x01010101BABAAEE6
GLOBL tbl2high<>(SB), RODATA|NOPTR, $32

DATA tblthird<>+0(SB)/8, $0x0000000000000000
DATA tblthird<>+8(SB)/8, $0x8080000000000000
DATA tblthird<>+16(SB)/8, $0x0000000000000000
DATA tblthird<>+24(SB)/8, $0x8080000000000000
GLOBL tblthird<>(SB), RODATA|NOPTR, $32

DATA tblfourth<>+0(SB)/8, $0x0000000000000000
DATA tblfourth<>+8(SB)/8, $0x8000000000000000
DATA tblfourth<>+16(SB)/8, $0x0000000000000000
DATA tblfourth<>+24(SB)/8, $0x8000000000000000
GLOBL tblfourth<>(SB), RODATA|NOPTR, $32

DATA const0f<>+0(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA const0f<>+8(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA const0f<>+16(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA const0f<>+24(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL const0f<>(SB), RODATA|NOPTR, $32

// func utf8ValidAVX2(p *byte, n int) bool
TEXT ·utf8ValidAVX2(SB), NOSPLIT, $0-17
	MOVQ p+0(FP), AX
	MOVQ n+8(FP), CX

	VMOVDQU tbl1high<>(SB), Y7
	VMOVDQU tbl1low<>(SB), Y8
	VMOVDQU tbl2high<>(SB), Y9
	VMOVDQU tblthird<>(SB), Y10
	VMOVDQU tblfourth<>(SB), Y11
	VMOVDQU const0f<>(SB), Y12

	VPXOR Y1, Y1, Y1 // prev_input = 0
	VPXOR Y6, Y6, Y6 // error = 0

	TESTQ CX, CX
	JZ    valid

block:
	VMOVDQU (AX), Y0 // input

	// prev1/2/3 = input shifted right 1/2/3 bytes, carrying from prev_input.
	VPERM2I128 $0x21, Y0, Y1, Y2 // perm = [prev.hi128, input.lo128]
	VPALIGNR   $15, Y2, Y0, Y3   // prev1
	VPALIGNR   $14, Y2, Y0, Y4   // prev2
	VPALIGNR   $13, Y2, Y0, Y5   // prev3

	// special cases = tbl1high[hi(prev1)] & tbl1low[lo(prev1)] & tbl2high[hi(input)]
	VPSRLW  $4, Y0, Y13
	VPAND   Y12, Y13, Y13 // hi(input)
	VPSRLW  $4, Y3, Y14
	VPAND   Y12, Y14, Y14 // hi(prev1)
	VPAND   Y12, Y3, Y15  // lo(prev1)
	VPSHUFB Y14, Y7, Y14  // b1h
	VPSHUFB Y15, Y8, Y15  // b1l
	VPSHUFB Y13, Y9, Y13  // b2h
	VPAND   Y15, Y14, Y14
	VPAND   Y13, Y14, Y14 // sc

	// must23_80 = tblthird[hi(prev2)] | tblfourth[hi(prev3)]
	VPSRLW  $4, Y4, Y4
	VPAND   Y12, Y4, Y4
	VPSRLW  $4, Y5, Y5
	VPAND   Y12, Y5, Y5
	VPSHUFB Y4, Y10, Y4
	VPSHUFB Y5, Y11, Y5
	VPOR    Y5, Y4, Y4

	// error |= (must23_80 ^ sc)
	VPXOR Y14, Y4, Y4
	VPOR  Y4, Y6, Y6

	VMOVDQA Y0, Y1  // prev_input = input
	ADDQ    $32, AX
	SUBQ    $32, CX
	JNZ     block

	VPTEST Y6, Y6
	JNE    invalid

valid:
	VZEROUPPER
	MOVB $1, ret+16(FP)
	RET

invalid:
	VZEROUPPER
	MOVB $0, ret+16(FP)
	RET
