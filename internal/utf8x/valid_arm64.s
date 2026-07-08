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

#include "textflag.h"

// UTF-8 validation via the Keiser-Lemire "range" algorithm (simdutf), NEON
// port. Each 16-byte block is classified by three nibble-indexed lookup tables
// (byte_1_high, byte_1_low, byte_2_high) whose AND gives the per-position
// "special cases" flags; a continuation-length requirement (must23_80),
// computed here with two more nibble lookups over the high nibble of the byte
// two/three positions back, is XORed in. Any nonzero bit across all blocks is a
// structural error. A trailing incomplete sequence is intentionally NOT flagged
// (the caller's scalar DFA owns the boundary).

// Nibble lookup tables (see valid_test.go's exhaustive vectors for the encoding
// of every flag). Bytes are laid out low-to-high within each 8-byte DATA word.

// byte_1_high[hi(prev1)]: 0x02 x8, 0x80 x4, 0x21, 0x01, 0x15, 0x49
DATA tbl1high<>+0(SB)/8, $0x0202020202020202
DATA tbl1high<>+8(SB)/8, $0x4915012180808080
GLOBL tbl1high<>(SB), RODATA|NOPTR, $16

// byte_1_low[lo(prev1)]
DATA tbl1low<>+0(SB)/8, $0xCBCBCB8B8383A3E7
DATA tbl1low<>+8(SB)/8, $0xCBCBDBCBCBCBCBCB
GLOBL tbl1low<>(SB), RODATA|NOPTR, $16

// byte_2_high[hi(input)]
DATA tbl2high<>+0(SB)/8, $0x0101010101010101
DATA tbl2high<>+8(SB)/8, $0x01010101BABAAEE6
GLOBL tbl2high<>(SB), RODATA|NOPTR, $16

// is_third[hi(prev2)]: 0x80 at nibbles 14,15 (prev2 >= 0xE0)
DATA tblthird<>+0(SB)/8, $0x0000000000000000
DATA tblthird<>+8(SB)/8, $0x8080000000000000
GLOBL tblthird<>(SB), RODATA|NOPTR, $16

// is_fourth[hi(prev3)]: 0x80 at nibble 15 (prev3 >= 0xF0)
DATA tblfourth<>+0(SB)/8, $0x0000000000000000
DATA tblfourth<>+8(SB)/8, $0x8000000000000000
GLOBL tblfourth<>(SB), RODATA|NOPTR, $16

// low-nibble mask, all 0x0F
DATA masklow<>+0(SB)/8, $0x0F0F0F0F0F0F0F0F
DATA masklow<>+8(SB)/8, $0x0F0F0F0F0F0F0F0F
GLOBL masklow<>(SB), RODATA|NOPTR, $16

// func utf8ValidNEON(p *byte, n int) bool
TEXT ·utf8ValidNEON(SB), NOSPLIT, $0-17
	MOVD p+0(FP), R0
	MOVD n+8(FP), R1

	// Load the constant tables once (V6..V10) and the low-nibble mask (V11).
	MOVD  $tbl1high<>(SB), R2
	VLD1  (R2), [V6.B16]
	MOVD  $tbl1low<>(SB), R2
	VLD1  (R2), [V7.B16]
	MOVD  $tbl2high<>(SB), R2
	VLD1  (R2), [V8.B16]
	MOVD  $tblthird<>(SB), R2
	VLD1  (R2), [V9.B16]
	MOVD  $tblfourth<>(SB), R2
	VLD1  (R2), [V10.B16]
	MOVD  $masklow<>(SB), R2
	VLD1  (R2), [V11.B16]

	VEOR V1.B16, V1.B16, V1.B16 // prev_input = 0
	VEOR V5.B16, V5.B16, V5.B16 // error = 0

	CBZ R1, valid_ret // defensive: n == 0 has no structural error

loop:
	VLD1 (R0), [V0.B16] // input

	// prev1 = [prev[15], input[0..14]]; prev2, prev3 shift by 2, 3.
	VEXT $15, V0.B16, V1.B16, V2.B16
	VEXT $14, V0.B16, V1.B16, V3.B16
	VEXT $13, V0.B16, V1.B16, V4.B16

	// special cases = tbl1high[hi(prev1)] & tbl1low[lo(prev1)] & tbl2high[hi(input)]
	VUSHR $4, V2.B16, V12.B16   // hi(prev1)
	VAND  V11.B16, V2.B16, V13.B16 // lo(prev1)
	VUSHR $4, V0.B16, V14.B16   // hi(input)
	VTBL  V12.B16, [V6.B16], V15.B16
	VTBL  V13.B16, [V7.B16], V13.B16
	VTBL  V14.B16, [V8.B16], V14.B16
	VAND  V13.B16, V15.B16, V15.B16
	VAND  V14.B16, V15.B16, V15.B16 // V15 = sc

	// must23_80 = is_third[hi(prev2)] | is_fourth[hi(prev3)]  (0x80 where a
	// continuation is required at this position).
	VUSHR $4, V3.B16, V3.B16
	VUSHR $4, V4.B16, V4.B16
	VTBL  V3.B16, [V9.B16], V3.B16
	VTBL  V4.B16, [V10.B16], V4.B16
	VORR  V4.B16, V3.B16, V3.B16

	// error |= (must23_80 ^ sc)
	VEOR V15.B16, V3.B16, V3.B16
	VORR V3.B16, V5.B16, V5.B16

	VMOV V0.B16, V1.B16 // prev_input = input

	ADD $16, R0
	SUB $16, R1
	CBNZ R1, loop

	// error != 0 -> invalid
	VMOV V5.D[0], R2
	VMOV V5.D[1], R3
	ORR  R2, R3, R2
	CBNZ R2, invalid

valid_ret:
	MOVD $1, R0
	MOVB R0, ret+16(FP)
	RET

invalid:
	MOVB ZR, ret+16(FP)
	RET
