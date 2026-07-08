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

// The three kernels share a scalar tail structure:
//   AX = data pointer, CX = remaining bytes, DX = live 32-bit key,
//   X0 = key broadcast into four 32-bit lanes (its low 128 bits survive
//        VZEROUPPER, so the AVX paths reuse it for the 16-byte tail),
//   BX = key duplicated into a 64-bit word for the 8-byte tail loop.
// Every block above the per-byte loop consumes a multiple of four bytes, so
// the key phase is unchanged until the final 0-3 bytes, which rotate DX. The
// returned key is DX after those rotations, i.e. RotateLeft32(key, -8*(n%4)).

// func maskSSE2(b *byte, n int, key uint32) uint32
TEXT ·maskSSE2(SB), NOSPLIT, $0-28
	MOVQ   b+0(FP), AX
	MOVQ   n+8(FP), CX
	MOVL   key+16(FP), DX
	MOVD   DX, X0
	PSHUFD $0, X0, X0

sse2_loop64:
	CMPQ  CX, $64
	JB    sse2_tail16
	MOVOU 0(AX), X1
	MOVOU 16(AX), X2
	MOVOU 32(AX), X3
	MOVOU 48(AX), X4
	PXOR  X0, X1
	PXOR  X0, X2
	PXOR  X0, X3
	PXOR  X0, X4
	MOVOU X1, 0(AX)
	MOVOU X2, 16(AX)
	MOVOU X3, 32(AX)
	MOVOU X4, 48(AX)
	ADDQ  $64, AX
	SUBQ  $64, CX
	JMP   sse2_loop64

sse2_tail16:
	CMPQ  CX, $16
	JB    sse2_tail8setup
	MOVOU (AX), X1
	PXOR  X0, X1
	MOVOU X1, (AX)
	ADDQ  $16, AX
	SUBQ  $16, CX
	JMP   sse2_tail16

sse2_tail8setup:
	MOVL DX, BX
	MOVQ BX, R8
	SHLQ $32, R8
	ORQ  R8, BX

sse2_tail8:
	CMPQ CX, $8
	JB   sse2_tailbyte
	MOVQ (AX), R9
	XORQ BX, R9
	MOVQ R9, (AX)
	ADDQ $8, AX
	SUBQ $8, CX
	JMP  sse2_tail8

sse2_tailbyte:
	TESTQ   CX, CX
	JZ      sse2_done
	MOVBLZX (AX), R9
	XORL    DX, R9
	MOVB    R9, (AX)
	RORL    $8, DX
	INCQ    AX
	DECQ    CX
	JMP     sse2_tailbyte

sse2_done:
	MOVL DX, ret+24(FP)
	RET

// func maskAVX2(b *byte, n int, key uint32) uint32
TEXT ·maskAVX2(SB), NOSPLIT, $0-28
	MOVQ        b+0(FP), AX
	MOVQ        n+8(FP), CX
	MOVL        key+16(FP), DX
	VMOVD       DX, X0
	VPBROADCASTD X0, Y0

avx2_loop128:
	CMPQ    CX, $128
	JB      avx2_loop32
	VMOVDQU 0(AX), Y1
	VMOVDQU 32(AX), Y2
	VMOVDQU 64(AX), Y3
	VMOVDQU 96(AX), Y4
	VPXOR   Y0, Y1, Y1
	VPXOR   Y0, Y2, Y2
	VPXOR   Y0, Y3, Y3
	VPXOR   Y0, Y4, Y4
	VMOVDQU Y1, 0(AX)
	VMOVDQU Y2, 32(AX)
	VMOVDQU Y3, 64(AX)
	VMOVDQU Y4, 96(AX)
	ADDQ    $128, AX
	SUBQ    $128, CX
	JMP     avx2_loop128

avx2_loop32:
	CMPQ    CX, $32
	JB      avx2_leaveupper
	VMOVDQU (AX), Y1
	VPXOR   Y0, Y1, Y1
	VMOVDQU Y1, (AX)
	ADDQ    $32, AX
	SUBQ    $32, CX
	JMP     avx2_loop32

avx2_leaveupper:
	VZEROUPPER

avx2_tail16:
	CMPQ  CX, $16
	JB    avx2_tail8setup
	MOVOU (AX), X1
	PXOR  X0, X1
	MOVOU X1, (AX)
	ADDQ  $16, AX
	SUBQ  $16, CX
	JMP   avx2_tail16

avx2_tail8setup:
	MOVL DX, BX
	MOVQ BX, R8
	SHLQ $32, R8
	ORQ  R8, BX

avx2_tail8:
	CMPQ CX, $8
	JB   avx2_tailbyte
	MOVQ (AX), R9
	XORQ BX, R9
	MOVQ R9, (AX)
	ADDQ $8, AX
	SUBQ $8, CX
	JMP  avx2_tail8

avx2_tailbyte:
	TESTQ   CX, CX
	JZ      avx2_done
	MOVBLZX (AX), R9
	XORL    DX, R9
	MOVB    R9, (AX)
	RORL    $8, DX
	INCQ    AX
	DECQ    CX
	JMP     avx2_tailbyte

avx2_done:
	MOVL DX, ret+24(FP)
	RET

// func maskAVX512(b *byte, n int, key uint32) uint32
TEXT ·maskAVX512(SB), NOSPLIT, $0-28
	MOVQ         b+0(FP), AX
	MOVQ         n+8(FP), CX
	MOVL         key+16(FP), DX
	VMOVD        DX, X0
	VPBROADCASTD X0, Z0

avx512_loop256:
	CMPQ      CX, $256
	JB        avx512_loop64
	VMOVDQU64 0(AX), Z1
	VMOVDQU64 64(AX), Z2
	VMOVDQU64 128(AX), Z3
	VMOVDQU64 192(AX), Z4
	VPXORQ    Z0, Z1, Z1
	VPXORQ    Z0, Z2, Z2
	VPXORQ    Z0, Z3, Z3
	VPXORQ    Z0, Z4, Z4
	VMOVDQU64 Z1, 0(AX)
	VMOVDQU64 Z2, 64(AX)
	VMOVDQU64 Z3, 128(AX)
	VMOVDQU64 Z4, 192(AX)
	ADDQ      $256, AX
	SUBQ      $256, CX
	JMP       avx512_loop256

avx512_loop64:
	CMPQ      CX, $64
	JB        avx512_leaveupper
	VMOVDQU64 (AX), Z1
	VPXORQ    Z0, Z1, Z1
	VMOVDQU64 Z1, (AX)
	ADDQ      $64, AX
	SUBQ      $64, CX
	JMP       avx512_loop64

avx512_leaveupper:
	VZEROUPPER

avx512_tail16:
	CMPQ  CX, $16
	JB    avx512_tail8setup
	MOVOU (AX), X1
	PXOR  X0, X1
	MOVOU X1, (AX)
	ADDQ  $16, AX
	SUBQ  $16, CX
	JMP   avx512_tail16

avx512_tail8setup:
	MOVL DX, BX
	MOVQ BX, R8
	SHLQ $32, R8
	ORQ  R8, BX

avx512_tail8:
	CMPQ CX, $8
	JB   avx512_tailbyte
	MOVQ (AX), R9
	XORQ BX, R9
	MOVQ R9, (AX)
	ADDQ $8, AX
	SUBQ $8, CX
	JMP  avx512_tail8

avx512_tailbyte:
	TESTQ   CX, CX
	JZ      avx512_done
	MOVBLZX (AX), R9
	XORL    DX, R9
	MOVB    R9, (AX)
	RORL    $8, DX
	INCQ    AX
	DECQ    CX
	JMP     avx512_tailbyte

avx512_done:
	MOVL DX, ret+24(FP)
	RET
