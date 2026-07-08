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

// func maskNEON(b *byte, n int, key uint32) uint32
//
// Registers:
//   R0 = data pointer
//   R1 = remaining byte count
//   R2 = current 32-bit key (rotated only across the per-byte tail)
//   R3 = 64-bit key (key duplicated into both halves) for the 8-byte loop
//   R4 = scratch load/store value
//   V0 = key broadcast into all four 32-bit lanes
//   V1..V4 = payload vectors
TEXT ·maskNEON(SB), NOSPLIT, $0-28
	MOVD  b+0(FP), R0
	MOVD  n+8(FP), R1
	MOVWU key+16(FP), R2
	VDUP  R2, V0.S4

loop64:
	CMP  $64, R1
	BLO  tail16
	VLD1 (R0), [V1.B16, V2.B16, V3.B16, V4.B16]
	VEOR V0.B16, V1.B16, V1.B16
	VEOR V0.B16, V2.B16, V2.B16
	VEOR V0.B16, V3.B16, V3.B16
	VEOR V0.B16, V4.B16, V4.B16
	VST1 [V1.B16, V2.B16, V3.B16, V4.B16], (R0)
	ADD  $64, R0
	SUB  $64, R1
	B    loop64

tail16:
	CMP  $16, R1
	BLO  tail8setup
	VLD1 (R0), [V1.B16]
	VEOR V0.B16, V1.B16, V1.B16
	VST1 [V1.B16], (R0)
	ADD  $16, R0
	SUB  $16, R1
	B    tail16

tail8setup:
	// R3 = key | key<<32, the 64-bit mask for the 8-byte loop.
	LSL $32, R2, R3
	ORR R2, R3, R3

tail8:
	CMP  $8, R1
	BLO  tailbyte
	MOVD (R0), R4
	EOR  R3, R4, R4
	MOVD R4, (R0)
	ADD  $8, R0
	SUB  $8, R1
	B    tail8

tailbyte:
	CBZ   R1, done
	MOVBU (R0), R4
	EOR   R2, R4, R4
	MOVB  R4, (R0)
	RORW  $8, R2, R2
	ADD   $1, R0
	SUB   $1, R1
	B     tailbyte

done:
	MOVW R2, ret+24(FP)
	RET
