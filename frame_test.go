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

package gows_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/zchee/gows"
)

func TestOpcodeClassification(t *testing.T) {
	tests := map[string]struct {
		op          gows.Opcode
		wantControl bool
		wantData    bool
	}{
		"continuation":         {op: gows.OpcodeContinuation, wantControl: false, wantData: false},
		"text":                 {op: gows.OpcodeText, wantControl: false, wantData: true},
		"binary":               {op: gows.OpcodeBinary, wantControl: false, wantData: true},
		"close":                {op: gows.OpcodeClose, wantControl: true, wantData: false},
		"ping":                 {op: gows.OpcodePing, wantControl: true, wantData: false},
		"pong":                 {op: gows.OpcodePong, wantControl: true, wantData: false},
		"reserved non-control": {op: gows.Opcode(0x5), wantControl: false, wantData: false},
		"reserved control":     {op: gows.Opcode(0xF), wantControl: true, wantData: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.op.IsControl(); got != tt.wantControl {
				t.Errorf("IsControl() = %v, want %v", got, tt.wantControl)
			}
			if got := tt.op.IsData(); got != tt.wantData {
				t.Errorf("IsData() = %v, want %v", got, tt.wantData)
			}
		})
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	tests := map[string]struct {
		h gows.Header
	}{
		"length 0, text, fin, unmasked": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeText, Length: 0},
		},
		"length 125, binary, fin, masked": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Masked: true, MaskKey: 0x11223344, Length: 125},
		},
		"length 126, text, unfin": {
			h: gows.Header{Fin: false, Opcode: gows.OpcodeText, Length: 126},
		},
		"length 127, binary": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Length: 127},
		},
		"length 128, text, masked": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeText, Masked: true, MaskKey: 0xdeadbeef, Length: 128},
		},
		"length 65535, binary": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Length: 65535},
		},
		"length 65536, text": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeText, Length: 65536},
		},
		"length 1<<40, binary, masked": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Masked: true, MaskKey: 0x01020304, Length: 1 << 40},
		},
		"close, fin, length 0": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeClose, Length: 0},
		},
		"ping, fin, length 125 (max control payload)": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodePing, Length: 125},
		},
		"pong, fin, masked": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodePong, Masked: true, MaskKey: 0xcafebabe, Length: 10},
		},
		"continuation, unfin": {
			h: gows.Header{Fin: false, Opcode: gows.OpcodeContinuation, Length: 50},
		},
		"rsv1 set": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeText, Rsv: gows.RSV1, Length: 4},
		},
		"rsv2 set": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Rsv: gows.RSV2, Length: 4},
		},
		"rsv3 set": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeText, Rsv: gows.RSV3, Length: 4},
		},
		"all rsv bits set": {
			h: gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Rsv: gows.RSV1 | gows.RSV2 | gows.RSV3, Length: 4},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			encoded := gows.AppendHeader(nil, tt.h)
			got, n, err := gows.DecodeHeader(encoded)
			if err != nil {
				t.Fatalf("DecodeHeader: unexpected error %v (encoded=% x)", err, encoded)
			}
			if n != len(encoded) {
				t.Fatalf("DecodeHeader: consumed %d, want %d", n, len(encoded))
			}
			if got != tt.h {
				t.Fatalf("DecodeHeader round-trip mismatch:\n got  %+v\n want %+v", got, tt.h)
			}
		})
	}
}

func TestDecodeHeaderShortBuffer(t *testing.T) {
	full := gows.AppendHeader(nil, gows.Header{
		Fin: true, Opcode: gows.OpcodeBinary, Masked: true,
		MaskKey: 0x11223344, Length: 1 << 21,
	})
	if len(full) != gows.MaxHeaderSize {
		t.Fatalf("setup: full header is %d bytes, want %d", len(full), gows.MaxHeaderSize)
	}

	for n := range len(full) {
		t.Run(fmt.Sprintf("truncated_at_%d", n), func(t *testing.T) {
			_, consumed, err := gows.DecodeHeader(full[:n])
			if !errors.Is(err, gows.ErrShortHeader) {
				t.Fatalf("DecodeHeader(len=%d): err = %v, want ErrShortHeader", n, err)
			}
			if consumed != 0 {
				t.Fatalf("DecodeHeader(len=%d): consumed = %d, want 0", n, consumed)
			}
		})
	}
}

func TestDecodeHeaderErrors(t *testing.T) {
	tests := map[string]struct {
		b       []byte
		wantErr error
	}{
		"error: reserved opcode 0x3": {
			b:       []byte{0x83, 0x00},
			wantErr: gows.ErrReservedOpcode,
		},
		"error: reserved opcode 0xB": {
			b:       []byte{0x8B, 0x00},
			wantErr: gows.ErrReservedOpcode,
		},
		"error: reserved opcode 0xF": {
			b:       []byte{0x8F, 0x00},
			wantErr: gows.ErrReservedOpcode,
		},
		"error: non-minimal 16-bit length (100 encoded as code 126)": {
			b:       []byte{0x82, 0x7E, 0x00, 0x64},
			wantErr: gows.ErrNonMinimalLength,
		},
		"error: non-minimal 64-bit length (65535 encoded as code 127)": {
			b: []byte{
				0x82, 0x7F,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
			},
			wantErr: gows.ErrNonMinimalLength,
		},
		"error: 64-bit length MSB set": {
			b: []byte{
				0x82, 0x7F,
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			wantErr: gows.ErrReservedLengthBit,
		},
		"error: control frame fragmented (ping, fin=0)": {
			b:       []byte{0x09, 0x00},
			wantErr: gows.ErrControlFrameFragmented,
		},
		"error: control frame too long (close, length 126)": {
			b:       gows.AppendHeader(nil, gows.Header{Fin: true, Opcode: gows.OpcodeClose, Length: 126}),
			wantErr: gows.ErrControlFrameTooLong,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, n, err := gows.DecodeHeader(tt.b)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("DecodeHeader(% x): err = %v, want %v", tt.b, err, tt.wantErr)
			}
			if n != 0 {
				t.Fatalf("DecodeHeader(% x): consumed = %d, want 0", tt.b, n)
			}
		})
	}
}

func TestValidCloseCode(t *testing.T) {
	tests := map[string]struct {
		code gows.CloseCode
		want bool
	}{
		"valid: 1000 normal closure":  {code: 1000, want: true},
		"valid: 1003 unsupported":     {code: 1003, want: true},
		"valid: 1007 invalid payload": {code: 1007, want: true},
		"valid: 1011 internal error":  {code: 1011, want: true},
		"valid: 1012 service restart": {code: 1012, want: true},
		"valid: 1013 try again later": {code: 1013, want: true},
		"valid: 1014 bad gateway":     {code: 1014, want: true},
		"valid: 3000":                 {code: 3000, want: true},
		"valid: 3999":                 {code: 3999, want: true},
		"valid: 4000":                 {code: 4000, want: true},
		"valid: 4999":                 {code: 4999, want: true},
		"invalid: 0":                  {code: 0, want: false},
		"invalid: 999":                {code: 999, want: false},
		"invalid: 1004 reserved":      {code: 1004, want: false},
		"invalid: 1005 no status":     {code: 1005, want: false},
		"invalid: 1006 abnormal":      {code: 1006, want: false},
		"invalid: 1015 tls handshake": {code: 1015, want: false},
		"invalid: 1016 unassigned":    {code: 1016, want: false},
		"invalid: 1100 unassigned":    {code: 1100, want: false},
		"invalid: 2000 unassigned":    {code: 2000, want: false},
		"invalid: 2999 unassigned":    {code: 2999, want: false},
		"invalid: 5000 out of range":  {code: 5000, want: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := gows.ValidCloseCode(tt.code); got != tt.want {
				t.Errorf("ValidCloseCode(%d) = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestCloseBodyRoundTrip(t *testing.T) {
	tests := map[string]struct {
		code   gows.CloseCode
		reason string
	}{
		"normal closure, no reason": {code: gows.CloseNormalClosure, reason: ""},
		"going away, with reason":   {code: gows.CloseGoingAway, reason: "server shutting down"},
		"protocol error":            {code: gows.CloseProtocolError, reason: "bad frame"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			body := gows.AppendCloseBody(nil, tt.code, []byte(tt.reason))
			code, reason, err := gows.ParseCloseBody(body)
			if err != nil {
				t.Fatalf("ParseCloseBody: unexpected error %v", err)
			}
			if code != tt.code {
				t.Errorf("code = %d, want %d", code, tt.code)
			}
			if string(reason) != tt.reason {
				t.Errorf("reason = %q, want %q", reason, tt.reason)
			}
		})
	}
}

func TestParseCloseBodyEmptyAndShort(t *testing.T) {
	code, reason, err := gows.ParseCloseBody(nil)
	if err != nil {
		t.Fatalf("ParseCloseBody(nil): unexpected error %v", err)
	}
	if code != gows.CloseNoStatusReceived {
		t.Errorf("ParseCloseBody(nil): code = %d, want %d (CloseNoStatusReceived)", code, gows.CloseNoStatusReceived)
	}
	if reason != nil {
		t.Errorf("ParseCloseBody(nil): reason = %q, want nil", reason)
	}

	_, _, err = gows.ParseCloseBody([]byte{0x01})
	if !errors.Is(err, gows.ErrShortCloseBody) {
		t.Fatalf("ParseCloseBody(1 byte): err = %v, want ErrShortCloseBody", err)
	}
}

func TestAppendHeaderAllocs(t *testing.T) {
	h := gows.Header{Fin: true, Opcode: gows.OpcodeBinary, Masked: true, MaskKey: 0x11223344, Length: 1 << 20}
	dst := make([]byte, 0, gows.MaxHeaderSize)
	f := func() {
		dst = gows.AppendHeader(dst[:0], h)
	}
	if avg := testing.AllocsPerRun(100, f); avg != 0 {
		t.Fatalf("AppendHeader: %.2f allocs/op, want 0", avg)
	}
}

func TestDecodeHeaderAllocs(t *testing.T) {
	encoded := gows.AppendHeader(nil, gows.Header{
		Fin: true, Opcode: gows.OpcodeBinary, Masked: true,
		MaskKey: 0x11223344, Length: 1 << 20,
	})
	f := func() {
		if _, _, err := gows.DecodeHeader(encoded); err != nil {
			t.Fatal(err)
		}
	}
	if avg := testing.AllocsPerRun(100, f); avg != 0 {
		t.Fatalf("DecodeHeader: %.2f allocs/op, want 0", avg)
	}
}

// FuzzDecodeHeader asserts that DecodeHeader never panics on arbitrary
// input, and that any header it successfully decodes re-encodes back to
// exactly the bytes it consumed.
func FuzzDecodeHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(gows.AppendHeader(nil, gows.Header{Fin: true, Opcode: gows.OpcodeText, Length: 0}))
	f.Add(gows.AppendHeader(nil, gows.Header{
		Fin: true, Opcode: gows.OpcodeBinary, Masked: true,
		MaskKey: 0x12345678, Length: 1 << 20,
	}))
	f.Add([]byte{0x82, 0x7E, 0x00, 0x64})
	f.Add([]byte{0x83, 0x00})
	f.Add([]byte{0x8B, 0x00})
	f.Add([]byte{0x09, 0x00})
	f.Add([]byte{0x82, 0x7F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, b []byte) {
		h, n, err := gows.DecodeHeader(b)
		if err != nil {
			if n != 0 {
				t.Fatalf("DecodeHeader error path: consumed = %d, want 0 (err=%v)", n, err)
			}
			return
		}
		if n < 2 || n > gows.MaxHeaderSize {
			t.Fatalf("DecodeHeader: consumed = %d, out of [2,%d]", n, gows.MaxHeaderSize)
		}
		if n > len(b) {
			t.Fatalf("DecodeHeader: consumed %d exceeds input length %d", n, len(b))
		}
		got := gows.AppendHeader(nil, h)
		if string(got) != string(b[:n]) {
			t.Fatalf("re-encode mismatch: decoded %+v from % x, re-encoded as % x", h, b[:n], got)
		}
	})
}

// FuzzHeaderRoundTrip asserts that AppendHeader followed by DecodeHeader
// reproduces the original header exactly, for any header value the
// fuzzer can construct that satisfies AppendHeader's documented
// preconditions (non-negative Length, Fin set and Length<=125 for
// control opcodes, a defined non-reserved opcode).
func FuzzHeaderRoundTrip(f *testing.F) {
	f.Add(true, byte(0), byte(0x1), false, uint32(0), int64(0))
	f.Add(true, byte(0x7), byte(0x2), true, uint32(0xdeadbeef), int64(1<<40))
	f.Add(false, byte(0), byte(0x0), false, uint32(0), int64(65536))

	f.Fuzz(func(t *testing.T, fin bool, rsv, opcode byte, masked bool, maskKey uint32, length int64) {
		op := gows.Opcode(opcode & 0x0f)
		if op >= 0x3 && op <= 0x7 || op >= 0xB {
			op = gows.OpcodeText // Steer reserved opcodes onto a defined one.
		}

		const lengthMask = 1<<62 - 1
		length &= lengthMask // Clamp to non-negative without risking MinInt64 negation overflow.

		if op.IsControl() {
			fin = true
			if length > 125 {
				length %= 126
			}
		}

		h := gows.Header{
			Fin:     fin,
			Rsv:     rsv & 0x7,
			Opcode:  op,
			Masked:  masked,
			MaskKey: maskKey,
			Length:  length,
		}
		if !masked {
			h.MaskKey = 0
		}

		encoded := gows.AppendHeader(nil, h)
		got, n, err := gows.DecodeHeader(encoded)
		if err != nil {
			t.Fatalf("DecodeHeader: unexpected error %v for header %+v (encoded=% x)", err, h, encoded)
		}
		if n != len(encoded) {
			t.Fatalf("DecodeHeader: consumed %d, want %d", n, len(encoded))
		}
		if got != h {
			t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got, h)
		}
	})
}

func BenchmarkAppendHeader(b *testing.B) {
	tests := map[string]gows.Header{
		"7-bit length":          {Fin: true, Opcode: gows.OpcodeText, Length: 100},
		"16-bit length":         {Fin: true, Opcode: gows.OpcodeBinary, Length: 65535},
		"64-bit length, masked": {Fin: true, Opcode: gows.OpcodeBinary, Masked: true, MaskKey: 0x11223344, Length: 1 << 32},
	}
	for name, h := range tests {
		b.Run(name, func(b *testing.B) {
			dst := make([]byte, 0, gows.MaxHeaderSize)
			b.ReportAllocs()
			for b.Loop() {
				dst = gows.AppendHeader(dst[:0], h)
			}
		})
	}
}

func BenchmarkDecodeHeader(b *testing.B) {
	tests := map[string]gows.Header{
		"7-bit length":          {Fin: true, Opcode: gows.OpcodeText, Length: 100},
		"16-bit length":         {Fin: true, Opcode: gows.OpcodeBinary, Length: 65535},
		"64-bit length, masked": {Fin: true, Opcode: gows.OpcodeBinary, Masked: true, MaskKey: 0x11223344, Length: 1 << 32},
	}
	for name, h := range tests {
		b.Run(name, func(b *testing.B) {
			encoded := gows.AppendHeader(nil, h)
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := gows.DecodeHeader(encoded); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
