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

package gows

import (
	"encoding/binary"
	"errors"
	"testing"
)

// The tests in this file validate the table-driven frame-header decoder
// ([decodeFrameHeaderFast] and its [headerTables]) against the semantics of the
// [DecodeHeader]+checkFrameHeader pair it replaced. The oracle below
// reconstructs that pair: it drives the still-present [DecodeHeader] and then
// applies checkFrameHeader's role/RSV rules exactly as reader.go did at commit
// 2c13770, so any divergence in accept/reject decision, decoded Header, or
// close message is a regression the differential fuzz and unit tests catch.

// oracleKind classifies an oracle decode: needs more bytes, a valid header, or
// a rejected header.
type oracleKind uint8

const (
	oracleShort  oracleKind = iota // more bytes are needed; not a violation.
	oracleAccept                   // a valid header was decoded.
	oracleReject                   // the header violated an RFC 6455 rule.
)

// oracleDecodeHeader is the independent reference implementation of the frame
// header hot path for a Conn with the given role and negotiated compression
// state. It composes the retained [DecodeHeader] with a verbatim
// reconstruction of the former checkFrameHeader (reader.go @2c13770), and
// reports, for a rejected header, the exact close code and message reader.go
// failed the connection with at that commit. It is deliberately written from the
// original two-step formulation, not in terms of [decodeFrameHeaderFast], so
// that it is a genuine oracle rather than a restatement of the code under test.
func oracleDecodeHeader(client, compression bool, b []byte) (h Header, n int, kind oracleKind, code CloseCode, msg string) {
	dh, dn, err := DecodeHeader(b)
	if err != nil {
		if errors.Is(err, ErrShortHeader) {
			return Header{}, 0, oracleShort, 0, ""
		}
		// Every other DecodeHeader error was mapped by readHeaderWithPartialEOF
		// to a 1002 close with this exact prefix.
		return Header{}, 0, oracleReject, CloseProtocolError, "malformed frame header: " + err.Error()
	}

	// checkFrameHeader (reader.go @2c13770), reconstructed verbatim.
	rsv1OK := compression && dh.Rsv == RSV1 && !dh.Opcode.IsControl() && dh.Opcode != OpcodeContinuation
	if dh.Rsv != 0 && !rsv1OK {
		return Header{}, 0, oracleReject, CloseProtocolError, "invalid RSV bit for the negotiated extension set"
	}
	if client && dh.Masked {
		return Header{}, 0, oracleReject, CloseProtocolError, "masked frame received by client"
	}
	if !client && !dh.Masked {
		return Header{}, 0, oracleReject, CloseProtocolError, "unmasked frame received by server"
	}
	return dh, dn, oracleAccept, 0, ""
}

// fastDecodeHeader drives the code under test and normalizes its result into
// the same (kind, code, message) shape as [oracleDecodeHeader], mirroring how
// readHeaderWithPartialEOF consumes [decodeFrameHeaderFast]'s [hdrReject].
func fastDecodeHeader(client, compression bool, b []byte) (h Header, n int, kind oracleKind, code CloseCode, msg string) {
	tbl, maskBit := headerTableFor(client, compression)
	fh, fn, reason := decodeFrameHeaderFast(tbl, maskBit, b)
	switch reason {
	case rejectNone:
		return fh, fn, oracleAccept, 0, ""
	case rejectShort:
		return Header{}, 0, oracleShort, 0, ""
	default:
		// reader.go fails every non-short rejection with a 1002 protocol close.
		return Header{}, 0, oracleReject, CloseProtocolError, reason.closeMessage(client)
	}
}

// roleMatrix is the full {role x compression} matrix a single header-byte
// sequence must decode identically under: the b0 classification is
// role-independent, but the mask-bit expectation and RSV1 legality are not.
var roleMatrix = [...]struct {
	name        string
	client      bool
	compression bool
}{
	{"server/plain", false, false},
	{"server/deflate", false, true},
	{"client/plain", true, false},
	{"client/deflate", true, true},
}

// diffHeaderDecode asserts the fast decoder agrees with the oracle for b across
// the whole role/compression matrix, on the decision, the decoded Header, and
// the close code/message. It returns without failing for inputs both classify
// as needing more bytes.
func diffHeaderDecode(t *testing.T, b []byte) {
	t.Helper()
	for _, rc := range roleMatrix {
		wantH, wantN, wantKind, wantCode, wantMsg := oracleDecodeHeader(rc.client, rc.compression, b)
		gotH, gotN, gotKind, gotCode, gotMsg := fastDecodeHeader(rc.client, rc.compression, b)

		if gotKind != wantKind {
			t.Fatalf("%s: decision = %d, want %d\n input: % x", rc.name, gotKind, wantKind, b)
		}
		switch wantKind {
		case oracleAccept:
			if gotH != wantH || gotN != wantN {
				t.Fatalf("%s: accept mismatch\n got  header=%+v n=%d\n want header=%+v n=%d\n input: % x",
					rc.name, gotH, gotN, wantH, wantN, b)
			}
		case oracleReject:
			if gotCode != wantCode {
				t.Fatalf("%s: close code = %d, want %d\n input: % x", rc.name, gotCode, wantCode, b)
			}
			if gotMsg != wantMsg {
				t.Fatalf("%s: close message = %q, want %q\n input: % x", rc.name, gotMsg, wantMsg, b)
			}
		}
	}
}

// FuzzHeaderTableDifferential drives random header-byte sequences through the
// table-driven [decodeFrameHeaderFast] and the [DecodeHeader]+checkFrameHeader
// oracle for every {role x compression} combination, asserting they agree on
// the accept/reject decision, the decoded Header fields, and the 1002 close
// code and message text of each rejection.
func FuzzHeaderTableDifferential(f *testing.F) {
	// Seed: every possible first header byte, with a complete 2-byte
	// (unmasked, zero-length) header, exercising each opcode/Fin/RSV
	// classification and the reserved-opcode rejection.
	for b0 := range 256 {
		f.Add([]byte{byte(b0), 0x00})
	}

	// Seed: boundary payload lengths in each length encoding, minimal and
	// non-minimal, masked and unmasked, plus the reserved 64-bit MSB.
	lengthSeeds := [][]byte{
		{0x82, 0x7d},                                     // 7-bit max (125), unmasked.
		{0x82, 0x00},                                     // 7-bit zero, unmasked.
		{0x82, 0xfd, 0xde, 0xad, 0xbe, 0xef},             // 7-bit max (125), masked.
		{0x82, 0x7e, 0x00, 0x7e},                         // 16-bit minimal boundary (126).
		{0x82, 0x7e, 0xff, 0xff},                         // 16-bit max (65535).
		{0x82, 0x7e, 0x00, 0x64},                         // 16-bit non-minimal (100).
		{0x82, 0x7e, 0x00, 0x7d},                         // 16-bit non-minimal boundary (125).
		{0x82, 0xfe, 0x03, 0xe8, 0xde, 0xad, 0xbe, 0xef}, // 16-bit masked (old fast-path shape).
		{0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},             // 64-bit minimal boundary (65536).
		{0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff},             // 64-bit non-minimal (65535).
		{0x82, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},             // 64-bit max (2^63-1).
		{0x82, 0x7f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},             // 64-bit reserved MSB set (2^63).
		{0x82, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 1, 2, 3, 4}, // 64-bit masked (1<<20).
		{0x81, 0x85, 0xde, 0xad, 0xbe, 0xef},                                     // 7-bit masked text (5).
	}
	for _, s := range lengthSeeds {
		f.Add(s)
	}

	// Seed: RSV-bit combinations (legal only as RSV1 on a compressed data
	// frame), control-frame rules, reserved opcodes, and mask-bit violations
	// for both roles.
	otherSeeds := [][]byte{
		{0xc2, 0x00},               // RSV1 + binary (compressed data frame start).
		{0xc1, 0x00},               // RSV1 + text.
		{0xc0, 0x00},               // RSV1 + continuation (illegal even compressed).
		{0xc8, 0x00},               // RSV1 + close control (illegal even compressed).
		{0xa2, 0x00},               // RSV2 + binary (always illegal).
		{0x92, 0x00},               // RSV3 + binary (always illegal).
		{0xe2, 0x00},               // RSV1+RSV2 + binary (never legal, not bare RSV1).
		{0x88, 0x00},               // Close, Fin, empty (valid control).
		{0x08, 0x00},               // Close, not Fin (fragmented control).
		{0x88, 0x7e, 0x00, 0x7e},   // Close, 126 bytes (control too long).
		{0x89, 0x7d},               // Ping, 125 bytes (valid control boundary).
		{0x83, 0x00}, {0x87, 0x00}, // Reserved data opcodes.
		{0x8b, 0x00}, {0x8f, 0x00}, // Reserved control opcodes.
		{0x82, 0x80, 0x01, 0x02, 0x03, 0x04},         // Masked binary (rejected by a client).
		{0x82, 0x00},                                 // Unmasked binary (rejected by a server).
		{}, {0x82}, {0x82, 0xfe}, {0x82, 0xff, 0x00}, // Truncated at various points.
	}
	for _, s := range otherSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		diffHeaderDecode(t, b)
	})
}

// TestHeaderTableDifferentialSeeds runs the differential check over the fuzz
// seed corpus deterministically, so the parity guarantee is exercised by the
// normal (non-fuzz) test run as well.
func TestHeaderTableDifferentialSeeds(t *testing.T) {
	t.Parallel()
	for b0 := range 256 {
		diffHeaderDecode(t, []byte{byte(b0), 0x00})
		diffHeaderDecode(t, []byte{byte(b0), 0x80, 1, 2, 3, 4})
		diffHeaderDecode(t, []byte{byte(b0), 0xfe, 0x04, 0x00, 1, 2, 3, 4})
	}
}

// TestClassifyHeaderByte pins classifyHeaderByte's per-b0 classification
// against first-principles expectations across the opcode/Fin/RSV space and
// both compression states, including the RSV1-legality divergence RFC 7692
// introduces when permessage-deflate is negotiated.
func TestClassifyHeaderByte(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		b0          byte
		compression bool
		want        headerClass
	}{
		"text, fin, no rsv": {
			b0:   0x81,
			want: headerClass{opcode: OpcodeText, rsv: 0, fin: true},
		},
		"binary, fin, no rsv": {
			b0:   0x82,
			want: headerClass{opcode: OpcodeBinary, rsv: 0, fin: true},
		},
		"text, no fin": {
			b0:   0x01,
			want: headerClass{opcode: OpcodeText, rsv: 0, fin: false},
		},
		"continuation, no fin, no rsv": {
			b0:   0x00,
			want: headerClass{opcode: OpcodeContinuation, rsv: 0, fin: false},
		},
		"close control, fin": {
			b0:   0x88,
			want: headerClass{opcode: OpcodeClose, rsv: 0, fin: true, control: true},
		},
		"ping control, fin": {
			b0:   0x89,
			want: headerClass{opcode: OpcodePing, rsv: 0, fin: true, control: true},
		},
		"pong control, fin": {
			b0:   0x8a,
			want: headerClass{opcode: OpcodePong, rsv: 0, fin: true, control: true},
		},
		"reserved data opcode 0x3": {
			b0:   0x83,
			want: headerClass{opcode: Opcode(0x3), rsv: 0, fin: true, reserved: true},
		},
		"reserved data opcode 0x7": {
			b0:   0x87,
			want: headerClass{opcode: Opcode(0x7), rsv: 0, fin: true, reserved: true},
		},
		"reserved control opcode 0xB": {
			b0:   0x8b,
			want: headerClass{opcode: Opcode(0xb), rsv: 0, fin: true, control: true, reserved: true},
		},
		"reserved control opcode 0xF": {
			b0:   0x8f,
			want: headerClass{opcode: Opcode(0xf), rsv: 0, fin: true, control: true, reserved: true},
		},
		"rsv1 binary, no compression": {
			b0:   0xc2,
			want: headerClass{opcode: OpcodeBinary, rsv: RSV1, fin: true, rsvBad: true},
		},
		"rsv1 binary, compression": {
			b0:          0xc2,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV1, fin: true, rsvBad: false},
		},
		"rsv1 text, compression": {
			b0:          0xc1,
			compression: true,
			want:        headerClass{opcode: OpcodeText, rsv: RSV1, fin: true, rsvBad: false},
		},
		"rsv1 continuation, compression": {
			b0:          0xc0,
			compression: true,
			want:        headerClass{opcode: OpcodeContinuation, rsv: RSV1, fin: true, rsvBad: true},
		},
		"rsv1 close control, compression": {
			b0:          0xc8,
			compression: true,
			want:        headerClass{opcode: OpcodeClose, rsv: RSV1, fin: true, control: true, rsvBad: true},
		},
		"rsv2 binary, compression": {
			b0:          0xa2,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV2, fin: true, rsvBad: true},
		},
		"rsv3 binary, compression": {
			b0:          0x92,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV3, fin: true, rsvBad: true},
		},
		"rsv1+rsv2 binary, compression": {
			b0:          0xe2,
			compression: true,
			want:        headerClass{opcode: OpcodeBinary, rsv: RSV1 | RSV2, fin: true, rsvBad: true},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := classifyHeaderByte(tt.b0, tt.compression)
			if got != tt.want {
				t.Errorf("classifyHeaderByte(%#02x, %v) = %+v, want %+v", tt.b0, tt.compression, got, tt.want)
			}
			// The package-level table must hold precisely this value.
			idx := 0
			if tt.compression {
				idx = 1
			}
			if tbl := headerTables[idx][tt.b0]; tbl != tt.want {
				t.Errorf("headerTables[%d][%#02x] = %+v, want %+v", idx, tt.b0, tbl, tt.want)
			}
		})
	}
}

// TestHeaderTablesExhaustive cross-checks every entry of both precomputed
// tables against an inline recomputation of the classification rules, covering
// all 256 first-byte values under both compression states.
func TestHeaderTablesExhaustive(t *testing.T) {
	t.Parallel()
	for _, compression := range []bool{false, true} {
		idx := 0
		if compression {
			idx = 1
		}
		for b0 := range 256 {
			op := Opcode(byte(b0) & 0x0f)
			rsv := (byte(b0) >> 4) & 0x7
			control := op&0x8 != 0
			reserved := op >= 0x3 && op <= 0x7 || op >= 0xB
			rsv1OK := compression && rsv == RSV1 && !control && op != OpcodeContinuation
			want := headerClass{
				opcode:   op,
				rsv:      rsv,
				fin:      byte(b0)&0x80 != 0,
				control:  control,
				reserved: reserved,
				rsvBad:   rsv != 0 && !rsv1OK,
			}
			if got := headerTables[idx][b0]; got != want {
				t.Fatalf("headerTables[%d][%#02x] = %+v, want %+v", idx, b0, got, want)
			}
		}
	}
}

// TestHeaderTableFor verifies role/compression selection of the b0 table and
// the b1 mask-bit expectation (0x80 for a server, 0x00 for a client).
func TestHeaderTableFor(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		client      bool
		compression bool
		wantMaskBit byte
		wantIdx     int
	}{
		"server, plain":   {client: false, compression: false, wantMaskBit: 0x80, wantIdx: 0},
		"server, deflate": {client: false, compression: true, wantMaskBit: 0x80, wantIdx: 1},
		"client, plain":   {client: true, compression: false, wantMaskBit: 0x00, wantIdx: 0},
		"client, deflate": {client: true, compression: true, wantMaskBit: 0x00, wantIdx: 1},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tbl, maskBit := headerTableFor(tt.client, tt.compression)
			if maskBit != tt.wantMaskBit {
				t.Errorf("maskBit = %#02x, want %#02x", maskBit, tt.wantMaskBit)
			}
			if tbl != &headerTables[tt.wantIdx] {
				t.Errorf("table = %p, want &headerTables[%d] (%p)", tbl, tt.wantIdx, &headerTables[tt.wantIdx])
			}
		})
	}
}

// TestDecodeFrameHeaderFastRejects pins the fast decoder's reject reason, 1002
// close message, and (on the accept path) decoded Header and consumed length
// for one representative input per rule, including the compression-dependent
// RSV1 divergence and the role-dependent mask rule.
func TestDecodeFrameHeaderFastRejects(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		client      bool
		compression bool
		in          []byte
		wantReason  hdrReject
		wantMsg     string // close message (empty for accept/short).
		wantHeader  Header // meaningful only when wantReason == rejectNone.
		wantN       int    // consumed bytes when wantReason == rejectNone.
	}{
		"reserved opcode": {
			in:         []byte{0x83, 0x80, 0, 0, 0, 0},
			wantReason: rejectReservedOpcode,
			wantMsg:    "malformed frame header: gows: reserved opcode",
		},
		"reserved control opcode": {
			in:         []byte{0x8b, 0x80, 0, 0, 0, 0},
			wantReason: rejectReservedOpcode,
			wantMsg:    "malformed frame header: gows: reserved opcode",
		},
		"non-minimal 16-bit length": {
			in:         []byte{0x82, 0xfe, 0x00, 0x64, 0, 0, 0, 0},
			wantReason: rejectNonMinimalLength,
			wantMsg:    "malformed frame header: gows: non-minimal length encoding",
		},
		"non-minimal 64-bit length": {
			in:         []byte{0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4},
			wantReason: rejectNonMinimalLength,
			wantMsg:    "malformed frame header: gows: non-minimal length encoding",
		},
		"reserved length bit": {
			in:         []byte{0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4},
			wantReason: rejectReservedLengthBit,
			wantMsg:    "malformed frame header: gows: reserved length bit set",
		},
		"fragmented control": {
			in:         []byte{0x08, 0x80, 0, 0, 0, 0},
			wantReason: rejectControlFragmented,
			wantMsg:    "malformed frame header: gows: fragmented control frame",
		},
		"oversized control": {
			in:         []byte{0x88, 0xfe, 0x00, 0x7e, 0, 0, 0, 0},
			wantReason: rejectControlTooLong,
			wantMsg:    "malformed frame header: gows: control frame payload exceeds 125 bytes",
		},
		"bad rsv2 without compression": {
			in:         []byte{0xa2, 0x80, 0, 0, 0, 0},
			wantReason: rejectRSV,
			wantMsg:    "invalid RSV bit for the negotiated extension set",
		},
		"rsv1 without compression": {
			in:         []byte{0xc2, 0x80, 0, 0, 0, 0},
			wantReason: rejectRSV,
			wantMsg:    "invalid RSV bit for the negotiated extension set",
		},
		"rsv1 on continuation with compression": {
			compression: true,
			in:          []byte{0xc0, 0x80, 0, 0, 0, 0},
			wantReason:  rejectRSV,
			wantMsg:     "invalid RSV bit for the negotiated extension set",
		},
		"unmasked frame to server": {
			in:         []byte{0x82, 0x00},
			wantReason: rejectMask,
			wantMsg:    "unmasked frame received by server",
		},
		"masked frame to client": {
			client:     true,
			in:         []byte{0x82, 0x80, 0, 0, 0, 0},
			wantReason: rejectMask,
			wantMsg:    "masked frame received by client",
		},
		"short: one byte": {
			in:         []byte{0x82},
			wantReason: rejectShort,
		},
		"short: 16-bit length truncated": {
			in:         []byte{0x82, 0xfe, 0x04},
			wantReason: rejectShort,
		},
		"accept masked binary, server": {
			in:         []byte{0x82, 0x81, 0xde, 0xad, 0xbe, 0xef},
			wantReason: rejectNone,
			wantHeader: Header{Fin: true, Opcode: OpcodeBinary, Masked: true, MaskKey: binary.LittleEndian.Uint32([]byte{0xde, 0xad, 0xbe, 0xef}), Length: 1},
			wantN:      6,
		},
		"accept unmasked binary, client": {
			client:     true,
			in:         []byte{0x82, 0x05},
			wantReason: rejectNone,
			wantHeader: Header{Fin: true, Opcode: OpcodeBinary, Length: 5},
			wantN:      2,
		},
		"accept rsv1 compressed, server": {
			compression: true,
			in:          []byte{0xc2, 0x81, 0xde, 0xad, 0xbe, 0xef},
			wantReason:  rejectNone,
			wantHeader:  Header{Fin: true, Rsv: RSV1, Opcode: OpcodeBinary, Masked: true, MaskKey: binary.LittleEndian.Uint32([]byte{0xde, 0xad, 0xbe, 0xef}), Length: 1},
			wantN:       6,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tbl, maskBit := headerTableFor(tt.client, tt.compression)
			h, n, reason := decodeFrameHeaderFast(tbl, maskBit, tt.in)
			if reason != tt.wantReason {
				t.Fatalf("reason = %d, want %d", reason, tt.wantReason)
			}
			if got := reason.closeMessage(tt.client); got != tt.wantMsg {
				t.Errorf("closeMessage = %q, want %q", got, tt.wantMsg)
			}
			if tt.wantReason == rejectNone {
				if h != tt.wantHeader {
					t.Errorf("header = %+v, want %+v", h, tt.wantHeader)
				}
				if n != tt.wantN {
					t.Errorf("consumed = %d, want %d", n, tt.wantN)
				}
			} else if n != 0 {
				t.Errorf("consumed = %d on reject, want 0", n)
			}
		})
	}
}

// TestFrameHeaderRejectReasonParity drives the whole reader (not just the pure
// decoder) so that the 1002 close code and the exact reason string surfaced to
// the peer and the caller through [Conn.ReadMessage] match the former two-step
// decode's text.
// It complements TestReadMessageProtocolErrors, which asserts the code but not
// the message, closing the error-string parity gap at the integration boundary.
func TestFrameHeaderRejectReasonParity(t *testing.T) {
	t.Parallel()
	oversizedControl := frameBytes(true, OpcodeClose, 0, true, testKey, make([]byte, 126))
	tests := map[string]struct {
		client     bool
		in         []byte
		wantReason string
	}{
		"reserved opcode": {
			in:         frameBytes(true, Opcode(0x3), 0, true, testKey, []byte("x")),
			wantReason: "malformed frame header: gows: reserved opcode",
		},
		"non-minimal 16-bit length": {
			in:         []byte{0x82, 0xfe, 0x00, 0x64, 1, 2, 3, 4},
			wantReason: "malformed frame header: gows: non-minimal length encoding",
		},
		"oversized control": {
			in:         oversizedControl,
			wantReason: "malformed frame header: gows: control frame payload exceeds 125 bytes",
		},
		"bad rsv to server": {
			in:         frameBytes(true, OpcodeBinary, RSV1, true, testKey, []byte("x")),
			wantReason: "invalid RSV bit for the negotiated extension set",
		},
		"unmasked frame to server": {
			in:         serverFrame(true, OpcodeText, []byte("x")),
			wantReason: "unmasked frame received by server",
		},
		"masked frame to client": {
			client:     true,
			in:         clientFrame(true, OpcodeText, []byte("x")),
			wantReason: "masked frame received by client",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := &scriptConn{in: tt.in}
			var c *Conn
			if tt.client {
				c = NewClientConn(sc)
			} else {
				c = NewServerConn(sc)
			}
			_, _, err := c.ReadMessage()
			var ce *CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("error = %v, want *CloseError", err)
			}
			if ce.Code != CloseProtocolError {
				t.Errorf("close code = %d, want %d", ce.Code, CloseProtocolError)
			}
			if ce.Reason != tt.wantReason {
				t.Errorf("close reason = %q, want %q", ce.Reason, tt.wantReason)
			}
			// The peer must have received a Close frame carrying the same code.
			if code, reason, ok := firstClose(t, parseFrames(t, sc.out.Bytes())); !ok {
				t.Errorf("no Close frame sent to peer")
			} else if code != CloseProtocolError || reason != tt.wantReason {
				t.Errorf("sent close = (%d, %q), want (%d, %q)", code, reason, CloseProtocolError, tt.wantReason)
			}
		})
	}
}

// headerBenchShape is one frame-header wire shape the decode benchmark
// exercises, together with the receiving role that makes its mask bit valid.
type headerBenchShape struct {
	name   string
	client bool // receiving-side role: a client receives unmasked frames, a server masked.
	buf    []byte
}

// headerBenchShapes returns the benchmark shapes shared by the new
// (decodeFrameHeaderFast) and old (DecodeHeader+checkFrameHeader) header
// decoders, so the two can be compared across a git worktree. Masked frames
// are decoded as a server (their mask bit is valid there); unmasked frames as a
// client.
func headerBenchShapes() []headerBenchShape {
	mask := []byte{0xde, 0xad, 0xbe, 0xef}
	shape := func(name string, client bool, head []byte, masked bool) headerBenchShape {
		buf := append([]byte(nil), head...)
		if masked {
			buf = append(buf, mask...)
		}
		return headerBenchShape{name: name, client: client, buf: buf}
	}
	var len16 [2]byte
	binary.BigEndian.PutUint16(len16[:], 1000)
	var len64 [8]byte
	binary.BigEndian.PutUint64(len64[:], 1<<20)
	return []headerBenchShape{
		shape("7bit-text-masked", false, []byte{0x81, 0x80 | 100}, true),
		shape("7bit-binary-masked", false, []byte{0x82, 0x80 | 100}, true),
		shape("16bit-binary-masked", false, append([]byte{0x82, 0x80 | 126}, len16[:]...), true),
		shape("16bit-unmasked-server", true, append([]byte{0x82, 126}, len16[:]...), false),
		shape("64bit-masked", false, append([]byte{0x82, 0x80 | 127}, len64[:]...), true),
	}
}

// BenchmarkHeaderDecode measures the table-driven frame-header decoder across
// representative wire shapes, including the 16-bit masked binary shape the
// former code special-cased. The identically named benchmark in the
// 2c13770 worktree measures the old DecodeHeader+checkFrameHeader path over the
// same shapes for an apples-to-apples comparison.
func BenchmarkHeaderDecode(b *testing.B) {
	for _, sh := range headerBenchShapes() {
		tbl, maskBit := headerTableFor(sh.client, false)
		buf := sh.buf
		b.Run(sh.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, r := decodeFrameHeaderFast(tbl, maskBit, buf); r != rejectNone {
					b.Fatalf("unexpected reject %d", r)
				}
			}
		})
	}
}
