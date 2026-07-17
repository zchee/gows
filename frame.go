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
)

// Opcode identifies the interpretation of a frame's payload, per RFC 6455
// §5.2. It occupies the low 4 bits of the first header byte.
type Opcode byte

// Opcode values defined by RFC 6455 §5.2. Opcode 0x3-0x7 and 0xB-0xF are
// reserved for future non-control and control frames respectively;
// [DecodeHeader] rejects them with [ErrReservedOpcode].
const (
	// OpcodeContinuation identifies a continuation frame.
	OpcodeContinuation Opcode = 0x0
	// OpcodeText identifies a text data frame.
	OpcodeText Opcode = 0x1
	// OpcodeBinary identifies a binary data frame.
	OpcodeBinary Opcode = 0x2
	// OpcodeClose identifies a close control frame.
	OpcodeClose Opcode = 0x8
	// OpcodePing identifies a ping control frame.
	OpcodePing Opcode = 0x9
	// OpcodePong identifies a pong control frame.
	OpcodePong Opcode = 0xA
)

// IsControl reports whether op identifies a control frame (Close, Ping,
// Pong, or a reserved control opcode). Per RFC 6455 §5.2, control opcodes
// are exactly those with the most significant bit of the 4-bit opcode
// set (0x8-0xF), and per RFC 6455 §5.5 every control frame MUST be
// unfragmented (Fin set) and carry a payload of at most 125 bytes; this
// applies to the whole control-opcode class, not only the three
// currently assigned values, which is why IsControl also reports true
// for the reserved control opcodes 0xB-0xF.
func (op Opcode) IsControl() bool { return op&0x8 != 0 }

// IsData reports whether op starts a data frame (Text or Binary), per
// RFC 6455 §5.6. It reports false for OpcodeContinuation, which
// continues a data frame's fragmented message rather than starting one.
func (op Opcode) IsData() bool { return op == OpcodeText || op == OpcodeBinary }

// RSV bit masks within [Header.Rsv], per RFC 6455 §5.2. Whether a given
// RSV bit may legally be set depends entirely on which extensions were
// negotiated for the connection (e.g. permessage-deflate, RFC 7692,
// signals a compressed frame with RSV1); frame.go has no notion of
// negotiated extensions, so [DecodeHeader] does not itself reject any
// combination of RSV bits. Callers that know the negotiated extension
// set should reject undeclared bits themselves, e.g.
// "if h.Rsv & ^negotiatedMask != 0 { failConnection() }".
const (
	// RSV1 is the mask for the first reserved header bit.
	RSV1 byte = 0x4
	// RSV2 is the mask for the second reserved header bit.
	RSV2 byte = 0x2
	// RSV3 is the mask for the third reserved header bit.
	RSV3 byte = 0x1
)

// Header is the decoded form of an RFC 6455 §5.2 base frame header. All
// fields describe wire-level framing only; interpreting Length as
// belonging to a fragmented message, or MaskKey as a running XOR-mask
// state, is the responsibility of a higher layer.
type Header struct {
	// Fin reports whether this frame is the final fragment of a
	// message. Control frames (see [Opcode.IsControl]) always have Fin
	// set; [DecodeHeader] enforces this.
	Fin bool
	// Rsv holds the three RSV bits (RSV1 in bit 2, RSV2 in bit 1, RSV3
	// in bit 0; see the [RSV1], [RSV2], [RSV3] masks). See the RSV bit
	// masks' documentation for who is responsible for validating them.
	Rsv byte
	// Opcode identifies the frame type.
	Opcode Opcode
	// Masked reports whether the payload is masked with MaskKey. Per
	// RFC 6455 §5.1, clients MUST mask and servers MUST NOT; frame.go
	// does not know the connection's role, so DecodeHeader does not
	// enforce this either way, leaving it to the caller.
	Masked bool
	// MaskKey is the 32-bit masking key, valid only when Masked is true.
	// It is stored little-endian: the wire's raw mask-key byte m[i] is
	// byte(MaskKey >> (8 * (i % 4))), matching the convention documented
	// by, and consumed by, the internal/mask package.
	MaskKey uint32
	// Length is the payload length in bytes (RFC 6455 §5.2 "Payload
	// length"), excluding the header itself. It is signed so that its
	// full range (0 to 1<<63-1) can never set the 64-bit wire length
	// field's most significant bit, which RFC 6455 requires to be zero;
	// see [AppendHeader].
	Length int64
}

// MaxHeaderSize is the largest possible encoded size of a frame header:
// 2 fixed bytes, up to 8 bytes of extended length, and a 4-byte masking
// key.
const MaxHeaderSize = 14

// Sentinel errors returned by [DecodeHeader], [ParseCloseBody], and
// related functions in this file. Each is comparable with [errors.Is].
var (
	// ErrShortHeader indicates b does not yet contain a complete frame
	// header. Unlike the other errors here, this is not a protocol
	// violation: the caller should read more bytes into b and call
	// DecodeHeader again from the start, enabling resumable parsing
	// across partial reads.
	ErrShortHeader = errors.New("gows: short frame header")
	// ErrReservedOpcode indicates the frame's opcode is one of the
	// values RFC 6455 §5.2 reserves for future definition (0x3-0x7,
	// 0xB-0xF), which a conformant receiver must treat as a fatal
	// protocol error.
	ErrReservedOpcode = errors.New("gows: reserved opcode")
	// ErrNonMinimalLength indicates the frame used a longer extended
	// length field than necessary to represent its payload length, which
	// RFC 6455 §5.2 forbids ("the minimal number of bytes MUST be used
	// to encode the length").
	ErrNonMinimalLength = errors.New("gows: non-minimal length encoding")
	// ErrReservedLengthBit indicates the 64-bit extended payload length
	// had its most significant bit set, which RFC 6455 §5.2 forbids.
	ErrReservedLengthBit = errors.New("gows: reserved length bit set")
	// ErrControlFrameFragmented indicates a control frame (see
	// [Opcode.IsControl]) did not have Fin set; RFC 6455 §5.5 requires
	// every control frame to be unfragmented.
	ErrControlFrameFragmented = errors.New("gows: fragmented control frame")
	// ErrControlFrameTooLong indicates a control frame's payload length
	// exceeded 125 bytes, the limit RFC 6455 §5.5 imposes on every
	// control frame.
	ErrControlFrameTooLong = errors.New("gows: control frame payload exceeds 125 bytes")
	// ErrShortCloseBody indicates a Close control frame body of exactly
	// one byte, too short to hold a 2-byte close code.
	ErrShortCloseBody = errors.New("gows: close body too short for a close code")
)

// AppendHeader encodes h and appends the result to dst, returning the
// extended buffer. AppendHeader always chooses the shortest valid length
// encoding for h.Length (RFC 6455 §5.2's "minimal number of bytes"
// requirement), so its output is always accepted by DecodeHeader.
//
// AppendHeader assumes h.Length is non-negative (a negative value
// produces output with no defined meaning) and masks h.Rsv to its low 3
// bits; it performs no other validation and never returns an error.
//
// AppendHeader performs no heap allocations of its own: the header is
// built in a fixed [MaxHeaderSize]-byte stack array before being
// appended to dst. Appending to dst itself allocates only if dst lacks
// sufficient spare capacity, exactly as with [append].
func AppendHeader(dst []byte, h Header) []byte {
	var buf [MaxHeaderSize]byte

	b0 := byte(h.Opcode)&0x0f | (h.Rsv&0x7)<<4
	if h.Fin {
		b0 |= 0x80
	}
	buf[0] = b0

	var b1 byte
	if h.Masked {
		b1 = 0x80
	}

	n := 2
	switch {
	case h.Length <= 125:
		b1 |= byte(h.Length)
	case h.Length <= 0xffff:
		b1 |= 126
		binary.BigEndian.PutUint16(buf[2:4], uint16(h.Length))
		n = 4
	default:
		b1 |= 127
		binary.BigEndian.PutUint64(buf[2:10], uint64(h.Length))
		n = 10
	}
	buf[1] = b1

	if h.Masked {
		binary.LittleEndian.PutUint32(buf[n:n+4], h.MaskKey)
		n += 4
	}

	return append(dst, buf[:n]...)
}

// DecodeHeader decodes the frame header at the start of b and returns it
// along with the number of bytes consumed.
//
// If b does not yet contain a complete header, DecodeHeader returns
// [ErrShortHeader] and a consumed count of 0; the caller should read
// more bytes into b and call DecodeHeader again from the start of the
// same (now longer) buffer. This makes DecodeHeader safe to call
// incrementally as bytes arrive from a partial read, without any
// buffering scheme of its own.
//
// For any other error, the consumed count is also 0 and must not be
// used; the error indicates a fatal RFC 6455 protocol violation; per
// RFC 6455 §7.1.7 the caller should fail the WebSocket connection rather
// than retry.
//
// DecodeHeader enforces: the opcode is not one of the values reserved by
// RFC 6455 §5.2 ([ErrReservedOpcode]); control frames have Fin set and a
// payload length of at most 125 bytes ([ErrControlFrameFragmented],
// [ErrControlFrameTooLong]); the 64-bit extended length's most
// significant bit is 0 ([ErrReservedLengthBit]); and the length uses the
// minimal encoding required by RFC 6455 §5.2 ([ErrNonMinimalLength]).
//
// DecodeHeader does not enforce the RSV bits or the mask bit; see
// [Header.Rsv] and [Header.Masked] for why, and who is responsible.
func DecodeHeader(b []byte) (h Header, n int, err error) {
	if len(b) < 2 {
		return Header{}, 0, ErrShortHeader
	}
	b0, b1 := b[0], b[1]

	h.Fin = b0&0x80 != 0
	h.Rsv = (b0 >> 4) & 0x7
	h.Opcode = Opcode(b0 & 0x0f)
	h.Masked = b1&0x80 != 0
	lengthCode := b1 & 0x7f

	if h.Opcode >= 0x3 && h.Opcode <= 0x7 || h.Opcode >= 0xB {
		return Header{}, 0, ErrReservedOpcode
	}

	extLen := 0
	switch lengthCode {
	case 126:
		extLen = 2
	case 127:
		extLen = 8
	}
	maskLen := 0
	if h.Masked {
		maskLen = 4
	}

	need := 2 + extLen + maskLen
	if len(b) < need {
		return Header{}, 0, ErrShortHeader
	}

	switch lengthCode {
	case 126:
		v := binary.BigEndian.Uint16(b[2:4])
		if v <= 125 {
			return Header{}, 0, ErrNonMinimalLength
		}
		h.Length = int64(v)
	case 127:
		v := binary.BigEndian.Uint64(b[2:10])
		if v&(1<<63) != 0 {
			return Header{}, 0, ErrReservedLengthBit
		}
		if v <= 0xffff {
			return Header{}, 0, ErrNonMinimalLength
		}
		h.Length = int64(v)
	default:
		h.Length = int64(lengthCode)
	}

	if h.Masked {
		h.MaskKey = binary.LittleEndian.Uint32(b[2+extLen : 2+extLen+4])
	}

	if h.Opcode.IsControl() {
		if !h.Fin {
			return Header{}, 0, ErrControlFrameFragmented
		}
		if h.Length > 125 {
			return Header{}, 0, ErrControlFrameTooLong
		}
	}

	return h, need, nil
}

// headerClass is everything the fast frame-header decoder can decide from the
// first header byte (b0) alone for a given negotiated extension set. It is
// precomputed once per b0 value (see [headerTables]) so the hot path pays a
// single indexed load instead of re-deriving the opcode's legality, the RSV
// bits' legality, and the control/data split on every frame -- work a split
// decode-then-validate pair would re-derive per frame, and which
// protocol_fuzz_test.go's oracleDecodeHeader still spells out as the
// differential reference.
//
// b0 packs Fin (bit 7), the three RSV bits (bits 6-4), and the opcode (bits
// 3-0); none of those depend on the connection's role, so the classification
// is role-independent. The only role-dependent framing rule -- clients send
// masked frames and servers send unmasked ones (RFC 6455 §5.1) -- lives in the
// second header byte (b1) and is applied separately as a single compare (see
// [decodeFrameHeaderFast] and [Conn.hdrMaskBit]). That is why two tables (one
// per compression state), not four (role x compression), cover every Conn.
type headerClass struct {
	opcode   Opcode // decoded opcode (b0 & 0x0f).
	rsv      byte   // decoded RSV bits ((b0 >> 4) & 0x7), for Header.Rsv.
	fin      bool   // Fin bit (b0 & 0x80).
	control  bool   // opcode is a control opcode (RFC 6455 §5.5).
	reserved bool   // opcode is RFC 6455 §5.2 reserved; reject before length decode.
	rsvBad   bool   // RSV bits illegal for this extension set; reject after length/control.
}

// hdrReject identifies which RFC 6455 rule a frame header violated (or that
// more bytes are needed), so [decodeFrameHeaderFast] stays free of side
// effects while its caller maps the reason to the exact close code and message
// the connection must fail with. Rejections surface in a fixed first-violation
// precedence, pinned by the differential fuzz oracle: reserved opcode, then
// the length-encoding checks, then the control-frame checks, then the RSV
// check, then the mask-role check.
type hdrReject uint8

const (
	rejectNone              hdrReject = iota // valid header (a Header and consumed count are returned).
	rejectShort                              // not a violation: more bytes are needed.
	rejectReservedOpcode                     // ErrReservedOpcode.
	rejectNonMinimalLength                   // ErrNonMinimalLength.
	rejectReservedLengthBit                  // ErrReservedLengthBit.
	rejectControlFragmented                  // ErrControlFrameFragmented.
	rejectControlTooLong                     // ErrControlFrameTooLong.
	rejectRSV                                // RSV bit illegal for the negotiated extension set.
	rejectMask                               // frame masked/unmasked contrary to the peer's role.
)

// closeMessage returns the exact failure text a rejected header must close
// with. These strings are a compatibility contract: the differential fuzz
// oracle (oracleDecodeHeader) and the protocol tests pin every one of them
// byte for byte, so they must not drift. The mask-role text is
// role-specific, so client reports the receiving side. It returns the empty
// string for rejectNone and rejectShort, which never fail a connection.
func (r hdrReject) closeMessage(client bool) string {
	switch r {
	case rejectReservedOpcode:
		return "malformed frame header: " + ErrReservedOpcode.Error()
	case rejectNonMinimalLength:
		return "malformed frame header: " + ErrNonMinimalLength.Error()
	case rejectReservedLengthBit:
		return "malformed frame header: " + ErrReservedLengthBit.Error()
	case rejectControlFragmented:
		return "malformed frame header: " + ErrControlFrameFragmented.Error()
	case rejectControlTooLong:
		return "malformed frame header: " + ErrControlFrameTooLong.Error()
	case rejectRSV:
		return "invalid RSV bit for the negotiated extension set"
	case rejectMask:
		if client {
			return "masked frame received by client"
		}
		return "unmasked frame received by server"
	default:
		return ""
	}
}

// headerTables holds the two b0-classification tables, indexed by whether
// permessage-deflate (RFC 7692) is negotiated: headerTables[0] for a Conn
// without compression, headerTables[1] with it. As documented on [headerClass],
// the first header byte's classification is role-independent -- only the b1
// mask-bit expectation differs by role -- so these two tables cover all four
// role x compression combinations without duplication.
var headerTables [2][256]headerClass

func init() {
	for comp := range 2 {
		for b0 := range 256 {
			headerTables[comp][b0] = classifyHeaderByte(byte(b0), comp == 1)
		}
	}
}

// classifyHeaderByte precomputes the [headerClass] for one first-header-byte
// value under the given negotiated compression state. Its field extraction
// matches [DecodeHeader]'s opcode/Fin/RSV handling exactly, and rsvBad encodes
// the negotiated-extension RSV legality rule of RFC 7692 §6.1.
func classifyHeaderByte(b0 byte, compression bool) headerClass {
	op := Opcode(b0 & 0x0f)
	rsv := (b0 >> 4) & 0x7
	control := op.IsControl()
	// RSV1 (RFC 7692 §6.1) is legal only with compression negotiated, on a data
	// frame that starts a message (never a control or continuation frame); any
	// other RSV bit set is illegal.
	rsv1OK := compression && rsv == RSV1 && !control && op != OpcodeContinuation
	return headerClass{
		opcode:   op,
		rsv:      rsv,
		fin:      b0&0x80 != 0,
		control:  control,
		reserved: op >= 0x3 && op <= 0x7 || op >= 0xB,
		rsvBad:   rsv != 0 && !rsv1OK,
	}
}

// headerTableFor selects the b0-classification table and the expected b1
// mask-bit (0x80 for a server, whose peer must mask; 0x00 for a client, whose
// peer must not) for a Conn with the given role and compression state.
func headerTableFor(client, compression bool) (*[256]headerClass, byte) {
	idx := 0
	if compression {
		idx = 1
	}
	maskBit := byte(0x80)
	if client {
		maskBit = 0
	}
	return &headerTables[idx], maskBit
}

// decodeFrameHeaderFast decodes and fully validates the frame header at the
// start of b for a Conn described by tbl (its b0-classification table) and
// maskBit (its expected b1 mask bit). It fuses the wire-level checks
// [DecodeHeader] performs with the connection-level role and RSV checks, so a
// caller needs no re-validation afterward. It reads only b, has no side
// effects, and never allocates, which is what lets the differential fuzz diff
// it against oracleDecodeHeader's independent two-step formulation.
//
// On success it returns the decoded Header, the number of bytes consumed
// (rejectNone). When b does not yet hold a complete header it returns
// rejectShort. Otherwise it returns the [hdrReject] naming the first rule
// violated, in the same precedence order the two former steps applied.
func decodeFrameHeaderFast(tbl *[256]headerClass, maskBit byte, b []byte) (Header, int, hdrReject) {
	if len(b) < 2 {
		return Header{}, 0, rejectShort
	}
	e := &tbl[b[0]]
	if e.reserved {
		return Header{}, 0, rejectReservedOpcode
	}

	b1 := b[1]
	lengthCode := b1 & 0x7f
	masked := b1&0x80 != 0

	extLen := 0
	switch lengthCode {
	case 126:
		extLen = 2
	case 127:
		extLen = 8
	}
	need := 2 + extLen
	if masked {
		need += 4
	}
	if len(b) < need {
		return Header{}, 0, rejectShort
	}

	var length int64
	switch lengthCode {
	case 126:
		v := binary.BigEndian.Uint16(b[2:4])
		if v <= 125 {
			return Header{}, 0, rejectNonMinimalLength
		}
		length = int64(v)
	case 127:
		v := binary.BigEndian.Uint64(b[2:10])
		if v&(1<<63) != 0 {
			return Header{}, 0, rejectReservedLengthBit
		}
		if v <= 0xffff {
			return Header{}, 0, rejectNonMinimalLength
		}
		length = int64(v)
	default:
		length = int64(lengthCode)
	}

	if e.control {
		if !e.fin {
			return Header{}, 0, rejectControlFragmented
		}
		if length > 125 {
			return Header{}, 0, rejectControlTooLong
		}
	}

	if e.rsvBad {
		return Header{}, 0, rejectRSV
	}

	if b1&0x80 != maskBit {
		return Header{}, 0, rejectMask
	}

	var maskKey uint32
	if masked {
		maskKey = binary.LittleEndian.Uint32(b[2+extLen : 2+extLen+4])
	}
	return Header{
		Fin:     e.fin,
		Rsv:     e.rsv,
		Opcode:  e.opcode,
		Masked:  masked,
		MaskKey: maskKey,
		Length:  length,
	}, need, rejectNone
}

// CloseCode is a WebSocket close status code, sent as the first two
// bytes of a Close control frame's application data, per RFC 6455 §7.4.
type CloseCode uint16

// Close codes defined by RFC 6455 §7.4.1, plus 1012-1014, registered
// after RFC 6455's publication by the IANA "WebSocket Close Code Number
// Registry". See [ValidCloseCode] for which of these (and which other
// codes) are permitted on the wire.
const (
	// CloseNormalClosure indicates that the connection fulfilled its purpose.
	CloseNormalClosure CloseCode = 1000
	// CloseGoingAway indicates that an endpoint is going away.
	CloseGoingAway CloseCode = 1001
	// CloseProtocolError indicates that an endpoint encountered a protocol error.
	CloseProtocolError CloseCode = 1002
	// CloseUnsupportedData indicates receipt of an unsupported data type.
	CloseUnsupportedData CloseCode = 1003
	// CloseNoStatusReceived is the reserved sentinel for a missing status code.
	CloseNoStatusReceived CloseCode = 1005 // Reserved; never sent on the wire. See ParseCloseBody.
	// CloseAbnormalClosure is the reserved sentinel for an abnormal closure.
	CloseAbnormalClosure CloseCode = 1006 // Reserved; never sent on the wire.
	// CloseInvalidFramePayloadData indicates inconsistent message data.
	CloseInvalidFramePayloadData CloseCode = 1007
	// ClosePolicyViolation indicates receipt of a message that violates policy.
	ClosePolicyViolation CloseCode = 1008
	// CloseMessageTooBig indicates receipt of a message that is too large.
	CloseMessageTooBig CloseCode = 1009
	// CloseMandatoryExtension indicates that a required extension was not negotiated.
	CloseMandatoryExtension CloseCode = 1010
	// CloseInternalServerErr indicates an unexpected server condition.
	CloseInternalServerErr CloseCode = 1011
	// CloseServiceRestart indicates that the service is restarting.
	CloseServiceRestart CloseCode = 1012
	// CloseTryAgainLater indicates a temporary service condition.
	CloseTryAgainLater CloseCode = 1013
	// CloseBadGateway indicates an invalid response from an upstream server.
	CloseBadGateway CloseCode = 1014
	// CloseTLSHandshake is the reserved sentinel for a failed TLS handshake.
	CloseTLSHandshake CloseCode = 1015 // Reserved; never sent on the wire.
)

// ValidCloseCode reports whether c is a close code permitted to appear
// on the wire in a Close control frame, per RFC 6455 §7.4 and the IANA
// "WebSocket Close Code Number Registry"
// (https://www.iana.org/assignments/websocket/websocket.xml):
//
//   - 1000-1003 and 1007-1011 are defined by RFC 6455 §7.4.1 and valid.
//   - 1012 (Service Restart), 1013 (Try Again Later), and 1014 (Bad
//     Gateway) were registered via the IETF HyBi mailing list after
//     RFC 6455 was published, and are valid despite RFC 6455's own text
//     listing them as "reserved for future use". The Autobahn Testsuite
//     (crossbario/autobahn-testsuite, case/case7_7_X.py and
//     case/case7_9_X.py) does not exercise 1012-1014 in either its valid
//     or invalid close-code list, so treating them as valid cannot
//     regress Autobahn conformance.
//   - 1004, 1005, 1006, and 1015 are reserved values that RFC 6455
//     explicitly forbids an endpoint from ever setting on the wire (they
//     exist only as internal sentinels, e.g. for "no status code was
//     present"); invalid, matching Autobahn case7_9_X.py, which lists
//     1004-1006 among its invalid close codes.
//   - 1016-2999 are unassigned; invalid, matching Autobahn
//     case7_9_X.py's invalid-code list (1016, 1100, 2000, 2999).
//   - 3000-3999 are reserved for libraries, frameworks, and applications
//     (first-come-first-served IANA registration); valid without
//     requiring the specific code to be individually registered here,
//     matching Autobahn case7_7_X.py's valid-code list (3000, 3999).
//   - 4000-4999 are reserved for private use; valid, matching Autobahn
//     case7_7_X.py's valid-code list (4000, 4999).
//   - Codes below 1000 or above 4999 are invalid (0 and 999 appear in
//     Autobahn case7_9_X.py's invalid-code list).
func ValidCloseCode(c CloseCode) bool {
	switch {
	case c >= 3000 && c <= 4999:
		return true
	case c >= 1000 && c <= 1003:
		return true
	case c >= 1007 && c <= 1014:
		return true
	default:
		return false
	}
}

// AppendCloseBody encodes the application data of a Close control frame
// -- code as a 2-byte big-endian value followed by reason, per RFC 6455
// §5.5.1 and §7.4 -- and appends it to dst, returning the extended
// buffer. To send a Close frame with no code at all (RFC 6455 §7.1.5),
// use a zero-length payload directly rather than calling
// AppendCloseBody.
func AppendCloseBody(dst []byte, code CloseCode, reason []byte) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(code))
	dst = append(dst, buf[:]...)
	return append(dst, reason...)
}

// ParseCloseBody parses the application data of a Close control frame
// into its close code and reason text, both referencing subslices of b
// where applicable; no allocation is performed.
//
// Per RFC 6455 §7.1.5, a Close frame may carry no application data at
// all; in that case there is no close code on the wire, and by
// convention the application-level close code is considered to be
// [CloseNoStatusReceived] (1005). ParseCloseBody returns that value
// directly for an empty b, with a nil reason, so callers do not need to
// special-case the empty body themselves. A body of exactly one byte
// cannot hold a code and is rejected with [ErrShortCloseBody].
//
// ParseCloseBody does not validate that the returned code is one a
// conformant peer may send (call [ValidCloseCode] separately) or that
// reason is valid UTF-8 (RFC 6455 §5.5.1 requires it to be, but
// validation is the internal/utf8x package's responsibility).
func ParseCloseBody(b []byte) (code CloseCode, reason []byte, err error) {
	switch len(b) {
	case 0:
		return CloseNoStatusReceived, nil, nil
	case 1:
		return 0, nil, ErrShortCloseBody
	default:
		return CloseCode(binary.BigEndian.Uint16(b[:2])), b[2:], nil
	}
}
