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

// Package utf8x validates UTF-8 text incrementally across fragmented
// WebSocket messages. RFC 6455 §8.1 requires a text message's payload,
// reassembled across all of its fragments, to be valid UTF-8; a
// truncated or malformed sequence must fail the connection even though
// it only becomes truncated at the point the message ends.
//
// [Validator] accepts a message in arbitrarily many pieces via
// [Validator.Feed] and reports at message end, via [Validator.Done],
// whether a multi-byte sequence was left incomplete — without ever
// needing the whole message buffered in memory. It accepts exactly the
// byte sequences [unicode/utf8.Valid] accepts: RFC 3629's shortest-form
// encodings of U+0000-U+10FFFF excluding the UTF-16 surrogate range
// U+D800-U+DFFF, rejecting overlong encodings and truncated or otherwise
// malformed sequences.
//
// The validation core is a byte-at-a-time DFA (see the [dfaState] doc
// comment for why a single byte of state is enough to carry across Feed
// calls) with an ASCII word fast path for the common case of long
// ASCII-only runs. Architecture-specific SIMD kernels in this package
// accelerate the interior bulk loop behind the same Feed/Done/Reset
// contract; boundary handling stays scalar and self-contained here.
package utf8x

import "encoding/binary"

// dfaState is one state of the byte-level UTF-8 acceptor, encoded as a
// single byte so a [Validator] can carry "how much of a multi-byte
// sequence is pending" across Feed calls.
//
// A UTF-8 validator (as opposed to a decoder) never needs to remember
// the bits of the code point assembled so far: it only needs to know
// which continuation bytes are still owed, and whether the very next one
// is range-restricted. Per RFC 3629 Table 3-7, every continuation byte
// after the first one in any sequence always uses the same generic
// 0x80-0xBF range; only the first continuation byte after certain
// leading bytes (0xE0, 0xED, 0xF0, 0xF4) is restricted to a narrower
// range, to rule out overlong encodings, encoded UTF-16 surrogates, and
// code points beyond U+10FFFF. That is why the whole "pending sequence"
// obligation collapses into a small, enumerable set of states: how many
// more bytes (1-3) are owed, and, only for the very next byte, whether
// its range is generic or restricted to one of four specific bounds.
type dfaState uint8

const (
	// accept is the state between sequences: the next byte starts a new
	// ASCII byte or a new multi-byte sequence.
	accept dfaState = iota
	// reject is sticky: once entered, every further byte and every
	// further [Validator.Feed] call stays rejected until
	// [Validator.Reset].
	reject
	// want1 means one more continuation byte is owed, using the generic
	// 0x80-0xBF range. Reached after a 2-byte leading byte (0xC2-0xDF).
	want1
	// want2 means two more continuation bytes are owed, the first one
	// using the generic range. Reached after a "plain" 3-byte leading
	// byte (0xE1-0xEC or 0xEE-0xEF).
	want2
	// want2AfterE0 means two more continuation bytes are owed, but the
	// very next one must fall in 0xA0-0xBF rather than the generic
	// range: 0xE0 followed by 0x80-0x9F would be an overlong encoding of
	// a code point below U+0800.
	want2AfterE0
	// want2AfterED means two more continuation bytes are owed, but the
	// very next one must fall in 0x80-0x9F rather than the generic
	// range: 0xED followed by 0xA0-0xBF would encode a UTF-16 surrogate
	// (U+D800-U+DFFF), which is not a valid Unicode scalar value.
	want2AfterED
	// want3 means three more continuation bytes are owed, the first one
	// using the generic range. Reached after a "plain" 4-byte leading
	// byte (0xF1-0xF3).
	want3
	// want3AfterF0 means three more continuation bytes are owed, but the
	// very next one must fall in 0x90-0xBF rather than the generic
	// range: 0xF0 followed by 0x80-0x8F would be an overlong encoding of
	// a code point below U+10000.
	want3AfterF0
	// want3AfterF4 means three more continuation bytes are owed, but the
	// very next one must fall in 0x80-0x8F rather than the generic
	// range: 0xF4 followed by 0x90-0xBF would encode a code point above
	// U+10FFFF, the maximum Unicode scalar value.
	want3AfterF4
)

// asciiHighBits has the high bit of every byte lane set. ANDing it with
// a little- or big-endian-agnostic word read tests whether any of the
// word's 8 bytes falls outside the ASCII range 0x00-0x7F.
const asciiHighBits = 0x8080808080808080

// step consumes one byte from state st and returns the resulting state.
// It never needs to inspect more than the current state and the current
// byte: [dfaState] already narrows to the specific expectation, if any,
// left by whatever bytes came before.
func step(st dfaState, b byte) dfaState {
	switch st {
	case accept:
		switch {
		case b < 0x80:
			return accept
		case b < 0xC2:
			// 0x80-0xBF: a continuation byte with no leading byte.
			// 0xC0-0xC1: would only ever encode an overlong 2-byte
			// sequence (a code point below U+0080).
			return reject
		case b < 0xE0:
			return want1 // 0xC2-0xDF
		case b == 0xE0:
			return want2AfterE0
		case b < 0xED:
			return want2 // 0xE1-0xEC
		case b == 0xED:
			return want2AfterED
		case b < 0xF0:
			return want2 // 0xEE-0xEF
		case b == 0xF0:
			return want3AfterF0
		case b < 0xF4:
			return want3 // 0xF1-0xF3
		case b == 0xF4:
			return want3AfterF4
		default:
			// 0xF5-0xFF would only ever encode a code point above
			// U+10FFFF.
			return reject
		}
	case want1:
		if b < 0x80 || b > 0xBF {
			return reject
		}
		return accept
	case want2:
		if b < 0x80 || b > 0xBF {
			return reject
		}
		return want1
	case want2AfterE0:
		if b < 0xA0 || b > 0xBF {
			return reject
		}
		return want1
	case want2AfterED:
		if b < 0x80 || b > 0x9F {
			return reject
		}
		return want1
	case want3:
		if b < 0x80 || b > 0xBF {
			return reject
		}
		return want2
	case want3AfterF0:
		if b < 0x90 || b > 0xBF {
			return reject
		}
		return want2
	case want3AfterF4:
		if b < 0x80 || b > 0x8F {
			return reject
		}
		return want2
	default: // reject
		return reject
	}
}

// Validator incrementally validates that a byte stream, delivered across
// any number of [Validator.Feed] calls, is well-formed UTF-8 as defined
// by RFC 3629 — the same acceptance set as [unicode/utf8.Valid].
//
// The zero value is a ready-to-use Validator positioned at the start of
// a message. Validator carries only a single byte of state (see
// [dfaState]), so it never allocates and is cheap to embed or copy.
//
// Validator is not safe for concurrent use by multiple goroutines.
type Validator struct {
	state dfaState
}

// Feed validates the next chunk b of the message and reports whether the
// stream is still potentially valid. Once Feed returns false the
// rejection is sticky: every subsequent call, including one with valid
// or empty input, also returns false until [Validator.Reset].
//
// A false return means b, combined with whatever was fed before it,
// definitely cannot be valid UTF-8. A true return does not by itself
// mean the message is complete: it may end in the middle of a multi-byte
// sequence, which [Validator.Done] detects.
func (v *Validator) Feed(b []byte) bool {
	if v.state == reject {
		return false
	}

	i := 0
	for i < len(b) {
		if v.state == accept {
			// ASCII word fast path: while positioned between sequences,
			// consume 8 bytes at a time as long as none of them has its
			// high bit set. Every such byte independently keeps the
			// state at accept, so the state itself never needs updating
			// here.
			for i+8 <= len(b) && binary.NativeEndian.Uint64(b[i:i+8])&asciiHighBits == 0 {
				i += 8
			}
			if i >= len(b) {
				break
			}

			// SIMD bulk fast path (Phase 3): from a sequence boundary, a
			// vector kernel validates the largest prefix it can own and
			// reports how many bytes to advance while staying at a boundary,
			// leaving the trailing partial sequence to the scalar DFA below.
			// simdBulk returns 0 when it does not engage (payload below the
			// threshold, no SIMD support, or the purego build), keeping this
			// path behaviorally identical to the pure-scalar validator.
			if n := simdBulk(b[i:]); n < 0 {
				v.state = reject
				return false
			} else if n > 0 {
				i += n
				continue
			}
		}

		v.state = step(v.state, b[i])
		if v.state == reject {
			return false
		}
		i++
	}
	return true
}

// Done reports whether the message ended cleanly: no multi-byte sequence
// was left incomplete. Call Done once after the last [Validator.Feed] of
// a message; a false result means the message must be rejected even
// though every individual Feed call returned true, per RFC 6455 §8.1's
// requirement that a text message's payload be valid UTF-8 in full once
// reassembled.
//
// Done also returns false if the Validator has already rejected the
// stream.
func (v *Validator) Done() bool {
	return v.state == accept
}

// Reset returns v to the initial state, ready to validate a new message.
func (v *Validator) Reset() {
	v.state = accept
}

// Valid reports whether b is, in its entirety, valid UTF-8 under the
// same definition as [Validator]: RFC 3629's shortest-form encodings of
// U+0000-U+10FFFF excluding the surrogate range, with no trailing
// incomplete sequence. It is a convenience wrapper over
// [Validator.Feed] and [Validator.Done] for callers validating an
// unfragmented message, or a close-frame reason string, in one shot.
func Valid(b []byte) bool {
	var v Validator
	return v.Feed(b) && v.Done()
}
