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

// Package httpx provides allocation-free primitives for parsing and
// building the HTTP/1.1 request line and header fields of a WebSocket
// upgrade handshake (RFC 6455 §4.2), without depending on net/http or
// net/textproto.
package httpx

import (
	"bytes"
	"errors"
)

// Sentinel errors returned by the parsing functions in this package. Each
// is comparable with [errors.Is] and carries no per-call allocation.
var (
	// ErrMissingCRLF indicates the input is missing a required CRLF
	// ("\r\n") terminator, or contains a bare LF not preceded by CR.
	ErrMissingCRLF = errors.New("httpx: missing CRLF terminator")
	// ErrMalformedRequestLine indicates the request line does not have
	// the "method SP target SP version" form.
	ErrMalformedRequestLine = errors.New("httpx: malformed request line")
	// ErrNotGet indicates the request method was not GET, as required by
	// RFC 6455 §4.2.1 for a WebSocket handshake.
	ErrNotGet = errors.New("httpx: method is not GET")
	// ErrNotHTTP11 indicates the request did not use HTTP/1.1.
	ErrNotHTTP11 = errors.New("httpx: version is not HTTP/1.1")
	// ErrMalformedHeader indicates a header line is missing the ':'
	// name/value separator.
	ErrMalformedHeader = errors.New("httpx: malformed header line")
	// ErrObsoleteLineFolding indicates a header line begins with SP or
	// HTAB, the obsolete line-folding continuation form forbidden by
	// RFC 7230 §3.2.4.
	ErrObsoleteLineFolding = errors.New("httpx: obsolete line folding is not supported")
)

// RequestLine holds the method, request-target, and HTTP-version fields
// of an HTTP request line as subslices of the original input.
type RequestLine struct {
	Method  []byte
	Target  []byte
	Version []byte
}

// ParseRequestLine parses the request line at the start of b and returns
// it along with the number of bytes consumed, including the terminating
// CRLF. The returned fields reference subslices of b; no allocation is
// performed.
//
// Per RFC 6455 §4.2.1, a WebSocket handshake request line must use the
// GET method and HTTP/1.1: any other method is rejected with [ErrNotGet]
// and any other version with [ErrNotHTTP11]. Both comparisons are
// case-sensitive, matching the literal tokens mandated by RFC 7230 §3.1.1
// and §2.6.
func ParseRequestLine(b []byte) (line RequestLine, n int, err error) {
	raw, _, ok := cutCRLF(b)
	if !ok {
		return RequestLine{}, 0, ErrMissingCRLF
	}
	n = len(raw) + 2

	method, remainder, ok := cutByte(raw, ' ')
	if !ok {
		return RequestLine{}, n, ErrMalformedRequestLine
	}
	target, version, ok := cutByte(remainder, ' ')
	if !ok {
		return RequestLine{}, n, ErrMalformedRequestLine
	}
	if string(method) != "GET" {
		return RequestLine{}, n, ErrNotGet
	}
	if string(version) != "HTTP/1.1" {
		return RequestLine{}, n, ErrNotHTTP11
	}
	return RequestLine{Method: method, Target: target, Version: version}, n, nil
}

// HeaderScanner scans the header fields of an HTTP/1.1 header block held
// in a single byte slice, yielding each field's name and value as
// subslices of the input without allocating, without building a map, and
// without net/textproto's MIME-header normalization.
//
// b must contain zero or more CRLF-terminated header lines followed by
// the terminating blank-line CRLF (i.e. the buffer that follows the
// request line up to and including the empty line that ends the header
// block); a buffer that ends immediately after the last header line
// without a following blank line yields [ErrMissingCRLF].
//
// The zero value is not usable; construct one with [NewHeaderScanner].
type HeaderScanner struct {
	b   []byte
	key []byte
	val []byte
	err error
}

// NewHeaderScanner returns a [HeaderScanner] over b.
func NewHeaderScanner(b []byte) HeaderScanner {
	return HeaderScanner{b: b}
}

// Next advances the scanner to the next header field and reports whether
// one was found. It returns false at the terminating blank line and
// after any error; call [HeaderScanner.Err] to distinguish the two.
//
// Next rejects obsolete line folding (RFC 7230 §3.2.4): a line beginning
// with SP or HTAB, which would otherwise be interpreted as a
// continuation of the previous header's value, stops iteration with
// [ErrObsoleteLineFolding].
func (s *HeaderScanner) Next() bool {
	if s.err != nil {
		return false
	}
	if len(s.b) >= 2 && s.b[0] == '\r' && s.b[1] == '\n' {
		return false // Terminating blank line: end of header block.
	}

	line, rest, ok := cutCRLF(s.b)
	if !ok {
		s.err = ErrMissingCRLF
		return false
	}
	if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
		s.err = ErrObsoleteLineFolding
		return false
	}
	key, val, ok := cutByte(line, ':')
	if !ok {
		s.err = ErrMalformedHeader
		return false
	}

	s.key, s.val, s.b = key, TrimOWS(val), rest
	return true
}

// Key returns the header field name found by the most recent call to
// [HeaderScanner.Next], as a subslice of the original input. The name is
// not case-folded; use [EqualFold] to compare it.
func (s *HeaderScanner) Key() []byte { return s.key }

// Value returns the header field value found by the most recent call to
// [HeaderScanner.Next], as a subslice of the original input with optional
// leading and trailing whitespace (RFC 7230 §3.2.3 OWS) already trimmed.
func (s *HeaderScanner) Value() []byte { return s.val }

// Err returns the first error encountered by [HeaderScanner.Next], if
// any.
func (s *HeaderScanner) Err() error { return s.err }

// EqualFold reports whether b, interpreted as ASCII, equals lower under
// ASCII case folding. lower must already be lowercased; EqualFold never
// allocates and never calls strings.ToLower or bytes.ToLower. Only ASCII
// letters are folded, which is sufficient for the tokens defined by
// RFC 7230 (header names and structured field values are always ASCII).
func EqualFold(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := range b {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// ContainsToken reports whether b, a comma-separated list of tokens such
// as the value of a Connection header ("keep-alive, Upgrade"), contains a
// token equal to lower under ASCII case folding, ignoring optional
// whitespace around each token. lower must already be lowercased.
func ContainsToken(b []byte, lower string) bool {
	for len(b) > 0 {
		var tok []byte
		if i := bytes.IndexByte(b, ','); i >= 0 {
			tok, b = b[:i], b[i+1:]
		} else {
			tok, b = b, nil
		}
		if EqualFold(TrimOWS(tok), lower) {
			return true
		}
	}
	return false
}

// cutCRLF splits b at the first CRLF ("\r\n"), returning the content
// before it and the remainder after it. It reports false if b contains no
// CRLF, or if a bare LF not preceded by CR is found first; bare-LF line
// endings are rejected outright rather than tolerated, per the strict
// CRLF requirement of RFC 7230 §3.5.
func cutCRLF(b []byte) (line, rest []byte, ok bool) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 || i == 0 || b[i-1] != '\r' {
		return nil, nil, false
	}
	return b[:i-1], b[i+1:], true
}

// cutByte splits b at the first occurrence of c, returning the parts
// before and after c. It reports false if c is not present in b.
func cutByte(b []byte, c byte) (before, after []byte, ok bool) {
	i := bytes.IndexByte(b, c)
	if i < 0 {
		return nil, nil, false
	}
	return b[:i], b[i+1:], true
}

// TrimOWS trims leading and trailing optional whitespace (SP or HTAB)
// from b, per RFC 7230 §3.2.3.
func TrimOWS(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}
