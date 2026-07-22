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

// Package extension provides allocation-free primitives for parsing the
// WebSocket "Sec-WebSocket-Extensions" header field (RFC 6455 §9.1, RFC
// 7692 §5), plus a permessage-deflate (RFC 7692 §7) specific layer built
// on top of them.
//
// The generic layer -- [OfferScanner] and [ParamScanner] -- scans the
// header value's grammar:
//
//	Sec-WebSocket-Extensions = extension-list
//	extension-list           = 1#extension
//	extension                = extension-token *( ";" extension-param )
//	extension-token          = registered-token   ; = token
//	extension-param          = token [ "=" (token | quoted-string) ]
//
// without depending on net/http or net/textproto. Reuses EqualFold and
// TrimOWS from the sibling internal/httpx package rather than duplicating them.
package extension

import (
	"bytes"
	"errors"

	"github.com/zchee/gows/internal/httpx"
)

// ErrMalformedExtensionParam indicates an extension-param's value used
// quoted-string syntax without a matching closing quote, or its value
// (after unescaping, if quoted) was not a valid token per RFC 6455
// §9.1's ABNF note ("the value after quoted-string unescaping MUST
// conform to the 'token' ABNF").
var ErrMalformedExtensionParam = errors.New("extension: malformed extension parameter")

// OfferScanner scans the comma-separated extension elements of a
// Sec-WebSocket-Extensions header value -- despite the name, this is
// used for both a client's offers and a server's response, which share
// the same grammar (RFC 6455 §9.1) -- yielding each element's name and
// raw parameter list without allocating.
//
// Per RFC 7230 §7's list ("#rule") extension, empty elements (from
// leading/trailing/repeated commas, e.g. when multiple
// Sec-WebSocket-Extensions header lines were concatenated with commas
// by the caller) are silently skipped rather than treated as malformed.
//
// The zero value is not usable; construct one with [NewOfferScanner].
type OfferScanner struct {
	b      []byte
	name   []byte
	params []byte
}

// NewOfferScanner returns an [OfferScanner] over b.
func NewOfferScanner(b []byte) OfferScanner {
	return OfferScanner{b: b}
}

// Next advances the scanner to the next extension element and reports
// whether one was found.
func (s *OfferScanner) Next() bool {
	for len(s.b) > 0 {
		var raw []byte
		if before, after, ok := splitOutsideQuotes(s.b, ','); ok {
			raw, s.b = before, after
		} else {
			raw, s.b = s.b, nil
		}
		raw = httpx.TrimOWS(raw)
		if len(raw) == 0 {
			continue // Empty list element (RFC 7230 §7): skip, not an error.
		}

		name, params, ok := splitOutsideQuotes(raw, ';')
		if !ok {
			name, params = raw, nil
		}
		name = httpx.TrimOWS(name)
		if len(name) == 0 {
			continue // No extension-token at all: not a parseable element.
		}
		s.name, s.params = name, httpx.TrimOWS(params)
		return true
	}
	return false
}

// Name returns the extension name (extension-token) found by the most
// recent call to [OfferScanner.Next], as a subslice of the original
// input. The name is not case-folded; use internal/httpx's EqualFold to
// compare it (extension names are registered tokens, compared
// case-sensitively by some implementations and case-insensitively by
// others; this package takes no position and leaves the choice to the
// caller).
func (s *OfferScanner) Name() []byte { return s.name }

// Params returns a [ParamScanner] over the current element's parameter
// list.
func (s *OfferScanner) Params() ParamScanner {
	return ParamScanner{b: s.params}
}

// ParamScanner scans the ";"-separated parameters of one extension
// element, yielding each parameter's name and value (nil for a bare
// parameter with no value) without allocating, except when a
// quoted-string value contains a backslash-escape (RFC 7230 §3.2.6),
// which requires rewriting bytes to unescape.
//
// The zero value is not usable; obtain one via [OfferScanner.Params].
type ParamScanner struct {
	b     []byte
	name  []byte
	value []byte
	err   error
}

// Next advances the scanner to the next parameter and reports whether
// one was found. It returns false at the end of the parameter list and
// after any error; call [ParamScanner.Err] to distinguish the two.
func (s *ParamScanner) Next() bool {
	if s.err != nil {
		return false
	}
	for len(s.b) > 0 {
		var raw []byte
		if before, after, ok := splitOutsideQuotes(s.b, ';'); ok {
			raw, s.b = before, after
		} else {
			raw, s.b = s.b, nil
		}
		raw = httpx.TrimOWS(raw)
		if len(raw) == 0 {
			continue
		}

		if name, rawValue, hasValue := bytes.Cut(raw, []byte("=")); hasValue {
			name = httpx.TrimOWS(name)
			if len(name) == 0 || !isToken(name) {
				s.err = ErrMalformedExtensionParam
				return false
			}
			value, ok := unquoteToken(httpx.TrimOWS(rawValue))
			if !ok {
				s.err = ErrMalformedExtensionParam
				return false
			}
			s.name, s.value = name, value
			return true
		}

		if !isToken(raw) {
			s.err = ErrMalformedExtensionParam
			return false
		}
		s.name, s.value = raw, nil
		return true
	}
	return false
}

// Name returns the parameter name found by the most recent call to
// [ParamScanner.Next], as a subslice of the original input.
func (s *ParamScanner) Name() []byte { return s.name }

// Value returns the parameter value found by the most recent call to
// [ParamScanner.Next], or nil if the parameter was bare (no value). A
// quoted-string value is returned unquoted and unescaped; it is a
// subslice of the original input only when it contained no
// backslash-escapes, and a freshly allocated copy otherwise.
func (s *ParamScanner) Value() []byte { return s.value }

// Err returns the first error encountered by [ParamScanner.Next], if
// any.
func (s *ParamScanner) Err() error { return s.err }

// splitOutsideQuotes finds the first occurrence of sep in b that is not
// inside a double-quoted string (itself respecting backslash-escapes
// within the quotes, per RFC 7230 §3.2.6's quoted-string/quoted-pair
// grammar), and splits b there. It reports ok=false if sep does not
// occur outside quotes, in which case before is left as the whole of b
// (equivalent to "no more separators", which also correctly covers an
// unterminated quoted string: the caller ends up treating the malformed
// tail as a single last element, and the actual problem then surfaces
// when that element's value is unquoted).
func splitOutsideQuotes(b []byte, sep byte) (before, after []byte, ok bool) {
	inQuotes := false
	for i := 0; i < len(b); i++ {
		switch {
		case inQuotes && b[i] == '\\' && i+1 < len(b):
			i++
		case b[i] == '"':
			inQuotes = !inQuotes
		case !inQuotes && b[i] == sep:
			return b[:i], b[i+1:], true
		}
	}
	return b, nil, false
}

// unquoteToken returns v's value as an unescaped token: if v is a
// double-quoted string, it is unescaped and the result validated as a
// token; otherwise v itself is validated as a token directly. It
// reports ok=false if v is not a valid quoted-string (no closing quote)
// or the resulting value is not a valid token.
//
// The common cases -- a bare unquoted token, and a quoted value with no
// backslash-escapes (e.g. `"10"`) -- return a subslice of v with no
// allocation; only an escaped quoted value requires rewriting bytes.
func unquoteToken(v []byte) (tok []byte, ok bool) {
	if len(v) == 0 {
		return nil, false
	}
	if v[0] != '"' {
		if !isToken(v) {
			return nil, false
		}
		return v, true
	}
	if len(v) < 2 || v[len(v)-1] != '"' {
		return nil, false
	}
	inner := v[1 : len(v)-1]
	if bytes.IndexByte(inner, '\\') < 0 {
		if !isToken(inner) {
			return nil, false
		}
		return inner, true
	}

	buf := make([]byte, 0, len(inner))
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) {
			i++
		}
		buf = append(buf, inner[i])
	}
	if !isToken(buf) {
		return nil, false
	}
	return buf, true
}

// isToken reports whether b is non-empty and consists entirely of RFC
// 7230 §3.2.6 tchar characters.
func isToken(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !isTchar(c) {
			return false
		}
	}
	return true
}

// isTchar reports whether c is an RFC 7230 §3.2.6 tchar.
func isTchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}
