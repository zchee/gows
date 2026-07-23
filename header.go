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
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/zchee/gows/internal/httpx"
)

// wsHandshakeHeaders holds the WebSocket-relevant fields collected from a
// request or response header block. Request-only and response-only fields
// share one type so Upgrade and Dial scan through a single classify loop.
type wsHandshakeHeaders struct {
	hostSeen, upgradeOK, connectionOK, versionOK bool
	key, origin, protocol, extensions, accept    []byte
}

// scanWSHandshakeHeaders classifies the opening-handshake headers both
// [Upgrader.Upgrade] (request) and [Dialer.Dial] (response) need.
func scanWSHandshakeHeaders(headers []byte) (wsHandshakeHeaders, error) {
	var f wsHandshakeHeaders
	sc := httpx.NewHeaderScanner(headers)
	for sc.Next() {
		switch {
		case httpx.EqualFold(sc.Key(), "host"):
			f.hostSeen = true
		case httpx.EqualFold(sc.Key(), "upgrade"):
			f.upgradeOK = f.upgradeOK || httpx.ContainsToken(sc.Value(), "websocket")
		case httpx.EqualFold(sc.Key(), "connection"):
			f.connectionOK = f.connectionOK || httpx.ContainsToken(sc.Value(), "upgrade")
		case httpx.EqualFold(sc.Key(), "sec-websocket-version"):
			f.versionOK = f.versionOK || string(sc.Value()) == "13"
		case httpx.EqualFold(sc.Key(), "sec-websocket-key"):
			f.key = sc.Value()
		case httpx.EqualFold(sc.Key(), "origin"):
			f.origin = sc.Value()
		case httpx.EqualFold(sc.Key(), "sec-websocket-protocol"):
			f.protocol = sc.Value()
		case httpx.EqualFold(sc.Key(), "sec-websocket-extensions"):
			f.extensions = sc.Value()
		case httpx.EqualFold(sc.Key(), "sec-websocket-accept"):
			f.accept = sc.Value()
		}
	}
	return f, sc.Err()
}

// secWebSocketPrefix is the case-insensitive prefix shared by every
// Sec-WebSocket-* header (RFC 6455 §11.3). The whole family is reserved
// for [Dialer.HTTPHeader]: this package computes each member itself as
// part of the opening handshake, and future members of the family
// belong to the protocol, not to callers.
const secWebSocketPrefix = "Sec-WebSocket-"

// reservedRequestHeaders lists the non-Sec-WebSocket-* header names
// [Dialer.HTTPHeader] may never carry. Each either is computed by this
// package as part of the opening handshake (RFC 6455 §4.1), would
// change how the peer frames or routes the handshake exchange itself
// (Host, Content-Length, Transfer-Encoding, Trailer, TE), or is
// hop-by-hop state owned by the proxy path (Proxy-Authorization: proxy
// credentials travel in the [Dialer.Proxy] URL and are emitted only on
// the proxy leg, never through the origin header seam). Overriding any
// of them would desynchronize the handshake state this package
// validates against.
var reservedRequestHeaders = [...]string{
	"Host",
	"Upgrade",
	"Connection",
	"Content-Length",
	"Transfer-Encoding",
	"Trailer",
	"TE",
	"Keep-Alive",
	"Proxy-Authorization",
	"Proxy-Connection",
}

// reservedHeaderName reports whether name is reserved for
// [Dialer.HTTPHeader], comparing case-insensitively so a case-variant
// spelling cannot bypass the rejection.
func reservedHeaderName(name string) bool {
	if len(name) >= len(secWebSocketPrefix) && strings.EqualFold(name[:len(secWebSocketPrefix)], secWebSocketPrefix) {
		return true
	}
	for _, reserved := range reservedRequestHeaders {
		if strings.EqualFold(name, reserved) {
			return true
		}
	}
	return false
}

// validateExtraHeaders checks every name and value in h for use as
// extra handshake request headers: names must be RFC 7230 tokens and
// not reserved ([ErrReservedHeader]), values must be RFC 7230
// field-content ([ErrMalformedHeader] otherwise -- in particular no CR,
// LF, or NUL, so a hostile value cannot smuggle additional header lines
// or terminate the block early), and the combined serialized size of
// every "Name: value" CRLF line must fit the handshake header ceiling
// ([ErrHeaderTooLarge] past defaultMaxHeaderBytes). Errors name the
// offending header but never include its value. A nil or empty h is
// valid.
func validateExtraHeaders(h http.Header) error {
	total := 0
	for name, values := range h {
		if !validHeaderName(name) {
			return fmt.Errorf("%w: invalid header name %q", ErrMalformedHeader, name)
		}
		if reservedHeaderName(name) {
			return fmt.Errorf("%w: %q", ErrReservedHeader, name)
		}
		for _, v := range values {
			if !validHeaderValue(v) {
				return fmt.Errorf("%w: invalid value for header %q", ErrMalformedHeader, name)
			}
			total += len(name) + len(": \r\n") + len(v)
		}
	}
	if total > defaultMaxHeaderBytes {
		return fmt.Errorf("%w: extra handshake headers serialize to %d bytes (limit %d)", ErrHeaderTooLarge, total, defaultMaxHeaderBytes)
	}
	return nil
}

// appendExtraHeaders appends the "Name: value" CRLF lines h describes
// to dst -- keys in sorted order so the emitted bytes are deterministic
// regardless of map iteration, one line per value in slice order -- and
// returns the extended buffer. The caller must have validated h with
// [validateExtraHeaders] first; appendExtraHeaders performs no checking
// of its own.
func appendExtraHeaders(dst []byte, h http.Header) []byte {
	if len(h) == 0 {
		return dst
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, v := range h[name] {
			dst = append(dst, name...)
			dst = append(dst, ": "...)
			dst = append(dst, v...)
			dst = append(dst, "\r\n"...)
		}
	}
	return dst
}

// deleteHeaderFold removes every entry of h whose key is a
// case-insensitive match for name. [http.Header.Del] only removes the
// canonical spelling, which would let a non-canonical map key (e.g.
// "authorization") survive the credential stripping the redirect path
// relies on.
func deleteHeaderFold(h http.Header, name string) {
	for k := range h {
		if strings.EqualFold(k, name) {
			delete(h, k)
		}
	}
}

// validHeaderName reports whether s is a valid header field name: a
// non-empty RFC 7230 token (1*tchar).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

// isTokenChar reports whether b is an RFC 7230 tchar: any VCHAR except
// the delimiters DQUOTE and (),/:;<=>?@[\]{}.
func isTokenChar(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '\u0060', '|', '~':
		return true
	}
	return false
}

// validHeaderValue reports whether s is valid header field-content per
// RFC 7230 §3.2: HTAB, SP, VCHAR, or obs-text (0x80-0xFF); every other
// control byte -- most importantly CR, LF, and NUL -- is rejected, which
// is what makes an attacker-influenced value unable to inject additional
// header lines into the handshake block.
func validHeaderValue(s string) bool {
	for i := range len(s) {
		b := s[i]
		if b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7F {
			return false
		}
	}
	return true
}
