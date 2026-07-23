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

package extension

import (
	"errors"
	"strconv"

	"github.com/zchee/gows/internal/httpx"
)

// DeflateExtensionName is the registered extension-token for
// permessage-deflate (RFC 7692 §7).
const DeflateExtensionName = "permessage-deflate"

// Window-bits bounds shared by server_max_window_bits and
// client_max_window_bits (RFC 7692 §7.1.2, §7.1.2.1, §7.1.2.2): the
// base-2 logarithm of the LZ77 sliding window size.
const (
	minWindowBits = 8
	maxWindowBits = 15
)

// Sentinel errors returned by [ValidateDeflateResponse]. Each is
// comparable with [errors.Is].
var (
	// ErrDeflateInvalidResponse indicates a permessage-deflate response
	// element failed one of RFC 7692 §7's structural conditions: an
	// unknown parameter, a duplicate parameter, an out-of-range or
	// malformed window-bits value, a bare client_max_window_bits (which
	// RFC 7692 §7.1.2.2 permits only in an offer, never a response), or
	// no permessage-deflate element present in the response at all.
	ErrDeflateInvalidResponse = errors.New("extension: invalid permessage-deflate response")
	// ErrDeflateUnrequestedClientMaxWindowBits indicates a response
	// included client_max_window_bits although the offer it is
	// responding to never included that parameter at all (bare or
	// valued), which RFC 7692 §7.1.2.2 forbids.
	ErrDeflateUnrequestedClientMaxWindowBits = errors.New("extension: response set client_max_window_bits, but the offer did not include it")
	// ErrDeflateServerMaxWindowBitsTooLarge indicates a response's
	// server_max_window_bits exceeded the value the offer proposed,
	// which RFC 7692 §7.1.2.1 forbids ("the same or smaller value as
	// the offer").
	ErrDeflateServerMaxWindowBitsTooLarge = errors.New("extension: response set server_max_window_bits greater than the offer allowed")
)

// ClientMaxWindowBitsBare is stored in [DeflateParams.ClientMaxWindowBits]
// when client_max_window_bits was present without a value (offer-only form
// per RFC 7692 §7.1.2.2: the client accepts a valued response parameter
// and the server picks the value). Never used in a response.
const ClientMaxWindowBitsBare = -1

// DeflateParams describes one negotiated, offered, or responded
// configuration of the permessage-deflate extension (RFC 7692 §7).
type DeflateParams struct {
	// ServerNoContextTakeover corresponds to the server_no_context_takeover
	// parameter (RFC 7692 §7.1.1), a bare flag.
	ServerNoContextTakeover bool
	// ClientNoContextTakeover corresponds to the client_no_context_takeover
	// parameter (RFC 7692 §7.1.1), a bare flag.
	ClientNoContextTakeover bool
	// ServerMaxWindowBits corresponds to the server_max_window_bits
	// parameter (RFC 7692 §7.1.2.1): 0 if absent, otherwise 8-15. This
	// parameter never has a bare (valueless) form.
	ServerMaxWindowBits int
	// ClientMaxWindowBits corresponds to the client_max_window_bits
	// parameter (RFC 7692 §7.1.2.2): 0 if absent entirely,
	// [ClientMaxWindowBitsBare] if present but bare (valid only in an
	// offer), otherwise 8-15. A response's client_max_window_bits is
	// never bare; see [ValidateDeflateResponse]. Prefer
	// [DeflateParams.HasClientMaxWindowBits],
	// [DeflateParams.ClientMaxWindowBitsIsBare], and
	// [DeflateParams.ClientMaxWindowBitsValue] over comparing the raw
	// field to 0 / -1.
	ClientMaxWindowBits int
}

// HasClientMaxWindowBits reports whether client_max_window_bits was
// present at all (bare or valued).
func (p DeflateParams) HasClientMaxWindowBits() bool {
	return p.ClientMaxWindowBits != 0
}

// ClientMaxWindowBitsIsBare reports whether client_max_window_bits was
// present without a value (offer-only form).
func (p DeflateParams) ClientMaxWindowBitsIsBare() bool {
	return p.ClientMaxWindowBits == ClientMaxWindowBitsBare
}

// ClientMaxWindowBitsValue returns the numeric window bits when valued
// (8-15), or 0 when absent, bare, or outside the RFC 7692 range. Safe
// for public-API surfaces and response emission that must not observe
// the bare-offer sentinel or out-of-range values.
func (p DeflateParams) ClientMaxWindowBitsValue() int {
	if p.ClientMaxWindowBits < minWindowBits || p.ClientMaxWindowBits > maxWindowBits {
		return 0
	}
	return p.ClientMaxWindowBits
}

// ParseDeflateOffer scans b, a Sec-WebSocket-Extensions header value,
// for permessage-deflate offers, and returns the first one that is
// structurally valid per the decline conditions in RFC 7692 §7 (no
// parameter undefined for use in an offer, no duplicate parameters, no
// out-of-range or malformed window-bits value). Per RFC 7692 §5, "a
// client may also offer multiple [permessage-deflate] choices ... [and]
// the order of elements is important as it specifies the client's
// preference", so a later permessage-deflate offer is only considered
// if every earlier one is invalid.
//
// ParseDeflateOffer reports ok=false if b contains no permessage-deflate
// offer at all, or every one present is invalid; the caller should then
// omit permessage-deflate from its response entirely, per RFC 7692 §7's
// decline conditions.
//
// ParseDeflateOffer only checks structural validity: whether the
// resulting configuration is one the caller is actually willing to use
// (e.g. it may refuse to disable context takeover) is a policy decision
// left to the caller.
func ParseDeflateOffer(b []byte) (params DeflateParams, ok bool) {
	sc := NewOfferScanner(b)
	for sc.Next() {
		if !httpx.EqualFold(sc.Name(), DeflateExtensionName) {
			continue
		}
		if params, ok := ParseDeflateOfferParams(sc.Params()); ok {
			return params, true
		}
	}
	return DeflateParams{}, false
}

// ParseDeflateOfferParams validates one permessage-deflate offer's
// already-scanned parameters (typically params obtained from an
// [OfferScanner] whose Name() matched [DeflateExtensionName]), applying
// the same structural rules [ParseDeflateOffer] applies to every
// candidate internally.
//
// It is exported for callers that need to apply additional policy on top
// of structural validity per candidate offer and keep trying subsequent
// offers on rejection -- something ParseDeflateOffer's own "first
// structurally valid offer" selection does not support (e.g. a server
// that can only honor server_max_window_bits == 15 needs to decline an
// otherwise-valid offer requesting a smaller window and fall back to the
// client's next offer, which requires re-scanning with
// [NewOfferScanner] and calling this function per candidate directly
// instead of ParseDeflateOffer).
func ParseDeflateOfferParams(params ParamScanner) (DeflateParams, bool) {
	return parseDeflateParams(params)
}

// AppendDeflateResponse appends the permessage-deflate response element
// -- "permessage-deflate" followed by agreed's parameters -- to dst,
// returning the extended buffer. agreed is the configuration the server
// has decided to accept (typically derived from a [ParseDeflateOffer]
// result, possibly narrowed by the server's own policy).
//
// AppendDeflateResponse never emits a bare client_max_window_bits (RFC
// 7692 §7.1.2.2 requires a response's client_max_window_bits, if
// present at all, to carry a value): [ClientMaxWindowBitsBare] is treated
// the same as absent.
func AppendDeflateResponse(dst []byte, agreed DeflateParams) []byte {
	dst = append(dst, DeflateExtensionName...)
	if agreed.ServerNoContextTakeover {
		dst = append(dst, "; server_no_context_takeover"...)
	}
	if agreed.ClientNoContextTakeover {
		dst = append(dst, "; client_no_context_takeover"...)
	}
	if agreed.ServerMaxWindowBits >= minWindowBits && agreed.ServerMaxWindowBits <= maxWindowBits {
		dst = append(dst, "; server_max_window_bits="...)
		dst = strconv.AppendInt(dst, int64(agreed.ServerMaxWindowBits), 10)
	}
	if v := agreed.ClientMaxWindowBitsValue(); v != 0 {
		dst = append(dst, "; client_max_window_bits="...)
		dst = strconv.AppendInt(dst, int64(v), 10)
	}
	return dst
}

// ValidateDeflateResponse scans response, a server's
// Sec-WebSocket-Extensions response header value, for a
// permessage-deflate element, and validates it against offered, the
// DeflateParams the client itself sent in its offer, per the
// client-side conditions in RFC 7692 §7 and §7.1.2.2. Per RFC 6455
// §7.1.7 / RFC 7692 §7, the caller MUST fail the WebSocket connection if
// ValidateDeflateResponse returns a non-nil error.
//
// ValidateDeflateResponse rejects (with [ErrDeflateInvalidResponse]) a
// response containing no permessage-deflate element, an unknown or
// duplicate parameter, an out-of-range or malformed window-bits value,
// or a bare client_max_window_bits (valid only in an offer). It
// separately rejects, with a more specific error, a
// client_max_window_bits the offer never included at all
// ([ErrDeflateUnrequestedClientMaxWindowBits]) and a server_max_window_bits
// larger than the offer proposed ([ErrDeflateServerMaxWindowBitsTooLarge]).
func ValidateDeflateResponse(offered DeflateParams, response []byte) (DeflateParams, error) {
	sc := NewOfferScanner(response)
	for sc.Next() {
		if !httpx.EqualFold(sc.Name(), DeflateExtensionName) {
			continue
		}
		params, ok := parseDeflateParams(sc.Params())
		if !ok || params.ClientMaxWindowBitsIsBare() {
			return DeflateParams{}, ErrDeflateInvalidResponse
		}
		if params.HasClientMaxWindowBits() && !offered.HasClientMaxWindowBits() {
			return DeflateParams{}, ErrDeflateUnrequestedClientMaxWindowBits
		}
		if params.ServerMaxWindowBits != 0 && offered.ServerMaxWindowBits != 0 &&
			params.ServerMaxWindowBits > offered.ServerMaxWindowBits {
			return DeflateParams{}, ErrDeflateServerMaxWindowBitsTooLarge
		}
		return params, nil
	}
	return DeflateParams{}, ErrDeflateInvalidResponse
}

// parseDeflateParams validates and collects one permessage-deflate
// element's parameters (RFC 7692 §7's four defined parameters), sharing
// the same structural rules between an offer and a response: unknown
// parameter, duplicate parameter, and malformed/out-of-range
// window-bits values are always rejected. The one difference between
// offer- and response-side validity -- whether a bare
// client_max_window_bits is acceptable -- is left to the caller
	// ([ParseDeflateOffer] accepts it as [ClientMaxWindowBitsBare];
	// [ValidateDeflateResponse] rejects a bare result itself), since this
	// function has no way to know which side is calling it.
func parseDeflateParams(params ParamScanner) (DeflateParams, bool) {
	var p DeflateParams
	var haveServerNCT, haveClientNCT, haveServerBits, haveClientBits bool

	for params.Next() {
		name, value := params.Name(), params.Value()
		switch {
		case httpx.EqualFold(name, "server_no_context_takeover"):
			if haveServerNCT || value != nil {
				return DeflateParams{}, false
			}
			haveServerNCT = true
			p.ServerNoContextTakeover = true

		case httpx.EqualFold(name, "client_no_context_takeover"):
			if haveClientNCT || value != nil {
				return DeflateParams{}, false
			}
			haveClientNCT = true
			p.ClientNoContextTakeover = true

		case httpx.EqualFold(name, "server_max_window_bits"):
			if haveServerBits {
				return DeflateParams{}, false
			}
			bits, ok := parseWindowBits(value)
			if !ok {
				return DeflateParams{}, false
			}
			haveServerBits = true
			p.ServerMaxWindowBits = bits

		case httpx.EqualFold(name, "client_max_window_bits"):
			if haveClientBits {
				return DeflateParams{}, false
			}
			haveClientBits = true
			if value == nil {
				p.ClientMaxWindowBits = ClientMaxWindowBitsBare
				continue
			}
			bits, ok := parseWindowBits(value)
			if !ok {
				return DeflateParams{}, false
			}
			p.ClientMaxWindowBits = bits

		default:
			return DeflateParams{}, false // Parameter not defined for this extension.
		}
	}
	if params.Err() != nil {
		return DeflateParams{}, false
	}
	return p, true
}

// parseWindowBits parses v as an RFC 7692 window-bits value: a decimal
// integer 8-15 with no leading zero (the ABNF is "1*DIGIT"; the leading
// zero and range restrictions come from §7.1.2.1/§7.1.2.2's prose). It
// reports ok=false for a nil (bare) value, since server_max_window_bits
// and a response's client_max_window_bits are never bare.
func parseWindowBits(v []byte) (int, bool) {
	if len(v) == 0 || len(v) > 2 || v[0] == '0' {
		return 0, false
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n < minWindowBits || n > maxWindowBits {
		return 0, false
	}
	return n, true
}
