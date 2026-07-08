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

package httpx

import "errors"

// ErrMalformedStatusLine indicates the status line does not have the
// "HTTP-version SP status-code SP reason-phrase" form.
var ErrMalformedStatusLine = errors.New("httpx: malformed status line")

// StatusLine holds the HTTP-version, status-code, and reason-phrase
// fields of an HTTP status line as subslices of the original input.
type StatusLine struct {
	Version []byte
	Code    []byte
	Reason  []byte
}

// ParseStatusLine parses the status line at the start of b and returns
// it along with the number of bytes consumed, including the terminating
// CRLF. The returned fields reference subslices of b; no allocation is
// performed.
//
// Per RFC 7230 §3.1.2, a status line has the form
// "HTTP-version SP status-code SP reason-phrase CRLF"; the reason phrase
// may be empty, but the SP preceding it is not. ParseStatusLine performs
// no other validation: unlike [ParseRequestLine], it does not require
// HTTP/1.1 or any particular status code, since its only intended
// caller -- a client reading a handshake response -- must be able to
// report a "this wasn't a WebSocket upgrade" response the same way it
// reports acceptance.
func ParseStatusLine(b []byte) (line StatusLine, n int, err error) {
	raw, _, ok := cutCRLF(b)
	if !ok {
		return StatusLine{}, 0, ErrMissingCRLF
	}
	n = len(raw) + 2

	version, remainder, ok := cutByte(raw, ' ')
	if !ok {
		return StatusLine{}, n, ErrMalformedStatusLine
	}
	code, reason, ok := cutByte(remainder, ' ')
	if !ok {
		return StatusLine{}, n, ErrMalformedStatusLine
	}
	return StatusLine{Version: version, Code: code, Reason: reason}, n, nil
}
