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
	"errors"
	"net/http"
	"strings"
	"testing"
)

// boundaryValue returns a value sized so a single "X-A: <value>" line
// serializes h to exactly defaultMaxHeaderBytes plus extra bytes.
func boundaryValue(extra int) string {
	return strings.Repeat("v", defaultMaxHeaderBytes-len("X-A")-len(": \r\n")+extra)
}

func TestValidateExtraHeaders(t *testing.T) {
	tests := map[string]struct {
		header  http.Header
		wantErr error
	}{
		"success: nil header":   {header: nil},
		"success: empty header": {header: http.Header{}},
		"success: ordinary headers": {header: http.Header{
			"Authorization": {"Bearer tok"},
			"Cookie":        {"a=1", "b=2"},
			"X-Custom":      {"v"},
		}},
		"success: non-canonical key spelling":      {header: http.Header{"x-lower-case": {"v"}}},
		"success: value with HTAB and obs-text":    {header: http.Header{"X-A": {"a\tb\x80\xff"}}},
		"success: empty value":                     {header: http.Header{"X-A": {""}}},
		"success: total size at the exact ceiling": {header: http.Header{"X-A": {boundaryValue(0)}}},
		"error: total size one byte past the ceiling": {
			header:  http.Header{"X-A": {boundaryValue(1)}},
			wantErr: ErrHeaderTooLarge,
		},
		"error: combined size across headers past the ceiling": {
			header: http.Header{
				"X-A": {boundaryValue(-1)},
				"X-B": {""},
			},
			wantErr: ErrHeaderTooLarge,
		},
		"error: empty name":                      {header: http.Header{"": {"v"}}, wantErr: ErrMalformedHeader},
		"error: name with space":                 {header: http.Header{"X A": {"v"}}, wantErr: ErrMalformedHeader},
		"error: name with colon":                 {header: http.Header{"X:A": {"v"}}, wantErr: ErrMalformedHeader},
		"error: name with parenthesis delimiter": {header: http.Header{"X(A)": {"v"}}, wantErr: ErrMalformedHeader},
		"error: name with non-ASCII byte":        {header: http.Header{"X\x80A": {"v"}}, wantErr: ErrMalformedHeader},
		// validHeaderValue returns at the first offending byte, so the
		// CRLF-injection case stops on its CR and never reaches its LF:
		// lone CR and lone LF each need their own case. The 0x01 case
		// earns its own against a reject set enumerating NUL, DEL, CR
		// and LF: that set passes every other row here and lets 0x01
		// through. It pins one byte, not the whole C0 range.
		"error: value with CR":             {header: http.Header{"X-A": {"a\rb"}}, wantErr: ErrMalformedHeader},
		"error: value with LF":             {header: http.Header{"X-A": {"a\nb"}}, wantErr: ErrMalformedHeader},
		"error: value with CRLF injection": {header: http.Header{"X-A": {"a\r\nX-Injected: 1"}}, wantErr: ErrMalformedHeader},
		"error: value with NUL":            {header: http.Header{"X-A": {"a\x00b"}}, wantErr: ErrMalformedHeader},
		"error: value with control byte":   {header: http.Header{"X-A": {"a\x01b"}}, wantErr: ErrMalformedHeader},
		"error: value with DEL":            {header: http.Header{"X-A": {"a\x7fb"}}, wantErr: ErrMalformedHeader},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateExtraHeaders(tt.header)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("validateExtraHeaders(%v) = %v, want nil", tt.header, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateExtraHeaders(%v) = %v, want errors.Is %v", tt.header, err, tt.wantErr)
			}
		})
	}
}

// TestValidateExtraHeadersReservedNames walks every reserved name --
// the enumerated framing/routing/hop-by-hop set plus arbitrary members
// of the Sec-WebSocket-* family -- in canonical, lower, and upper case
// spellings, so a case-variant map key is never a bypass.
func TestValidateExtraHeadersReservedNames(t *testing.T) {
	names := []string{
		"Host",
		"Upgrade",
		"Connection",
		"Content-Length",
		"Transfer-Encoding",
		"Trailer",
		"TE",
		"Proxy-Authorization",
		"Sec-WebSocket-Future-Member",
	}
	for _, name := range names {
		for _, variant := range []string{name, strings.ToLower(name), strings.ToUpper(name)} {
			err := validateExtraHeaders(http.Header{variant: {"v"}})
			if !errors.Is(err, ErrReservedHeader) {
				t.Errorf("validateExtraHeaders(%q) = %v, want errors.Is ErrReservedHeader", variant, err)
				continue
			}
			if !strings.Contains(err.Error(), variant) {
				t.Errorf("error %q does not name the offending header %q", err, variant)
			}
		}
	}
}

// TestValidateExtraHeadersOmitsValues pins the secret-hygiene contract:
// every validation failure may name the header but must never include
// its value anywhere in the error chain.
func TestValidateExtraHeadersOmitsValues(t *testing.T) {
	const secret = "SECRET-bearer-credential-XYZ"
	tests := map[string]http.Header{
		"reserved name carrying the secret":   {"Proxy-Authorization": {secret}},
		"malformed value carrying the secret": {"X-Api-Key": {secret + "\r\ninjected: 1"}},
		"oversized value carrying the secret": {"X-Big": {secret + strings.Repeat("a", defaultMaxHeaderBytes)}},
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateExtraHeaders(h)
			if err == nil {
				t.Fatalf("validateExtraHeaders(%v keys) = nil, want error", len(h))
			}
			for e := err; e != nil; e = errors.Unwrap(e) {
				if strings.Contains(e.Error(), secret) {
					t.Fatalf("error chain leaks the header value: %q", e)
				}
			}
		})
	}
}

// TestAppendExtraHeaders pins the serialization contract: sorted keys
// regardless of map iteration, one line per value in slice order, the
// caller's key spelling preserved byte-for-byte.
func TestAppendExtraHeaders(t *testing.T) {
	h := http.Header{
		"B-Second": {"2"},
		"A-First":  {"1a", "1b"},
		"c-third":  {"3"},
	}
	want := "A-First: 1a\r\nA-First: 1b\r\nB-Second: 2\r\nc-third: 3\r\n"
	for range 32 {
		if got := string(appendExtraHeaders(nil, h)); got != want {
			t.Fatalf("appendExtraHeaders = %q, want %q", got, want)
		}
	}
	if got := appendExtraHeaders(nil, nil); got != nil {
		t.Errorf("appendExtraHeaders(nil, nil) = %q, want nil", got)
	}
}

// TestDeleteHeaderFold pins that credential stripping removes every
// case-variant map key, where http.Header.Del would only remove the
// canonical spelling.
func TestDeleteHeaderFold(t *testing.T) {
	h := http.Header{
		"Authorization": {"a"},
		"authorization": {"b"},
		"AUTHORIZATION": {"c"},
		"X-Keep":        {"kept"},
	}
	deleteHeaderFold(h, "Authorization")
	if len(h) != 1 || h["X-Keep"] == nil {
		t.Fatalf("deleteHeaderFold left %v, want only X-Keep", h)
	}
}
