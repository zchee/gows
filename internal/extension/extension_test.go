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

package extension_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/zchee/gows/internal/extension"
)

// param is a (name, value) pair used to express expected scan results;
// value == "" with hasValue == false represents a bare parameter.
type param struct {
	name     string
	value    string
	hasValue bool
}

type offer struct {
	name   string
	params []param
}

func scanAllOffers(t *testing.T, b []byte) []offer {
	t.Helper()
	var got []offer
	sc := extension.NewOfferScanner(b)
	for sc.Next() {
		o := offer{name: string(sc.Name())}
		ps := sc.Params()
		for ps.Next() {
			p := param{name: string(ps.Name())}
			if v := ps.Value(); v != nil {
				p.value, p.hasValue = string(v), true
			}
			o.params = append(o.params, p)
		}
		if err := ps.Err(); err != nil {
			t.Fatalf("scanAllOffers(%q): param scan error for offer %q: %v", b, o.name, err)
		}
		got = append(got, o)
	}
	return got
}

func TestOfferScannerRFCExamples(t *testing.T) {
	tests := map[string]struct {
		raw  string
		want []offer
	}{
		"simplest form": {
			raw:  "permessage-foo",
			want: []offer{{name: "permessage-foo"}},
		},
		"with unquoted parameter": {
			raw:  "permessage-foo; x=10",
			want: []offer{{name: "permessage-foo", params: []param{{name: "x", value: "10", hasValue: true}}}},
		},
		"with quoted parameter": {
			raw:  `permessage-foo; x="10"`,
			want: []offer{{name: "permessage-foo", params: []param{{name: "x", value: "10", hasValue: true}}}},
		},
		"multiple choices": {
			raw: "permessage-foo, permessage-bar",
			want: []offer{
				{name: "permessage-foo"},
				{name: "permessage-bar"},
			},
		},
		"feature toggle, same name twice": {
			raw: "permessage-foo; use_y, permessage-foo",
			want: []offer{
				{name: "permessage-foo", params: []param{{name: "use_y"}}},
				{name: "permessage-foo"},
			},
		},
		"permessage-deflate with window bits": {
			raw: "permessage-deflate; client_max_window_bits; server_max_window_bits=10",
			want: []offer{{
				name: "permessage-deflate",
				params: []param{
					{name: "client_max_window_bits"},
					{name: "server_max_window_bits", value: "10", hasValue: true},
				},
			}},
		},
		"fallback: two offers": {
			raw: "permessage-deflate; client_max_window_bits; server_max_window_bits=10, " +
				"permessage-deflate; client_max_window_bits",
			want: []offer{
				{name: "permessage-deflate", params: []param{
					{name: "client_max_window_bits"},
					{name: "server_max_window_bits", value: "10", hasValue: true},
				}},
				{name: "permessage-deflate", params: []param{{name: "client_max_window_bits"}}},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := scanAllOffers(t, []byte(tt.raw))
			if len(got) != len(tt.want) {
				t.Fatalf("scanned %d offers, want %d: got %+v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				if got[i].name != w.name {
					t.Errorf("offer[%d].name = %q, want %q", i, got[i].name, w.name)
				}
				if len(got[i].params) != len(w.params) {
					t.Fatalf("offer[%d] params = %+v, want %+v", i, got[i].params, w.params)
				}
				for j, wp := range w.params {
					if got[i].params[j] != wp {
						t.Errorf("offer[%d].params[%d] = %+v, want %+v", i, j, got[i].params[j], wp)
					}
				}
			}
		})
	}
}

func TestOfferScannerEmptyElements(t *testing.T) {
	tests := map[string]struct {
		raw  string
		want []offer
	}{
		"empty header":           {raw: "", want: nil},
		"only commas":            {raw: ",,,", want: nil},
		"leading/trailing comma": {raw: ",permessage-foo,", want: []offer{{name: "permessage-foo"}}},
		"whitespace around commas": {
			raw:  "permessage-foo ,  permessage-bar",
			want: []offer{{name: "permessage-foo"}, {name: "permessage-bar"}},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := scanAllOffers(t, []byte(tt.raw))
			if len(got) != len(tt.want) {
				t.Fatalf("scanned %d offers, want %d: got %+v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				if got[i].name != w.name {
					t.Errorf("offer[%d].name = %q, want %q", i, got[i].name, w.name)
				}
			}
		})
	}
}

func TestOfferScannerQuotedDelimitersNotSplitPrematurely(t *testing.T) {
	// A quoted value containing a literal comma and semicolon must not
	// be mistaken for offer/param boundaries while scanning -- even
	// though the resulting value is not itself a valid token (RFC 6455
	// §9.1: a quoted value must reduce to a token after unescaping, and
	// token characters never include ',' or ';'), so this element is
	// still correctly rejected in the end, but as ONE offer with ONE
	// malformed parameter, not as multiple offers/parameters
	// artificially produced by splitting inside the quotes.
	raw := `permessage-foo; x="a,b;c", permessage-bar`
	sc := extension.NewOfferScanner([]byte(raw))
	if !sc.Next() {
		t.Fatalf("Next() = false")
	}
	if string(sc.Name()) != "permessage-foo" {
		t.Fatalf("first offer name = %q, want permessage-foo (a comma inside quotes must not split the offer list)", sc.Name())
	}
	ps := sc.Params()
	if ps.Next() {
		t.Fatalf("Params Next() = true, want false (value contains non-token characters)")
	}
	if !errors.Is(ps.Err(), extension.ErrMalformedExtensionParam) {
		t.Fatalf("Err() = %v, want ErrMalformedExtensionParam", ps.Err())
	}

	if !sc.Next() {
		t.Fatalf("second Next() = false, want true for permessage-bar (the quoted comma must not have been consumed as a list separator)")
	}
	if string(sc.Name()) != "permessage-bar" {
		t.Fatalf("second offer name = %q, want permessage-bar", sc.Name())
	}
}

func TestParamScannerMalformed(t *testing.T) {
	tests := map[string]string{
		"unterminated quote":       `permessage-foo; x="unterminated`,
		"non-token unquoted value": "permessage-foo; x=has space",
		"empty parameter name":     "permessage-foo; =bar",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			sc := extension.NewOfferScanner([]byte(raw))
			if !sc.Next() {
				t.Fatalf("Next() = false, want true for the offer name itself")
			}
			ps := sc.Params()
			for ps.Next() {
				// Drain; the malformed parameter should surface via Err.
			}
			if !errors.Is(ps.Err(), extension.ErrMalformedExtensionParam) {
				t.Fatalf("Err() = %v, want ErrMalformedExtensionParam", ps.Err())
			}
		})
	}
}

func TestParamScannerEscapedQuotedValue(t *testing.T) {
	// The escaped byte sequence "1\0" (backslash-escaping the digit '0')
	// unescapes to the valid token "10".
	raw := `permessage-foo; x="1\0"`
	sc := extension.NewOfferScanner([]byte(raw))
	if !sc.Next() {
		t.Fatalf("Next() = false")
	}
	ps := sc.Params()
	if !ps.Next() {
		t.Fatalf("Params Next() = false, err=%v", ps.Err())
	}
	if string(ps.Value()) != "10" {
		t.Fatalf("Value() = %q, want %q", ps.Value(), "10")
	}
}

func TestParamScannerEscapedQuotedValueRejectedIfNotToken(t *testing.T) {
	// Unescaping "a\"b" yields a\"b -- a literal '"' in the middle of
	// the value, which is not a valid tchar, so this must be rejected
	// (RFC 6455 §9.1: the unescaped value MUST conform to the token
	// ABNF).
	raw := `permessage-foo; x="a\"b"`
	sc := extension.NewOfferScanner([]byte(raw))
	if !sc.Next() {
		t.Fatalf("Next() = false")
	}
	ps := sc.Params()
	if ps.Next() {
		t.Fatalf("Params Next() = true, want false (unescaped value %q is not a valid token)", ps.Value())
	}
	if !errors.Is(ps.Err(), extension.ErrMalformedExtensionParam) {
		t.Fatalf("Err() = %v, want ErrMalformedExtensionParam", ps.Err())
	}
}

func TestParamScannerAllocs(t *testing.T) {
	tests := map[string]string{
		"bare param":             "permessage-foo; use_y",
		"unquoted value":         "permessage-foo; client_max_window_bits=10",
		"quoted value no escape": `permessage-foo; client_max_window_bits="10"`,
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			b := []byte(raw)
			f := func() {
				sc := extension.NewOfferScanner(b)
				for sc.Next() {
					ps := sc.Params()
					for ps.Next() {
						_, _ = ps.Name(), ps.Value()
					}
					if err := ps.Err(); err != nil {
						t.Fatal(err)
					}
				}
			}
			if avg := testing.AllocsPerRun(200, f); avg != 0 {
				t.Fatalf("scan: %.2f allocs/op, want 0", avg)
			}
		})
	}
}

// FuzzParseExtensions asserts that OfferScanner/ParamScanner never
// panic on arbitrary input, and that any offer successfully scanned
// re-serializes to something that parses back to an equal name and
// parameter list.
func FuzzParseExtensions(f *testing.F) {
	f.Add([]byte("permessage-deflate"))
	f.Add([]byte("permessage-deflate; server_no_context_takeover; client_max_window_bits=10"))
	f.Add([]byte("foo, permessage-deflate; client_max_window_bits"))
	f.Add([]byte(`permessage-deflate; client_max_window_bits="10"`))
	f.Add([]byte(""))
	f.Add([]byte(",,,"))
	f.Add([]byte(`a="unterminated`))
	f.Add([]byte(`a; x="a,b;c"`))
	f.Add([]byte(`a; x="a\"b"`))
	f.Add([]byte("a;=b"))

	f.Fuzz(func(t *testing.T, b []byte) {
		type gotParam struct {
			name, value string
			hasValue    bool
		}
		sc := extension.NewOfferScanner(b)
		for sc.Next() {
			name := sc.Name()
			if len(name) == 0 {
				t.Fatalf("OfferScanner yielded an empty name for input % x", b)
			}

			var params []gotParam
			ps := sc.Params()
			for ps.Next() {
				gp := gotParam{name: string(ps.Name())}
				if v := ps.Value(); v != nil {
					gp.value, gp.hasValue = string(v), true
				}
				params = append(params, gp)
			}
			if ps.Err() != nil {
				continue // Malformed params: nothing valid to round-trip for this offer.
			}

			var rebuilt []byte
			rebuilt = append(rebuilt, name...)
			for _, p := range params {
				rebuilt = append(rebuilt, ';', ' ')
				rebuilt = append(rebuilt, p.name...)
				if p.hasValue {
					rebuilt = append(rebuilt, '=')
					rebuilt = append(rebuilt, p.value...)
				}
			}

			sc2 := extension.NewOfferScanner(rebuilt)
			if !sc2.Next() {
				t.Fatalf("re-parse of rebuilt offer %q (from % x) found no offer", rebuilt, b)
			}
			if !bytes.Equal(sc2.Name(), name) {
				t.Fatalf("re-parse name mismatch: got %q, want %q (rebuilt=%q)", sc2.Name(), name, rebuilt)
			}
			var got2 []gotParam
			ps2 := sc2.Params()
			for ps2.Next() {
				gp := gotParam{name: string(ps2.Name())}
				if v := ps2.Value(); v != nil {
					gp.value, gp.hasValue = string(v), true
				}
				got2 = append(got2, gp)
			}
			if ps2.Err() != nil {
				t.Fatalf("re-parse of rebuilt offer %q failed: %v", rebuilt, ps2.Err())
			}
			if len(got2) != len(params) {
				t.Fatalf("re-parse param count = %d, want %d (rebuilt=%q)", len(got2), len(params), rebuilt)
			}
			for i := range params {
				if got2[i] != params[i] {
					t.Fatalf("re-parse param[%d] = %+v, want %+v (rebuilt=%q)", i, got2[i], params[i], rebuilt)
				}
			}
		}
	})
}
