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
	"errors"
	"testing"

	"github.com/zchee/gows/internal/extension"
)

func TestParseDeflateOfferRFCExamples(t *testing.T) {
	tests := map[string]struct {
		raw    string
		want   extension.DeflateParams
		wantOK bool
	}{
		"simplest offer": {
			raw:    "permessage-deflate",
			want:   extension.DeflateParams{},
			wantOK: true,
		},
		"window size control": {
			raw: "permessage-deflate; client_max_window_bits; server_max_window_bits=10",
			want: extension.DeflateParams{
				ClientMaxWindowBits: -1,
				ServerMaxWindowBits: 10,
			},
			wantOK: true,
		},
		"with fallback, first offer valid": {
			raw: "permessage-deflate; client_max_window_bits; server_max_window_bits=10, " +
				"permessage-deflate; client_max_window_bits",
			want: extension.DeflateParams{
				ClientMaxWindowBits: -1,
				ServerMaxWindowBits: 10,
			},
			wantOK: true,
		},
		"no permessage-deflate offer at all": {
			raw:    "permessage-foo, permessage-bar; x=1",
			want:   extension.DeflateParams{},
			wantOK: false,
		},
		"empty header": {
			raw:    "",
			want:   extension.DeflateParams{},
			wantOK: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := extension.ParseDeflateOffer([]byte(tt.raw))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got=%+v)", ok, tt.wantOK, got)
			}
			if ok && got != tt.want {
				t.Fatalf("params = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseDeflateOfferFallback(t *testing.T) {
	// The first permessage-deflate offer (duplicate parameter, invalid)
	// must be skipped in favor of the second (valid).
	raw := "permessage-deflate; server_no_context_takeover; server_no_context_takeover, " +
		"permessage-deflate; client_max_window_bits"

	got, ok := extension.ParseDeflateOffer([]byte(raw))
	if !ok {
		t.Fatalf("ok = false, want true (should fall back to the second, valid offer)")
	}
	want := extension.DeflateParams{ClientMaxWindowBits: -1}
	if got != want {
		t.Fatalf("params = %+v, want %+v", got, want)
	}
}

func TestParseDeflateOfferMalformed(t *testing.T) {
	tests := map[string]string{
		"duplicate server_no_context_takeover":  "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
		"duplicate client_max_window_bits":      "permessage-deflate; client_max_window_bits; client_max_window_bits=10",
		"unknown parameter":                     "permessage-deflate; not_a_real_param",
		"unknown parameter with value":          "permessage-deflate; not_a_real_param=1",
		"server_max_window_bits bare":           "permessage-deflate; server_max_window_bits",
		"server_max_window_bits too small (7)":  "permessage-deflate; server_max_window_bits=7",
		"server_max_window_bits too large (16)": "permessage-deflate; server_max_window_bits=16",
		"server_max_window_bits leading zero":   "permessage-deflate; server_max_window_bits=08",
		"server_max_window_bits non-numeric":    "permessage-deflate; server_max_window_bits=abc",
		"client_max_window_bits out of range":   "permessage-deflate; client_max_window_bits=20",
		"server_no_context_takeover with value": "permessage-deflate; server_no_context_takeover=1",
		"client_no_context_takeover with value": "permessage-deflate; client_no_context_takeover=1",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := extension.ParseDeflateOffer([]byte(raw)); ok {
				t.Fatalf("ParseDeflateOffer(%q): ok = true, want false", raw)
			}
		})
	}
}

func TestParseDeflateOfferSkipsUnknownExtensionNames(t *testing.T) {
	raw := "permessage-foo; server_no_context_takeover, " + // Not permessage-deflate: ignored regardless of params.
		"permessage-deflate; client_no_context_takeover"
	got, ok := extension.ParseDeflateOffer([]byte(raw))
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	want := extension.DeflateParams{ClientNoContextTakeover: true}
	if got != want {
		t.Fatalf("params = %+v, want %+v", got, want)
	}
}

func TestParseDeflateOfferAllocs(t *testing.T) {
	b := []byte("permessage-deflate; client_max_window_bits; server_max_window_bits=10")
	f := func() {
		if _, ok := extension.ParseDeflateOffer(b); !ok {
			t.Fatal("ParseDeflateOffer: ok = false")
		}
	}
	if avg := testing.AllocsPerRun(200, f); avg != 0 {
		t.Fatalf("ParseDeflateOffer: %.2f allocs/op, want 0", avg)
	}
}

func TestAppendDeflateResponse(t *testing.T) {
	tests := map[string]struct {
		agreed extension.DeflateParams
		want   string
	}{
		"no parameters": {
			agreed: extension.DeflateParams{},
			want:   "permessage-deflate",
		},
		"both context takeover flags": {
			agreed: extension.DeflateParams{ServerNoContextTakeover: true, ClientNoContextTakeover: true},
			want:   "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
		},
		"server_max_window_bits only (RFC 7692 §7.1.3 example)": {
			agreed: extension.DeflateParams{ServerMaxWindowBits: 10},
			want:   "permessage-deflate; server_max_window_bits=10",
		},
		"both window bits": {
			agreed: extension.DeflateParams{ServerMaxWindowBits: 10, ClientMaxWindowBits: 12},
			want:   "permessage-deflate; server_max_window_bits=10; client_max_window_bits=12",
		},
		"bare ClientMaxWindowBits (-1) sentinel omitted, never emitted bare": {
			agreed: extension.DeflateParams{ClientMaxWindowBits: -1},
			want:   "permessage-deflate",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := extension.AppendDeflateResponse(nil, tt.agreed)
			if string(got) != tt.want {
				t.Fatalf("AppendDeflateResponse(%+v) = %q, want %q", tt.agreed, got, tt.want)
			}
		})
	}
}

func TestAppendDeflateResponseAppendsToExistingDst(t *testing.T) {
	dst := []byte("Sec-WebSocket-Extensions: ")
	got := extension.AppendDeflateResponse(dst, extension.DeflateParams{ServerMaxWindowBits: 10})
	want := "Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=10"
	if string(got) != want {
		t.Fatalf("= %q, want %q", got, want)
	}
}

func TestValidateDeflateResponse(t *testing.T) {
	tests := map[string]struct {
		offered  extension.DeflateParams
		response string
		want     extension.DeflateParams
		wantErr  error
	}{
		"simplest accept": {
			offered:  extension.DeflateParams{},
			response: "permessage-deflate",
			want:     extension.DeflateParams{},
		},
		"RFC 7692 §7.1.3: first option accepted": {
			offered:  extension.DeflateParams{ClientMaxWindowBits: -1, ServerMaxWindowBits: 10},
			response: "permessage-deflate; server_max_window_bits=10",
			want:     extension.DeflateParams{ServerMaxWindowBits: 10},
		},
		"RFC 7692 §7.1.3: second option accepted": {
			offered:  extension.DeflateParams{ClientMaxWindowBits: -1},
			response: "permessage-deflate",
			want:     extension.DeflateParams{},
		},
		"server_max_window_bits smaller than offered is fine": {
			offered:  extension.DeflateParams{ServerMaxWindowBits: 10},
			response: "permessage-deflate; server_max_window_bits=8",
			want:     extension.DeflateParams{ServerMaxWindowBits: 8},
		},
		"server_max_window_bits greater than offered rejected": {
			offered:  extension.DeflateParams{ServerMaxWindowBits: 10},
			response: "permessage-deflate; server_max_window_bits=12",
			wantErr:  extension.ErrDeflateServerMaxWindowBitsTooLarge,
		},
		"server_max_window_bits with no offered value at all is fine": {
			offered:  extension.DeflateParams{},
			response: "permessage-deflate; server_max_window_bits=12",
			want:     extension.DeflateParams{ServerMaxWindowBits: 12},
		},
		"client_max_window_bits when offer never had it": {
			offered:  extension.DeflateParams{},
			response: "permessage-deflate; client_max_window_bits=10",
			wantErr:  extension.ErrDeflateUnrequestedClientMaxWindowBits,
		},
		"client_max_window_bits valued when offer had it bare": {
			offered:  extension.DeflateParams{ClientMaxWindowBits: -1},
			response: "permessage-deflate; client_max_window_bits=10",
			want:     extension.DeflateParams{ClientMaxWindowBits: 10},
		},
		"client_max_window_bits bare in response is invalid": {
			offered:  extension.DeflateParams{ClientMaxWindowBits: -1},
			response: "permessage-deflate; client_max_window_bits",
			wantErr:  extension.ErrDeflateInvalidResponse,
		},
		"unknown parameter": {
			offered:  extension.DeflateParams{},
			response: "permessage-deflate; not_a_real_param",
			wantErr:  extension.ErrDeflateInvalidResponse,
		},
		"duplicate parameter": {
			offered:  extension.DeflateParams{},
			response: "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
			wantErr:  extension.ErrDeflateInvalidResponse,
		},
		"no permessage-deflate element in response": {
			offered:  extension.DeflateParams{},
			response: "permessage-foo",
			wantErr:  extension.ErrDeflateInvalidResponse,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := extension.ValidateDeflateResponse(tt.offered, []byte(tt.response))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if got != tt.want {
				t.Fatalf("params = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func BenchmarkParseDeflateOffer(b *testing.B) {
	raw := []byte("permessage-deflate; client_max_window_bits; server_max_window_bits=10")
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := extension.ParseDeflateOffer(raw); !ok {
			b.Fatal("ParseDeflateOffer: ok = false")
		}
	}
}

func BenchmarkAppendDeflateResponse(b *testing.B) {
	agreed := extension.DeflateParams{ServerMaxWindowBits: 10, ClientMaxWindowBits: 12}
	dst := make([]byte, 0, 128)
	b.ReportAllocs()
	for b.Loop() {
		dst = extension.AppendDeflateResponse(dst[:0], agreed)
	}
}
