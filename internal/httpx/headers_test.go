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

package httpx_test

import (
	"errors"
	"testing"

	"github.com/zchee/gows/internal/httpx"
)

// upgradeRequest is a realistic RFC 6455 §1.2 example handshake request,
// used by both correctness tests and benchmarks.
const upgradeRequest = "GET /chat HTTP/1.1\r\n" +
	"Host: server.example.com\r\n" +
	"Upgrade: websocket\r\n" +
	"Connection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
	"Origin: http://example.com\r\n" +
	"Sec-WebSocket-Protocol: chat, superchat\r\n" +
	"Sec-WebSocket-Version: 13\r\n" +
	"\r\n"

// splitRequestLineAndHeaders parses the request line out of raw and
// returns the parsed line along with the remaining header block.
func splitRequestLineAndHeaders(raw string) (line httpx.RequestLine, headerBlock []byte, err error) {
	line, n, err := httpx.ParseRequestLine([]byte(raw))
	if err != nil {
		return httpx.RequestLine{}, nil, err
	}
	return line, []byte(raw)[n:], nil
}

func TestParseRequestLine(t *testing.T) {
	tests := map[string]struct {
		raw        string
		wantMethod string
		wantTarget string
		wantVer    string
		wantErr    error
	}{
		"success: basic upgrade request": {
			raw:        "GET /chat HTTP/1.1\r\n",
			wantMethod: "GET",
			wantTarget: "/chat",
			wantVer:    "HTTP/1.1",
		},
		"success: root target": {
			raw:        "GET / HTTP/1.1\r\n",
			wantMethod: "GET",
			wantTarget: "/",
			wantVer:    "HTTP/1.1",
		},
		"error: method is not GET": {
			raw:     "POST /chat HTTP/1.1\r\n",
			wantErr: httpx.ErrNotGet,
		},
		"error: lowercase get rejected (case-sensitive)": {
			raw:     "get /chat HTTP/1.1\r\n",
			wantErr: httpx.ErrNotGet,
		},
		"error: version is not HTTP/1.1": {
			raw:     "GET /chat HTTP/1.0\r\n",
			wantErr: httpx.ErrNotHTTP11,
		},
		"error: missing CRLF": {
			raw:     "GET /chat HTTP/1.1",
			wantErr: httpx.ErrMissingCRLF,
		},
		"error: bare LF rejected": {
			raw:     "GET /chat HTTP/1.1\n",
			wantErr: httpx.ErrMissingCRLF,
		},
		"error: missing version field": {
			raw:     "GET /chat\r\n",
			wantErr: httpx.ErrMalformedRequestLine,
		},
		"error: missing target and version fields": {
			raw:     "GET\r\n",
			wantErr: httpx.ErrMalformedRequestLine,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			line, _, err := httpx.ParseRequestLine([]byte(tt.raw))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseRequestLine(%q): err = %v, want %v", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRequestLine(%q): unexpected error %v", tt.raw, err)
			}
			if string(line.Method) != tt.wantMethod {
				t.Errorf("Method = %q, want %q", line.Method, tt.wantMethod)
			}
			if string(line.Target) != tt.wantTarget {
				t.Errorf("Target = %q, want %q", line.Target, tt.wantTarget)
			}
			if string(line.Version) != tt.wantVer {
				t.Errorf("Version = %q, want %q", line.Version, tt.wantVer)
			}
		})
	}
}

// header is a (name, value) pair used to express expected scan results.
type header struct {
	key, val string
}

func scanAllHeaders(b []byte) ([]header, error) {
	sc := httpx.NewHeaderScanner(b)
	var got []header
	for sc.Next() {
		got = append(got, header{key: string(sc.Key()), val: string(sc.Value())})
	}
	return got, sc.Err()
}

func TestHeaderScannerRealisticRequest(t *testing.T) {
	_, headerBlock, err := splitRequestLineAndHeaders(upgradeRequest)
	if err != nil {
		t.Fatalf("splitRequestLineAndHeaders: unexpected error %v", err)
	}

	got, err := scanAllHeaders(headerBlock)
	if err != nil {
		t.Fatalf("scanAllHeaders: unexpected error %v", err)
	}
	want := []header{
		{"Host", "server.example.com"},
		{"Upgrade", "websocket"},
		{"Connection", "Upgrade"},
		{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="},
		{"Origin", "http://example.com"},
		{"Sec-WebSocket-Protocol", "chat, superchat"},
		{"Sec-WebSocket-Version", "13"},
	}
	if len(got) != len(want) {
		t.Fatalf("scanned %d headers, want %d: got %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("header[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

func TestHeaderScannerCaseVariants(t *testing.T) {
	tests := map[string]string{
		"lowercase":  "upgrade: websocket\r\n\r\n",
		"uppercase":  "UPGRADE: websocket\r\n\r\n",
		"mixed case": "Upgrade: websocket\r\n\r\n",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			sc := httpx.NewHeaderScanner([]byte(raw))
			if !sc.Next() {
				t.Fatalf("Next() = false, want true (err = %v)", sc.Err())
			}
			if !httpx.EqualFold(sc.Key(), "upgrade") {
				t.Errorf("EqualFold(%q, \"upgrade\") = false, want true", sc.Key())
			}
			if !httpx.EqualFold(sc.Value(), "websocket") {
				t.Errorf("EqualFold(%q, \"websocket\") = false, want true", sc.Value())
			}
		})
	}
}

func TestHeaderScannerMultiValueConnection(t *testing.T) {
	tests := map[string]struct {
		value        string
		wantContains bool
	}{
		"exact token":             {value: "Upgrade", wantContains: true},
		"leading token":           {value: "keep-alive, Upgrade", wantContains: true},
		"trailing token":          {value: "Upgrade, keep-alive", wantContains: true},
		"case-insensitive token":  {value: "keep-alive, upgrade", wantContains: true},
		"whitespace around token": {value: "keep-alive,   Upgrade  ", wantContains: true},
		"no matching token":       {value: "keep-alive", wantContains: false},
		"empty value":             {value: "", wantContains: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			raw := "Connection: " + tt.value + "\r\n\r\n"
			sc := httpx.NewHeaderScanner([]byte(raw))
			if !sc.Next() {
				t.Fatalf("Next() = false, want true (err = %v)", sc.Err())
			}
			if got := httpx.ContainsToken(sc.Value(), "upgrade"); got != tt.wantContains {
				t.Errorf("ContainsToken(%q, \"upgrade\") = %v, want %v", sc.Value(), got, tt.wantContains)
			}
		})
	}
}

func TestHeaderScannerMalformedInputs(t *testing.T) {
	tests := map[string]struct {
		raw     string
		wantErr error
	}{
		"error: missing CRLF": {
			raw:     "Host: example.com",
			wantErr: httpx.ErrMissingCRLF,
		},
		"error: bare LF": {
			raw:     "Host: example.com\n\r\n",
			wantErr: httpx.ErrMissingCRLF,
		},
		"error: obsolete line folding": {
			raw:     "Host: example.com\r\n continuation\r\n\r\n",
			wantErr: httpx.ErrObsoleteLineFolding,
		},
		"error: missing colon separator": {
			raw:     "Malformed Header Line\r\n\r\n",
			wantErr: httpx.ErrMalformedHeader,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := scanAllHeaders([]byte(tt.raw))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("scanAllHeaders(%q): err = %v, want %v", tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestHeaderScannerEmptyBlock(t *testing.T) {
	got, err := scanAllHeaders([]byte("\r\n"))
	if err != nil {
		t.Fatalf("scanAllHeaders: unexpected error %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("scanAllHeaders: got %d headers, want 0", len(got))
	}
}

func TestEqualFold(t *testing.T) {
	tests := map[string]struct {
		b     string
		lower string
		want  bool
	}{
		"success: exact match":      {b: "upgrade", lower: "upgrade", want: true},
		"success: uppercase input":  {b: "UPGRADE", lower: "upgrade", want: true},
		"success: mixed case input": {b: "UpGrAdE", lower: "upgrade", want: true},
		"error: length mismatch":    {b: "upgrades", lower: "upgrade", want: false},
		"error: different token":    {b: "downgrade", lower: "upgrade", want: false},
		"success: empty vs empty":   {b: "", lower: "", want: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := httpx.EqualFold([]byte(tt.b), tt.lower); got != tt.want {
				t.Errorf("EqualFold(%q, %q) = %v, want %v", tt.b, tt.lower, got, tt.want)
			}
		})
	}
}

func TestParseRequestLineAllocs(t *testing.T) {
	raw := []byte(upgradeRequest)
	f := func() {
		if _, _, err := httpx.ParseRequestLine(raw); err != nil {
			t.Fatal(err)
		}
	}
	if avg := testing.AllocsPerRun(100, f); avg != 0 {
		t.Fatalf("ParseRequestLine: %.2f allocs/op, want 0", avg)
	}
}

func TestHeaderScannerAllocs(t *testing.T) {
	_, headerBlock, err := splitRequestLineAndHeaders(upgradeRequest)
	if err != nil {
		t.Fatalf("splitRequestLineAndHeaders: unexpected error %v", err)
	}
	f := func() {
		sc := httpx.NewHeaderScanner(headerBlock)
		for sc.Next() {
			_, _ = sc.Key(), sc.Value()
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	if avg := testing.AllocsPerRun(100, f); avg != 0 {
		t.Fatalf("HeaderScanner scan: %.2f allocs/op, want 0", avg)
	}
}

func BenchmarkParseRequestLine(b *testing.B) {
	raw := []byte(upgradeRequest)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := httpx.ParseRequestLine(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHeaderScan(b *testing.B) {
	_, headerBlock, err := splitRequestLineAndHeaders(upgradeRequest)
	if err != nil {
		b.Fatalf("splitRequestLineAndHeaders: unexpected error %v", err)
	}
	b.ReportAllocs()
	for b.Loop() {
		sc := httpx.NewHeaderScanner(headerBlock)
		for sc.Next() {
			_, _ = sc.Key(), sc.Value()
		}
		if err := sc.Err(); err != nil {
			b.Fatal(err)
		}
	}
}
