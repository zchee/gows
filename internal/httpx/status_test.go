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

func TestParseStatusLine(t *testing.T) {
	tests := map[string]struct {
		raw        string
		wantVer    string
		wantCode   string
		wantReason string
		wantErr    error
	}{
		"success: 101 switching protocols": {
			raw:        "HTTP/1.1 101 Switching Protocols\r\n",
			wantVer:    "HTTP/1.1",
			wantCode:   "101",
			wantReason: "Switching Protocols",
		},
		"success: empty reason phrase": {
			raw:        "HTTP/1.1 101 \r\n",
			wantVer:    "HTTP/1.1",
			wantCode:   "101",
			wantReason: "",
		},
		"success: non-101 status (caller decides)": {
			raw:        "HTTP/1.1 400 Bad Request\r\n",
			wantVer:    "HTTP/1.1",
			wantCode:   "400",
			wantReason: "Bad Request",
		},
		"error: missing CRLF": {
			raw:     "HTTP/1.1 101 Switching Protocols",
			wantErr: httpx.ErrMissingCRLF,
		},
		"error: bare LF rejected": {
			raw:     "HTTP/1.1 101 Switching Protocols\n",
			wantErr: httpx.ErrMissingCRLF,
		},
		"error: missing status code": {
			raw:     "HTTP/1.1\r\n",
			wantErr: httpx.ErrMalformedStatusLine,
		},
		"error: missing reason SP": {
			raw:     "HTTP/1.1 101\r\n",
			wantErr: httpx.ErrMalformedStatusLine,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			line, _, err := httpx.ParseStatusLine([]byte(tt.raw))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseStatusLine(%q): err = %v, want %v", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStatusLine(%q): unexpected error %v", tt.raw, err)
			}
			if string(line.Version) != tt.wantVer {
				t.Errorf("Version = %q, want %q", line.Version, tt.wantVer)
			}
			if string(line.Code) != tt.wantCode {
				t.Errorf("Code = %q, want %q", line.Code, tt.wantCode)
			}
			if string(line.Reason) != tt.wantReason {
				t.Errorf("Reason = %q, want %q", line.Reason, tt.wantReason)
			}
		})
	}
}

func TestParseStatusLineAllocs(t *testing.T) {
	raw := []byte("HTTP/1.1 101 Switching Protocols\r\n")
	f := func() {
		if _, _, err := httpx.ParseStatusLine(raw); err != nil {
			t.Fatal(err)
		}
	}
	if avg := testing.AllocsPerRun(100, f); avg != 0 {
		t.Fatalf("ParseStatusLine: %.2f allocs/op, want 0", avg)
	}
}
