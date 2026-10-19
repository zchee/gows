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

package autobahnreport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDocumentsRoundTrip decodes each checked-in document and re-encodes it the
// way the provenance and appreceipt commands write them. The fixtures were
// written by the per-command types these replaced, so a byte difference means
// a field, JSON tag, omitempty option, or field order changed on the wire.
func TestDocumentsRoundTrip(t *testing.T) {
	tests := map[string]struct {
		fixture string
		decoded any
	}{
		"canonical provenance omits empty application fields": {fixture: "provenance-canonical.json", decoded: &Provenance{}},
		"feature provenance keeps every field":                {fixture: "provenance-feature.json", decoded: &Provenance{}},
		"application receipt":                                 {fixture: "application-receipt.json", decoded: &ApplicationReceipt{}},
		"index case results":                                  {fixture: "index.json", decoded: &map[string]map[string]CaseResult{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(want, tt.decoded); err != nil {
				t.Fatalf("decode %s: %v", tt.fixture, err)
			}
			got, err := json.MarshalIndent(tt.decoded, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			if !bytes.Equal(got, want) {
				t.Fatalf("re-encoded %s differs from fixture:\ngot:\n%s\nwant:\n%s", tt.fixture, got, want)
			}
		})
	}
}

func TestFormatChecks(t *testing.T) {
	hex64 := "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdef0123"
	tests := map[string]struct {
		check func(string) bool
		input string
		want  bool
	}{
		"duration: zero":                        {check: IsNormalizedDuration, input: "0s", want: true},
		"duration: normalized fraction":         {check: IsNormalizedDuration, input: "1.5s", want: true},
		"duration: unnormalized spelling":       {check: IsNormalizedDuration, input: "1000ms", want: false},
		"duration: bare zero":                   {check: IsNormalizedDuration, input: "0", want: false},
		"duration: negative":                    {check: IsNormalizedDuration, input: "-1s", want: false},
		"duration: empty":                       {check: IsNormalizedDuration, input: "", want: false},
		"pinned image: digest reference":        {check: IsPinnedImage, input: "crossbario/autobahn-testsuite@sha256:" + hex64, want: true},
		"pinned image: tag only":                {check: IsPinnedImage, input: "crossbario/autobahn-testsuite:latest", want: false},
		"pinned image: short digest":            {check: IsPinnedImage, input: "image@sha256:abc", want: false},
		"pinned image: empty name":              {check: IsPinnedImage, input: "@sha256:" + hex64, want: false},
		"image id: sha256 prefixed":             {check: IsImageID, input: "sha256:" + hex64, want: true},
		"image id: missing prefix":              {check: IsImageID, input: hex64, want: false},
		"image id: non-hex":                     {check: IsImageID, input: "sha256:not-hex", want: false},
		"container id: short form":              {check: IsContainerID, input: hex64[:12], want: true},
		"container id: full form":               {check: IsContainerID, input: hex64, want: true},
		"container id: shorter than short form": {check: IsContainerID, input: hex64[:11], want: false},
		"container id: longer than full form":   {check: IsContainerID, input: hex64 + "0", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.check(tt.input); got != tt.want {
				t.Fatalf("check(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
