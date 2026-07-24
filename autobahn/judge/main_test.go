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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Note: judge lives in the gows root module but is a CI tool, not part of
// the public API, so (per plan) it must depend on nothing but the standard
// library. Assertions below therefore use slices.Equal / reflect-free
// comparisons instead of the repo-wide gocmp convention.

func TestLoadReport(t *testing.T) {
	tests := map[string]struct {
		content   string
		useDir    bool
		wantErr   bool
		wantAgent string
	}{
		"success: single agent single case": {
			content:   `{"gows":{"1.1.1":{"behavior":"OK","behaviorClose":"OK","duration":12.5}}}`,
			wantAgent: "gows",
		},
		"success: resolves index.json inside a directory": {
			content:   `{"gows":{"1.1.1":{"behavior":"OK","behaviorClose":"OK","duration":12.5}}}`,
			useDir:    true,
			wantAgent: "gows",
		},
		"error: empty report has no agents": {
			content: `{}`,
			wantErr: true,
		},
		"error: malformed json": {
			content: `{`,
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "index.json")
			if err := os.WriteFile(target, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			path := target
			if tt.useDir {
				path = dir
			}

			report, err := loadReport(path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("loadReport(%q) error = %v, wantErr %v", path, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if _, ok := report[tt.wantAgent]; !ok {
				t.Fatalf("loadReport(%q) = %v, want agent %q present", path, report, tt.wantAgent)
			}
		})
	}
}

func TestLoadReportMissingFile(t *testing.T) {
	_, err := loadReport(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("loadReport() error = nil, want error for missing file")
	}
}

func TestPrintReport(t *testing.T) {
	tests := map[string]struct {
		report       map[string]map[string]caseResult
		wantFailures []string
	}{
		"success: all cases acceptable": {
			report: map[string]map[string]caseResult{
				"gows": {
					"1.1.1":  {Behavior: "OK", BehaviorClose: "OK"},
					"6.1.1":  {Behavior: "NON-STRICT", BehaviorClose: "OK"},
					"12.1.1": {Behavior: "UNIMPLEMENTED", BehaviorClose: "UNIMPLEMENTED"},
				},
			},
			wantFailures: nil,
		},
		"failure: FAILED behavior reported": {
			report: map[string]map[string]caseResult{
				"gows": {
					"1.1.1": {Behavior: "FAILED", BehaviorClose: "OK"},
				},
			},
			wantFailures: []string{"gows/1.1.1: behavior=FAILED behaviorClose=OK"},
		},
		"failure: WRONG CODE close behavior reported": {
			report: map[string]map[string]caseResult{
				"gows": {
					"7.1.1": {Behavior: "OK", BehaviorClose: "WRONG CODE"},
				},
			},
			wantFailures: []string{"gows/7.1.1: behavior=OK behaviorClose=WRONG CODE"},
		},
		// Two agents, so the reported failures pin the sorted agent
		// order printReport imposes on the report map: without it the
		// slice order would follow Go's randomized map iteration.
		"failure: multiple agents report in sorted agent order": {
			report: map[string]map[string]caseResult{
				"gows":    {"1.1.1": {Behavior: "FAILED", BehaviorClose: "OK"}},
				"gorilla": {"1.1.1": {Behavior: "OK", BehaviorClose: "FAILED"}},
			},
			wantFailures: []string{
				"gorilla/1.1.1: behavior=OK behaviorClose=FAILED",
				"gows/1.1.1: behavior=FAILED behaviorClose=OK",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			failures := printReport(&buf, tt.report)
			if !slices.Equal(failures, tt.wantFailures) {
				t.Fatalf("printReport() failures = %v, want %v", failures, tt.wantFailures)
			}
			if buf.Len() == 0 {
				t.Fatal("printReport() wrote no output")
			}
		})
	}
}

func TestLessCaseID(t *testing.T) {
	tests := map[string]struct {
		a, b string
		want bool
	}{
		"success: numeric ordering across widths": {a: "2.9", b: "2.10", want: true},
		"success: reverse numeric ordering":       {a: "2.10", b: "2.9", want: false},
		"success: major version ordering":         {a: "6.1.1", b: "10.1.1", want: true},
		"success: equal ids are not less":         {a: "1.1.1", b: "1.1.1", want: false},
		"success: shorter prefix sorts first":     {a: "1.1", b: "1.1.1", want: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := lessCaseID(tt.a, tt.b); got != tt.want {
				t.Errorf("lessCaseID(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestRun(t *testing.T) {
	tests := map[string]struct {
		content string
		wantErr bool
	}{
		"success: report with only acceptable behaviors": {
			content: `{"gows":{"1.1.1":{"behavior":"OK","behaviorClose":"OK"}}}`,
		},
		"error: report contains a failed case": {
			content: `{"gows":{"1.1.1":{"behavior":"FAILED","behaviorClose":"FAILED"}}}`,
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "index.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			var buf bytes.Buffer
			err := run(&buf, path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
