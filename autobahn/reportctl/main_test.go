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
	"strings"
	"testing"
)

const usage = "usage: reportctl backup|publish|restore <source> <destination>\n"

func TestRun(t *testing.T) {
	tests := map[string]struct {
		// args builds the argument list from a fresh directory that holds a
		// complete "source" report and a complete "live" report.
		args       func(dir string) []string
		wantCode   int
		wantStderr string
		// wantTree names the directory whose report must equal "source"
		// afterwards; empty means nothing is checked.
		wantTree string
	}{
		"error: no arguments": {
			args:       func(string) []string { return nil },
			wantCode:   2,
			wantStderr: usage,
		},
		"error: missing destination": {
			args:       func(dir string) []string { return []string{"backup", filepath.Join(dir, "source")} },
			wantCode:   2,
			wantStderr: usage,
		},
		"error: extra argument": {
			args: func(dir string) []string {
				return []string{"backup", filepath.Join(dir, "source"), filepath.Join(dir, "backup"), "extra"}
			},
			wantCode:   2,
			wantStderr: usage,
		},
		"error: unknown operation": {
			args: func(dir string) []string {
				return []string{"copy", filepath.Join(dir, "source"), filepath.Join(dir, "backup")}
			},
			wantCode:   2,
			wantStderr: "reportctl: unknown operation \"copy\"\n",
		},
		"success: backup copies the report": {
			args: func(dir string) []string {
				return []string{"backup", filepath.Join(dir, "source"), filepath.Join(dir, "backup")}
			},
			wantTree: "backup",
		},
		"success: publish replaces the live report": {
			args: func(dir string) []string {
				return []string{"publish", filepath.Join(dir, "source"), filepath.Join(dir, "live")}
			},
			wantTree: "live",
		},
		"success: restore replaces the live report": {
			args: func(dir string) []string {
				return []string{"restore", filepath.Join(dir, "source"), filepath.Join(dir, "live")}
			},
			wantTree: "live",
		},
		"error: backup refuses an existing destination": {
			args: func(dir string) []string {
				return []string{"backup", filepath.Join(dir, "source"), filepath.Join(dir, "live")}
			},
			wantCode:   1,
			wantStderr: "reportctl: backup destination must not exist: ",
		},
		"error: publish of an incomplete source": {
			args: func(dir string) []string {
				return []string{"publish", filepath.Join(dir, "missing"), filepath.Join(dir, "live")}
			},
			wantCode:   1,
			wantStderr: "reportctl: report ",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeReport(t, filepath.Join(dir, "source"), "source")
			writeReport(t, filepath.Join(dir, "live"), "live")
			args := tt.args(dir)
			var stderr bytes.Buffer
			code := run(args, &stderr)
			if code != tt.wantCode {
				t.Fatalf("run(%q) = %d, want %d; stderr %q", args, code, tt.wantCode, stderr.String())
			}
			if tt.wantStderr == "" && stderr.Len() != 0 {
				t.Fatalf("run(%q) stderr = %q, want empty", args, stderr.String())
			}
			if !strings.HasPrefix(stderr.String(), tt.wantStderr) {
				t.Fatalf("run(%q) stderr = %q, want prefix %q", args, stderr.String(), tt.wantStderr)
			}
			if tt.wantCode != 0 {
				wantReport(t, filepath.Join(dir, "live"), "live")
			}
			if tt.wantTree != "" {
				wantReport(t, filepath.Join(dir, tt.wantTree), "source")
			}
		})
	}
}

func writeReport(t *testing.T, root, contents string) {
	t.Helper()
	for _, direction := range []string{"server", "clients"} {
		if err := os.MkdirAll(filepath.Join(root, direction), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, direction, "index.json"), []byte(contents+"-"+direction), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func wantReport(t *testing.T, root, contents string) {
	t.Helper()
	for _, direction := range []string{"server", "clients"} {
		got, err := os.ReadFile(filepath.Join(root, direction, "index.json"))
		if want := contents + "-" + direction; err != nil || string(got) != want {
			t.Fatalf("%s/%s/index.json = %q, %v; want %q", root, direction, got, err, want)
		}
	}
}
