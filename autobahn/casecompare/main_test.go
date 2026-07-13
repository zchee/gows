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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-json-experiment/json"
)

func TestCompareAllCasesAndRejectCompensatingStatusChange(t *testing.T) {
	dir := t.TempDir()
	base := cases()
	current := cases()
	bp := write(t, dir, "base", base)
	cp := write(t, dir, "current", current)
	if err := compare(bp, cp, "gows"); err != nil {
		t.Fatal(err)
	}
	current["1.1.1"] = result{"FAILED", "OK"}
	current["1.1.2"] = result{"OK", "FAILED"}
	cp = write(t, dir, "compensating", current)
	err := compare(bp, cp, "gows")
	if err == nil || !strings.Contains(err.Error(), "case 1.1.1 changed") {
		t.Fatalf("error=%v", err)
	}
}

func TestCompareSelectsRequestedAgentFromMultiAgentReport(t *testing.T) {
	dir := t.TempDir()
	reports := map[string]map[string]result{
		"gows":  cases(),
		"other": {"1.1.1": {Behavior: "FAILED", BehaviorClose: "FAILED"}},
	}
	baseline := writeReport(t, dir, "multi-agent-base", reports)
	current := writeReport(t, dir, "multi-agent-current", reports)
	if err := compare(baseline, current, "gows"); err != nil {
		t.Fatal(err)
	}
}

func cases() map[string]result {
	m := make(map[string]result, 517)
	for i := 1; i <= 517; i++ {
		m["1.1."+strconv.Itoa(i)] = result{"OK", "OK"}
	}
	return m
}

func write(t *testing.T, dir, name string, cases map[string]result) string {
	t.Helper()
	return writeReport(t, dir, name, map[string]map[string]result{"gows": cases})
}

func writeReport(t *testing.T, dir, name string, reports map[string]map[string]result) string {
	t.Helper()
	raw := make(map[string]map[string]map[string]string, len(reports))
	for agent, cases := range reports {
		raw[agent] = make(map[string]map[string]string, len(cases))
		for id, r := range cases {
			raw[agent][id] = map[string]string{"behavior": r.Behavior, "behaviorClose": r.BehaviorClose}
		}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name+".json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
