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

// Command judge parses an Autobahn|Testsuite index.json master report and
// fails the build if any test case did not behave acceptably.
//
// Usage:
//
//	judge <path-to-index.json-or-report-dir>
//
// judge is a CI tool, not part of the gows public API, and deliberately
// depends on nothing but the standard library.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/go-json-experiment/json"
)

// caseResult mirrors the fields judge cares about in one entry of
// Autobahn|Testsuite's index.json report, keyed by agent then by case ID.
type caseResult struct {
	Behavior      string  `json:"behavior"`
	BehaviorClose string  `json:"behaviorClose"`
	Duration      float64 `json:"duration"`
}

// acceptableBehaviors lists the Autobahn|Testsuite behavior/behaviorClose
// values gows treats as passing. Anything else (FAILED, WRONG CODE, FAILED
// BY CLIENT, ...) fails the build.
var acceptableBehaviors = map[string]bool{
	"OK":            true,
	"INFORMATIONAL": true,
	"NON-STRICT":    true,
	"UNIMPLEMENTED": true,
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path-to-index.json-or-report-dir>\n", os.Args[0])
		os.Exit(2)
	}

	if err := run(os.Stdout, os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "judge:", err)
		os.Exit(1)
	}
}

// run loads the report at path, prints a summary table to w, and returns an
// error describing every non-conformant case if there were any.
func run(w io.Writer, path string) error {
	report, err := loadReport(path)
	if err != nil {
		return err
	}

	failures := printReport(w, report)
	if len(failures) > 0 {
		return fmt.Errorf("%d case(s) failed:\n%s", len(failures), strings.Join(failures, "\n"))
	}

	fmt.Fprintln(w, "All cases passed.")
	return nil
}

// loadReport reads and parses an Autobahn|Testsuite index.json report. path
// may name the report file directly or the directory containing it.
func loadReport(path string) (map[string]map[string]caseResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat report path: %w", err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "index.json")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}

	var report map[string]map[string]caseResult
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse report %s: %w", path, err)
	}
	if len(report) == 0 {
		return nil, fmt.Errorf("report %s contains no agents (no test cases were run)", path)
	}
	return report, nil
}

// printReport writes a per-agent, per-case summary table to w in case ID
// order and returns a human-readable description of every case whose
// behavior or behaviorClose fell outside acceptableBehaviors.
func printReport(w io.Writer, report map[string]map[string]caseResult) []string {
	agents := make([]string, 0, len(report))
	for agent := range report {
		agents = append(agents, agent)
	}
	sort.Strings(agents)

	var failures []string
	for _, agent := range agents {
		cases := report[agent]

		caseIDs := make([]string, 0, len(cases))
		for id := range cases {
			caseIDs = append(caseIDs, id)
		}
		sort.Slice(caseIDs, func(i, j int) bool { return lessCaseID(caseIDs[i], caseIDs[j]) })

		fmt.Fprintf(w, "Agent: %s\n", agent)
		fmt.Fprintf(w, "%-10s %-16s %-16s %10s\n", "CASE", "BEHAVIOR", "CLOSE", "DURATION")
		for _, id := range caseIDs {
			c := cases[id]
			fmt.Fprintf(w, "%-10s %-16s %-16s %8.1fms\n", id, c.Behavior, c.BehaviorClose, c.Duration)
			if !acceptableBehaviors[c.Behavior] || !acceptableBehaviors[c.BehaviorClose] {
				failures = append(failures, fmt.Sprintf("%s/%s: behavior=%s behaviorClose=%s", agent, id, c.Behavior, c.BehaviorClose))
			}
		}
	}
	return failures
}

// lessCaseID orders Autobahn case IDs ("1.2.3") numerically component by
// component instead of lexicographically, so "2.9" sorts before "2.10".
func lessCaseID(a, b string) bool {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")

	for i := 0; i < min(len(as), len(bs)); i++ {
		if as[i] == bs[i] {
			continue
		}
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		if aerr == nil && berr == nil {
			return an < bn
		}
		return as[i] < bs[i]
	}
	return len(as) < len(bs)
}
