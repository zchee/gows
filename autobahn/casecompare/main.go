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

// Command casecompare compares all 517 canonical Autobahn case outcomes.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
)

type result struct{ Behavior, BehaviorClose string }

func main() {
	baseline := flag.String("baseline", "", "frozen baseline index.json")
	current := flag.String("current", "", "current canonical index.json")
	agent := flag.String("agent", "gows", "exact report agent")
	flag.Parse()
	if err := compare(*baseline, *current, *agent); err != nil {
		fmt.Fprintln(os.Stderr, "casecompare:", err)
		os.Exit(1)
	}
	fmt.Println("All 517 canonical cases match the frozen baseline.")
}

func compare(baselinePath, currentPath, agent string) error {
	baseline, err := load(baselinePath, agent)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	current, err := load(currentPath, agent)
	if err != nil {
		return fmt.Errorf("current: %w", err)
	}
	if len(baseline) != 517 || len(current) != 517 {
		return fmt.Errorf("case count baseline=%d current=%d, want 517", len(baseline), len(current))
	}
	ids := make([]string, 0, len(baseline))
	for id := range baseline {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		got, ok := current[id]
		if !ok {
			return fmt.Errorf("current missing case %s", id)
		}
		if got != baseline[id] {
			return fmt.Errorf("case %s changed: baseline=%+v current=%+v", id, baseline[id], got)
		}
	}
	for id := range current {
		if _, ok := baseline[id]; !ok {
			return fmt.Errorf("current has extra case %s", id)
		}
	}
	return nil
}

func load(path, agent string) (map[string]result, error) {
	if path == "" || agent == "" {
		return nil, errors.New("path and agent are required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report map[string]map[string]struct {
		Behavior      string `json:"behavior"`
		BehaviorClose string `json:"behaviorClose"`
	}
	if err := json.Unmarshal(b, &report); err != nil {
		return nil, err
	}
	if len(report) != 1 {
		return nil, fmt.Errorf("agent count=%d, want 1", len(report))
	}
	cases, ok := report[agent]
	if !ok {
		return nil, fmt.Errorf("missing exact agent %q", agent)
	}
	out := make(map[string]result, len(cases))
	for id, r := range cases {
		out[id] = result{r.Behavior, r.BehaviorClose}
	}
	return out, nil
}
