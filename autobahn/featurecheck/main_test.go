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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFeatureCheck(t *testing.T) {
	dir := t.TempDir()
	mfPath := filepath.Join("testdata", "window-case-manifest.json")
	var mf manifest
	if err := readJSON(mfPath, &mf); err != nil {
		t.Fatal(err)
	}
	mm := mf.Modes["server"]
	canonical := makeCases(mm, false)
	feature := makeCases(mm, true)
	before, beforeProv := writeEvidence(t, dir, "before", "canonical", "server", "gows", canonical, nil)
	featureConfig := map[string]any{"backend": "klauspost/compress/flate", "level": 6, "window_bits": 9, "allow_context_takeover": true, "negotiate_window_bits": true, "client_window_bits": 9}
	after, afterProv := writeEvidence(t, dir, "after", "feature", "server", "gows-v04-feature-server", feature, featureConfig)
	o := options{ManifestPath: mfPath, BeforePath: before, BeforeProvenance: beforeProv, AfterPath: after, AfterProvenance: afterProv, Direction: "server", Agent: "gows-v04-feature-server", BeforeRunID: "canonical-server", AfterRunID: "feature-server", ExpectedHead: strings.Repeat("a", 40), ExpectedWorkspace: strings.Repeat("b", 64), ExpectedApplicationSHA: strings.Repeat("d", 64), ExpectedCaseDelay: "1s"}

	var out bytes.Buffer
	if err := run(&out, o); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(out.String(), "\n"); lines != len(mm.Inventory)+1 {
		t.Fatalf("matrix lines=%d, want %d", lines, len(mm.Inventory)+1)
	}

	tests := []struct {
		name   string
		mutate func(*options)
		want   string
	}{
		{"wrong-agent", func(o *options) { o.Agent = "gows" }, "wrong feature agent"},
		{"truncated", func(o *options) {
			cases := makeCases(mm, true)
			delete(cases, "1.1.1")
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "truncated", "feature", "server", "gows-v04-feature-server", cases, featureConfig)
		}, "truncated report"},
		{"hash-mismatch", func(o *options) {
			b, _ := os.ReadFile(o.AfterPath)
			b = append(b, '\n')
			o.AfterPath = filepath.Join(dir, "hash-mismatch-index.json")
			if err := os.WriteFile(o.AfterPath, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "hash-mismatched"},
		{"target-unimplemented-generic-judge-pass", func(o *options) {
			cases := makeCases(mm, true)
			cases[mm.Targets[0]] = caseResult{Behavior: "UNIMPLEMENTED", BehaviorClose: "OK"}
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "unimplemented", "feature", "server", "gows-v04-feature-server", cases, featureConfig)
		}, "want OK"},
		{"non-strict", func(o *options) {
			cases := makeCases(mm, true)
			cases["1.1.1"] = caseResult{Behavior: "NON-STRICT", BehaviorClose: "OK"}
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "nonstrict", "feature", "server", "gows-v04-feature-server", cases, featureConfig)
		}, "NON-STRICT"},
		{"missing-target", func(o *options) {
			cases := makeCases(mm, true)
			delete(cases, mm.Targets[0])
			cases["1.1.999"] = caseResult{Behavior: "OK", BehaviorClose: "OK"}
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "missing", "feature", "server", "gows-v04-feature-server", cases, featureConfig)
		}, "missing inventory case"},
		{"extra-inventory", func(o *options) {
			cases := makeCases(mm, true)
			delete(cases, "1.1.1")
			cases["13.3.999"] = caseResult{Behavior: "OK", BehaviorClose: "OK"}
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "extra", "feature", "server", "gows-v04-feature-server", cases, featureConfig)
		}, "extra inventory case"},
		{"stale-canonical", func(o *options) {
			cases := makeCases(mm, false)
			cases[mm.Targets[0]] = caseResult{Behavior: "OK", BehaviorClose: "OK"}
			o.BeforePath, o.BeforeProvenance = writeEvidence(t, dir, "stale", "canonical", "server", "gows", cases, nil)
		}, "stale canonical"},
		{"missing-feature-config", func(o *options) {
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "no-config", "feature", "server", "gows-v04-feature-server", makeCases(mm, true), nil)
		}, "lacks flatekp"},
		{"late-code-change", func(o *options) {
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "late-change", "feature", "server", "gows-v04-feature-server", makeCases(mm, true), featureConfig)
			var p provenance
			if err := readJSON(o.AfterProvenance, &p); err != nil {
				t.Fatal(err)
			}
			p.WorkspaceSHA = strings.Repeat("c", 64)
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(o.AfterProvenance, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "different code states"},
		{"malformed-manifest-digest", func(o *options) {
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "bad-manifest-digest", "feature", "server", "gows-v04-feature-server", makeCases(mm, true), featureConfig)
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) { p.Image = "image@sha256:short" })
		}, "hash-mismatched provenance"},
		{"malformed-config-digest", func(o *options) {
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "bad-config-digest", "feature", "server", "gows-v04-feature-server", makeCases(mm, true), featureConfig)
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) { p.ImageID = "sha256:not-hex" })
		}, "hash-mismatched provenance"},
		{"missing-application-command", func(o *options) {
			o.AfterPath, o.AfterProvenance = writeEvidence(t, dir, "missing-app-command", "feature", "server", "gows-v04-feature-server", makeCases(mm, true), featureConfig)
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) { p.ApplicationCommand = "" })
		}, "lacks external application command"},
		{"wrong-reviewed-application-sha", func(o *options) { o.ExpectedApplicationSHA = strings.Repeat("0", 64) }, "application receipt content mismatch"},

		{"malformed-generator-evidence", func(o *options) {
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) { p.Generator = "relative@sha256:" + strings.Repeat("a", 64) })
		}, "want <absolute-path>"},
		{"missing-generator-evidence-file", func(o *options) {
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) { p.Generator = "/no/such/generator@sha256:" + strings.Repeat("a", 64) })
		}, "no such file"},
		{"generator-evidence-hash-mismatch", func(o *options) {
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) {
				path, _ := filepath.EvalSymlinks(filepath.Join(dir, "generator.txt"))
				p.Generator = path + "@sha256:" + strings.Repeat("0", 64)
			})
		}, "artifact hash mismatch"},
		{"network-mode-difference", func(o *options) {
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) {
				p.NetworkMode = "bridge"
				p.CaseDelay = "1s"
				path, _ := filepath.EvalSymlinks(filepath.Join(dir, "generator.txt"))
				data, _ := os.ReadFile(path)
				sum := sha256.Sum256(data)
				p.Generator = path + "@sha256:" + hex.EncodeToString(sum[:])
			})
		}, "network modes differ"},
		{"case-delay-difference", func(o *options) {
			rewriteProvenance(t, o.AfterProvenance, func(p *provenance) { p.NetworkMode = "host"; p.CaseDelay = "0s" })
		}, "case delay differs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := o
			tt.mutate(&copy)
			err := run(&bytes.Buffer{}, copy)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error=%v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestNumber(t *testing.T) {
	tests := map[string]struct {
		input any
		want  int
	}{
		"float64 from decoded JSON": {input: float64(9), want: 9},
		"programmatic int":          {input: int(9), want: 9},
		"programmatic int64":        {input: int64(9), want: 9},
		"unsupported type":          {input: "9", want: 0},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if got := number(test.input); got != test.want {
				t.Fatalf("number(%T(%v)) = %d, want %d", test.input, test.input, got, test.want)
			}
		})
	}
}

func TestFeatureCheckAllowsOldBoundReports(t *testing.T) {
	dir := t.TempDir()
	mfPath := filepath.Join("testdata", "window-case-manifest.json")
	var mf manifest
	if err := readJSON(mfPath, &mf); err != nil {
		t.Fatal(err)
	}
	mode := mf.Modes["server"]
	before, beforeProvenance := writeEvidence(t, dir, "old-before", "canonical", "server", "gows", makeCases(mode, false), nil)
	featureConfig := map[string]any{"backend": "klauspost/compress/flate", "level": 6, "window_bits": 9, "allow_context_takeover": true, "negotiate_window_bits": true, "client_window_bits": 9}
	after, afterProvenance := writeEvidence(t, dir, "old-after", "feature", "server", "gows-v04-feature-server", makeCases(mode, true), featureConfig)
	old := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	for _, path := range []string{beforeProvenance, afterProvenance} {
		rewriteProvenance(t, path, func(p *provenance) {
			p.StartedUTC = old.Format(time.RFC3339)
			p.EndedUTC = old.Add(time.Minute).Format(time.RFC3339)
		})
	}
	for _, path := range []string{before, after} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	o := options{ManifestPath: mfPath, BeforePath: before, BeforeProvenance: beforeProvenance, AfterPath: after, AfterProvenance: afterProvenance, Direction: "server", Agent: "gows-v04-feature-server", BeforeRunID: "canonical-server", AfterRunID: "feature-server", ExpectedHead: strings.Repeat("a", 40), ExpectedWorkspace: strings.Repeat("b", 64), ExpectedApplicationSHA: strings.Repeat("d", 64), ExpectedCaseDelay: "1s"}
	if err := run(&bytes.Buffer{}, o); err != nil {
		t.Fatal(err)
	}
	outsideRun := old.Add(-time.Minute)
	if err := os.Chtimes(after, outsideRun, outsideRun); err != nil {
		t.Fatal(err)
	}
	if err := run(&bytes.Buffer{}, o); err == nil || !strings.Contains(err.Error(), "stale report timing evidence") {
		t.Fatalf("error=%v, want stale report timing evidence", err)
	}
}

func TestFeatureCheckClientDirection(t *testing.T) {
	dir := t.TempDir()
	mfPath := filepath.Join("testdata", "window-case-manifest.json")
	var mf manifest
	if err := readJSON(mfPath, &mf); err != nil {
		t.Fatal(err)
	}
	mm := mf.Modes["client"]
	before, beforeProv := writeEvidence(t, dir, "client-before", "canonical", "client", "gows", makeCases(mm, false), nil)
	fc := map[string]any{"backend": "klauspost/compress/flate", "level": 6, "window_bits": 9, "allow_context_takeover": true, "offer_client_max_window_bits": true, "server_window_bits": 9}
	after, afterProv := writeEvidence(t, dir, "client-after", "feature", "client", "gows-v04-feature-client", makeCases(mm, true), fc)
	err := run(&bytes.Buffer{}, options{ManifestPath: mfPath, BeforePath: before, BeforeProvenance: beforeProv, AfterPath: after, AfterProvenance: afterProv, Direction: "client", Agent: "gows-v04-feature-client", BeforeRunID: "canonical-client", AfterRunID: "feature-client", ExpectedHead: strings.Repeat("a", 40), ExpectedWorkspace: strings.Repeat("b", 64), ExpectedApplicationSHA: strings.Repeat("d", 64), ExpectedCaseDelay: "1s"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFeatureCheckAllowsExplicitNetworkModeDifference(t *testing.T) {
	dir := t.TempDir()
	mfPath := filepath.Join("testdata", "window-case-manifest.json")
	var mf manifest
	if err := readJSON(mfPath, &mf); err != nil {
		t.Fatal(err)
	}
	mm := mf.Modes["server"]
	before, bp := writeEvidence(t, dir, "network-before", "canonical", "server", "gows", makeCases(mm, false), nil)
	fc := map[string]any{"backend": "klauspost/compress/flate", "level": 6, "window_bits": 9, "allow_context_takeover": true, "negotiate_window_bits": true, "client_window_bits": 9}
	after, ap := writeEvidence(t, dir, "network-after", "feature", "server", "gows-v04-feature-server", makeCases(mm, true), fc)
	rewriteProvenance(t, ap, func(p *provenance) { p.NetworkMode = "bridge" })
	o := options{ManifestPath: mfPath, BeforePath: before, BeforeProvenance: bp, AfterPath: after, AfterProvenance: ap, Direction: "server", Agent: "gows-v04-feature-server", BeforeRunID: "canonical-server", AfterRunID: "feature-server", ExpectedHead: strings.Repeat("a", 40), ExpectedWorkspace: strings.Repeat("b", 64), ExpectedApplicationSHA: strings.Repeat("d", 64), AllowNetworkModeDifference: true, ExpectedCaseDelay: "1s"}
	if err := run(&bytes.Buffer{}, o); err != nil {
		t.Fatal(err)
	}
}

func makeCases(m manifestMode, feature bool) map[string]caseResult {
	cases := make(map[string]caseResult, 517)
	for i := 1; i <= 517-len(m.Inventory); i++ {
		cases["1.1."+itoa(i)] = caseResult{Behavior: "OK", BehaviorClose: "OK"}
	}
	for id, result := range m.Inventory {
		if feature {
			result.Behavior = "OK"
		}
		cases[id] = result
	}
	return cases
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func writeEvidence(t *testing.T, dir, stem, mode, direction, agent string, cases map[string]caseResult, fc map[string]any) (string, string) {
	t.Helper()
	reportRoot := filepath.Join(dir, stem+"-"+mode+"-"+direction+"-root")
	subtree := "server"
	if direction == "client" {
		subtree = "clients"
	}
	if err := os.MkdirAll(filepath.Join(reportRoot, subtree), 0o755); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(reportRoot, subtree, "index.json")
	b, err := json.Marshal(map[string]map[string]caseResult{agent: cases})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index, b, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	generatorPath := filepath.Join(dir, "generator.txt")
	if _, err := os.Stat(generatorPath); os.IsNotExist(err) {
		if err := os.WriteFile(generatorPath, []byte("window-9 generator evidence\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	generatorPath, _ = filepath.EvalSymlinks(generatorPath)
	generatorData, err := os.ReadFile(generatorPath)
	if err != nil {
		t.Fatal(err)
	}
	generatorSum := sha256.Sum256(generatorData)
	now := time.Now().UTC()
	p := provenance{
		Version: 1, RunID: mode + "-" + direction, Mode: mode, Direction: direction, Agent: agent,
		Branch: "test", Head: strings.Repeat("a", 40), GoVersion: "go1.26", GOOS: "test", GOARCH: "test",
		Command: "test", Image: "image@sha256:" + strings.Repeat("a", 64), ImageID: "sha256:" + strings.Repeat("b", 64), CaseCount: 517,
		StartedUTC: now.Add(-time.Second).Format(time.RFC3339), EndedUTC: now.Add(time.Second).Format(time.RFC3339), Generator: generatorPath + "@sha256:" + hex.EncodeToString(generatorSum[:]),
		WorkspaceSHA: strings.Repeat("b", 64),
		IndexPath:    index, IndexSHA256: hex.EncodeToString(sum[:]), FeatureConfig: fc, CWD: dir,
		ReportRoot: reportRoot, ContainerID: strings.Repeat("e", 64), RunnerTimeout: 600,
		NetworkMode:         "host",
		CaseDelay:           "1s",
		CompletionMechanism: "default-timeout",
	}
	if mode == "feature" {
		p.ApplicationCommand = "/tmp/prebuilt-autobahn -mode " + direction
		receipt := filepath.Join(reportRoot, "application-receipt.json")
		p.ApplicationPID = 123
		p.ApplicationExitStatus = 0
		p.ApplicationTermination = "natural"
		if direction == "server" {
			p.ApplicationExitStatus = 143
			p.ApplicationTermination = "owned-cleanup"
		}
		rb, _ := json.Marshal(applicationReceipt{RunID: p.RunID, Direction: direction, Agent: agent, Command: p.ApplicationCommand, Termination: p.ApplicationTermination, PID: p.ApplicationPID, ExitStatus: p.ApplicationExitStatus, Executable: "/tmp/prebuilt-autobahn", ExecutableSHA256: strings.Repeat("d", 64), ExpectedExecutableSHA256: strings.Repeat("d", 64)})
		if err := os.WriteFile(receipt, rb, 0o644); err != nil {
			t.Fatal(err)
		}
		rsum := sha256.Sum256(rb)
		p.ApplicationReceipt = receipt
		p.ApplicationReceiptSHA = hex.EncodeToString(rsum[:])
		p.ApplicationTimeout = 480
		p.ApplicationExpectedSHA256 = strings.Repeat("d", 64)
		p.ApplicationObservedSHA256 = strings.Repeat("d", 64)
	}
	if direction == "client" {
		completion := filepath.Join(reportRoot, "client-complete")
		if err := os.WriteFile(completion, []byte("complete\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		p.CompletionFile = completion
		p.CompletionMechanism = "sentinel"
		p.CompletionStopReason = "sentinel"
		p.CompletionStopStatus = 137
	}
	prov := filepath.Join(dir, stem+"-provenance.json")
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prov, pb, 0o644); err != nil {
		t.Fatal(err)
	}
	return index, prov
}

func rewriteProvenance(t *testing.T, path string, mutate func(*provenance)) {
	t.Helper()
	var p provenance
	if err := readJSON(path, &p); err != nil {
		t.Fatal(err)
	}
	mutate(&p)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
