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

// Command featurecheck proves the v0.4 window-negotiation Autobahn cases from
// provenance-bound canonical and feature reports.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type caseResult struct {
	Behavior      string `json:"behavior"`
	BehaviorClose string `json:"behaviorClose"`
}

type manifest struct {
	Version int                     `json:"version"`
	Modes   map[string]manifestMode `json:"modes"`
}

type manifestMode struct {
	Agent      string                `json:"agent"`
	TotalCases int                   `json:"total_cases"`
	Inventory  map[string]caseResult `json:"inventory"`
	Targets    []string              `json:"targets"`
}

type provenance struct {
	Version                   int            `json:"version"`
	RunID                     string         `json:"run_id"`
	Mode                      string         `json:"mode"`
	Direction                 string         `json:"direction"`
	Agent                     string         `json:"agent"`
	Branch                    string         `json:"branch"`
	Head                      string         `json:"head"`
	DirtyEntries              int            `json:"dirty_entries"`
	GoVersion                 string         `json:"go_version"`
	GOOS                      string         `json:"goos"`
	GOARCH                    string         `json:"goarch"`
	Command                   string         `json:"command"`
	ExitStatus                int            `json:"exit_status"`
	Image                     string         `json:"image"`
	ImageID                   string         `json:"image_id"`
	CaseCount                 int            `json:"case_count"`
	IndexPath                 string         `json:"index_path"`
	IndexSHA256               string         `json:"index_sha256"`
	StartedUTC                string         `json:"started_utc"`
	EndedUTC                  string         `json:"ended_utc"`
	Generator                 string         `json:"generator_evidence"`
	WorkspaceSHA              string         `json:"workspace_sha256"`
	ApplicationCommand        string         `json:"application_command,omitempty"`
	ApplicationReceipt        string         `json:"application_receipt,omitempty"`
	ApplicationReceiptSHA     string         `json:"application_receipt_sha256,omitempty"`
	ApplicationPID            int            `json:"application_pid,omitempty"`
	ApplicationExitStatus     int            `json:"application_exit_status,omitempty"`
	ApplicationTermination    string         `json:"application_termination,omitempty"`
	ApplicationExpectedSHA256 string         `json:"application_expected_sha256,omitempty"`
	ApplicationObservedSHA256 string         `json:"application_observed_sha256,omitempty"`
	CWD                       string         `json:"cwd"`
	ReportRoot                string         `json:"report_root"`
	ContainerID               string         `json:"container_id"`
	RunnerTimeout             int            `json:"runner_timeout_seconds"`
	ApplicationTimeout        int            `json:"application_timeout_seconds"`
	NetworkMode               string         `json:"network_mode"`
	CaseDelay                 string         `json:"case_delay"`
	CompletionFile            string         `json:"completion_file,omitempty"`
	CompletionMechanism       string         `json:"completion_mechanism"`
	CompletionStopReason      string         `json:"completion_stop_reason"`
	CompletionStopStatus      int            `json:"completion_stop_status"`
	FeatureConfig             map[string]any `json:"feature_config"`
}

type applicationReceipt struct {
	RunID                    string `json:"run_id"`
	Direction                string `json:"direction"`
	Agent                    string `json:"agent"`
	Command                  string `json:"command"`
	Termination              string `json:"termination"`
	PID                      int    `json:"pid"`
	ExitStatus               int    `json:"exit_status"`
	Executable               string `json:"executable"`
	ExecutableSHA256         string `json:"executable_sha256"`
	ExpectedExecutableSHA256 string `json:"expected_executable_sha256"`
}

type options struct {
	ManifestPath, BeforePath, BeforeProvenance               string
	AfterPath, AfterProvenance, Direction, Agent             string
	BeforeRunID, AfterRunID, ExpectedHead, ExpectedWorkspace string
	ExpectedApplicationSHA                                   string
	AllowNetworkModeDifference                               bool
	ExpectedCaseDelay                                        string
}

func main() {
	fs := flag.NewFlagSet("featurecheck", flag.ExitOnError)
	var o options
	fs.StringVar(&o.ManifestPath, "manifest", "autobahn/featurecheck/testdata/window-case-manifest.json", "checked-in baseline manifest")
	fs.StringVar(&o.BeforePath, "before", "", "canonical index.json")
	fs.StringVar(&o.BeforeProvenance, "before-provenance", "", "canonical provenance JSON")
	fs.StringVar(&o.AfterPath, "after", "", "feature index.json")
	fs.StringVar(&o.AfterProvenance, "after-provenance", "", "feature provenance JSON")
	fs.StringVar(&o.Direction, "direction", "", "server or client")
	fs.StringVar(&o.Agent, "agent", "", "expected feature agent")
	fs.StringVar(&o.BeforeRunID, "before-run-id", "", "expected canonical run ID")
	fs.StringVar(&o.AfterRunID, "after-run-id", "", "expected feature run ID")
	fs.StringVar(&o.ExpectedHead, "expected-head", "", "expected current HEAD")
	fs.StringVar(&o.ExpectedWorkspace, "expected-workspace-sha256", "", "expected current workspace SHA-256")
	fs.StringVar(&o.ExpectedApplicationSHA, "expected-application-sha256", "", "expected reviewed feature binary SHA-256")
	fs.BoolVar(&o.AllowNetworkModeDifference, "allow-network-mode-difference", false, "allow canonical and feature reports to use different effective Docker network modes")
	fs.StringVar(&o.ExpectedCaseDelay, "expected-case-delay", "", "expected normalized case delay")
	fs.Parse(os.Args[1:])
	if err := run(os.Stdout, o); err != nil {
		fmt.Fprintln(os.Stderr, "featurecheck:", err)
		os.Exit(1)
	}
}

func run(w io.Writer, o options) error {
	if o.Direction != "server" && o.Direction != "client" {
		return errors.New("direction must be server or client")
	}
	if o.BeforeRunID == "" || o.AfterRunID == "" || o.ExpectedHead == "" || o.ExpectedWorkspace == "" || !rawSHA.MatchString(o.ExpectedApplicationSHA) || !normalizedDuration(o.ExpectedCaseDelay) {
		return errors.New("explicit run IDs, HEAD, and workspace SHA are required")
	}
	wantAgent := "gows-v04-feature-" + o.Direction
	if o.Agent == "" {
		o.Agent = wantAgent
	}
	if o.Agent != wantAgent {
		return fmt.Errorf("wrong feature agent %q, want %q", o.Agent, wantAgent)
	}

	var mf manifest
	if err := readJSON(o.ManifestPath, &mf); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	mm, ok := mf.Modes[o.Direction]
	if !ok || mf.Version != 1 || mm.TotalCases != 517 || mm.Agent != "gows" || len(mm.Inventory) == 0 || len(mm.Targets) == 0 {
		return errors.New("manifest is incomplete or has unexpected baseline metadata")
	}
	if err := validateManifest(mm); err != nil {
		return err
	}

	before, beforeMeta, err := loadBoundReport(o.BeforePath, o.BeforeProvenance, "canonical", o.Direction, "gows", false, "")
	if err != nil {
		return fmt.Errorf("canonical evidence: %w", err)
	}
	after, afterMeta, err := loadBoundReport(o.AfterPath, o.AfterProvenance, "feature", o.Direction, o.Agent, true, o.ExpectedApplicationSHA)
	if err != nil {
		return fmt.Errorf("feature evidence: %w", err)
	}
	if len(before) != 517 || len(after) != 517 {
		return fmt.Errorf("truncated report: canonical=%d feature=%d, want 517 each", len(before), len(after))
	}
	if beforeMeta.Head != afterMeta.Head || beforeMeta.WorkspaceSHA != afterMeta.WorkspaceSHA {
		return errors.New("canonical and feature reports were generated from different code states")
	}
	if beforeMeta.RunID != o.BeforeRunID || afterMeta.RunID != o.AfterRunID || beforeMeta.Head != o.ExpectedHead || afterMeta.Head != o.ExpectedHead || beforeMeta.WorkspaceSHA != o.ExpectedWorkspace || afterMeta.WorkspaceSHA != o.ExpectedWorkspace {
		return errors.New("evidence does not match explicit current run/code identity")
	}
	if !o.AllowNetworkModeDifference && beforeMeta.NetworkMode != afterMeta.NetworkMode {
		return errors.New("canonical and feature network modes differ without explicit acceptance")
	}
	if beforeMeta.CaseDelay != o.ExpectedCaseDelay || afterMeta.CaseDelay != o.ExpectedCaseDelay {
		return errors.New("canonical or feature case delay differs from explicit expected delay")
	}
	if beforeMeta.CompletionMechanism != afterMeta.CompletionMechanism {
		return errors.New("canonical and feature completion mechanisms differ")
	}
	if err := rejectReportFailures(before); err != nil {
		return fmt.Errorf("canonical report: %w", err)
	}
	if err := rejectReportFailures(after); err != nil {
		return err
	}

	ids := sortedKeys(mm.Inventory)
	for id := range before {
		if (strings.HasPrefix(id, "13.3.") || strings.HasPrefix(id, "13.5.")) && mm.Inventory[id].Behavior == "" {
			return fmt.Errorf("canonical report has extra inventory case %s", id)
		}
	}
	for id := range after {
		if (strings.HasPrefix(id, "13.3.") || strings.HasPrefix(id, "13.5.")) && mm.Inventory[id].Behavior == "" {
			return fmt.Errorf("feature report has extra inventory case %s", id)
		}
	}
	for _, id := range ids {
		base, ok := before[id]
		if !ok {
			return fmt.Errorf("canonical report missing inventory case %s", id)
		}
		if base != mm.Inventory[id] {
			return fmt.Errorf("stale canonical report at %s: got %+v want %+v", id, base, mm.Inventory[id])
		}
		if _, ok := after[id]; !ok {
			return fmt.Errorf("feature report missing inventory case %s", id)
		}
	}
	targets := make(map[string]bool, len(mm.Targets))
	for _, id := range mm.Targets {
		targets[id] = true
		if before[id].Behavior != "UNIMPLEMENTED" {
			return fmt.Errorf("target %s canonical behavior=%s, want UNIMPLEMENTED", id, before[id].Behavior)
		}
		if after[id].Behavior != "OK" {
			return fmt.Errorf("target %s feature behavior=%s, want OK", id, after[id].Behavior)
		}
	}

	fmt.Fprintln(w, "CASE       TARGET  CANONICAL       FEATURE")
	for _, id := range ids {
		fmt.Fprintf(w, "%-10s %-7t %-15s %s\n", id, targets[id], before[id].Behavior, after[id].Behavior)
	}
	return nil
}

func validateManifest(m manifestMode) error {
	targets := make(map[string]bool, len(m.Targets))
	for _, id := range m.Targets {
		if targets[id] {
			return fmt.Errorf("duplicate target %s", id)
		}
		targets[id] = true
		if _, ok := m.Inventory[id]; !ok {
			return fmt.Errorf("target %s absent from inventory", id)
		}
	}
	for id := range m.Inventory {
		if !strings.HasPrefix(id, "13.3.") && !strings.HasPrefix(id, "13.5.") {
			return fmt.Errorf("unexpected inventory case %s", id)
		}
	}
	return nil
}

func loadBoundReport(indexPath, provenancePath, mode, direction, agent string, feature bool, expectedApplicationSHA string) (map[string]caseResult, provenance, error) {
	if indexPath == "" || provenancePath == "" {
		return nil, provenance{}, errors.New("index and provenance paths are required")
	}
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, provenance{}, fmt.Errorf("read index: %w", err)
	}
	var reports map[string]map[string]caseResult
	if err := json.Unmarshal(data, &reports); err != nil {
		return nil, provenance{}, fmt.Errorf("parse index: %w", err)
	}
	if len(reports) != 1 {
		return nil, provenance{}, fmt.Errorf("wrong agent count %d, want exactly 1", len(reports))
	}
	cases, ok := reports[agent]
	if !ok {
		return nil, provenance{}, fmt.Errorf("wrong agent, want %q", agent)
	}
	var p provenance
	if err := readJSON(provenancePath, &p); err != nil {
		return nil, provenance{}, fmt.Errorf("provenance: %w", err)
	}
	sum := sha256.Sum256(data)
	started, startErr := time.Parse(time.RFC3339, p.StartedUTC)
	ended, endErr := time.Parse(time.RFC3339, p.EndedUTC)
	if p.Version != 1 || p.RunID == "" || p.Mode != mode || p.Direction != direction || p.Agent != agent ||
		p.Branch == "" || p.Head == "" || p.GoVersion == "" || p.GOOS == "" || p.GOARCH == "" || p.Command == "" ||
		p.ExitStatus != 0 || !pinnedImage.MatchString(p.Image) || !imageID.MatchString(p.ImageID) || p.CaseCount != 517 || p.IndexPath == "" ||
		startErr != nil || endErr != nil || ended.Before(started) ||
		p.WorkspaceSHA == "" || p.CWD == "" || p.ReportRoot == "" || !filepath.IsAbs(p.ReportRoot) || !containerID.MatchString(p.ContainerID) || p.RunnerTimeout <= 0 || (p.NetworkMode != "host" && p.NetworkMode != "bridge") || !normalizedDuration(p.CaseDelay) || (p.CompletionMechanism != "default-timeout" && p.CompletionMechanism != "sentinel") ||
		p.IndexSHA256 != hex.EncodeToString(sum[:]) {
		return nil, provenance{}, errors.New("missing, stale, or hash-mismatched provenance")
	}
	if err := verifyGeneratorEvidence(p.Generator); err != nil {
		return nil, provenance{}, fmt.Errorf("generator evidence: %w", err)
	}
	if filepath.Base(p.IndexPath) != filepath.Base(indexPath) {
		return nil, provenance{}, errors.New("provenance index path does not name index.json")
	}
	wantIndex, _ := filepath.Abs(filepath.Clean(indexPath))
	gotIndex, _ := filepath.Abs(filepath.Clean(p.IndexPath))
	if wantIndex != gotIndex {
		return nil, provenance{}, errors.New("provenance index path is not the exact cleaned index path")
	}
	info, err := os.Stat(indexPath)
	if err != nil {
		return nil, provenance{}, err
	}
	if info.ModTime().Before(started.Add(-2*time.Second)) || info.ModTime().After(ended.Add(2*time.Second)) {
		return nil, provenance{}, errors.New("stale report timing evidence")
	}
	rootFromIndex := filepath.Dir(filepath.Dir(wantIndex))
	cleanedRoot, _ := filepath.Abs(filepath.Clean(p.ReportRoot))
	if cleanedRoot != rootFromIndex {
		return nil, provenance{}, errors.New("report root does not match exact index path")
	}
	if !strings.Contains(filepath.Base(cleanedRoot), p.RunID) {
		return nil, provenance{}, errors.New("report root does not contain provenance run ID")
	}
	if direction == "server" && (p.CompletionFile != "" || p.CompletionMechanism != "default-timeout") {
		return nil, provenance{}, errors.New("server completion evidence is invalid")
	}
	if direction == "client" && p.CompletionMechanism == "sentinel" {
		completion, _ := filepath.Abs(filepath.Clean(p.CompletionFile))
		if completion == "" || filepath.Dir(completion) != cleanedRoot || p.CompletionStopReason != "sentinel" {
			return nil, provenance{}, errors.New("client completion sentinel evidence is invalid")
		}
		if _, err := os.Stat(completion); err != nil {
			return nil, provenance{}, fmt.Errorf("client completion sentinel: %w", err)
		}
	}
	if feature {
		if p.ApplicationCommand == "" || p.ApplicationReceipt == "" || p.ApplicationPID <= 0 || p.ApplicationTimeout <= 0 {
			return nil, provenance{}, errors.New("feature provenance lacks external application command")
		}
		cleanedReceipt, _ := filepath.Abs(filepath.Clean(p.ApplicationReceipt))
		if cleanedRoot != rootFromIndex || filepath.Dir(cleanedReceipt) != cleanedRoot {
			return nil, provenance{}, errors.New("feature report root or receipt path mismatch")
		}
		rb, err := os.ReadFile(p.ApplicationReceipt)
		if err != nil {
			return nil, provenance{}, fmt.Errorf("application receipt: %w", err)
		}
		rsum := sha256.Sum256(rb)
		if p.ApplicationReceiptSHA != hex.EncodeToString(rsum[:]) {
			return nil, provenance{}, errors.New("application receipt hash mismatch")
		}
		var receipt applicationReceipt
		if err := json.Unmarshal(rb, &receipt); err != nil {
			return nil, provenance{}, err
		}
		if receipt.RunID != p.RunID || receipt.Direction != direction || receipt.Agent != agent || receipt.Command != p.ApplicationCommand || receipt.PID != p.ApplicationPID || receipt.ExitStatus != p.ApplicationExitStatus || receipt.Termination != p.ApplicationTermination || receipt.Executable == "" || receipt.ExecutableSHA256 != expectedApplicationSHA || receipt.ExpectedExecutableSHA256 != expectedApplicationSHA || p.ApplicationExpectedSHA256 != expectedApplicationSHA || p.ApplicationObservedSHA256 != expectedApplicationSHA {
			return nil, provenance{}, errors.New("application receipt content mismatch")
		}
		if direction == "server" && (p.ApplicationTermination != "owned-cleanup" || p.ApplicationExitStatus != 143) {
			return nil, provenance{}, errors.New("server application receipt lacks expected owned cleanup status")
		}
		if direction == "client" && (p.ApplicationTermination != "natural" || p.ApplicationExitStatus != 0) {
			return nil, provenance{}, errors.New("client application receipt lacks natural success")
		}
		if len(p.FeatureConfig) == 0 || p.FeatureConfig["backend"] != "klauspost/compress/flate" || number(p.FeatureConfig["level"]) != 6 || number(p.FeatureConfig["window_bits"]) != 9 {
			return nil, provenance{}, errors.New("feature provenance lacks flatekp level-6/window-9 configuration")
		}
		if p.FeatureConfig["allow_context_takeover"] != true ||
			(direction == "server" && (p.FeatureConfig["negotiate_window_bits"] != true || number(p.FeatureConfig["client_window_bits"]) != 9)) ||
			(direction == "client" && (p.FeatureConfig["offer_client_max_window_bits"] != true || number(p.FeatureConfig["server_window_bits"]) != 9)) {
			return nil, provenance{}, errors.New("feature provenance lacks exact direction-specific window policy")
		}
	} else if len(p.FeatureConfig) != 0 {
		return nil, provenance{}, errors.New("canonical provenance unexpectedly has feature configuration")
	}
	return cases, p, nil
}

var (
	pinnedImage       = regexp.MustCompile(`^[^@]+@sha256:[0-9a-fA-F]{64}$`)
	imageID           = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
	containerID       = regexp.MustCompile(`^[0-9a-fA-F]{12,64}$`)
	rawSHA            = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	generatorIdentity = regexp.MustCompile(`^(/.*)@sha256:([0-9a-f]{64})$`)
)

func verifyGeneratorEvidence(identity string) error {
	m := generatorIdentity.FindStringSubmatch(identity)
	if m == nil {
		return errors.New("want <absolute-path>@sha256:<64 lowercase hex>")
	}
	cleaned, err := filepath.Abs(filepath.Clean(m[1]))
	if err != nil || cleaned != m[1] {
		return errors.New("path is not normalized absolute")
	}
	b, err := os.ReadFile(cleaned)
	if err != nil {
		return err
	}
	real, realErr := filepath.EvalSymlinks(cleaned)
	if realErr != nil || real != cleaned {
		return errors.New("path is not normalized absolute")
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != m[2] {
		return errors.New("artifact hash mismatch")
	}
	return nil
}

func normalizedDuration(value string) bool {
	d, err := time.ParseDuration(value)
	return err == nil && d >= 0 && d.String() == value
}

func rejectReportFailures(cases map[string]caseResult) error {
	for id, c := range cases {
		if c.Behavior == "NON-STRICT" || c.BehaviorClose == "NON-STRICT" ||
			!allowed(c.Behavior) || !allowed(c.BehaviorClose) {
			return fmt.Errorf("feature report has failed or NON-STRICT case %s: %+v", id, c)
		}
	}
	return nil
}

func allowed(s string) bool { return s == "OK" || s == "INFORMATIONAL" || s == "UNIMPLEMENTED" }

func readJSON(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return err
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func number(v any) int {
	f, _ := v.(float64)
	return int(f)
}
