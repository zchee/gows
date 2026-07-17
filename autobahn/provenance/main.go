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

// Command provenance writes a hash-bound Autobahn run sidecar.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/zchee/gows/autobahn/internal/sidecar"
)

type appReceipt struct {
	RunID                    string `json:"run_id"`
	Direction                string `json:"direction"`
	Agent                    string `json:"agent"`
	Command                  string `json:"command"`
	StartedUTC               string `json:"started_utc"`
	EndedUTC                 string `json:"ended_utc"`
	Termination              string `json:"termination"`
	PID                      int    `json:"pid"`
	ExitStatus               int    `json:"exit_status"`
	ExecutableSHA256         string `json:"executable_sha256"`
	ExpectedExecutableSHA256 string `json:"expected_executable_sha256"`
}

func main() {
	var p sidecar.Sidecar
	var index, output, profile, receiptPath, normalizeDuration string
	var printWorkspace bool
	flag.BoolVar(&printWorkspace, "print-workspace", false, "print the current workspace SHA-256 and exit")
	flag.StringVar(&p.RunID, "run-id", "", "unique run ID")
	flag.StringVar(&profile, "profile", "canonical", "canonical or feature")
	flag.StringVar(&p.Direction, "direction", "", "server or client")
	flag.StringVar(&p.Agent, "agent", "", "report agent")
	flag.StringVar(&index, "index", "", "index.json path")
	flag.StringVar(&output, "output", "", "sidecar output path")
	flag.StringVar(&p.Command, "command", "", "exact run command")
	flag.IntVar(&p.ExitStatus, "status", -1, "run exit status")
	flag.StringVar(&p.Image, "image", "", "image reference")
	flag.StringVar(&p.ImageID, "image-id", "", "inspected immutable image ID")
	flag.StringVar(&p.StartedUTC, "started", "", "UTC RFC3339 start")
	flag.StringVar(&p.Generator, "generator", "", "case generator evidence")
	flag.StringVar(&p.ApplicationCommand, "application-command", "", "external gows application command")
	flag.StringVar(&receiptPath, "application-receipt", "", "observed application receipt")
	flag.StringVar(&p.ReportRoot, "report-root", "", "absolute owned report root")
	flag.StringVar(&p.ContainerID, "container-id", "", "actual owned container ID")
	flag.IntVar(&p.RunnerTimeout, "runner-timeout", 0, "runner timeout seconds")
	flag.IntVar(&p.ApplicationTimeout, "application-timeout", 0, "application timeout seconds")
	flag.StringVar(&p.NetworkMode, "network-mode", "", "effective Docker network mode")
	flag.StringVar(&p.CaseDelay, "case-delay", "0s", "effective inter-case delay")
	flag.StringVar(&p.CompletionFile, "completion-file", "", "client completion sentinel")
	flag.StringVar(&p.CompletionMechanism, "completion-mechanism", "default-timeout", "completion mechanism")
	flag.StringVar(&p.CompletionStopReason, "completion-stop-reason", "", "observed completion stop reason")
	flag.IntVar(&p.CompletionStopStatus, "completion-stop-status", 0, "observed runner stop status")
	flag.StringVar(&normalizeDuration, "normalize-duration", "", "normalize a nonnegative Go duration and exit")
	flag.Parse()
	if normalizeDuration != "" {
		d, err := time.ParseDuration(normalizeDuration)
		if err != nil || d < 0 {
			fmt.Fprintln(os.Stderr, "provenance: invalid nonnegative duration")
			os.Exit(2)
		}
		fmt.Println(d.String())
		return
	}
	if printWorkspace {
		fmt.Println(workspaceSHA256())
		return
	}
	if p.RunID == "" || (profile != "canonical" && profile != "feature") ||
		(p.Direction != "server" && p.Direction != "client") || p.Agent == "" || index == "" || output == "" ||
		p.Command == "" || p.ExitStatus != 0 || !sidecar.PinnedImage.MatchString(p.Image) || !sidecar.ImageID.MatchString(p.ImageID) || p.StartedUTC == "" || p.Generator == "" || (p.NetworkMode != "host" && p.NetworkMode != "bridge") || !sidecar.NormalizedDuration(p.CaseDelay) || (p.CompletionMechanism != "default-timeout" && p.CompletionMechanism != "sentinel") ||
		(profile == "feature" && (p.ApplicationCommand == "" || receiptPath == "" || p.ReportRoot == "" || !sidecar.ContainerID.MatchString(p.ContainerID) || p.RunnerTimeout <= 0 || p.ApplicationTimeout <= 0)) {
		fmt.Fprintln(os.Stderr, "provenance: incomplete or invalid arguments")
		os.Exit(2)
	}
	if p.Direction == "server" && (p.CompletionFile != "" || p.CompletionMechanism != "default-timeout") {
		fmt.Fprintln(os.Stderr, "provenance: server cannot use completion sentinel")
		os.Exit(2)
	}
	if p.Direction == "client" && p.CompletionMechanism == "sentinel" {
		if p.CompletionFile == "" || !filepath.IsAbs(p.CompletionFile) || filepath.Clean(p.CompletionFile) != p.CompletionFile || filepath.Dir(p.CompletionFile) != filepath.Clean(p.ReportRoot) || p.CompletionStopReason != "sentinel" {
			fmt.Fprintln(os.Stderr, "provenance: invalid client completion sentinel evidence")
			os.Exit(2)
		}
	}
	b, err := os.ReadFile(index)
	if err != nil {
		fatal(err)
	}
	var report map[string]map[string]json.RawMessage
	if err := json.Unmarshal(b, &report); err != nil {
		fatal(err)
	}
	cases, ok := report[p.Agent]
	if len(report) != 1 || !ok || len(cases) != 517 {
		fatal(fmt.Errorf("report agent/count mismatch"))
	}
	sum := sha256.Sum256(b)
	p.Version = 1
	p.CWD, _ = os.Getwd()
	p.Mode = profile
	p.Branch = git("branch", "--show-current")
	p.Head = git("rev-parse", "HEAD")
	p.DirtyEntries = len(strings.FieldsFunc(git("status", "--porcelain"), func(r rune) bool { return r == '\n' }))
	p.GoVersion = runtime.Version()
	p.GOOS, p.GOARCH = runtime.GOOS, runtime.GOARCH
	p.CaseCount = len(cases)
	p.IndexPath = index
	p.IndexSHA256 = hex.EncodeToString(sum[:])
	p.EndedUTC = time.Now().UTC().Format(time.RFC3339)
	p.WorkspaceSHA = workspaceSHA256()
	if profile == "feature" {
		receiptData, err := os.ReadFile(receiptPath)
		if err != nil {
			fatal(err)
		}
		var receipt appReceipt
		if err := json.Unmarshal(receiptData, &receipt); err != nil {
			fatal(err)
		}
		if receipt.RunID != p.RunID || receipt.Direction != p.Direction || receipt.Agent != p.Agent || receipt.Command != p.ApplicationCommand || receipt.PID <= 0 ||
			(p.Direction == "client" && (receipt.Termination != "natural" || receipt.ExitStatus != 0)) ||
			(p.Direction == "server" && (receipt.Termination != "owned-cleanup" || receipt.ExitStatus != 143)) {
			fatal(fmt.Errorf("application receipt mismatch"))
		}
		rsum := sha256.Sum256(receiptData)
		p.ApplicationReceipt = receiptPath
		p.ApplicationReceiptSHA = hex.EncodeToString(rsum[:])
		p.ApplicationPID = receipt.PID
		p.ApplicationExitStatus = receipt.ExitStatus
		p.ApplicationTermination = receipt.Termination
		p.ApplicationExpectedSHA256 = receipt.ExpectedExecutableSHA256
		p.ApplicationObservedSHA256 = receipt.ExecutableSHA256
		p.FeatureConfig = map[string]any{
			"backend": "klauspost/compress/flate", "level": 6, "window_bits": 9,
			"negotiate_window_bits": p.Direction == "server", "client_window_bits": 9,
			"offer_client_max_window_bits": p.Direction == "client", "server_window_bits": 9,
			"allow_context_takeover": true,
		}
	}
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		fatal(err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(output, out, 0o644); err != nil {
		fatal(err)
	}
}

func workspaceSHA256() string {
	h := sha256.New()
	diff, err := exec.Command("git", "diff", "--binary", "HEAD").Output()
	if err != nil {
		fatal(err)
	}
	_, _ = h.Write(diff)
	out, err := exec.Command("git", "ls-files", "--others", "--exclude-standard", "-z").Output()
	if err != nil {
		fatal(err)
	}
	paths := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	slices.Sort(paths)
	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fatal(err)
		}
		_, _ = h.Write([]byte(path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func git(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "provenance:", err); os.Exit(1) }
