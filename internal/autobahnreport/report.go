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

// Package autobahnreport defines the JSON documents the Autobahn gate commands
// exchange and the format checks more than one of them applies. The documents
// are a case entry of Autobahn|Testsuite's index.json, the provenance sidecar
// that binds a report to the run and code state that produced it, and the
// receipt of the feature application's process. Each command keeps its own
// acceptance policy; this package only fixes the wire shape.
package autobahnreport

import (
	"regexp"
	"time"
)

// CaseResult is the part of one index.json case entry that the gate compares.
type CaseResult struct {
	Behavior      string `json:"behavior"`
	BehaviorClose string `json:"behaviorClose"`
}

// Provenance is the sidecar written next to an index.json report. It records
// the run, image, code state and, for the feature profile, the application
// receipt and deflate configuration that produced the report.
type Provenance struct {
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

// ApplicationReceipt records one observed run of the feature application: the
// exact command, how it ended, and the hash of the executable that ran.
type ApplicationReceipt struct {
	RunID                    string `json:"run_id"`
	Direction                string `json:"direction"`
	Agent                    string `json:"agent"`
	Command                  string `json:"command"`
	StartedUTC               string `json:"started_utc"`
	EndedUTC                 string `json:"ended_utc"`
	Termination              string `json:"termination"`
	PID                      int    `json:"pid"`
	ExitStatus               int    `json:"exit_status"`
	Executable               string `json:"executable"`
	ExecutableSHA256         string `json:"executable_sha256"`
	ExpectedExecutableSHA256 string `json:"expected_executable_sha256"`
}

var (
	pinnedImage = regexp.MustCompile(`^[^@]+@sha256:[0-9a-fA-F]{64}$`)
	imageID     = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
	containerID = regexp.MustCompile(`^[0-9a-fA-F]{12,64}$`)
)

// IsNormalizedDuration reports whether value is a nonnegative Go duration
// spelled exactly as [time.Duration.String] prints it, so that two records of
// the same delay compare equal as strings.
func IsNormalizedDuration(value string) bool {
	d, err := time.ParseDuration(value)
	return err == nil && d >= 0 && d.String() == value
}

// IsPinnedImage reports whether ref names an image by its sha256 digest.
func IsPinnedImage(ref string) bool { return pinnedImage.MatchString(ref) }

// IsImageID reports whether id is an inspected image ID, sha256:<64 hex>.
func IsImageID(id string) bool { return imageID.MatchString(id) }

// IsContainerID reports whether id is a short or full Docker container ID.
func IsContainerID(id string) bool { return containerID.MatchString(id) }
