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

// Package sidecar defines the hash-bound Autobahn run sidecar contract
// shared by its writer (autobahn/provenance) and its validator
// (autobahn/featurecheck), so emission and verification cannot drift apart.
package sidecar

import (
	"regexp"
	"time"
)

// Sidecar is the provenance record written next to an Autobahn report. Every
// field is part of the recorded evidence contract; validators reject sidecars
// whose identities do not match the run they claim to describe.
type Sidecar struct {
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
	ApplicationCommand        string         `json:"application_command,omitzero"`
	ApplicationReceipt        string         `json:"application_receipt,omitzero"`
	ApplicationReceiptSHA     string         `json:"application_receipt_sha256,omitzero"`
	ApplicationPID            int            `json:"application_pid,omitzero"`
	ApplicationExitStatus     int            `json:"application_exit_status,omitzero"`
	ApplicationTermination    string         `json:"application_termination,omitzero"`
	ApplicationExpectedSHA256 string         `json:"application_expected_sha256,omitzero"`
	ApplicationObservedSHA256 string         `json:"application_observed_sha256,omitzero"`
	CWD                       string         `json:"cwd"`
	ReportRoot                string         `json:"report_root"`
	ContainerID               string         `json:"container_id"`
	RunnerTimeout             int            `json:"runner_timeout_seconds"`
	ApplicationTimeout        int            `json:"application_timeout_seconds"`
	NetworkMode               string         `json:"network_mode"`
	CaseDelay                 string         `json:"case_delay"`
	CompletionFile            string         `json:"completion_file,omitzero"`
	CompletionMechanism       string         `json:"completion_mechanism"`
	CompletionStopReason      string         `json:"completion_stop_reason"`
	CompletionStopStatus      int            `json:"completion_stop_status"`
	FeatureConfig             map[string]any `json:"feature_config"`
}

// PinnedImage, ImageID, and ContainerID validate the docker identities
// recorded in a sidecar: a digest-pinned image reference, an inspected
// immutable image ID, and an owned container ID.
var (
	PinnedImage = regexp.MustCompile(`^[^@]+@sha256:[0-9a-fA-F]{64}$`)
	ImageID     = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)
	ContainerID = regexp.MustCompile(`^[0-9a-fA-F]{12,64}$`)
)

// NormalizedDuration reports whether value is a nonnegative Go duration
// spelled in canonical time.Duration.String form.
func NormalizedDuration(value string) bool {
	d, err := time.ParseDuration(value)
	return err == nil && d >= 0 && d.String() == value
}
