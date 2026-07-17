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

// Command appreceipt writes an observed feature-application process receipt.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type receipt struct {
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

func main() {
	var r receipt
	var output string
	flag.StringVar(&r.RunID, "run-id", "", "run ID")
	flag.StringVar(&r.Direction, "direction", "", "direction")
	flag.StringVar(&r.Agent, "agent", "", "agent")
	flag.StringVar(&r.Command, "command", "", "exact argv rendering")
	flag.StringVar(&r.StartedUTC, "started", "", "start UTC")
	flag.StringVar(&r.EndedUTC, "ended", "", "end UTC")
	flag.StringVar(&r.Termination, "termination", "", "natural or owned-cleanup")
	flag.IntVar(&r.PID, "pid", 0, "owned PID")
	flag.IntVar(&r.ExitStatus, "status", -1, "observed exit status")
	flag.StringVar(&r.Executable, "executable", "", "prebuilt executable path")
	flag.StringVar(&r.ExpectedExecutableSHA256, "expected-executable-sha256", "", "reviewed executable SHA-256")
	flag.StringVar(&output, "output", "", "output JSON")
	flag.Parse()
	if r.RunID == "" || (r.Direction != "server" && r.Direction != "client") || r.Agent != "gows-v04-feature-"+r.Direction || r.Command == "" || r.StartedUTC == "" || r.EndedUTC == "" || r.PID <= 0 || r.ExitStatus < 0 || output == "" || r.Executable == "" || len(r.ExpectedExecutableSHA256) != 64 {
		fmt.Fprintln(os.Stderr, "appreceipt: incomplete receipt")
		os.Exit(2)
	}
	exe, err := os.ReadFile(r.Executable)
	if err != nil {
		fatal(err)
	}
	sum := sha256.Sum256(exe)
	r.ExecutableSHA256 = hex.EncodeToString(sum[:])
	if r.ExecutableSHA256 != r.ExpectedExecutableSHA256 {
		fmt.Fprintln(os.Stderr, "appreceipt: executable SHA-256 mismatch")
		os.Exit(1)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fatal(err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(output, b, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "appreceipt:", err); os.Exit(1) }
