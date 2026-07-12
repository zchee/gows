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
	"os/exec"
	"strings"
	"testing"
)

func TestCanonicalCLIUsageAndFlags(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-mode", "invalid")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("invalid mode succeeded")
	}
	want := "usage: autobahn -mode server|client [-addr :9001] [-server ws://127.0.0.1:9001]"
	if !strings.Contains(string(out), want) {
		t.Fatalf("output %q does not contain %q", out, want)
	}
}

func TestCanonicalCLIHelpGolden(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-h")
	out, _ := cmd.CombinedOutput()
	for _, want := range []string{"-addr string", "-echo string", "-mode string", "-server string", "-takeover"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("help missing %q:\n%s", want, out)
		}
	}
}

func TestCanonicalCLIRejectsUnknownEcho(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-mode", "client", "-echo", "invalid")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), `unknown -echo mode "invalid" (want message or stream)`) {
		t.Fatalf("output=%q err=%v", out, err)
	}
}

func TestCanonicalCLIServerListenErrorMessage(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-mode", "server", "-addr", "invalid-address")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "listen invalid-address:") {
		t.Fatalf("output=%q err=%v", out, err)
	}
}
