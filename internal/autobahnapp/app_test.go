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

package autobahnapp

import (
	"bytes"
	"testing"
	"time"

	"github.com/zchee/gows"
)

func TestCaseDelayParsingAndPreActionValidation(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    time.Duration
		invalid bool
	}{{"", 0, false}, {"0", 0, false}, {"1s", time.Second, false}, {"1000ms", time.Second, false}, {"-1s", 0, true}, {"invalid", 0, true}} {
		got, err := parseCaseDelay(tc.value)
		if (err != nil) != tc.invalid || got != tc.want {
			t.Fatalf("parseCaseDelay(%q)=(%s,%v)", tc.value, got, err)
		}
	}
	t.Setenv("AUTOBAHN_CASE_DELAY", "invalid")
	var stderr bytes.Buffer
	if code := Run([]string{"-mode", "server", "-addr", "invalid-address"}, Config{AgentName: "test", Upgrader: gows.Upgrader{}, Dialer: gows.Dialer{}}, &bytes.Buffer{}, &stderr); code != 2 || !bytes.Contains(stderr.Bytes(), []byte("invalid AUTOBAHN_CASE_DELAY")) {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestServerAndClientCasePacing(t *testing.T) {
	var sleeps []time.Duration
	a := application{caseDelay: 25 * time.Millisecond, sleep: func(d time.Duration) { sleeps = append(sleeps, d) }}
	a.beforeServerUpgrade()
	a.afterClientCase(1, 3)
	a.afterClientCase(2, 3)
	a.afterClientCase(3, 3)
	if len(sleeps) != 3 {
		t.Fatalf("sleeps=%v, want server plus two between-case delays", sleeps)
	}
	for _, d := range sleeps {
		if d != 25*time.Millisecond {
			t.Fatalf("delay=%s", d)
		}
	}
}
