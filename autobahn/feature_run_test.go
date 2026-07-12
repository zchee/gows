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

package autobahn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFeatureRunServerLaunchReceiptAndCleanup(t *testing.T) {
	dir, bin := featureSandbox(t)
	reports := filepath.Join(dir, "server-success-reports")
	fixture := filepath.Join(dir, "index.json")
	writeIndexFixture(t, fixture, "gows-v04-feature-server", "OK")
	writeFeatureDocker(t, bin, false)
	app := writeFeatureApp(t, bin, "server-app", "trap 'exit 143' TERM; while :; do sleep 1; done")
	cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
	cmd.Dir = "."
	cmd.Env = featureEnv(cmd.Environ(), bin, dir, reports, fixture, "server-success")
	cmd.Env = append(cmd.Env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256="+fileSHA256(t, app))
	cmd.Env = setEnv(cmd.Env, "AUTOBAHN_CASE_DELAY", "10ms")
	auditLog := filepath.Join(dir, "ownership-audit.log")
	cmd.Env = append(cmd.Env, "AUTOBAHN_OWNERSHIP_AUDIT_LOG="+auditLog)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("err=%v\n%s", err, out)
	}
	var p map[string]any
	readJSONFile(t, filepath.Join(reports, "server", "provenance.json"), &p)
	if p["agent"] != "gows-v04-feature-server" || p["application_termination"] != "owned-cleanup" || int(p["application_exit_status"].(float64)) != 143 || p["container_id"] != strings.Repeat("c", 64) || p["application_expected_sha256"] != fileSHA256(t, app) || p["application_observed_sha256"] != fileSHA256(t, app) || p["case_delay"] != "10ms" {
		t.Fatalf("provenance=%v", p)
	}
	pid := int(p["application_pid"].(float64))
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("application PID %d still alive", pid)
	}
	audit, err := os.ReadFile(auditLog)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(audit))
	if len(lines) != 1 || lines[0] != fmt.Sprint(pid) {
		t.Fatalf("owned kill audit=%q, want exactly one kill for %d", audit, pid)
	}
}

func TestFeatureRunClientCreatesCompletionAfterNaturalExit(t *testing.T) {
	dir, bin := featureSandbox(t)
	reports := filepath.Join(dir, "client-success-reports")
	fixture := filepath.Join(dir, "index.json")
	writeIndexFixture(t, fixture, "gows-v04-feature-client", "OK")
	writeFeatureDocker(t, bin, true)
	app := writeFeatureApp(t, bin, "client-success-app", "exit 0")
	cmd := exec.Command("bash", "./feature-run.sh", "client", "--", app, "-mode=client")
	cmd.Dir = "."
	cmd.Env = featureEnv(cmd.Environ(), bin, dir, reports, fixture, "client-success")
	cmd.Env = append(cmd.Env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256="+fileSHA256(t, app), "READY_REPORT_ROOT="+reports)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("err=%v\n%s", err, out)
	}
	completion := filepath.Join(reports, "client-success-client-complete")
	if _, err := os.Stat(completion); err != nil {
		t.Fatalf("completion sentinel: %v", err)
	}
	var p map[string]any
	readJSONFile(t, filepath.Join(reports, "clients", "provenance.json"), &p)
	if p["completion_file"] != completion || p["completion_mechanism"] != "sentinel" || p["completion_stop_reason"] != "sentinel" {
		t.Fatalf("provenance=%v", p)
	}
}

func TestFeatureRunClientReapsFailedRunnerWithoutSecondKill(t *testing.T) {
	dir, bin := featureSandbox(t)
	reports := filepath.Join(dir, "client-runner-failure-reports")
	fixture := filepath.Join(dir, "index.json")
	writeIndexFixture(t, fixture, "gows-v04-feature-client", "FAILED")
	writeFeatureDocker(t, bin, true)
	app := writeFeatureApp(t, bin, "client-runner-failure-app", "exit 0")
	audit := filepath.Join(dir, "runner-ownership-audit.log")
	cmd := exec.Command("bash", "./feature-run.sh", "client", "--", app, "-mode=client")
	cmd.Dir = "."
	cmd.Env = featureEnv(cmd.Environ(), bin, dir, reports, fixture, "client-runner-failure")
	cmd.Env = append(cmd.Env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256="+fileSHA256(t, app), "AUTOBAHN_RUNNER_OWNERSHIP_AUDIT_LOG="+audit, "READY_REPORT_ROOT="+reports)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "behavior=FAILED") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, statErr := os.Stat(audit); !os.IsNotExist(statErr) {
		auditData, _ := os.ReadFile(audit)
		t.Fatalf("reaped runner was killed again: %q err=%v", auditData, statErr)
	}
}

func TestFeatureRunInterruptWritesFailureReceipt(t *testing.T) {
	dir, bin := featureSandbox(t)
	writeExecutable(t, filepath.Join(bin, "nc"), "#!/bin/sh\nexit 1\n")
	app := writeFeatureApp(t, bin, "interrupt-app", "trap 'exit 143' TERM; while :; do sleep 1; done")
	reports := filepath.Join(dir, "interrupt-run-reports")
	cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
	cmd.Dir = "."
	cmd.Env = featureEnv(cmd.Environ(), bin, dir, reports, filepath.Join(dir, "unused"), "interrupt-run")
	cmd.Env = append(cmd.Env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256="+fileSHA256(t, app))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("interrupt succeeded")
	}
	var r map[string]any
	readJSONFile(t, filepath.Join(reports, "application-failure-receipt.json"), &r)
	if r["agent"] != "gows-v04-feature-server" || r["termination"] != "failure" {
		t.Fatalf("receipt=%v", r)
	}
	pid := int(r["pid"].(float64))
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("application PID %d still alive", pid)
	}
}

func TestFeatureRunRejectsOccupiedPortBeforeLaunch(t *testing.T) {
	dir, bin := featureSandbox(t)
	writeExecutable(t, filepath.Join(bin, "nc"), "#!/bin/sh\nexit 0\n")
	app := writeFeatureApp(t, bin, "never-launched", "exit 0")
	reports := filepath.Join(dir, "occupied-run-reports")
	cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
	cmd.Dir = "."
	cmd.Env = featureEnv(cmd.Environ(), bin, dir, reports, filepath.Join(dir, "unused"), "occupied-run")
	cmd.Env = append(cmd.Env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256="+fileSHA256(t, app))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "port 9001 is already occupied") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.pid")); !os.IsNotExist(err) {
		t.Fatalf("application launched: %v", err)
	}
}

func TestFeatureRunRejectsUnreviewedBinaryBeforeLaunch(t *testing.T) {
	dir, bin := featureSandbox(t)
	app := writeFeatureApp(t, bin, "unreviewed", "exit 0")
	reports := filepath.Join(dir, "unreviewed-run-reports")
	cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
	cmd.Dir = "."
	cmd.Env = featureEnv(cmd.Environ(), bin, dir, reports, filepath.Join(dir, "unused"), "unreviewed-run")
	cmd.Env = append(cmd.Env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256="+strings.Repeat("0", 64))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "does not match reviewed binary") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.pid")); !os.IsNotExist(err) {
		t.Fatalf("application launched: %v", err)
	}
}

func TestFeatureRunRejectsInvalidNetworkModeBeforeLaunch(t *testing.T) {
	dir, bin := featureSandbox(t)
	app := writeFeatureApp(t, bin, "network-app", "exit 0")
	reports := filepath.Join(dir, "invalid-network-reports")
	env := featureEnv(os.Environ(), bin, dir, reports, filepath.Join(dir, "unused"), "invalid-network")
	env = setEnv(env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256", fileSHA256(t, app))
	env = setEnv(env, "AUTOBAHN_NETWORK_MODE", "invalid")
	cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
	cmd.Dir = "."
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "must be auto, host, or bridge") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "app.pid")); !os.IsNotExist(err) {
		t.Fatalf("app launched: %v", err)
	}
}

func TestFeatureRunRejectsGeneratorEvidenceBeforeLaunch(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"malformed", "relative@sha256:" + strings.Repeat("a", 64), "must be <absolute-path>"},
		{"nonexistent", "/no/such/generator@sha256:" + strings.Repeat("a", 64), "file/hash mismatch"},
		{"hash-mismatch", "", "file/hash mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, bin := featureSandbox(t)
			app := writeFeatureApp(t, bin, "generator-app", "exit 0")
			reports := filepath.Join(dir, "generator-"+tc.name+"-reports")
			env := featureEnv(os.Environ(), bin, dir, reports, filepath.Join(dir, "unused"), "generator-"+tc.name)
			env = setEnv(env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256", fileSHA256(t, app))
			if tc.name == "hash-mismatch" {
				path := filepath.Join(dir, "generator.txt")
				tc.value = path + "@sha256:" + strings.Repeat("0", 64)
			}
			env = setEnv(env, "AUTOBAHN_GENERATOR_EVIDENCE", tc.value)
			cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
			cmd.Dir = "."
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v out=%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "app.pid")); !os.IsNotExist(err) {
				t.Fatalf("app launched: %v", err)
			}
		})
	}
}

func TestFeatureRunRejectsInvalidTimeoutsBeforeLaunch(t *testing.T) {
	for _, key := range []string{"AUTOBAHN_APPLICATION_TIMEOUT", "AUTOBAHN_READY_TIMEOUT", "AUTOBAHN_CLIENT_TIMEOUT", "AUTOBAHN_SERVER_TIMEOUT"} {
		for _, value := range []string{"0", "-1", "abc"} {
			t.Run(key+"="+value, func(t *testing.T) {
				dir, bin := featureSandbox(t)
				app := writeFeatureApp(t, bin, "timeout-app", "exit 0")
				reports := filepath.Join(dir, "timeout-validation-reports")
				env := featureEnv(os.Environ(), bin, dir, reports, filepath.Join(dir, "unused"), "timeout-validation")
				env = setEnv(env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256", fileSHA256(t, app))
				env = setEnv(env, key, value)
				cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
				cmd.Dir = "."
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(out), "positive base-10 integers") {
					t.Fatalf("err=%v out=%s", err, out)
				}
				if _, err := os.Stat(filepath.Join(dir, "app.pid")); !os.IsNotExist(err) {
					t.Fatalf("app launched: %v", err)
				}
			})
		}
	}
}

func TestFeatureRunRejectsInvalidCaseDelayBeforeLaunch(t *testing.T) {
	for _, value := range []string{"-1s", "invalid"} {
		t.Run(value, func(t *testing.T) {
			dir, bin := featureSandbox(t)
			app := writeFeatureApp(t, bin, "delay-app", "exit 0")
			reports := filepath.Join(dir, "delay-validation-reports")
			env := featureEnv(os.Environ(), bin, dir, reports, filepath.Join(dir, "unused"), "delay-validation")
			env = setEnv(env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256", fileSHA256(t, app))
			env = setEnv(env, "AUTOBAHN_CASE_DELAY", value)
			cmd := exec.Command("bash", "./feature-run.sh", "server", "--", app, "-mode", "server")
			cmd.Dir = "."
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "must be a nonnegative duration") {
				t.Fatalf("err=%v out=%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(dir, "app.pid")); !os.IsNotExist(err) {
				t.Fatalf("app launched: %v", err)
			}
		})
	}
}

func TestFeatureRunClientFailureAndTimeoutReceipts(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		timeout    bool
		want       int
	}{
		{"failure", "exit 7", false, 7},
		{"timeout", "sleep 10", true, 124},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, bin := featureSandbox(t)
			reports := filepath.Join(dir, "client-"+tc.name+"-reports")
			fixture := filepath.Join(dir, "index.json")
			writeIndexFixture(t, fixture, "gows-v04-feature-client", "OK")
			writeFeatureDocker(t, bin, true)
			app := writeFeatureApp(t, bin, "client-app", tc.body)
			cmd := exec.Command("bash", "./feature-run.sh", "client", "--", app, "-mode=client")
			cmd.Dir = "."
			cmd.Env = featureEnv(cmd.Environ(), bin, dir, reports, fixture, "client-"+tc.name)
			cmd.Env = append(cmd.Env, "AUTOBAHN_EXPECTED_APPLICATION_SHA256="+fileSHA256(t, app))
			auditLog := filepath.Join(dir, "ownership-audit.log")
			cmd.Env = append(cmd.Env, "AUTOBAHN_OWNERSHIP_AUDIT_LOG="+auditLog)
			if tc.timeout {
				cmd.Env = append(cmd.Env, "AUTOBAHN_APPLICATION_TIMEOUT=1")
			}
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("unexpected success: %s", out)
			}
			var ee *exec.ExitError
			if !strings.Contains(fmt.Sprint(err), "exit status") || !errorAs(err, &ee) {
				t.Fatalf("err=%v", err)
			}
			var r map[string]any
			readJSONFile(t, filepath.Join(reports, "application-failure-receipt.json"), &r)
			if r["agent"] != "gows-v04-feature-client" || int(r["exit_status"].(float64)) != tc.want {
				t.Fatalf("receipt=%v out=%s", r, out)
			}
			pid := int(r["pid"].(float64))
			if err := syscall.Kill(pid, 0); err == nil {
				t.Fatalf("application PID %d still alive", pid)
			}
			audit, readErr := os.ReadFile(auditLog)
			if tc.timeout {
				if readErr != nil || len(strings.Fields(string(audit))) != 1 {
					t.Fatalf("timeout kill audit=%q err=%v", audit, readErr)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("reaped PID was killed again: audit=%q err=%v", audit, readErr)
			}
		})
	}
}

func featureSandbox(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "nc-state")
	writeExecutable(t, filepath.Join(bin, "nc"), "#!/bin/sh\nif [ -n \"${READY_REPORT_ROOT:-}\" ] && [ ! -d \"$READY_REPORT_ROOT\" ]; then exit 1; fi\nif [ ! -e \"$NC_STATE\" ]; then : >\"$NC_STATE\"; exit 1; fi\nexit 0\n")
	t.Setenv("NC_STATE", state)
	return dir, bin
}

func featureEnv(base []string, bin, dir, reports, fixture, runID string) []string {
	generator := filepath.Join(dir, "generator.txt")
	_ = os.WriteFile(generator, []byte("generator\n"), 0o644)
	generator, _ = filepath.EvalSymlinks(generator)
	data, _ := os.ReadFile(generator)
	sum := sha256.Sum256(data)
	return append(base, "PATH="+bin+":"+os.Getenv("PATH"), "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID="+runID, "REPORT_FIXTURE="+fixture, "APP_PID_LOG="+filepath.Join(dir, "app.pid"), "AUTOBAHN_READY_TIMEOUT=2", "AUTOBAHN_CLIENT_TIMEOUT=5", "AUTOBAHN_GENERATOR_EVIDENCE="+generator+"@sha256:"+hex.EncodeToString(sum[:]))
}

func writeFeatureDocker(t *testing.T, bin string, slow bool) {
	t.Helper()
	sleep := ":"
	if slow {
		sleep = "sleep 3"
	}
	script := `#!/bin/sh
if [ "$1" = run ]; then prev="";for arg in "$@";do if [ "$prev" = --cidfile ];then echo "` + strings.Repeat("c", 64) + `" >"$arg";fi;prev="$arg";done;for arg in "$@"; do case "$arg" in *:/reports) root="${arg%%:*}"; if echo "$@"|grep -q fuzzingclient;then sub=server;else sub=clients;fi;mkdir -p "$root/$sub";cp "$REPORT_FIXTURE" "$root/$sub/index.json";;esac;done; ` + sleep + `; exit 0;fi
if [ "$1" = image ];then echo "sha256:` + strings.Repeat("b", 64) + `";fi
exit 0
`
	writeExecutable(t, filepath.Join(bin, "docker"), script)
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := env[:0]
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			out = append(out, entry)
		}
	}
	return append(out, prefix+value)
}

func writeFeatureApp(t *testing.T, bin, name, body string) string {
	t.Helper()
	p := filepath.Join(bin, name)
	writeExecutable(t, p, "#!/bin/sh\necho $$ >\"$APP_PID_LOG\"\n"+body+"\n")
	return p
}

func readJSONFile(t *testing.T, path string, dst any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatal(err)
	}
}

func errorAs(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

var _ = strconv.Itoa
