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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-json-experiment/json"
)

func TestRunHelpAndFeatureReportSafety(t *testing.T) {
	cmd := exec.Command("bash", "./run.sh", "help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help: %v\n%s", err, out)
	}
	for _, want := range []string{"AUTOBAHN_REPORTS_DIR", "AUTOBAHN_PROFILE", "AUTOBAHN_AGENT", "AUTOBAHN_SERVER_TIMEOUT"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("help missing %q", want)
		}
	}

	cmd = exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
	cmd.Env = append(cmd.Environ(), "AUTOBAHN_PROFILE=feature", "AUTOBAHN_AGENT=gows-v04-feature-server")
	out, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "feature profile requires a unique AUTOBAHN_REPORTS_DIR") {
		t.Fatalf("feature canonical-root guard: err=%v output=%q", err, out)
	}

	cmd = exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
	cmd.Env = append(cmd.Environ(), "AUTOBAHN_IMAGE=repo@sha256:short")
	out, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "AUTOBAHN_IMAGE must be pinned by digest") {
		t.Fatalf("malformed digest guard: err=%v output=%q", err, out)
	}
}

func TestStrictReportRootRejectsRelativeAndPreexisting(t *testing.T) {
	for _, tc := range []struct {
		name, root, want string
		precreate        bool
	}{
		{"relative", "relative-run-id", "strict report root must be absolute", false},
		{"preexisting", filepath.Join(t.TempDir(), "run-id-reports"), "strict report root already exists", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, bin, _, _ := runnerSandbox(t)
			writeExecutable(t, filepath.Join(bin, "docker"), "#!/bin/sh\necho 'unexpected docker invocation' >&2\nexit 125\n")
			generator := filepath.Join(t.TempDir(), "generator.txt")
			if err := os.WriteFile(generator, []byte("generator\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			generator, _ = filepath.EvalSymlinks(generator)
			if tc.precreate {
				if err := os.MkdirAll(tc.root, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
			cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AUTOBAHN_STRICT_EVIDENCE=1", "AUTOBAHN_RUN_ID=run-id", "AUTOBAHN_REPORTS_DIR="+tc.root, "AUTOBAHN_GENERATOR_EVIDENCE="+generator+"@sha256:"+fileSHA256(t, generator))
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v out=%s", err, out)
			}
		})
	}
}

func TestFeatureProfileRejectsCrossDirectionAgentBeforeDocker(t *testing.T) {
	for _, direction := range []string{"server", "client"} {
		t.Run(direction, func(t *testing.T) {
			runID := "cross-" + direction
			root := filepath.Join(t.TempDir(), runID+"-reports")
			wrong := "gows-v04-feature-server"
			if direction == "server" {
				wrong = "gows-v04-feature-client"
			}
			args := []string{direction}
			if direction == "server" {
				args = append(args, "ws://127.0.0.1:9001")
			}
			cmd := exec.Command("bash", append([]string{"./run.sh"}, args...)...)
			cmd.Env = append(cmd.Environ(), "AUTOBAHN_PROFILE=feature", "AUTOBAHN_AGENT="+wrong, "AUTOBAHN_REPORTS_DIR="+root, "AUTOBAHN_RUN_ID="+runID, "AUTOBAHN_APPLICATION_COMMAND=/tmp/prebuilt -mode "+direction, "AUTOBAHN_GENERATOR_EVIDENCE=artifact@sha256:"+strings.Repeat("a", 64))
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "requires agent gows-v04-feature-"+direction) {
				t.Fatalf("err=%v out=%s", err, out)
			}
		})
	}
}

func TestStrictGeneratorEvidenceValidationBeforeDocker(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(artifact, []byte("generator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, _ = filepath.EvalSymlinks(artifact)
	for _, tc := range []struct{ name, value, want string }{
		{"malformed", "relative@sha256:" + strings.Repeat("a", 64), "must be <absolute-path>"},
		{"nonexistent", "/no/such/artifact@sha256:" + strings.Repeat("a", 64), "file/hash mismatch"},
		{"hash-mismatch", artifact + "@sha256:" + strings.Repeat("0", 64), "file/hash mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runID := "generator-" + tc.name
			root := filepath.Join(dir, runID+"-reports")
			cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
			cmd.Env = append(cmd.Environ(), "AUTOBAHN_STRICT_EVIDENCE=1", "AUTOBAHN_RUN_ID="+runID, "AUTOBAHN_REPORTS_DIR="+root, "AUTOBAHN_GENERATOR_EVIDENCE="+tc.value)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v out=%s", err, out)
			}
		})
	}
}

func TestRunTimeoutCleansOnlyOwnedContainerAndRecordsFailure(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "docker.log")
	capture := filepath.Join(dir, "fuzzingclient.json")
	docker := `#!/bin/sh
echo "$@" >>"$DOCKER_LOG"
if [ "$1" = run ]; then
  prev=""; for arg in "$@"; do if [ "$prev" = --cidfile ]; then echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" >"$arg"; fi; prev="$arg"; done
  for arg in "$@"; do
    case "$arg" in *fuzzingclient.json:/config/*) cp "${arg%%:*}" "$CONFIG_CAPTURE";; esac
  done
  exit 124
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(docker), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestTimeout(t, bin)
	reports := filepath.Join(dir, "reports")
	generator := filepath.Join(dir, "generator.txt")
	if err := os.WriteFile(generator, []byte("generator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	generator, _ = filepath.EvalSymlinks(generator)
	cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
	cmd.Env = append(cmd.Environ(),
		"PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "CONFIG_CAPTURE="+capture,
		"AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=owned-test", "AUTOBAHN_SERVER_TIMEOUT=1",
		"AUTOBAHN_PROFILE=feature", "AUTOBAHN_AGENT=gows-v04-feature-server",
		"AUTOBAHN_APPLICATION_COMMAND=go run ./flatekp/cmd/autobahn -mode server",
		"AUTOBAHN_GENERATOR_EVIDENCE="+generator+"@sha256:"+fileSHA256(t, generator))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "timed out with status 124") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "rm -f "+strings.Repeat("a", 64)) {
		t.Fatalf("owned cleanup absent: %s", logData)
	}
	if strings.Contains(string(logData), "container prune") {
		t.Fatalf("broad cleanup: %s", logData)
	}
	config, err := os.ReadFile(capture)
	if err != nil || !strings.Contains(string(config), `"agent": "gows-v04-feature-server"`) {
		t.Fatalf("generated feature config=%q err=%v", config, err)
	}
	failure, err := os.ReadFile(filepath.Join(reports, "owned-test-server-failure.txt"))
	if err != nil || !strings.Contains(string(failure), "exit_status=124") || !strings.Contains(string(failure), "failure_stage=docker") || !strings.Contains(string(failure), "container_id="+strings.Repeat("a", 64)) {
		t.Fatalf("failure evidence=%q err=%v", failure, err)
	}
}

func TestContainerNameCollisionWithoutCIDFileRemovesNothing(t *testing.T) {
	dir, bin, reports, logPath := runnerSandbox(t)
	docker := "#!/bin/sh\necho \"$@\" >>\"$DOCKER_LOG\"\nif [ \"$1\" = run ];then exit 125;fi\nexit 0\n"
	writeExecutable(t, filepath.Join(bin, "docker"), docker)
	cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
	cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=collision")
	_, _ = cmd.CombinedOutput()
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "rm -f") {
		t.Fatalf("removed unowned container: %s", b)
	}
	_ = dir
}

func TestNetworkModeDockerArgumentsAndServerURL(t *testing.T) {
	for _, mode := range []string{"host", "bridge"} {
		t.Run("server-"+mode, func(t *testing.T) {
			dir, bin, reports, logPath := runnerSandbox(t)
			capture := filepath.Join(dir, "config.json")
			docker := `#!/bin/sh
echo "$@" >>"$DOCKER_LOG"
if [ "$1" = run ];then for arg in "$@";do case "$arg" in *fuzzingclient.json:/config/*)cp "${arg%%:*}" "$CONFIG_CAPTURE";;esac;done;exit 124;fi
exit 0
`
			writeExecutable(t, filepath.Join(bin, "docker"), docker)
			cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
			cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "CONFIG_CAPTURE="+capture, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=network-"+mode, "AUTOBAHN_NETWORK_MODE="+mode)
			_, _ = cmd.CombinedOutput()
			args, _ := os.ReadFile(logPath)
			config, _ := os.ReadFile(capture)
			if mode == "host" {
				if !strings.Contains(string(args), "--network=host") || !strings.Contains(string(config), "ws://127.0.0.1:9001") || strings.Contains(string(config), "host.docker.internal") {
					t.Fatalf("args=%s config=%s", args, config)
				}
			} else {
				if strings.Contains(string(args), "--network=host") || !strings.Contains(string(config), "ws://host.docker.internal:9001") {
					t.Fatalf("args=%s config=%s", args, config)
				}
			}
		})
		t.Run("client-"+mode, func(t *testing.T) {
			_, bin, reports, logPath := runnerSandbox(t)
			writeExecutable(t, filepath.Join(bin, "docker"), "#!/bin/sh\necho \"$@\" >>\"$DOCKER_LOG\"\n[ \"$1\" = run ] && exit 125\nexit 0\n")
			cmd := exec.Command("bash", "./run.sh", "client")
			cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=network-"+mode, "AUTOBAHN_NETWORK_MODE="+mode)
			_, _ = cmd.CombinedOutput()
			args, _ := os.ReadFile(logPath)
			if mode == "host" {
				if !strings.Contains(string(args), "--network=host") || strings.Contains(string(args), "-p 127.0.0.1:9001:9001") {
					t.Fatalf("args=%s", args)
				}
			} else if strings.Contains(string(args), "--network=host") || !strings.Contains(string(args), "-p 127.0.0.1:9001:9001") {
				t.Fatalf("args=%s", args)
			}
		})
	}
}

func TestInvalidNetworkModeRejectedBeforeDocker(t *testing.T) {
	_, bin, reports, logPath := runnerSandbox(t)
	writeExecutable(t, filepath.Join(bin, "docker"), "#!/bin/sh\necho invoked >>\"$DOCKER_LOG\"\n")
	cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
	cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=invalid-network", "AUTOBAHN_NETWORK_MODE=invalid")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "must be auto, host, or bridge") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("docker invoked: %v", err)
	}
}

func TestServerRejectsClientCompletionFileBeforeDocker(t *testing.T) {
	dir, bin, reports, logPath := runnerSandbox(t)
	writeExecutable(t, filepath.Join(bin, "docker"), "#!/bin/sh\necho invoked >>\"$DOCKER_LOG\"\n")
	cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
	cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=server-completion", "AUTOBAHN_COMPLETION_FILE="+filepath.Join(dir, "complete"))
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "client-mode only") {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("docker invoked: %v", err)
	}
}

func TestClientCompletionSentinelSuccess(t *testing.T) {
	dir, bin, _, logPath := runnerSandbox(t)
	runID := "completion-success"
	reports := filepath.Join(dir, runID+"-reports")
	fixture := filepath.Join(dir, "index.json")
	writeIndexFixture(t, fixture, "gows", "OK")
	stop := filepath.Join(dir, "stop")
	docker := `#!/bin/sh
echo "$@" >>"$DOCKER_LOG"
if [ "$1" = rm ];then : >"$STOP_FILE";exit 0;fi
if [ "$1" = run ];then prev="";for arg in "$@";do if [ "$prev" = --cidfile ];then echo "` + strings.Repeat("a", 64) + `" >"$arg";fi;case "$arg" in *:/reports)root="${arg%%:*}";;esac;prev="$arg";done;mkdir -p "$root/clients";cp "$REPORT_FIXTURE" "$root/clients/index.json";while [ ! -e "$STOP_FILE" ];do sleep 0.05;done;exit 0;fi
exit 0
`
	writeExecutable(t, filepath.Join(bin, "docker"), docker)
	generator := writeGeneratorArtifact(t, dir)
	completion := filepath.Join(reports, "client-complete")
	cmd := exec.Command("bash", "./run.sh", "client")
	cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "STOP_FILE="+stop, "REPORT_FIXTURE="+fixture, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID="+runID, "AUTOBAHN_STRICT_EVIDENCE=1", "AUTOBAHN_SKIP_PROVENANCE=1", "AUTOBAHN_COMPLETION_FILE="+completion, "AUTOBAHN_GENERATOR_EVIDENCE="+generator, "AUTOBAHN_CLIENT_TIMEOUT=5")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(reports, "clients", "index.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("report was not flushed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := os.WriteFile(completion, []byte("done\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("err=%v out=%s", err, output.String())
	}
	reason, _ := os.ReadFile(filepath.Join(reports, runID+"-client-completion-stop-reason.txt"))
	if strings.TrimSpace(string(reason)) != "sentinel" {
		t.Fatalf("reason=%q", reason)
	}
}

func TestClientCompletionSentinelFailures(t *testing.T) {
	for _, tc := range []struct{ name, script, want string }{{"early-exit", "#!/bin/sh\n[ \"$1\" = run ] && exit 0\nexit 0\n", "docker-exit"}, {"timeout", "#!/bin/sh\n[ \"$1\" = run ] && exit 124\nexit 0\n", "timeout"}} {
		t.Run(tc.name, func(t *testing.T) {
			dir, bin, _, logPath := runnerSandbox(t)
			writeExecutable(t, filepath.Join(bin, "docker"), tc.script)
			runID := "completion-" + tc.name
			reports := filepath.Join(dir, runID+"-reports")
			generator := writeGeneratorArtifact(t, dir)
			completion := filepath.Join(reports, "client-complete")
			cmd := exec.Command("bash", "./run.sh", "client")
			cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID="+runID, "AUTOBAHN_STRICT_EVIDENCE=1", "AUTOBAHN_SKIP_PROVENANCE=1", "AUTOBAHN_COMPLETION_FILE="+completion, "AUTOBAHN_GENERATOR_EVIDENCE="+generator, "AUTOBAHN_CLIENT_TIMEOUT=1")
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v out=%s", err, out)
			}
		})
	}
}

func TestCompletionFileOwnershipValidation(t *testing.T) {
	for _, kind := range []string{"relative", "outside", "traversal", "preexisting"} {
		t.Run(kind, func(t *testing.T) {
			dir, bin := featureSandbox(t)
			generator := writeGeneratorArtifact(t, dir)
			reports := filepath.Join(dir, "owned-reports")
			value := filepath.Join(reports, "client-complete")
			switch kind {
			case "relative":
				value = "relative"
			case "outside":
				value = filepath.Join(t.TempDir(), "outside")
			case "traversal":
				value = filepath.Join(reports, "..", "outside")
			case "preexisting":
				if err := os.MkdirAll(filepath.Dir(value), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(value, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "./run.sh", "client")
			cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=owned", "AUTOBAHN_STRICT_EVIDENCE=1", "AUTOBAHN_COMPLETION_FILE="+value, "AUTOBAHN_GENERATOR_EVIDENCE="+generator)
			out, err := cmd.CombinedOutput()
			want := "completion file must be"
			if kind == "preexisting" {
				want = "strict report root already exists"
			}
			if err == nil || !strings.Contains(string(out), want) {
				t.Fatalf("err=%v out=%s", err, out)
			}
		})
	}
}

func writeGeneratorArtifact(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "generator.txt")
	if err := os.WriteFile(path, []byte("generator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, _ = filepath.EvalSymlinks(path)
	return path + "@sha256:" + fileSHA256(t, path)
}

func TestRunRecordsJudgeAndProvenanceFailures(t *testing.T) {
	t.Run("missing-report-judge", func(t *testing.T) {
		dir, bin, reports, logPath := runnerSandbox(t)
		writeExecutable(t, filepath.Join(bin, "docker"), "#!/bin/sh\necho \"$@\" >>\"$DOCKER_LOG\"\nexit 0\n")
		cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
		cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath,
			"AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=judge-fail")
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "no report produced") {
			t.Fatalf("err=%v out=%s", err, out)
		}
		wantFailureStage(t, reports, "judge-fail-server-failure.txt", "judge")
		_ = dir
	})

	t.Run("generic-judge-allows-unimplemented-provenance-fails", func(t *testing.T) {
		_, bin, reports, logPath := runnerSandbox(t)
		fixture := filepath.Join(filepath.Dir(reports), "index.json")
		writeIndexFixture(t, fixture, "gows", "UNIMPLEMENTED")
		docker := `#!/bin/sh
echo "$@" >>"$DOCKER_LOG"
if [ "$1" = run ]; then
  for arg in "$@"; do case "$arg" in *:/reports) root="${arg%%:*}"; mkdir -p "$root/server"; cp "$REPORT_FIXTURE" "$root/server/index.json";; esac; done
fi
		if [ "$1" = image ]; then echo "not-a-config-digest"; fi
exit 0
`
		writeExecutable(t, filepath.Join(bin, "docker"), docker)
		cmd := exec.Command("bash", "./run.sh", "server", "ws://127.0.0.1:9001")
		cmd.Env = append(cmd.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "DOCKER_LOG="+logPath,
			"REPORT_FIXTURE="+fixture, "AUTOBAHN_REPORTS_DIR="+reports, "AUTOBAHN_RUN_ID=provenance-fail")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "provenance: incomplete or invalid arguments") {
			t.Fatalf("err=%v out=%s", err, out)
		}
		// Reaching provenance proves the generic judge accepted UNIMPLEMENTED.
		wantFailureStage(t, reports, "provenance-fail-server-failure.txt", "provenance")
	})
}

func runnerSandbox(t *testing.T) (dir, bin, reports, logPath string) {
	t.Helper()
	dir = t.TempDir()
	bin = filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestTimeout(t, bin)
	reports = filepath.Join(dir, "reports")
	logPath = filepath.Join(dir, "docker.log")
	return dir, bin, reports, logPath
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeTestTimeout(t *testing.T, bin string) {
	t.Helper()
	writeExecutable(t, filepath.Join(bin, "timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n")
}

func writeIndexFixture(t *testing.T, path, agent, behavior string) {
	t.Helper()
	cases := make(map[string]map[string]string, 517)
	for i := 1; i <= 517; i++ {
		cases["1.1."+fmt.Sprint(i)] = map[string]string{"behavior": behavior, "behaviorClose": "OK"}
	}
	b, err := json.Marshal(map[string]any{agent: cases})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func wantFailureStage(t *testing.T, reports, name, stage string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(reports, name))
	if err != nil || !strings.Contains(string(b), "failure_stage="+stage) {
		t.Fatalf("failure evidence=%q err=%v", b, err)
	}
}
