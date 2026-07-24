package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/zchee/gows/bench/harness/policy"
)

// deadPid returns the pid of a process that has already exited and been
// reaped, so processAlive must report false for it.
func deadPid(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("spawn short-lived process: %v", err)
	}
	return cmd.Process.Pid
}

// TestAcquireLock covers the host-hygiene lock's full decision table: fresh
// acquisition, live-holder rejection, and the stale-lock recovery paths (dead
// pid and unparsable content). A regression here either lets two benchruns
// overlap or permanently bricks runs behind a stale lockfile.
func TestAcquireLock(t *testing.T) {
	tests := map[string]struct {
		setup   func(t *testing.T, path string)
		wantErr bool
	}{
		"success: fresh path": {},
		"success: stale lock with dead pid is recovered": {
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(strconv.Itoa(deadPid(t))+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		"success: garbage lock content is treated as stale": {
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("not-a-pid\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		"error: live holder is rejected": {
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "benchrun.lock")
			if tt.setup != nil {
				tt.setup(t, path)
			}

			release, err := acquireLock(path)
			if tt.wantErr {
				if err == nil {
					release()
					t.Fatal("acquireLock: nil error, want live-holder rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("acquireLock: %v", err)
			}

			data, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatalf("read lockfile: %v", rerr)
			}
			if got := strings.TrimSpace(string(data)); got != strconv.Itoa(os.Getpid()) {
				t.Fatalf("lockfile pid = %q, want %d", got, os.Getpid())
			}

			release()
			if _, serr := os.Stat(path); !os.IsNotExist(serr) {
				t.Fatalf("lockfile still present after release (stat err = %v)", serr)
			}
			release() // must be idempotent
		})
	}
}

func TestParseLoadavg(t *testing.T) {
	tests := map[string]struct {
		raw     string
		want1   float64
		wantErr bool
	}{
		"darwin braces":   {raw: "{ 1.23 4.56 7.89 }", want1: 1.23},
		"plain triple":    {raw: "0.50 0.60 0.70", want1: 0.50},
		"trailing spaces": {raw: "  2.00 2.10 2.20 \n", want1: 2.00},
		"too few":         {raw: "{ 1.23 }", wantErr: true},
		"non numeric":     {raw: "{ a b c }", wantErr: true},
		"empty":           {raw: "", wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l1, l5, l15, err := parseLoadavg(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got (%v,%v,%v)", l1, l5, l15)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if l1 != tc.want1 {
				t.Fatalf("load1 = %v, want %v", l1, tc.want1)
			}
			if l5 == 0 && l15 == 0 {
				t.Fatalf("load5/load15 not parsed: %v %v", l5, l15)
			}
		})
	}
}

func TestDefaultOutDirSeparatesEvidenceIdentities(t *testing.T) {
	moduleRoot := filepath.Join(t.TempDir(), "repo", "bench")
	pol := &policy.Policy{Series: policy.Series{
		ID: "series", Toolchain: policy.ToolchainStock, EvidenceClass: policy.EvidenceClassClaim,
		HostMode: policy.HostModeSeparate, RunKind: policy.RunKindBaseline,
	}}
	want := filepath.Join(
		filepath.Dir(moduleRoot), ".omx", "bench", "stock", "claim", "separate_host",
		"baseline", "series", "session-deadbeef",
	)
	if got := defaultOutDir(moduleRoot, pol, "session", "deadbeef"); got != want {
		t.Fatalf("defaultOutDir = %q, want %q", got, want)
	}

	diagnostic := *pol
	diagnostic.Series.EvidenceClass = policy.EvidenceClassDiagnostic
	diagnostic.Series.HostMode = policy.HostModeSame
	diagnostic.Series.RunKind = policy.RunKindDiagnostic
	if seriesOutRoot(moduleRoot, &diagnostic) == seriesOutRoot(moduleRoot, pol) {
		t.Fatal("diagnostic/same-host and claim/separate-host roots collided")
	}
}
