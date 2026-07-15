package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
