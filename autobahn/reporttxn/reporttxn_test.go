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

package reporttxn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupPublishRestore(t *testing.T) {
	dir := t.TempDir()
	live := writeReport(t, dir, "live", "canonical")
	feature := writeReport(t, dir, "feature", "feature")
	backup := filepath.Join(dir, "backup")
	if err := Backup(live, backup); err != nil {
		t.Fatal(err)
	}
	liveHash, _ := TreeSHA256(live)
	backupHash, _ := TreeSHA256(backup)
	if liveHash != backupHash {
		t.Fatalf("live hash %s != backup %s", liveHash, backupHash)
	}
	if err := Backup(live, backup); err == nil {
		t.Fatal("overwrote backup")
	}
	if err := Publish(feature, live); err != nil {
		t.Fatal(err)
	}
	wantFile(t, live, "feature")
	if err := Restore(backup, live); err != nil {
		t.Fatal(err)
	}
	wantFile(t, live, "canonical")
}

func TestPublishFailureRestoresLive(t *testing.T) {
	dir := t.TempDir()
	live := writeReport(t, dir, "live", "canonical")
	feature := writeReport(t, dir, "feature", "feature")
	errInjected := errors.New("injected")
	if err := publish(feature, live, &publishHooks{afterMove: func() error { return errInjected }}); !errors.Is(err, errInjected) {
		t.Fatalf("error=%v", err)
	}
	wantFile(t, live, "canonical")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "live" && entry.Name() != "feature" {
			t.Fatalf("transaction debris: %s", entry.Name())
		}
	}
}

func TestRestoreFailureRetainsReplacementAndRollback(t *testing.T) {
	dir := t.TempDir()
	live := writeReport(t, dir, "live", "feature")
	backup := writeReport(t, dir, "backup", "canonical")
	errInjected := errors.New("restore injected")
	errRestore := errors.New("restore unavailable")
	err := publish(backup, live, &publishHooks{
		afterMove:     func() error { return errInjected },
		beforeRestore: func() error { return errRestore },
	})
	if !errors.Is(err, errInjected) || !errors.Is(err, errRestore) {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("live path unexpectedly exists: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	foundStage, foundRollback := false, false
	for _, entry := range entries {
		switch {
		case strings.HasPrefix(entry.Name(), ".reports-stage-"):
			foundStage = true
			wantFile(t, filepath.Join(dir, entry.Name()), "canonical")
		case strings.HasPrefix(entry.Name(), ".reports-rollback-"):
			foundRollback = true
			wantFile(t, filepath.Join(dir, entry.Name()), "feature")
		}
	}
	if !foundStage || !foundRollback {
		t.Fatalf("retained stage=%t rollback=%t", foundStage, foundRollback)
	}
}

func TestStagingFailureDoesNotMoveLive(t *testing.T) {
	dir := t.TempDir()
	live := writeReport(t, dir, "live", "canonical")
	feature := writeReport(t, dir, "feature", "feature")
	errInjected := errors.New("stage injected")
	if err := publish(feature, live, &publishHooks{afterStage: func() error { return errInjected }}); !errors.Is(err, errInjected) {
		t.Fatalf("error=%v", err)
	}
	wantFile(t, live, "canonical")
}

func TestPublishedHashMismatchRetainsLiveAndRollback(t *testing.T) {
	dir := t.TempDir()
	live := writeReport(t, dir, "live", "canonical")
	feature := writeReport(t, dir, "feature", "feature")
	err := publish(feature, live, &publishHooks{afterPublish: func() error {
		if err := os.WriteFile(filepath.Join(live, "server", "index.json"), []byte("corrupt"), 0o644); err != nil {
			t.Fatal(err)
		}
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "verify published report") {
		t.Fatalf("error=%v", err)
	}
	wantFile(t, live, "canonical")
	entries, _ := os.ReadDir(dir)
	foundFailed := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".reports-failed-") {
			foundFailed = true
			b, _ := os.ReadFile(filepath.Join(dir, e.Name(), "server", "index.json"))
			if string(b) != "corrupt" {
				t.Fatalf("failed evidence=%q", b)
			}
		}
	}
	if !foundFailed {
		t.Fatal("failed replacement not retained")
	}
}

func TestPostPublishRestoreFailureRetainsFailedAndRollback(t *testing.T) {
	dir := t.TempDir()
	live := writeReport(t, dir, "live", "canonical")
	feature := writeReport(t, dir, "feature", "feature")
	restoreErr := errors.New("restore blocked")
	err := publish(feature, live, &publishHooks{afterPublish: func() error { return errors.New("post publish") }, beforeRestore: func() error { return restoreErr }})
	if !errors.Is(err, restoreErr) {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("live unexpectedly exists: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	failed, rollback := false, false
	for _, e := range entries {
		failed = failed || strings.HasPrefix(e.Name(), ".reports-failed-")
		rollback = rollback || strings.HasPrefix(e.Name(), ".reports-rollback-")
	}
	if !failed || !rollback {
		t.Fatalf("failed=%t rollback=%t", failed, rollback)
	}
}

func TestPublishRejectsIncompleteAndSymlinkedReports(t *testing.T) {
	dir := t.TempDir()
	if err := Publish(filepath.Join(dir, "missing"), filepath.Join(dir, "live")); err == nil {
		t.Fatal("published missing report")
	}
	source := writeReport(t, dir, "source", "feature")
	if err := os.Symlink("index.json", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Publish(source, filepath.Join(dir, "live")); err == nil {
		t.Fatal("published symlinked report")
	}
}

func TestBackupRemovesIncompleteDestinationOnCopyFailure(t *testing.T) {
	dir := t.TempDir()
	source := writeReport(t, dir, "source", "canonical")
	if err := os.Symlink("index.json", filepath.Join(source, "zz-link")); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "backup")
	if err := Backup(source, backup); err == nil {
		t.Fatal("backup unexpectedly succeeded")
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("incomplete backup retained: %v", err)
	}
}

func TestTransactionsRejectOverlappingPaths(t *testing.T) {
	dir := t.TempDir()
	source := writeReport(t, dir, "source", "canonical")
	if err := Backup(source, filepath.Join(source, "backup")); err == nil {
		t.Fatal("backup accepted nested destination")
	}
	if err := Publish(source, filepath.Join(source, "live")); err == nil {
		t.Fatal("publish accepted nested live destination")
	}
}

func writeReport(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(path, "server"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "clients"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "server", "index.json"), []byte(contents+"-server"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "clients", "index.json"), []byte(contents+"-client"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func wantFile(t *testing.T, dir, want string) {
	t.Helper()
	for _, direction := range []string{"server", "clients"} {
		b, err := os.ReadFile(filepath.Join(dir, direction, "index.json"))
		wantDirection := want + "-" + strings.TrimSuffix(direction, "s")
		if err != nil || string(b) != wantDirection {
			t.Fatalf("%s index=%q err=%v, want %q", direction, b, err, wantDirection)
		}
	}
}
