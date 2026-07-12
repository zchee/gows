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

// Package reporttxn provides filesystem transactions for preserving and
// restoring canonical Autobahn reports.
package reporttxn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Backup copies live to a new, immutable backup directory.
func Backup(live, backup string) error {
	if overlap(live, backup) {
		return fmt.Errorf("backup paths overlap: %s and %s", live, backup)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		return fmt.Errorf("backup destination must not exist: %s", backup)
	}
	sourceHash, err := TreeSHA256(live)
	if err != nil {
		return err
	}
	if err := copyTree(live, backup); err != nil {
		if cleanupErr := os.RemoveAll(backup); cleanupErr != nil {
			return fmt.Errorf("backup report: %v; remove incomplete backup: %w", err, cleanupErr)
		}
		return fmt.Errorf("backup report: %w", err)
	}
	backupHash, err := TreeSHA256(backup)
	if err != nil || backupHash != sourceHash {
		_ = os.RemoveAll(backup)
		return fmt.Errorf("verify backup: source=%s backup=%s: %w", sourceHash, backupHash, err)
	}
	return nil
}

// Publish atomically replaces live with a copy of source. If replacement
// fails after moving live aside, the original live directory is restored.
func Publish(source, live string) error {
	return publish(source, live, nil)
}

// Restore is identical to Publish but names the safety intent at call sites.
func Restore(backup, live string) error { return Publish(backup, live) }

type publishHooks struct {
	afterStage, afterMove, beforeRestore, afterPublish func() error
}

func publish(source, live string, hooks *publishHooks) error {
	if overlap(source, live) {
		return fmt.Errorf("publish paths overlap: %s and %s", source, live)
	}
	sourceHash, err := TreeSHA256(source)
	if err != nil {
		return err
	}
	parent := filepath.Dir(live)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".reports-stage-")
	if err != nil {
		return err
	}
	if err := os.Remove(stage); err != nil {
		return err
	}
	removeStage := true
	defer func() {
		if removeStage {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := copyTree(source, stage); err != nil {
		return fmt.Errorf("stage report: %w", err)
	}
	stageHash, err := TreeSHA256(stage)
	if err != nil || stageHash != sourceHash {
		return fmt.Errorf("verify staged report: source=%s stage=%s: %w", sourceHash, stageHash, err)
	}
	if hooks != nil && hooks.afterStage != nil {
		if err := hooks.afterStage(); err != nil {
			return fmt.Errorf("after staging: %w", err)
		}
	}

	rollback, err := os.MkdirTemp(parent, ".reports-rollback-")
	if err != nil {
		return err
	}
	if err := os.Remove(rollback); err != nil {
		return err
	}
	liveExists := false
	oldHash := ""
	if _, err := os.Stat(live); err == nil {
		liveExists = true
		oldHash, err = TreeSHA256(live)
		if err != nil {
			return err
		}
		if err := os.Rename(live, rollback); err != nil {
			return fmt.Errorf("move live report aside: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	recoverLive := func(cause error) error {
		if liveExists {
			if hooks != nil && hooks.beforeRestore != nil {
				if err := hooks.beforeRestore(); err != nil {
					removeStage = false
					return fmt.Errorf("%w; restoration blocked: %w; retained replacement=%s rollback=%s", cause, err, stage, rollback)
				}
			}
			if err := os.Rename(rollback, live); err != nil {
				removeStage = false
				return fmt.Errorf("%w; restoring live report: %w; retained replacement=%s rollback=%s", cause, err, stage, rollback)
			}
			restoredHash, err := TreeSHA256(live)
			if err != nil || restoredHash != oldHash {
				_ = os.Rename(live, rollback)
				removeStage = false
				return fmt.Errorf("%w; restored live verification failed: old=%s restored=%s: %v; retained replacement=%s rollback=%s", cause, oldHash, restoredHash, err, stage, rollback)
			}
		}
		return cause
	}
	if hooks != nil && hooks.afterMove != nil {
		if err := hooks.afterMove(); err != nil {
			return recoverLive(fmt.Errorf("after moving live: %w", err))
		}
	}
	if err := os.Rename(stage, live); err != nil {
		return recoverLive(fmt.Errorf("publish staged report: %w", err))
	}
	removeStage = false
	recoverPublished := func(cause error) error {
		failed, err := os.MkdirTemp(parent, ".reports-failed-")
		if err != nil {
			return fmt.Errorf("%w; allocate failed evidence: %v; rollback=%s live=%s", cause, err, rollback, live)
		}
		if err := os.Remove(failed); err != nil {
			return fmt.Errorf("%w; prepare failed evidence: %v", cause, err)
		}
		if err := os.Rename(live, failed); err != nil {
			return fmt.Errorf("%w; retain failed replacement: %v; rollback=%s live=%s", cause, err, rollback, live)
		}
		if hooks != nil && hooks.beforeRestore != nil {
			if err := hooks.beforeRestore(); err != nil {
				return fmt.Errorf("%w; restoration blocked: %w; retained failed=%s rollback=%s", cause, err, failed, rollback)
			}
		}
		if err := os.Rename(rollback, live); err != nil {
			return fmt.Errorf("%w; restoring rollback: %v; retained failed=%s rollback=%s", cause, err, failed, rollback)
		}
		restoredHash, err := TreeSHA256(live)
		if err != nil || restoredHash != oldHash {
			_ = os.Rename(live, rollback)
			return fmt.Errorf("%w; restored live verification failed: old=%s restored=%s: %v; retained failed=%s rollback=%s", cause, oldHash, restoredHash, err, failed, rollback)
		}
		return fmt.Errorf("%w; restored verified live=%s; retained failed=%s", cause, live, failed)
	}
	if hooks != nil && hooks.afterPublish != nil {
		if err := hooks.afterPublish(); err != nil {
			return recoverPublished(fmt.Errorf("after publish: %w", err))
		}
	}
	liveHash, err := TreeSHA256(live)
	if err != nil || liveHash != sourceHash {
		if liveExists {
			return recoverPublished(fmt.Errorf("verify published report: source=%s live=%s: %w", sourceHash, liveHash, err))
		}
		return fmt.Errorf("verify published report: source=%s live=%s: %w", sourceHash, liveHash, err)
	}
	if liveExists {
		if err := os.RemoveAll(rollback); err != nil {
			return fmt.Errorf("published report but could not remove rollback %s: %w", rollback, err)
		}
	}
	return nil
}

// TreeSHA256 returns a deterministic hash of a complete canonical report tree.
// A valid tree contains both server/index.json and clients/index.json.
func TreeSHA256(root string) (string, error) {
	if err := requireReport(root); err != nil {
		return "", err
	}
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing report symlink %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, _ = h.Write([]byte(filepath.ToSlash(rel)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func overlap(a, b string) bool {
	a, errA := filepath.Abs(filepath.Clean(a))
	b, errB := filepath.Abs(filepath.Clean(b))
	if errA != nil || errB != nil {
		return true
	}
	relAB, errAB := filepath.Rel(a, b)
	relBA, errBA := filepath.Rel(b, a)
	inside := func(rel string) bool {
		return rel == "." || (rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
	}
	return errAB != nil || errBA != nil || inside(relAB) || inside(relBA)
}

func requireReport(path string) error {
	for _, rel := range []string{"server/index.json", "clients/index.json"} {
		info, err := os.Stat(filepath.Join(path, rel))
		if err != nil {
			return fmt.Errorf("report %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("report %s %s is not a regular file", path, rel)
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing report symlink %s", path)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		inErr := in.Close()
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if inErr != nil {
			return inErr
		}
		return closeErr
	})
}
