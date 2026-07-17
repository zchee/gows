package support

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// WriteJSONFile marshals v as indented, deterministically ordered JSON with a
// trailing newline and writes it to path atomically. The run directory's JSON
// artifacts (manifest.json, the env snapshots, done.json, verdict.json) funnel
// through it so they all share one format.
func WriteJSONFile(path string, v any) error {
	b, err := json.Marshal(v, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	b = append(b, '\n')
	return WriteFileAtomic(path, b, 0o644)
}

// WriteFileAtomic durably replaces path with data using a same-directory
// temporary file, fsync, rename, and parent-directory fsync. A crash therefore
// leaves either the previous complete artifact or the new complete artifact,
// never a truncated file with a final name.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) (resultErr error) {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	temporary := file.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if temporary != "" {
			if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temporary file for %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	closed = true
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("rename temporary file to %s: %w", path, err)
	}
	temporary = ""
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent directory for %s: %w", path, err)
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return fmt.Errorf("sync parent directory for %s: %w", path, err)
	}
	return nil
}

// WriteNewFileAtomic durably publishes data at path without ever replacing an
// existing file: the temporary file and its contents are synced, a
// same-directory hard link performs the atomic no-replace publication (an
// existing destination surfaces as a "destination already exists" error rather
// than being overwritten), and the parent directory is synced afterward. A
// crash therefore leaves either no published file or the complete new file,
// and the first publication always wins.
func WriteNewFileAtomic(path string, data []byte, mode os.FileMode) (resultErr error) {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("destination already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, file.Close())
		}
		if temporary != "" {
			if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("destination already exists: %s", path)
		}
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	temporary = ""
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
