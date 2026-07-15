package support

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// WriteJSONFile marshals v as indented JSON with a trailing newline and writes
// it to path. It is the one serialization point for every JSON artifact a run
// directory records (meta.json, the env snapshots, done.json, verdict.json),
// so they all share one format.
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
