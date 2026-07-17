package artifact

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-json-experiment/json"
)

const DirectoryReceiptSchemaVersion = 1

// DirectoryReceipt resolves every file in a strict immutable evidence bundle.
// Kind separates assembly, verification, and future bundle contracts even
// when two bundles happen to contain the same filenames.
type DirectoryReceipt struct {
	SchemaVersion int            `json:"schema_version"`
	Kind          string         `json:"kind"`
	Files         map[string]Ref `json:"files"`
}

// SealDirectory stores every regular file below dir and returns a compact
// receipt plus its own immutable CAS reference. Symlinks, invalidation markers,
// temporary files, missing required files, and empty bundles fail closed.
func SealDirectory(store Store, dir, kind string, required []string) (DirectoryReceipt, Ref, error) {
	if kind == "" || strings.TrimSpace(kind) != kind || strings.ContainsAny(kind, "\r\n\t") {
		return DirectoryReceipt{}, Ref{}, fmt.Errorf("artifact: valid directory receipt kind is required")
	}
	if _, err := os.Stat(filepath.Join(dir, "INVALIDATED.json")); err == nil {
		return DirectoryReceipt{}, Ref{}, fmt.Errorf("artifact: refusing invalidated bundle %s", dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return DirectoryReceipt{}, Ref{}, fmt.Errorf("artifact: inspect bundle invalidation marker: %w", err)
	}

	var names []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == dir || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact: symlink is forbidden in directory bundle: %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("artifact: non-regular directory artifact: %s", path)
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.Contains(filepath.Base(relative), ".tmp-") {
			return fmt.Errorf("artifact: temporary file is forbidden in directory bundle: %s", relative)
		}
		names = append(names, relative)
		return nil
	})
	if err != nil {
		return DirectoryReceipt{}, Ref{}, err
	}
	if len(names) == 0 {
		return DirectoryReceipt{}, Ref{}, fmt.Errorf("artifact: directory bundle %s is empty", dir)
	}
	slices.Sort(names)
	present := make(map[string]bool, len(names))
	files := make(map[string]Ref, len(names))
	for _, name := range names {
		present[name] = true
		ref, err := store.PutFile(filepath.Join(dir, filepath.FromSlash(name)), mediaType(name))
		if err != nil {
			return DirectoryReceipt{}, Ref{}, fmt.Errorf("artifact: seal %s: %w", name, err)
		}
		files[name] = ref
	}
	for _, name := range required {
		if validateArtifactName(name) != nil || !present[name] {
			return DirectoryReceipt{}, Ref{}, fmt.Errorf("artifact: directory bundle lacks required file %q", name)
		}
	}
	receipt := DirectoryReceipt{SchemaVersion: DirectoryReceiptSchemaVersion, Kind: kind, Files: files}
	if err := receipt.Validate(); err != nil {
		return DirectoryReceipt{}, Ref{}, err
	}
	raw, err := json.Marshal(receipt, json.Deterministic(true))
	if err != nil {
		return DirectoryReceipt{}, Ref{}, fmt.Errorf("artifact: marshal directory receipt: %w", err)
	}
	raw = append(raw, '\n')
	ref, err := store.PutBytes(raw, MediaTypeDirectoryReceipt)
	if err != nil {
		return DirectoryReceipt{}, Ref{}, err
	}
	return receipt, ref, nil
}

func (receipt DirectoryReceipt) Validate() error {
	if receipt.SchemaVersion != DirectoryReceiptSchemaVersion {
		return fmt.Errorf("artifact: directory receipt schema_version = %d, want %d", receipt.SchemaVersion, DirectoryReceiptSchemaVersion)
	}
	if receipt.Kind == "" || strings.TrimSpace(receipt.Kind) != receipt.Kind || strings.ContainsAny(receipt.Kind, "\r\n\t") {
		return fmt.Errorf("artifact: invalid directory receipt kind %q", receipt.Kind)
	}
	if len(receipt.Files) == 0 {
		return fmt.Errorf("artifact: directory receipt has no files")
	}
	for name, ref := range receipt.Files {
		if err := validateArtifactName(name); err != nil {
			return fmt.Errorf("artifact: invalid directory artifact name %q", name)
		}
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("artifact: %s: %w", name, err)
		}
		if want := mediaType(name); ref.MediaType != want {
			return fmt.Errorf("artifact: %s media_type = %q, want %q", name, ref.MediaType, want)
		}
	}
	return nil
}

// ResolveDirectory verifies both the receipt blob and every referenced file.
func ResolveDirectory(store Store, receiptRef Ref, wantKind string) (DirectoryReceipt, map[string]string, error) {
	if receiptRef.MediaType != MediaTypeDirectoryReceipt {
		return DirectoryReceipt{}, nil, fmt.Errorf("artifact: directory receipt media_type = %q", receiptRef.MediaType)
	}
	path, err := store.Resolve(receiptRef)
	if err != nil {
		return DirectoryReceipt{}, nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return DirectoryReceipt{}, nil, fmt.Errorf("artifact: read directory receipt: %w", err)
	}
	var receipt DirectoryReceipt
	if err := decodeStrictJSON(raw, &receipt); err != nil {
		return DirectoryReceipt{}, nil, fmt.Errorf("artifact: parse directory receipt: %w", err)
	}
	if err := receipt.Validate(); err != nil {
		return DirectoryReceipt{}, nil, err
	}
	if receipt.Kind != wantKind {
		return DirectoryReceipt{}, nil, fmt.Errorf("artifact: directory receipt kind = %q, want %q", receipt.Kind, wantKind)
	}
	resolved := make(map[string]string, len(receipt.Files))
	for name, ref := range receipt.Files {
		path, err := store.Resolve(ref)
		if err != nil {
			return DirectoryReceipt{}, nil, fmt.Errorf("artifact: resolve %s: %w", name, err)
		}
		resolved[name] = path
	}
	return receipt, resolved, nil
}

// MaterializeDirectory copies verified CAS blobs into a new read-only bundle
// directory. It never overwrites an existing destination.
func MaterializeDirectory(paths map[string]string, destination string) (resultErr error) {
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("artifact: materialize destination already exists: %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".materialize-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(temporary); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("artifact: clean materialization: %w", err))
		}
	}()
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := validateArtifactName(name); err != nil {
			return fmt.Errorf("artifact: invalid materialized path %q", name)
		}
		target := filepath.Join(temporary, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		source, err := os.Open(paths[name])
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444)
		if err != nil {
			return errors.Join(err, source.Close())
		}
		_, copyErr := io.Copy(output, source)
		closeErr := errors.Join(source.Close(), output.Sync(), output.Close())
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	return nil
}
