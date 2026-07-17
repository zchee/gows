// Package artifact implements the benchmark harness's local immutable,
// content-addressed evidence store and compact run receipts.
package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zchee/gows/bench/harness/support"
)

const uriPrefix = "omx-cas://sha256/"

// MediaTypeRunReceipt identifies a sealed benchrun run receipt in the
// content-addressed store. Every producer and validator of run receipts
// references this one definition so the recorded media type cannot drift.
const MediaTypeRunReceipt = "application/vnd.gows.bench-run-receipt+json"

// MediaTypeDirectoryReceipt identifies a sealed immutable-directory receipt
// (verification and assembly bundles) in the content-addressed store.
const MediaTypeDirectoryReceipt = "application/vnd.gows.directory-receipt+json"

// Ref is an immutable content-addressed artifact reference.
type Ref struct {
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
}

// Store resolves omx-cas references below one local root.
type Store struct {
	root   string
	anchor string
}

func NewStore(root string) (Store, error) {
	if root == "" {
		return Store{}, fmt.Errorf("artifact: store root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Store{}, fmt.Errorf("artifact: absolute store root: %w", err)
	}
	absolute, anchor, err := createSecureDirectoryTree(absolute)
	if err != nil {
		return Store{}, fmt.Errorf("artifact: store root: %w", err)
	}
	if err := requireRealDirectoryFrom(anchor, filepath.Join(absolute, "sha256"), true); err != nil {
		return Store{}, fmt.Errorf("artifact: digest root: %w", err)
	}
	return Store{root: absolute, anchor: anchor}, nil
}

func (store Store) Root() string { return store.root }

// PutBytes stores an in-memory deterministic artifact without requiring the
// caller to manage a temporary file. The bytes are first synced below the
// store root and then ingested through the same verified path as PutFile.
func (store Store) PutBytes(data []byte, mediaType string) (_ Ref, resultErr error) {
	if err := requireRealDirectoryFrom(store.anchor, store.root, false); err != nil {
		return Ref{}, fmt.Errorf("artifact: store root: %w", err)
	}
	temporary, err := os.CreateTemp(store.root, ".bytes-*")
	if err != nil {
		return Ref{}, fmt.Errorf("artifact: create bytes source: %w", err)
	}
	path := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, temporary.Close())
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("artifact: remove bytes source: %w", err))
		}
	}()
	if _, err := io.Copy(temporary, bytes.NewReader(data)); err != nil {
		return Ref{}, fmt.Errorf("artifact: write bytes source: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return Ref{}, fmt.Errorf("artifact: sync bytes source: %w", err)
	}
	closeErr := temporary.Close()
	closed = true
	if closeErr != nil {
		return Ref{}, fmt.Errorf("artifact: close bytes source: %w", closeErr)
	}
	return store.PutFile(path, mediaType)
}

// PutFile copies path into the store and returns its immutable reference.
func (store Store) PutFile(path, mediaType string) (_ Ref, resultErr error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Ref{}, fmt.Errorf("artifact: stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return Ref{}, fmt.Errorf("artifact: %s is not a regular file", path)
	}
	source, err := os.Open(path)
	if err != nil {
		return Ref{}, fmt.Errorf("artifact: open %s: %w", path, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, source.Close())
	}()

	temporaryDir := filepath.Join(store.root, "sha256")
	if err := requireRealDirectoryFrom(store.anchor, temporaryDir, false); err != nil {
		return Ref{}, fmt.Errorf("artifact: digest root: %w", err)
	}
	temporary, err := os.CreateTemp(temporaryDir, ".ingest-*")
	if err != nil {
		return Ref{}, fmt.Errorf("artifact: create ingest file: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, temporary.Close())
		}
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("artifact: remove ingest file: %w", err))
		}
	}()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(temporary, hash), source)
	if err != nil {
		return Ref{}, fmt.Errorf("artifact: ingest %s: %w", path, err)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if err := temporary.Chmod(0o444); err != nil {
		return Ref{}, fmt.Errorf("artifact: chmod ingest %s: %w", path, err)
	}
	if err := temporary.Sync(); err != nil {
		return Ref{}, fmt.Errorf("artifact: sync ingest %s: %w", path, err)
	}
	closeErr := temporary.Close()
	closed = true
	if closeErr != nil {
		return Ref{}, fmt.Errorf("artifact: close ingest %s: %w", path, closeErr)
	}

	targetDir := filepath.Join(store.root, "sha256", digest[:2])
	if err := requireRealDirectoryFrom(store.anchor, targetDir, true); err != nil {
		return Ref{}, fmt.Errorf("artifact: create digest directory: %w", err)
	}
	target := filepath.Join(targetDir, digest)
	if err := os.Link(temporaryPath, target); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return Ref{}, fmt.Errorf("artifact: install %s: %w", digest, err)
		}
		if err := verifyFile(target, digest, size); err != nil {
			return Ref{}, err
		}
	}
	directory, err := os.Open(targetDir)
	if err != nil {
		return Ref{}, fmt.Errorf("artifact: open digest directory: %w", err)
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return Ref{}, fmt.Errorf("artifact: sync digest directory: %w", err)
	}
	return Ref{URI: uriPrefix + digest, SHA256: digest, SizeBytes: size, MediaType: mediaType}, nil
}

// Resolve verifies ref and returns the local immutable blob path.
func (store Store) Resolve(ref Ref) (string, error) {
	if err := ref.Validate(); err != nil {
		return "", err
	}
	path := filepath.Join(store.root, "sha256", ref.SHA256[:2], ref.SHA256)
	if err := requireRealDirectoryFrom(store.anchor, filepath.Dir(path), false); err != nil {
		return "", fmt.Errorf("artifact: digest directory: %w", err)
	}
	if err := verifyFile(path, ref.SHA256, ref.SizeBytes); err != nil {
		return "", err
	}
	return path, nil
}

func createSecureDirectoryTree(path string) (directory, anchor string, resultErr error) {
	base, err := stablePathBase(path)
	if err != nil {
		return "", "", err
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", "", fmt.Errorf("resolve stable path base %s: %w", base, err)
	}
	relative, err := filepath.Rel(base, path)
	if err != nil || (relative != "." && !filepath.IsLocal(relative)) {
		return "", "", fmt.Errorf("store root %s is not below stable path base %s", path, base)
	}
	directory = filepath.Clean(filepath.Join(resolvedBase, relative))
	anchor = filepath.Clean(resolvedBase)
	if err := requireRealDirectoryFrom(anchor, directory, true); err != nil {
		return "", "", err
	}
	return directory, anchor, nil
}

func stablePathBase(path string) (string, error) {
	path = filepath.Clean(path)
	candidates := []string{filepath.VolumeName(path) + string(filepath.Separator)}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if temporary := os.TempDir(); temporary != "" {
		candidates = append(candidates, temporary)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home)
	}
	best := ""
	for _, candidate := range candidates {
		candidate, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(candidate, path)
		if err != nil || (relative != "." && !filepath.IsLocal(relative)) {
			continue
		}
		if len(candidate) > len(best) {
			best = candidate
		}
	}
	if best == "" {
		return "", fmt.Errorf("cannot select a stable path base for %s", path)
	}
	info, err := os.Stat(best)
	if err != nil {
		return "", fmt.Errorf("stat stable path base %s: %w", best, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("stable path base %s is not a directory", best)
	}
	return filepath.Clean(best), nil
}

func requireRealDirectoryFrom(anchor, directory string, create bool) error {
	anchor = filepath.Clean(anchor)
	directory = filepath.Clean(directory)
	relative, err := filepath.Rel(anchor, directory)
	if err != nil || (relative != "." && !filepath.IsLocal(relative)) {
		return fmt.Errorf("%s is not below directory anchor %s", directory, anchor)
	}
	current := anchor
	components := []string(nil)
	if relative != "." {
		components = strings.Split(relative, string(filepath.Separator))
	}
	for index := -1; index < len(components); index++ {
		if index >= 0 {
			current = filepath.Join(current, components[index])
		}
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) && create && index >= 0 {
			if mkdirErr := os.Mkdir(current, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%s is not a real directory", current)
		}
	}
	return nil
}

func (ref Ref) Validate() error {
	if !support.ValidSHA256(ref.SHA256) {
		return fmt.Errorf("artifact: invalid SHA-256 %q", ref.SHA256)
	}
	if ref.URI != uriPrefix+ref.SHA256 {
		return fmt.Errorf("artifact: URI %q does not match SHA-256 %s", ref.URI, ref.SHA256)
	}
	if ref.SizeBytes < 0 {
		return fmt.Errorf("artifact: negative size %d", ref.SizeBytes)
	}
	if ref.MediaType == "" {
		return fmt.Errorf("artifact: media_type is required")
	}
	return nil
}

func verifyFile(path, wantDigest string, wantSize int64) (resultErr error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("artifact: resolve %s: %w", wantDigest, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact: resolved path %s is not a regular file", path)
	}
	if info.Size() != wantSize {
		return fmt.Errorf("artifact: blob %s size = %d, want %d", wantDigest, info.Size(), wantSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("artifact: open blob %s: %w", wantDigest, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
	}()
	opened, err := file.Stat()
	if err != nil {
		return fmt.Errorf("artifact: stat opened blob %s: %w", wantDigest, err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return fmt.Errorf("artifact: blob %s changed identity while opening", wantDigest)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("artifact: hash blob %s: %w", wantDigest, err)
	}
	got := hex.EncodeToString(hash.Sum(nil))
	if got != wantDigest {
		return fmt.Errorf("artifact: blob digest = %s, want %s", got, wantDigest)
	}
	return nil
}
