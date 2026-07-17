// Package phase0 defines the handoff from the Phase 0 verification producer
// to the tracked evidence receipt producer.
package phase0

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/evidence"
)

const (
	ResultSchemaVersion = 1
	ResultFile          = "result.json"
)

// Result contains the immutable references produced by phase0verify. It does
// not duplicate raw artifacts; the tracked receipt producer resolves these
// references from the content-addressed artifact store.
type Result struct {
	SchemaVersion int                         `json:"schema_version"`
	Repository    evidence.RepositoryIdentity `json:"repository"`
	Verification  artifact.Ref                `json:"verification"`
	Assemblies    []evidence.AssemblyEvidence `json:"assemblies"`
}

// Validate rejects incomplete, duplicate, or target-mismatched handoffs.
func (result Result) Validate() error {
	if result.SchemaVersion != ResultSchemaVersion {
		return fmt.Errorf("phase0: result schema_version = %d, want %d", result.SchemaVersion, ResultSchemaVersion)
	}
	if err := evidence.ValidateRepositoryIdentity(result.Repository); err != nil {
		return err
	}
	if result.Verification.MediaType != artifact.MediaTypeDirectoryReceipt {
		return fmt.Errorf("phase0: verification receipt has media_type %q", result.Verification.MediaType)
	}
	if err := result.Verification.Validate(); err != nil {
		return fmt.Errorf("phase0: verification receipt: %w", err)
	}
	if len(result.Assemblies) != 2 {
		return fmt.Errorf("phase0: assembly receipts = %d, want 2", len(result.Assemblies))
	}
	seenDigests := map[string]string{result.Verification.SHA256: "verification"}
	for i, assembly := range result.Assemblies {
		// The exact-length check above plus this canonical per-index arch pin
		// already guarantee support, uniqueness, and completeness of the
		// amd64/arm64 pair, so no separate seen-set bookkeeping is needed.
		wantArch := []string{"amd64", "arm64"}[i]
		if assembly.GOARCH != wantArch {
			return fmt.Errorf("phase0: assemblies[%d] GOARCH = %q, want canonical %q", i, assembly.GOARCH, wantArch)
		}
		if assembly.GOOS != result.Repository.GOOS {
			return fmt.Errorf("phase0: assemblies[%d] GOOS = %q, want %q", i, assembly.GOOS, result.Repository.GOOS)
		}
		if assembly.Bundle.MediaType != artifact.MediaTypeDirectoryReceipt {
			return fmt.Errorf("phase0: assemblies[%d] has media_type %q", i, assembly.Bundle.MediaType)
		}
		if err := assembly.Bundle.Validate(); err != nil {
			return fmt.Errorf("phase0: assemblies[%d]: %w", i, err)
		}
		if previous, ok := seenDigests[assembly.Bundle.SHA256]; ok {
			return fmt.Errorf("phase0: assemblies[%d] reuses %s receipt", i, previous)
		}
		seenDigests[assembly.Bundle.SHA256] = "assembly " + assembly.GOARCH
	}
	return nil
}

// Marshal validates result and returns its deterministic JSON representation.
func Marshal(result Result) ([]byte, error) {
	result.Assemblies = slices.Clone(result.Assemblies)
	slices.SortFunc(result.Assemblies, func(a, b evidence.AssemblyEvidence) int {
		return strings.Compare(a.GOARCH, b.GOARCH)
	})
	if err := result.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, fmt.Errorf("phase0: marshal result: %w", err)
	}
	return append(raw, '\n'), nil
}

// Load strictly decodes and validates a producer result.
func Load(path string) (Result, error) {
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "INVALIDATED.json")); err == nil {
		return Result{}, errors.New("phase0: result directory is invalidated")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Result{}, fmt.Errorf("phase0: inspect result invalidation marker: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("phase0: read result: %w", err)
	}
	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	var result Result
	if err := json.UnmarshalDecode(decoder, &result, json.RejectUnknownMembers(true)); err != nil {
		return Result{}, fmt.Errorf("phase0: parse result: %w", err)
	}
	if _, err := decoder.ReadToken(); !errors.Is(err, io.EOF) {
		if err == nil {
			return Result{}, errors.New("phase0: result contains trailing JSON")
		}
		return Result{}, fmt.Errorf("phase0: trailing result data: %w", err)
	}
	if err := result.Validate(); err != nil {
		return Result{}, err
	}
	return result, nil
}
