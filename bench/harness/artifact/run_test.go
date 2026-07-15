package artifact

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-json-experiment/json"
)

func TestRunReceiptRoundTripBindsExpandedIdentity(t *testing.T) {
	t.Parallel()

	runDir, store := writeTestRun(t)
	want, ref, err := SealRun(store, runDir)
	if err != nil {
		t.Fatal(err)
	}
	got, paths, err := ResolveRun(store, ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != RunReceiptSchemaVersion || got.SourceHead != strings.Repeat("1", 40) || got.ModulePath != "github.com/zchee/gows" {
		t.Fatalf("resolved identity = %#v", got)
	}
	if len(paths) != len(want.Files) {
		t.Fatalf("resolved files = %d, want %d", len(paths), len(want.Files))
	}

	forged := got
	forged.SourceSHA256 = strings.Repeat("f", 64)
	raw, err := json.Marshal(forged, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	forgedRef, err := store.PutBytes(append(raw, '\n'), "application/vnd.gows.bench-run-receipt+json")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveRun(store, forgedRef); err == nil || !strings.Contains(err.Error(), "disagrees with resolved manifest") {
		t.Fatalf("ResolveRun forged header error = %v", err)
	}
}

func TestRunReceiptRejectsInvalidatedMediaAndNoncanonicalEntries(t *testing.T) {
	t.Parallel()

	runDir, store := writeTestRun(t)
	receipt, _, err := SealRun(store, runDir)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*RunReceipt){
		"invalidation marker": func(r *RunReceipt) {
			r.Files["INVALIDATED.json"] = r.Files["policy.json"]
		},
		"wrong media type": func(r *RunReceipt) {
			ref := r.Files["policy.json"]
			ref.MediaType = "text/plain"
			r.Files["policy.json"] = ref
		},
		"noncanonical path": func(r *RunReceipt) {
			r.Files[`logs\sample.log`] = r.Files["policy.json"]
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			got := cloneRunReceipt(receipt)
			mutate(&got)
			if err := got.Validate(); err == nil {
				t.Fatalf("Validate accepted %s", name)
			}
		})
	}
}

func TestLoadRunReceiptRejectsUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()

	runDir, store := writeTestRun(t)
	_, _, err := SealRun(store, runDir)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(runDir, "receipt.json")
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string][]byte{
		"trailing value": append(append([]byte(nil), raw...), []byte("{}\n")...),
		"unknown field":  []byte(strings.Replace(string(raw), "\"schema_version\": 2,", "\"schema_version\": 2, \"unknown\": true,", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipt.json")
			if err := os.WriteFile(path, mutated, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRunReceipt(path); err == nil {
				t.Fatalf("LoadRunReceipt accepted %s", name)
			}
		})
	}
}

func writeTestRun(t *testing.T) (string, Store) {
	t.Helper()
	root := t.TempDir()
	store, err := NewStore(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, "run")
	if err := os.Mkdir(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"policy.json":    []byte("{\"schema_version\":2}\n"),
		"env-start.json": []byte("{}\n"),
		"env-end.json":   []byte("{}\n"),
		"samples.jsonl":  {},
		"done.json":      []byte("{}\n"),
		"echoserver":     []byte("echo-binary"),
		"loadgen":        []byte("load-binary"),
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(runDir, name), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	policySum := fmt.Sprintf("%x", sha256.Sum256(files["policy.json"]))
	echoSum := fmt.Sprintf("%x", sha256.Sum256(files["echoserver"]))
	loadSum := fmt.Sprintf("%x", sha256.Sum256(files["loadgen"]))
	digest := strings.Repeat("a", 64)
	manifest := map[string]any{
		"schema_version": 2, "session_id": "session-test", "git_commit": strings.Repeat("1", 40),
		"git_remote": "git@github.com:zchee/gows.git", "git_branch": "fastest-claude", "git_status": "", "git_dirty": false,
		"git_tree": strings.Repeat("2", 40), "source_sha256": digest,
		"module_path": "github.com/zchee/gows", "module_files_sha256": digest,
		"go_version": "go1.26.5", "go_binary_sha256": digest, "goos": "darwin", "goarch": "arm64", "go_experiment": "",
		"client": "gows", "echoserver_sha256": echoSum, "loadgen_sha256": loadSum,
		"adapter_sha256":          map[string]string{"candidate": digest, "comparator": digest},
		"library_binaries_sha256": map[string]string{"candidate": echoSum, "comparator": echoSum},
		"policy_sha256":           policySum, "run_kind": "aa", "evidence_class": "self-validation", "toolchain_series": "stock",
		"full_provenance": map[string]any{"intentionally": "outside artifact identity projection"},
	}
	rawManifest, err := json.Marshal(manifest, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), append(rawManifest, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return runDir, store
}

func cloneRunReceipt(receipt RunReceipt) RunReceipt {
	clone := receipt
	clone.Files = make(map[string]Ref, len(receipt.Files))
	for name, ref := range receipt.Files {
		clone.Files[name] = ref
	}
	clone.AdapterSHA256 = make(map[string]string, len(receipt.AdapterSHA256))
	for name, digest := range receipt.AdapterSHA256 {
		clone.AdapterSHA256[name] = digest
	}
	clone.LibraryBinarySHA256 = make(map[string]string, len(receipt.LibraryBinarySHA256))
	for name, digest := range receipt.LibraryBinarySHA256 {
		clone.LibraryBinarySHA256[name] = digest
	}
	return clone
}
