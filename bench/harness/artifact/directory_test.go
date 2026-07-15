package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryReceiptRoundTrip(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewStore(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle")
	if err := os.MkdirAll(filepath.Join(bundle, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifest.json"), []byte("{}\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "nested", "raw.txt"), []byte("evidence\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	want, ref, err := SealDirectory(store, bundle, "assembly/darwin-arm64", []string{"manifest.json", "nested/raw.txt"})
	if err != nil {
		t.Fatal(err)
	}
	got, paths, err := ResolveDirectory(store, ref, want.Kind)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != len(want.Files) || len(paths) != 2 {
		t.Fatalf("resolved files = %d/%d, want 2", len(got.Files), len(paths))
	}
	materialized := filepath.Join(root, "materialized")
	if err := MaterializeDirectory(paths, materialized); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(materialized, "nested", "raw.txt"))
	if err != nil || string(data) != "evidence\n" {
		t.Fatalf("materialized data = %q, err=%v", data, err)
	}
}

func TestSealDirectoryFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	store, err := NewStore(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "bundle")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifest.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SealDirectory(store, bundle, "test", []string{"missing.json"}); err == nil {
		t.Fatal("SealDirectory accepted a missing required file")
	}
	if err := os.WriteFile(filepath.Join(bundle, "INVALIDATED.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SealDirectory(store, bundle, "test", nil); err == nil {
		t.Fatal("SealDirectory accepted an invalidated bundle")
	}
}
