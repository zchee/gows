package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRejectsTamperedBlob(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "sample.jsonl")
	if err := os.WriteFile(source, []byte("{\"ok\":true}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref, err := store.PutFile(source, "application/x-ndjson")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := store.Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resolved, store.Root()) {
		t.Fatalf("resolved path %s is outside %s", resolved, store.Root())
	}
	if err := os.Chmod(resolved, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolved, []byte("tampered-data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(ref); err == nil {
		t.Fatal("Resolve accepted a tampered blob")
	}
}

func TestStorePutLeavesNoTemporaryFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("immutable\n")
	if _, err := store.PutBytes(data, "text/plain"); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutFile(source, "text/plain"); err != nil {
		t.Fatal(err)
	}

	patterns := []string{
		filepath.Join(store.Root(), ".bytes-*"),
		filepath.Join(store.Root(), "sha256", ".ingest-*"),
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("temporary artifacts remain for %s: %v", pattern, matches)
		}
	}
}

func TestRefRejectsIdentityMismatch(t *testing.T) {
	t.Parallel()

	sha := strings.Repeat("a", 64)
	ref := Ref{URI: uriPrefix + strings.Repeat("b", 64), SHA256: sha, MediaType: "application/json"}
	if err := ref.Validate(); err == nil {
		t.Fatal("Ref.Validate accepted mismatched URI and SHA")
	}
}

func TestStoreRejectsSymlinkedPathComponents(t *testing.T) {
	t.Run("ancestor component", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(parent, "alias")
		if err := os.Symlink(real, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(filepath.Join(alias, "artifacts", "phase0")); err == nil {
			t.Fatal("NewStore accepted a symlinked ancestor component")
		}
	})

	t.Run("repository .omx ancestor", func(t *testing.T) {
		root := t.TempDir()
		real := filepath.Join(root, "real-omx")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(root, ".omx")); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(filepath.Join(root, ".omx", "artifacts")); err == nil {
			t.Fatal("NewStore accepted a symlinked .omx ancestor")
		}
	})

	t.Run("store root", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "cas")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(link); err == nil {
			t.Fatal("NewStore accepted a symlinked store root")
		}
	})

	t.Run("sha256 root", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "cas")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		real := filepath.Join(parent, "real-sha256")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(root, "sha256")); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(root); err == nil {
			t.Fatal("NewStore accepted a symlinked sha256 root")
		}
	})

	t.Run("digest prefix on put", func(t *testing.T) {
		parent := t.TempDir()
		store, err := NewStore(filepath.Join(parent, "cas"))
		if err != nil {
			t.Fatal(err)
		}
		data := []byte("immutable\n")
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		real := filepath.Join(parent, "real-prefix")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(store.Root(), "sha256", digest[:2])); err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(parent, "source")
		if err := os.WriteFile(source, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PutFile(source, "text/plain"); err == nil {
			t.Fatal("PutFile accepted a symlinked digest prefix")
		}
	})

	t.Run("digest prefix on resolve", func(t *testing.T) {
		parent := t.TempDir()
		store, err := NewStore(filepath.Join(parent, "cas"))
		if err != nil {
			t.Fatal(err)
		}
		source := filepath.Join(parent, "source")
		data := []byte("immutable\n")
		if err := os.WriteFile(source, data, 0o644); err != nil {
			t.Fatal(err)
		}
		ref, err := store.PutFile(source, "text/plain")
		if err != nil {
			t.Fatal(err)
		}
		prefix := filepath.Join(store.Root(), "sha256", ref.SHA256[:2])
		real := filepath.Join(parent, "real-prefix")
		if err := os.Rename(prefix, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, prefix); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Resolve(ref); err == nil {
			t.Fatal("Resolve accepted a symlinked digest prefix")
		}
	})
}
