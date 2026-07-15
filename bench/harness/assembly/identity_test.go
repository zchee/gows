package assembly

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSourceIdentityPathsExcludesOnlyCurrentReceiptSubtree(t *testing.T) {
	paths := []string{
		"bench/evidence/phase0/current",
		"bench/evidence/phase0/current/receipt.json",
		"bench/evidence/phase0/currently/receipt.json",
		"bench/evidence/phase0/history/receipt.json",
		"internal/mask/mask_amd64.s",
	}
	want := []string{
		"bench/evidence/phase0/current",
		"bench/evidence/phase0/currently/receipt.json",
		"bench/evidence/phase0/history/receipt.json",
		"internal/mask/mask_amd64.s",
	}
	if got := sourceIdentityPaths(paths); !slices.Equal(got, want) {
		t.Fatalf("sourceIdentityPaths() = %v, want %v", got, want)
	}
}

func TestCanonicalRelativePathRejectsAliasesAndEscapes(t *testing.T) {
	valid := []string{
		"go.mod",
		"internal/mask/mask_amd64.s",
		"bench/internal/thirdparty/coder/mask.go",
	}
	for _, name := range valid {
		if err := validateCanonicalRelativePath(name); err != nil {
			t.Errorf("validateCanonicalRelativePath(%q) error = %v", name, err)
		}
	}
	invalid := []string{
		"",
		".",
		"..",
		"../go.mod",
		"internal/../go.mod",
		"./go.mod",
		"internal//mask.go",
		"internal\\mask.go",
		"/absolute/path",
	}
	for _, name := range invalid {
		if err := validateCanonicalRelativePath(name); err == nil {
			t.Errorf("validateCanonicalRelativePath(%q) unexpectedly succeeded", name)
		}
	}
}

func TestSHA256IdentityRequiresLowercaseCanonicalHex(t *testing.T) {
	if !validSHA256(strings.Repeat("ab", 32)) {
		t.Fatal("lowercase SHA-256 rejected")
	}
	for _, value := range []string{
		strings.Repeat("AB", 32),
		strings.Repeat("0", 63),
		strings.Repeat("g", 64),
	} {
		if validSHA256(value) {
			t.Errorf("invalid SHA-256 %q accepted", value)
		}
	}
}

func TestRepositoryTreeHashBindsPathAndContent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "source.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := hashRepositoryTree(root, []string{"a/source.go"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "source.go"), []byte("package changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	contentChanged, err := hashRepositoryTree(root, []string{"a/source.go"})
	if err != nil {
		t.Fatal(err)
	}
	if first == contentChanged {
		t.Fatal("repository tree hash did not change with content")
	}
	if err := os.Rename(filepath.Join(root, "a", "source.go"), filepath.Join(root, "a", "renamed.go")); err != nil {
		t.Fatal(err)
	}
	pathChanged, err := hashRepositoryTree(root, []string{"a/renamed.go"})
	if err != nil {
		t.Fatal(err)
	}
	if contentChanged == pathChanged {
		t.Fatal("repository tree hash did not change with path")
	}
}
