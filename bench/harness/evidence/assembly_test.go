package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/zchee/gows/bench/harness/assembly"
)

func TestValidateAssemblySourcesBindsSelectedBytesToSourceCommit(t *testing.T) {
	root := t.TempDir()
	runTestGit(t, root, "init", "-b", "main")
	runTestGit(t, root, "config", "user.name", "Phase Zero Test")
	runTestGit(t, root, "config", "user.email", "phase0@example.invalid")
	const path = "internal/mask/mask_arm64.s"
	const source = "TEXT maskNEON(SB), NOSPLIT, $0-0\nRET\n"
	writeTestFile(t, root, path, source)
	runTestGit(t, root, "add", ".")
	runTestGit(t, root, "commit", "-m", "assembly source")
	revision := testGitOutput(t, root, "rev-parse", "HEAD")
	sum := sha256.Sum256([]byte(source))
	manifest := assembly.Manifest{
		Target: assembly.Target{GOARCH: "arm64"},
		Packages: []assembly.PackageProvenance{{
			ImportPath: "github.com/zchee/gows/internal/mask",
			SelectedFiles: []assembly.SourceFile{{
				Path: path, Kind: "assembly", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(source)),
			}},
		}},
	}
	if err := validateAssemblySources(root, revision, manifest); err != nil {
		t.Fatalf("exact selected source: %v", err)
	}
	manifest.Packages[0].SelectedFiles[0].SHA256 = strings.Repeat("0", 64)
	if err := validateAssemblySources(root, revision, manifest); err == nil {
		t.Fatal("assembly source hash mismatch was accepted")
	}
}
