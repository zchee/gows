package evidence

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePhase0PathNamesRejectsProductionChanges(t *testing.T) {
	allowed := []string{"README.md", ".github/workflows/bench.yml", "bench/harness/evidence/evaluate.go", ""}
	if err := validatePhase0PathNames(allowed); err != nil {
		t.Fatalf("allowed Phase 0 paths: %v", err)
	}
	for _, forbidden := range []string{"conn.go", "internal/mask/mask_amd64.s", "internal/utf8x/valid.go"} {
		if err := validatePhase0PathNames([]string{forbidden}); err == nil || !strings.Contains(err.Error(), forbidden) {
			t.Fatalf("path %q was not rejected precisely: %v", forbidden, err)
		}
	}
}

func TestValidateSourceAncestryQuarantinesDivergentAndHistoricalEvidence(t *testing.T) {
	root := t.TempDir()
	runTestGit(t, root, "init", "-b", "main")
	runTestGit(t, root, "config", "user.name", "Phase Zero Test")
	runTestGit(t, root, "config", "user.email", "phase0@example.invalid")

	writeTestFile(t, root, "README.md", "planning\n")
	runTestGit(t, root, "add", ".")
	runTestGit(t, root, "commit", "-m", "planning")
	planning := testGitOutput(t, root, "rev-parse", "HEAD")

	writeTestFile(t, root, "bench/harness.txt", "source\n")
	runTestGit(t, root, "add", ".")
	runTestGit(t, root, "commit", "-m", "source")
	source := testGitOutput(t, root, "rev-parse", "HEAD")
	writeTestFile(t, root, "bench/evidence/phase0/current/receipt.json", "{}\n")
	runTestGit(t, root, "add", ".")
	runTestGit(t, root, "commit", "-m", "evidence")
	current := testGitOutput(t, root, "rev-parse", "HEAD")
	if err := validateSourceAncestry(root, planning, source, current); err != nil {
		t.Fatalf("valid planning/source/current ancestry: %v", err)
	}

	runTestGit(t, root, "checkout", "-b", "divergent", planning)
	writeTestFile(t, root, "bench/divergent.txt", "divergent\n")
	runTestGit(t, root, "add", ".")
	runTestGit(t, root, "commit", "-m", "divergent")
	divergent := testGitOutput(t, root, "rev-parse", "HEAD")
	if err := validateSourceAncestry(root, planning, source, divergent); err == nil || !strings.Contains(err.Error(), "not an ancestor") {
		t.Fatalf("divergent current evidence was not quarantined: %v", err)
	}

	runTestGit(t, root, "checkout", "--orphan", "historical")
	runTestGit(t, root, "rm", "-rf", ".")
	writeTestFile(t, root, "historical.go", "package historical\n")
	runTestGit(t, root, "add", "-f", "historical.go")
	runTestGit(t, root, "commit", "-m", "historical")
	historical := testGitOutput(t, root, "rev-parse", "HEAD")
	if err := validateSourceAncestry(root, planning, historical, historical); err == nil || !strings.Contains(err.Error(), "does not descend") {
		t.Fatalf("non-ancestor historical source was not quarantined: %v", err)
	}
}

func TestValidateTrackedEvidenceStateRequiresExactRegularFiles(t *testing.T) {
	t.Run("receipt and final verdict", func(t *testing.T) {
		root := newEvidenceTestRepository(t)
		source := testGitOutput(t, root, "rev-parse", "HEAD")
		receipt := filepath.ToSlash(filepath.Join(EvidencePath, "receipt.json"))
		verdict := filepath.ToSlash(filepath.Join(EvidencePath, VerdictFile))
		writeTestFile(t, root, receipt, "{}\n")
		runTestGit(t, root, "add", receipt)
		runTestGit(t, root, "commit", "-m", "receipt")
		head := testGitOutput(t, root, "rev-parse", "HEAD")
		directory := filepath.Join(root, filepath.FromSlash(EvidencePath))
		if err := validateTrackedEvidenceState(root, head, directory, []string{receipt}, false); err != nil {
			t.Fatalf("receipt-only evidence: %v", err)
		}

		writeTestFile(t, root, verdict, "{}\n")
		runTestGit(t, root, "add", verdict)
		runTestGit(t, root, "commit", "-m", "verdict")
		head = testGitOutput(t, root, "rev-parse", "HEAD")
		if err := validateTrackedEvidenceState(root, head, directory, []string{receipt, verdict}, true); err != nil {
			t.Fatalf("final evidence: %v", err)
		}
		if err := validateSourceAncestry(root, source, source, head); err != nil {
			t.Fatalf("evidence commits must retain source ancestry: %v", err)
		}
	})

	t.Run("extra tracked Go source", func(t *testing.T) {
		root := newEvidenceTestRepository(t)
		receipt := filepath.ToSlash(filepath.Join(EvidencePath, "receipt.json"))
		extra := filepath.ToSlash(filepath.Join(EvidencePath, "escape.go"))
		writeTestFile(t, root, receipt, "{}\n")
		writeTestFile(t, root, extra, "package escape\n")
		runTestGit(t, root, "add", ".")
		runTestGit(t, root, "commit", "-m", "extra evidence source")
		head := testGitOutput(t, root, "rev-parse", "HEAD")
		directory := filepath.Join(root, filepath.FromSlash(EvidencePath))
		err := validateTrackedEvidenceState(root, head, directory, []string{receipt, extra}, false)
		if err == nil || !strings.Contains(err.Error(), "want exactly") {
			t.Fatalf("extra tracked Go source was not rejected: %v", err)
		}
	})

	t.Run("tracked receipt symlink", func(t *testing.T) {
		root := newEvidenceTestRepository(t)
		writeTestFile(t, root, "mutable.json", "{}\n")
		runTestGit(t, root, "add", "mutable.json")
		runTestGit(t, root, "commit", "-m", "mutable target")
		receipt := filepath.ToSlash(filepath.Join(EvidencePath, "receipt.json"))
		path := filepath.Join(root, filepath.FromSlash(receipt))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../../../mutable.json", path); err != nil {
			t.Fatal(err)
		}
		runTestGit(t, root, "add", receipt)
		runTestGit(t, root, "commit", "-m", "symlink receipt")
		head := testGitOutput(t, root, "rev-parse", "HEAD")
		directory := filepath.Join(root, filepath.FromSlash(EvidencePath))
		err := validateTrackedEvidenceState(root, head, directory, []string{receipt}, false)
		if err == nil || !strings.Contains(err.Error(), "100644") {
			t.Fatalf("tracked receipt symlink was not rejected: %v", err)
		}
	})

	t.Run("ignored extra file", func(t *testing.T) {
		root := newEvidenceTestRepository(t)
		receipt := filepath.ToSlash(filepath.Join(EvidencePath, "receipt.json"))
		writeTestFile(t, root, receipt, "{}\n")
		runTestGit(t, root, "add", receipt)
		runTestGit(t, root, "commit", "-m", "receipt")
		writeTestFile(t, root, ".git/info/exclude", EvidencePath+"/ignored.tmp\n")
		writeTestFile(t, root, EvidencePath+"/ignored.tmp", "ignored\n")
		head := testGitOutput(t, root, "rev-parse", "HEAD")
		directory := filepath.Join(root, filepath.FromSlash(EvidencePath))
		err := validateTrackedEvidenceState(root, head, directory, []string{receipt}, false)
		if err == nil || !strings.Contains(err.Error(), "directory files") {
			t.Fatalf("ignored extra evidence file was not rejected: %v", err)
		}
	})
}

func TestRequireRealDirectoryPathRejectsSymlinkedComponent(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "phase0", "current"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "bench")); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "bench", "phase0", "current")
	if err := requireRealDirectoryPath(root, directory); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("symlinked evidence path component was not rejected: %v", err)
	}
}

func newEvidenceTestRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runTestGit(t, root, "init", "-b", "main")
	runTestGit(t, root, "config", "user.name", "Phase Zero Test")
	runTestGit(t, root, "config", "user.email", "phase0@example.invalid")
	writeTestFile(t, root, "README.md", "source\n")
	runTestGit(t, root, "add", ".")
	runTestGit(t, root, "commit", "-m", "source")
	return root
}

func runTestGit(t *testing.T, root string, args ...string) {
	t.Helper()
	// Synthetic repositories must not inherit the developer's global commit
	// signing policy. The verification runner intentionally uses a minimal
	// tool environment, so an inherited commit.gpgsign=true would make fixtures
	// depend on an unrelated signing executable or key.
	commandArgs := append([]string{"-c", "commit.gpgsign=false"}, args...)
	command := exec.Command("git", commandArgs...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func testGitOutput(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(output))
}

func writeTestFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
