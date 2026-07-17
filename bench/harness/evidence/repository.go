package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/zchee/gows/bench/harness/support"
)

type RepositoryState struct {
	Root string
}

// CollectRepositoryIdentity captures the clean current implementation source
// using the same formulas later enforced by the evaluator. It accepts only the
// expected repository, branch, plan lineage, Phase 0 path allowlist, stock Go
// tool, and native controller target.
func CollectRepositoryIdentity(root string) (RepositoryIdentity, error) {
	root, err := normalizeRepositoryRoot(root)
	if err != nil {
		return RepositoryIdentity{}, err
	}
	if err := validatePlan(root, PlanSHA256); err != nil {
		return RepositoryIdentity{}, err
	}
	remote, branch, status, err := checkoutIdentity(root)
	if err != nil {
		return RepositoryIdentity{}, err
	}
	if status != "" {
		return RepositoryIdentity{}, fmt.Errorf("evidence: dirty worktree rejected: %s", strings.ReplaceAll(status, "\n", "; "))
	}
	if remote != ExpectedRemote {
		return RepositoryIdentity{}, fmt.Errorf("evidence: repository remote = %q, want %q", remote, ExpectedRemote)
	}
	if branch != ExpectedBranch {
		return RepositoryIdentity{}, fmt.Errorf("evidence: repository branch = %q, want %q", branch, ExpectedBranch)
	}
	head, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return RepositoryIdentity{}, err
	}
	if err := validateSourceAncestry(root, PlanningHead, head, head); err != nil {
		return RepositoryIdentity{}, err
	}
	if err := validatePhase0SourcePaths(root, PlanningHead, head); err != nil {
		return RepositoryIdentity{}, err
	}
	tree, sourceSum, moduleSum, err := sourceIdentity(root, head)
	if err != nil {
		return RepositoryIdentity{}, err
	}
	goVersion, goSum, goSize, err := stockGoIdentity()
	if err != nil {
		return RepositoryIdentity{}, err
	}
	identity := RepositoryIdentity{
		PlanSHA256: PlanSHA256, Remote: remote, Branch: branch,
		SourceHead: head, SourceTree: tree, SourceSHA256: sourceSum,
		ModulePath: "github.com/zchee/gows", ModuleFilesSHA256: moduleSum,
		GoVersion: goVersion, GoBinarySHA256: goSum, GoBinarySizeBytes: goSize,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, EvidencePath: EvidencePath,
	}
	if err := identity.validate(); err != nil {
		return RepositoryIdentity{}, err
	}
	return identity, nil
}

// ValidateRepository proves that the evaluator is running in the intended
// clean checkout and that every post-measurement commit changes only the
// tracked Phase 0 receipt/verdict directory.
func ValidateRepository(evidenceDir string, identity RepositoryIdentity, requireTrackedVerdict bool) (RepositoryState, error) {
	if err := identity.validate(); err != nil {
		return RepositoryState{}, err
	}
	root, err := gitOutput("", "rev-parse", "--show-toplevel")
	if err != nil {
		return RepositoryState{}, err
	}
	root, err = normalizeRepositoryRoot(root)
	if err != nil {
		return RepositoryState{}, err
	}
	wantDir := filepath.Join(root, filepath.FromSlash(EvidencePath))
	gotDir, err := filepath.Abs(evidenceDir)
	if err != nil {
		return RepositoryState{}, fmt.Errorf("evidence: absolute evidence directory: %w", err)
	}
	if gotDir != wantDir {
		return RepositoryState{}, fmt.Errorf("evidence: evaluator directory = %s, want %s", gotDir, wantDir)
	}
	if err := validatePlan(root, identity.PlanSHA256); err != nil {
		return RepositoryState{}, err
	}

	remote, branch, status, err := checkoutIdentity(root)
	if err != nil {
		return RepositoryState{}, err
	}
	if status != "" {
		return RepositoryState{}, fmt.Errorf("evidence: dirty worktree rejected: %s", strings.ReplaceAll(status, "\n", "; "))
	}
	if remote != identity.Remote {
		return RepositoryState{}, fmt.Errorf("evidence: repository remote = %q, want %q", remote, identity.Remote)
	}
	if branch != identity.Branch {
		return RepositoryState{}, fmt.Errorf("evidence: repository branch = %q, want %q", branch, identity.Branch)
	}
	head, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return RepositoryState{}, err
	}
	if err := validateSourceAncestry(root, PlanningHead, identity.SourceHead, head); err != nil {
		return RepositoryState{}, err
	}
	if err := validatePhase0SourcePaths(root, PlanningHead, identity.SourceHead); err != nil {
		return RepositoryState{}, err
	}

	tree, sourceSum, moduleSum, err := sourceIdentity(root, identity.SourceHead)
	if err != nil {
		return RepositoryState{}, err
	}
	if tree != identity.SourceTree {
		return RepositoryState{}, fmt.Errorf("evidence: source tree = %s, want %s", tree, identity.SourceTree)
	}
	if sourceSum != identity.SourceSHA256 {
		return RepositoryState{}, fmt.Errorf("evidence: source SHA-256 = %s, want %s", sourceSum, identity.SourceSHA256)
	}
	if moduleSum != identity.ModuleFilesSHA256 {
		return RepositoryState{}, fmt.Errorf("evidence: module files SHA-256 = %s, want %s", moduleSum, identity.ModuleFilesSHA256)
	}

	diff, err := gitOutput(root, "diff", "--name-only", "--diff-filter=ACDMRTUXB", identity.SourceHead+".."+head)
	if err != nil {
		return RepositoryState{}, err
	}
	if err := validateTrackedEvidenceState(root, head, gotDir, strings.Split(diff, "\n"), requireTrackedVerdict); err != nil {
		return RepositoryState{}, err
	}
	currentVersion, currentSum, currentSize, err := stockGoIdentity()
	if err != nil {
		return RepositoryState{}, err
	}
	if currentVersion != identity.GoVersion {
		return RepositoryState{}, fmt.Errorf("evidence: current stock Go version = %q, want %q", currentVersion, identity.GoVersion)
	}
	if currentSum != identity.GoBinarySHA256 || currentSize != identity.GoBinarySizeBytes {
		return RepositoryState{}, fmt.Errorf("evidence: current stock Go binary identity mismatch")
	}
	if runtime.GOOS != identity.GOOS || runtime.GOARCH != identity.GOARCH {
		return RepositoryState{}, fmt.Errorf("evidence: evaluator host = %s/%s, want %s/%s", runtime.GOOS, runtime.GOARCH, identity.GOOS, identity.GOARCH)
	}
	return RepositoryState{Root: root}, nil
}

func validateTrackedEvidenceState(root, currentHead, evidenceDir string, changed []string, requireTrackedVerdict bool) error {
	expected := []string{filepath.ToSlash(filepath.Join(EvidencePath, "receipt.json"))}
	if requireTrackedVerdict {
		expected = append(expected, filepath.ToSlash(filepath.Join(EvidencePath, VerdictFile)))
	}
	actual := make([]string, 0, len(changed))
	for _, name := range changed {
		if name != "" {
			actual = append(actual, name)
		}
	}
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		return fmt.Errorf("evidence: post-measurement paths = %q, want exactly %q", actual, expected)
	}

	raw, err := gitOutputBytes(root, "ls-files", "--stage", "-z", "--", EvidencePath)
	if err != nil {
		return err
	}
	tracked, modes, err := parseTrackedEvidence(raw)
	if err != nil {
		return err
	}
	if !slices.Equal(tracked, expected) {
		return fmt.Errorf("evidence: tracked evidence paths = %q, want exactly %q", tracked, expected)
	}
	for _, name := range expected {
		if modes[name] != "100644" {
			return fmt.Errorf("evidence: tracked evidence path %q has Git mode %s, want 100644", name, modes[name])
		}
	}

	if err := requireRealDirectoryPath(root, evidenceDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(evidenceDir)
	if err != nil {
		return fmt.Errorf("evidence: read evidence directory: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		path := filepath.Join(evidenceDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("evidence: stat tracked evidence %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("evidence: tracked evidence path %s is not a regular non-symlink file", path)
		}
		files = append(files, filepath.ToSlash(filepath.Join(EvidencePath, entry.Name())))
	}
	slices.Sort(files)
	if !slices.Equal(files, expected) {
		return fmt.Errorf("evidence: evidence directory files = %q, want exactly %q", files, expected)
	}

	// Bind the index entries to currentHead rather than trusting a mutable index.
	for _, name := range expected {
		mode, err := gitOutput(root, "ls-tree", currentHead, "--", name)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(mode, "100644 blob ") || !strings.HasSuffix(mode, "\t"+name) {
			return fmt.Errorf("evidence: current HEAD does not contain regular blob %q", name)
		}
	}
	return nil
}

func parseTrackedEvidence(raw []byte) ([]string, map[string]string, error) {
	records := bytes.Split(raw, []byte{0})
	paths := make([]string, 0, len(records))
	modes := make(map[string]string, len(records))
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		header, path, ok := bytes.Cut(record, []byte{'\t'})
		if !ok {
			return nil, nil, fmt.Errorf("evidence: malformed git ls-files record %q", record)
		}
		fields := strings.Fields(string(header))
		name := string(path)
		if len(fields) != 3 || fields[2] != "0" || name == "" || modes[name] != "" {
			return nil, nil, fmt.Errorf("evidence: invalid tracked evidence index record %q", record)
		}
		paths = append(paths, name)
		modes[name] = fields[0]
	}
	slices.Sort(paths)
	return paths, modes, nil
}

func requireRealDirectoryPath(root, directory string) error {
	relative, err := filepath.Rel(root, directory)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return fmt.Errorf("evidence: evidence directory %s is not below repository root %s", directory, root)
	}
	current := root
	for component := range strings.SplitSeq(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("evidence: stat evidence path component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("evidence: evidence path component %s is not a real directory", current)
		}
	}
	return nil
}

func normalizeRepositoryRoot(root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("evidence: repository root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("evidence: absolute repository root: %w", err)
	}
	resolved, err := gitOutput(absolute, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("evidence: absolute Git root: %w", err)
	}
	if filepath.Clean(absolute) != filepath.Clean(resolved) {
		return "", fmt.Errorf("evidence: repository root = %s, want Git top-level %s", absolute, resolved)
	}
	return resolved, nil
}

func validatePlan(root, want string) error {
	planRaw, err := os.ReadFile(filepath.Join(root, ".omx", "plans", "2026-07-15-gows-vnext-quickws-limit-optimized.md"))
	if err != nil {
		return fmt.Errorf("evidence: read approved plan: %w", err)
	}
	planSum := sha256.Sum256(planRaw)
	if got := hex.EncodeToString(planSum[:]); got != want {
		return fmt.Errorf("evidence: approved plan SHA-256 = %s, want %s", got, want)
	}
	return nil
}

func checkoutIdentity(root string) (remote, branch, status string, resultErr error) {
	remote, err := gitOutput(root, "remote", "get-url", "origin")
	if err != nil {
		return "", "", "", err
	}
	branch, err = gitOutput(root, "branch", "--show-current")
	if err != nil {
		return "", "", "", err
	}
	status, err = gitOutput(root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", "", "", err
	}
	return remote, branch, status, nil
}

func validateSourceAncestry(root, planningHead, sourceHead, currentHead string) error {
	if err := gitRun(root, "merge-base", "--is-ancestor", planningHead, sourceHead); err != nil {
		return fmt.Errorf("evidence: implementation source %s does not descend from planning HEAD %s", sourceHead, planningHead)
	}
	if err := gitRun(root, "merge-base", "--is-ancestor", sourceHead, currentHead); err != nil {
		return fmt.Errorf("evidence: source head %s is not an ancestor of current HEAD %s", sourceHead, currentHead)
	}
	return nil
}

func validatePhase0SourcePaths(root, planningHead, sourceHead string) error {
	sourceDiff, err := gitOutput(root, "diff", "--name-only", "--diff-filter=ACDMRTUXB", planningHead+".."+sourceHead)
	if err != nil {
		return err
	}
	return validatePhase0PathNames(strings.Split(sourceDiff, "\n"))
}

func validatePhase0PathNames(names []string) error {
	for _, name := range names {
		if name == "" || name == "README.md" || name == ".github/workflows/bench.yaml" || strings.HasPrefix(name, "bench/") {
			continue
		}
		return fmt.Errorf("evidence: Phase 0 source changed forbidden production path %q", name)
	}
	return nil
}

func sourceIdentity(root, revision string) (tree, sourceSum, moduleSum string, resultErr error) {
	tree, err := gitOutput(root, "rev-parse", revision+"^{tree}")
	if err != nil {
		return "", "", "", fmt.Errorf("evidence: resolve source tree: %w", err)
	}
	lsTree, err := gitOutputBytes(root, "ls-tree", "-r", "--full-tree", revision)
	if err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256(lsTree)
	sourceSum = hex.EncodeToString(sum[:])
	moduleSum, err = hashGitFileSet(root, revision, moduleIdentityPaths)
	if err != nil {
		return "", "", "", err
	}
	return tree, sourceSum, moduleSum, nil
}

var moduleIdentityPaths = []string{
	"go.mod", "go.sum", "bench/go.mod", "bench/go.sum", "flatekp/go.mod", "flatekp/go.sum",
}

func hashGitFileSet(root, revision string, paths []string) (string, error) {
	paths = slices.Clone(paths)
	slices.Sort(paths)
	hash := sha256.New()
	for _, name := range paths {
		if !filepath.IsLocal(filepath.FromSlash(name)) {
			return "", fmt.Errorf("evidence: source path %q is not local", name)
		}
		raw, err := gitOutputBytes(root, "show", revision+":"+name)
		if err != nil {
			return "", fmt.Errorf("evidence: read %s at %s: %w", name, revision, err)
		}
		fileSum := sha256.Sum256(raw)
		if _, err := fmt.Fprintf(hash, "%d:%s:%s\n", len(name), name, hex.EncodeToString(fileSum[:])); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func stockGoVersion() (string, error) {
	goTool := stockGoToolPath()
	command := exec.Command(goTool, "version")
	command.Env = overrideEnv(os.Environ(), "GOENV=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=")
	raw, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("evidence: stock go version: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func stockGoIdentity() (version, sum string, size int64, resultErr error) {
	version, err := stockGoVersion()
	if err != nil {
		return "", "", 0, err
	}
	goTool := stockGoToolPath()
	info, err := os.Lstat(goTool)
	if err != nil {
		return "", "", 0, fmt.Errorf("evidence: stat stock Go binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", 0, fmt.Errorf("evidence: stock Go binary is not a regular file: %s", goTool)
	}
	sum, hashedSize, err := support.FileSHA256(goTool)
	if err != nil {
		return "", "", 0, fmt.Errorf("evidence: read stock Go binary: %w", err)
	}
	return version, sum, hashedSize, nil
}

// stockGoRoot returns the compiler toolchain embedded in the evaluator. The
// evidence contract deliberately binds that immutable compiler instead of a
// potentially different Go launcher found through PATH.
func stockGoRoot() string {
	//lint:ignore SA1019 Exact build-toolchain identity is required by the evidence contract.
	return runtime.GOROOT() //nolint:staticcheck // Exact build-toolchain identity is required by the evidence contract.
}

func stockGoToolPath() string { return filepath.Join(stockGoRoot(), "bin", "go") }

func overrideEnv(base []string, overrides ...string) []string {
	keys := make(map[string]bool, len(overrides))
	for _, value := range overrides {
		key, _, ok := strings.Cut(value, "=")
		if ok {
			keys[key] = true
		}
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, value := range base {
		key, _, _ := strings.Cut(value, "=")
		if !keys[key] {
			result = append(result, value)
		}
	}
	return append(result, overrides...)
}

func gitOutput(root string, args ...string) (string, error) {
	raw, err := gitOutputBytes(root, args...)
	return strings.TrimSpace(string(raw)), err
}

func gitOutputBytes(root string, args ...string) ([]byte, error) {
	command := exec.Command("git", args...)
	if root != "" {
		command.Dir = root
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	raw, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("evidence: git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return raw, nil
}

func gitRun(root string, args ...string) error {
	command := exec.Command("git", args...)
	command.Dir = root
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return fmt.Errorf("git %s exited %d: %s", strings.Join(args, " "), exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}
