package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/support"
)

const VerificationSchemaVersion = 2

// MicroAllocationTestPattern is the exact zero-allocation regression set
// shared by the verification producer and evaluator. Keeping the regex here
// prevents the recorded command from drifting away from the accepted command.
const MicroAllocationTestPattern = "(?i)^(testappendheaderallocs|testdecodeheaderallocs|testupgradeallocs|testserveechozeroallocs|testwritemessagestaged16kbzeroallocs|testreadmessagezeroallocs|testreadmessage16kbzeroallocs|testwritemessageserverallocs|testwritemessagecompressedzeroallocs|testgetputsteadystateallocs|testparsestatuslineallocs|testparserequestlineallocs|testheaderscannerallocs|testappendacceptallocs|testfeedallocs|testparsedeflateofferallocs|testparamscannerallocs)$"

var requiredVerificationChecks = []string{
	"root-test",
	"root-vet",
	"root-race",
	"bench-test",
	"bench-vet",
	"flatekp-test",
	"flatekp-vet",
	"build-amd64",
	"build-arm64",
	"assembly-amd64",
	"assembly-arm64",
	"micro-allocations",
	"format",
	"static",
	"diff-check",
}

// RequiredVerificationChecks returns the exact sequential check IDs accepted
// by the Phase 0 evaluator. The returned slice is independent and safe for a
// producer command to retain or modify.
func RequiredVerificationChecks() []string {
	return slices.Clone(requiredVerificationChecks)
}

// VerificationCommandInputs are live, path-bound inputs used to build and
// independently validate the exact Phase 0 verification commands.
type VerificationCommandInputs struct {
	RepositoryRoot string
	GoTool         string
	Gofmt          string
	Gopls          string
	Git            string
	HomeDir        string
	TempDir        string
	Tools          []VerificationToolIdentity
	TrackedGoFiles []string
}

// VerificationToolIdentity binds every executable used by a verification
// check to immutable bytes and version/build metadata. Path records the fully
// resolved executable, never a mutable symlink used by PATH lookup.
type VerificationToolIdentity struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	Version   string `json:"version"`
}

// CollectVerificationCommandInputs resolves the exact stock tools and the Go
// source list from the immutable source commit. The evaluator recollects this
// independently instead of trusting paths or file lists supplied by a receipt.
func CollectVerificationCommandInputs(root, sourceHead string) (VerificationCommandInputs, error) {
	root, err := normalizeRepositoryRoot(root)
	if err != nil {
		return VerificationCommandInputs{}, err
	}
	toolPaths := map[string]string{
		"go":    stockGoToolPath(),
		"gofmt": filepath.Join(stockGoRoot(), "bin", "gofmt"),
	}
	for _, name := range []string{"gopls", "git"} {
		path, err := exec.LookPath(name)
		if err != nil {
			return VerificationCommandInputs{}, fmt.Errorf("evidence: resolve %s: %w", name, err)
		}
		toolPaths[name] = path
	}
	for name, path := range toolPaths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return VerificationCommandInputs{}, fmt.Errorf("evidence: absolute %s: %w", name, err)
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return VerificationCommandInputs{}, fmt.Errorf("evidence: resolve %s executable %s: %w", name, absolute, err)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return VerificationCommandInputs{}, fmt.Errorf("evidence: absolute resolved %s: %w", name, err)
		}
		info, err := os.Lstat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			return VerificationCommandInputs{}, fmt.Errorf("evidence: %s executable is not an executable regular file: %s", name, resolved)
		}
		toolPaths[name] = filepath.Clean(resolved)
	}
	toolIdentities, err := collectVerificationToolIdentities(toolPaths)
	if err != nil {
		return VerificationCommandInputs{}, err
	}
	raw, err := gitOutputBytes(root, "ls-tree", "-r", "--name-only", "-z", sourceHead)
	if err != nil {
		return VerificationCommandInputs{}, fmt.Errorf("evidence: list source Go files: %w", err)
	}
	var goFiles []string
	for part := range bytes.SplitSeq(raw, []byte{0}) {
		if len(part) == 0 {
			continue
		}
		name := filepath.ToSlash(string(part))
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if !filepath.IsLocal(filepath.FromSlash(name)) || filepath.Clean(name) != name {
			return VerificationCommandInputs{}, fmt.Errorf("evidence: non-canonical tracked Go path %q", name)
		}
		goFiles = append(goFiles, name)
	}
	if len(goFiles) == 0 {
		return VerificationCommandInputs{}, fmt.Errorf("evidence: source commit has no tracked Go files")
	}
	slices.Sort(goFiles)
	home, err := os.UserHomeDir()
	if err != nil {
		return VerificationCommandInputs{}, fmt.Errorf("evidence: resolve verification HOME: %w", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return VerificationCommandInputs{}, fmt.Errorf("evidence: absolute verification HOME: %w", err)
	}
	temporary, err := filepath.Abs(os.TempDir())
	if err != nil {
		return VerificationCommandInputs{}, fmt.Errorf("evidence: absolute verification TMPDIR: %w", err)
	}
	return VerificationCommandInputs{
		RepositoryRoot: root,
		GoTool:         toolPaths["go"],
		Gofmt:          toolPaths["gofmt"],
		Gopls:          toolPaths["gopls"],
		Git:            toolPaths["git"],
		HomeDir:        filepath.Clean(home),
		TempDir:        filepath.Clean(temporary),
		Tools:          toolIdentities,
		TrackedGoFiles: goFiles,
	}, nil
}

func collectVerificationToolIdentities(paths map[string]string) ([]VerificationToolIdentity, error) {
	const toolCount = 4
	order := [toolCount]string{"go", "gofmt", "gopls", "git"}
	goTool := paths["go"]
	identities := make([]VerificationToolIdentity, 0, toolCount)
	for _, name := range order {
		path := paths[name]
		identity, err := verificationToolIdentity(name, path, goTool)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

func verificationToolIdentity(name, path, goTool string) (VerificationToolIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return VerificationToolIdentity{}, fmt.Errorf("evidence: stat verification tool %s: %w", name, err)
	}
	if !before.Mode().IsRegular() || before.Mode()&0o111 == 0 {
		return VerificationToolIdentity{}, fmt.Errorf("evidence: verification tool %s is not an executable regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return VerificationToolIdentity{}, fmt.Errorf("evidence: open verification tool %s: %w", name, err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	after, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(copyErr, statErr, closeErr); err != nil {
		return VerificationToolIdentity{}, fmt.Errorf("evidence: hash verification tool %s: %w", name, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || size != before.Size() {
		return VerificationToolIdentity{}, fmt.Errorf("evidence: verification tool %s changed identity while hashing", name)
	}

	var command *exec.Cmd
	if name == "git" {
		command = exec.Command(path, "--version")
	} else {
		command = exec.Command(goTool, "version", "-m", path)
	}
	command.Env = overrideEnv(os.Environ(), "GOENV=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=", "LANG=C", "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		return VerificationToolIdentity{}, fmt.Errorf("evidence: inspect verification tool %s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	version := strings.TrimSpace(string(output))
	if version == "" {
		return VerificationToolIdentity{}, fmt.Errorf("evidence: verification tool %s has empty version metadata", name)
	}
	return VerificationToolIdentity{
		Name: name, Path: path, SizeBytes: size,
		SHA256: hex.EncodeToString(hash.Sum(nil)), Version: version,
	}, nil
}

// VerificationManifest is the typed command record inside the immutable
// verification directory bundle. Command argv and environment are arrays so
// shell quoting cannot change their meaning during review.
type VerificationManifest struct {
	SchemaVersion     int                        `json:"schema_version"`
	SourceHead        string                     `json:"source_head"`
	SourceTree        string                     `json:"source_tree"`
	ModuleFilesSHA256 string                     `json:"module_files_sha256"`
	GoVersion         string                     `json:"go_version"`
	GoBinarySHA256    string                     `json:"go_binary_sha256"`
	GOOS              string                     `json:"goos"`
	GOARCH            string                     `json:"goarch"`
	Hostname          string                     `json:"hostname"`
	BootIdentity      string                     `json:"boot_identity"`
	Tools             []VerificationToolIdentity `json:"tools"`
	Checks            []VerificationCheck        `json:"checks"`
}

type VerificationCheck struct {
	ID           string   `json:"id"`
	Argv         []string `json:"argv"`
	WorkingDir   string   `json:"working_directory"`
	Environment  []string `json:"environment"`
	StartedAt    string   `json:"started_at"`
	EndedAt      string   `json:"ended_at"`
	ExitCode     int      `json:"exit_code"`
	StdoutPath   string   `json:"stdout_path"`
	StdoutSHA256 string   `json:"stdout_sha256"`
	StderrPath   string   `json:"stderr_path"`
	StderrSHA256 string   `json:"stderr_sha256"`
}

// MarshalVerificationManifest validates the typed command records and returns
// deterministic JSON. ValidateVerificationBundle must still be called after
// writing the manifest so every declared stdout/stderr hash is checked against
// the actual bundle files.
func MarshalVerificationManifest(manifest VerificationManifest, repository RepositoryIdentity, inputs VerificationCommandInputs) ([]byte, error) {
	if _, err := validateVerificationRecord(manifest, repository, inputs); err != nil {
		return nil, err
	}
	raw, err := jsonv2.Marshal(manifest, jsonv2.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal verification manifest: %w", err)
	}
	return append(raw, '\n'), nil
}

// ValidateVerificationBundle strictly loads and validates a local verification
// directory before it is sealed into an immutable DirectoryReceipt.
func ValidateVerificationBundle(bundleDir string, repository RepositoryIdentity, inputs VerificationCommandInputs) error {
	paths, err := verificationBundlePaths(bundleDir)
	if err != nil {
		return err
	}
	manifestPath, ok := paths["manifest.json"]
	if !ok {
		return fmt.Errorf("evidence: verification bundle lacks manifest.json")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest VerificationManifest
	if err := decodeStrict(raw, &manifest); err != nil {
		return fmt.Errorf("evidence: verification manifest: %w", err)
	}
	return validateVerificationManifest(manifest, paths, repository, inputs)
}

func verificationBundlePaths(bundleDir string) (map[string]string, error) {
	absolute, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("evidence: absolute verification bundle: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("evidence: stat verification bundle: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("evidence: verification bundle is not a real directory")
	}
	paths := make(map[string]string)
	err = filepath.WalkDir(absolute, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == absolute || entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence: verification bundle contains symlink %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("evidence: verification bundle contains non-regular file %s", path)
		}
		relative, err := filepath.Rel(absolute, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !filepath.IsLocal(filepath.FromSlash(relative)) || strings.Contains(filepath.Base(relative), ".tmp-") {
			return fmt.Errorf("evidence: verification bundle contains invalid path %q", relative)
		}
		paths[relative] = path
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func resolveVerification(store artifact.Store, ref artifact.Ref, repository RepositoryIdentity, root string) (VerificationVerdict, error) {
	_, paths, err := artifact.ResolveDirectory(store, ref, VerificationKind)
	if err != nil {
		return VerificationVerdict{}, fmt.Errorf("evidence: resolve verification bundle: %w", err)
	}
	manifestPath, ok := paths["manifest.json"]
	if !ok {
		return VerificationVerdict{}, fmt.Errorf("evidence: verification bundle lacks manifest.json")
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return VerificationVerdict{}, err
	}
	var manifest VerificationManifest
	if err := decodeStrict(raw, &manifest); err != nil {
		return VerificationVerdict{}, fmt.Errorf("evidence: verification manifest: %w", err)
	}
	inputs, err := CollectVerificationCommandInputs(root, repository.SourceHead)
	if err != nil {
		return VerificationVerdict{}, err
	}
	if err := validateVerificationManifest(manifest, paths, repository, inputs); err != nil {
		return VerificationVerdict{}, err
	}
	checks := make([]string, len(manifest.Checks))
	for i, check := range manifest.Checks {
		checks[i] = check.ID
	}
	return VerificationVerdict{BundleSHA256: ref.SHA256, Checks: checks}, nil
}

func validateVerificationManifest(manifest VerificationManifest, paths map[string]string, repository RepositoryIdentity, inputs VerificationCommandInputs) error {
	wantFiles, err := validateVerificationRecord(manifest, repository, inputs)
	if err != nil {
		return err
	}
	for _, check := range manifest.Checks {
		for label, record := range map[string]struct{ path, hash string }{
			"stdout": {check.StdoutPath, check.StdoutSHA256},
			"stderr": {check.StderrPath, check.StderrSHA256},
		} {
			path, ok := paths[record.path]
			if !ok {
				return fmt.Errorf("evidence: verification check %q lacks %s artifact %q", check.ID, label, record.path)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != record.hash {
				return fmt.Errorf("evidence: verification check %q %s hash mismatch", check.ID, label)
			}
			if check.ID == "format" && label == "stdout" && len(raw) != 0 {
				return fmt.Errorf("evidence: verification format check produced non-empty stdout")
			}
		}
	}
	if len(paths) != len(wantFiles) {
		return fmt.Errorf("evidence: verification bundle contains %d files, manifest declares %d", len(paths), len(wantFiles))
	}
	for name := range paths {
		if !wantFiles[name] {
			return fmt.Errorf("evidence: verification bundle has undeclared file %q", name)
		}
	}
	return nil
}

func validateVerificationRecord(manifest VerificationManifest, repository RepositoryIdentity, inputs VerificationCommandInputs) (map[string]bool, error) {
	if err := inputs.validate(); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != VerificationSchemaVersion {
		return nil, fmt.Errorf("evidence: verification schema_version = %d, want %d", manifest.SchemaVersion, VerificationSchemaVersion)
	}
	if manifest.SourceHead != repository.SourceHead || manifest.SourceTree != repository.SourceTree ||
		manifest.ModuleFilesSHA256 != repository.ModuleFilesSHA256 || manifest.GoVersion != repository.GoVersion ||
		manifest.GoBinarySHA256 != repository.GoBinarySHA256 || manifest.GOOS != repository.GOOS || manifest.GOARCH != repository.GOARCH {
		return nil, fmt.Errorf("evidence: verification source/toolchain identity mismatch")
	}
	if !slices.Equal(manifest.Tools, inputs.Tools) {
		return nil, fmt.Errorf("evidence: verification tool identities do not match current executable bytes")
	}
	if inputs.Tools[0].SHA256 != repository.GoBinarySHA256 || inputs.Tools[0].SizeBytes != repository.GoBinarySizeBytes {
		return nil, fmt.Errorf("evidence: verification Go tool identity does not match repository stock Go identity")
	}
	if manifest.Hostname == "" || manifest.BootIdentity == "" {
		return nil, fmt.Errorf("evidence: verification host identity is incomplete")
	}
	if err := support.ValidateBootIdentity(manifest.GOOS, manifest.BootIdentity); err != nil {
		return nil, fmt.Errorf("evidence: verification boot identity: %w", err)
	}
	if len(manifest.Checks) != len(requiredVerificationChecks) {
		return nil, fmt.Errorf("evidence: verification checks = %d, want %d", len(manifest.Checks), len(requiredVerificationChecks))
	}
	wantFiles := map[string]bool{"manifest.json": true}
	var previousEnd time.Time
	for i, check := range manifest.Checks {
		wantID := requiredVerificationChecks[i]
		if check.ID != wantID {
			return nil, fmt.Errorf("evidence: verification check %d = %q, want %q", i, check.ID, wantID)
		}
		if len(check.Argv) == 0 || check.Argv[0] == "" || check.ExitCode != 0 {
			return nil, fmt.Errorf("evidence: verification check %q has empty argv or exit %d", check.ID, check.ExitCode)
		}
		if err := validateVerificationCommand(check, repository, inputs); err != nil {
			return nil, err
		}
		started, err := time.Parse(time.RFC3339Nano, check.StartedAt)
		if err != nil {
			return nil, fmt.Errorf("evidence: verification check %q invalid started_at: %w", check.ID, err)
		}
		ended, err := time.Parse(time.RFC3339Nano, check.EndedAt)
		if err != nil || !started.Before(ended) {
			return nil, fmt.Errorf("evidence: verification check %q invalid ended_at", check.ID)
		}
		if !previousEnd.IsZero() && started.Before(previousEnd) {
			return nil, fmt.Errorf("evidence: verification checks overlap at %q", check.ID)
		}
		previousEnd = ended
		for label, record := range map[string]struct{ path, hash string }{
			"stdout": {check.StdoutPath, check.StdoutSHA256},
			"stderr": {check.StderrPath, check.StderrSHA256},
		} {
			wantPath := fmt.Sprintf("logs/%02d-%s.%s.log", i+1, check.ID, label)
			if record.path != wantPath || !filepath.IsLocal(filepath.FromSlash(record.path)) || !support.ValidSHA256(record.hash) || wantFiles[record.path] {
				return nil, fmt.Errorf("evidence: verification check %q has invalid %s artifact", check.ID, label)
			}
			wantFiles[record.path] = true
		}
	}
	return wantFiles, nil
}

func (inputs VerificationCommandInputs) validate() error {
	if !filepath.IsAbs(inputs.RepositoryRoot) {
		return fmt.Errorf("evidence: verification repository root is not absolute")
	}
	for name, path := range map[string]string{
		"go": inputs.GoTool, "gofmt": inputs.Gofmt, "gopls": inputs.Gopls, "git": inputs.Git,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("evidence: verification %s path is not canonical and absolute", name)
		}
	}
	for name, path := range map[string]string{"HOME": inputs.HomeDir, "TMPDIR": inputs.TempDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("evidence: verification %s is not canonical and absolute", name)
		}
	}
	wantTools := []struct{ name, path string }{
		{"go", inputs.GoTool},
		{"gofmt", inputs.Gofmt},
		{"gopls", inputs.Gopls},
		{"git", inputs.Git},
	}
	if len(inputs.Tools) != len(wantTools) {
		return fmt.Errorf("evidence: verification tool identities = %d, want %d", len(inputs.Tools), len(wantTools))
	}
	for i, want := range wantTools {
		tool := inputs.Tools[i]
		if tool.Name != want.name || tool.Path != want.path || !filepath.IsAbs(tool.Path) || filepath.Clean(tool.Path) != tool.Path ||
			tool.SizeBytes <= 0 || !support.ValidSHA256(tool.SHA256) || tool.Version == "" {
			return fmt.Errorf("evidence: invalid verification tool identity at %d: %+v", i, tool)
		}
	}
	if len(inputs.TrackedGoFiles) == 0 || !slices.IsSorted(inputs.TrackedGoFiles) {
		return fmt.Errorf("evidence: verification tracked Go files are empty or unsorted")
	}
	for i, name := range inputs.TrackedGoFiles {
		if !filepath.IsLocal(filepath.FromSlash(name)) || filepath.ToSlash(filepath.Clean(name)) != name || filepath.Ext(name) != ".go" || i > 0 && inputs.TrackedGoFiles[i-1] == name {
			return fmt.Errorf("evidence: invalid tracked Go file %q", name)
		}
	}
	return nil
}

func validateVerificationCommand(check VerificationCheck, repository RepositoryIdentity, inputs VerificationCommandInputs) error {
	workingDirectories := map[string]string{
		"root-test": ".", "root-vet": ".", "root-race": ".",
		"bench-test": "bench", "bench-vet": "bench",
		"flatekp-test": "flatekp", "flatekp-vet": "flatekp",
		"build-amd64": ".", "build-arm64": ".",
		"assembly-amd64": "bench", "assembly-arm64": "bench",
		"micro-allocations": ".", "format": ".", "static": ".", "diff-check": ".",
	}
	if check.WorkingDir != workingDirectories[check.ID] {
		return fmt.Errorf("evidence: verification check %q working directory = %q, want %q", check.ID, check.WorkingDir, workingDirectories[check.ID])
	}
	wantArch := repository.GOARCH
	if arch, ok := strings.CutPrefix(check.ID, "build-"); ok {
		wantArch = arch
	}
	if err := validateVerificationEnvironment(check, repository.GOOS, wantArch, inputs); err != nil {
		return err
	}
	exact := func(want ...string) error {
		if !slices.Equal(check.Argv, want) {
			return fmt.Errorf("evidence: verification check %q argv = %q, want %q", check.ID, check.Argv, want)
		}
		return nil
	}
	switch check.ID {
	case "root-test", "bench-test", "flatekp-test":
		return exact(inputs.GoTool, "test", "./...", "-count=1")
	case "root-vet", "bench-vet", "flatekp-vet":
		return exact(inputs.GoTool, "vet", "./...")
	case "root-race":
		return exact(inputs.GoTool, "test", "-race", "./...", "-count=1")
	case "build-amd64", "build-arm64":
		return validateBuildCommand(check, inputs, wantArch)
	case "assembly-amd64", "assembly-arm64":
		return validateAssemblyCommand(check, inputs, strings.TrimPrefix(check.ID, "assembly-"))
	case "micro-allocations":
		return exact(inputs.GoTool, "test", "-run", MicroAllocationTestPattern, "-count=1", ".", "./internal/extension", "./internal/httpx", "./internal/pool", "./internal/utf8x")
	case "format":
		return exact(append([]string{inputs.Gofmt, "-d"}, inputs.TrackedGoFiles...)...)
	case "static":
		return exact(append([]string{inputs.Gopls, "check"}, inputs.TrackedGoFiles...)...)
	case "diff-check":
		return exact(inputs.Git, "diff", "--check")
	default:
		return fmt.Errorf("evidence: unknown verification check %q", check.ID)
	}
}

func validateVerificationEnvironment(check VerificationCheck, goos, goarch string, inputs VerificationCommandInputs) error {
	if len(check.Environment) != 15 || !slices.IsSorted(check.Environment) {
		return fmt.Errorf("evidence: verification check %q environment is not the exact sorted 15-field set", check.ID)
	}
	values := make(map[string]string, len(check.Environment))
	for _, assignment := range check.Environment {
		key, value, ok := strings.Cut(assignment, "=")
		if !ok || key == "" {
			return fmt.Errorf("evidence: verification check %q has malformed environment entry %q", check.ID, assignment)
		}
		if _, duplicate := values[key]; duplicate {
			return fmt.Errorf("evidence: verification check %q repeats environment key %q", check.ID, key)
		}
		values[key] = value
	}
	want := map[string]string{
		"CGO_ENABLED": "0", "GOARCH": goarch, "GOENV": "off", "GOEXPERIMENT": "",
		"GOFIPS140": "latest", "GOFLAGS": "-mod=mod", "GOOS": goos, "GOTELEMETRY": "off",
		"GOTOOLCHAIN": "local", "GOWORK": "off", "LANG": "C", "LC_ALL": "C",
		"PATH": strings.Join([]string{filepath.Dir(inputs.GoTool), "/usr/bin", "/bin", "/usr/sbin", "/sbin"}, string(os.PathListSeparator)),
	}
	for key, value := range want {
		if values[key] != value {
			return fmt.Errorf("evidence: verification check %q environment %s = %q, want %q", check.ID, key, values[key], value)
		}
	}
	for key, value := range map[string]string{"HOME": inputs.HomeDir, "TMPDIR": inputs.TempDir} {
		if values[key] != value {
			return fmt.Errorf("evidence: verification check %q environment %s = %q, want %q", check.ID, key, values[key], value)
		}
	}
	if len(values) != len(want)+2 {
		return fmt.Errorf("evidence: verification check %q environment has unknown fields", check.ID)
	}
	return nil
}

func validateBuildCommand(check VerificationCheck, inputs VerificationCommandInputs, arch string) error {
	if len(check.Argv) != 6 || !slices.Equal(check.Argv[:4], []string{inputs.GoTool, "test", "-c", "-o"}) || check.Argv[5] != "." {
		return fmt.Errorf("evidence: verification check %q has noncanonical compile-link argv", check.ID)
	}
	output := check.Argv[4]
	wantBase := "gows-" + arch + ".test"
	if !filepath.IsAbs(output) || filepath.Base(output) != wantBase || !strings.HasPrefix(filepath.Base(filepath.Dir(output)), ".phase0verify-work-") || !pathBelow(filepath.Join(inputs.RepositoryRoot, ".omx"), output) {
		return fmt.Errorf("evidence: verification check %q output path %q is not the expected temporary compile-link artifact", check.ID, output)
	}
	return nil
}

func validateAssemblyCommand(check VerificationCheck, inputs VerificationCommandInputs, arch string) error {
	if len(check.Argv) != 13 || !slices.Equal(check.Argv[:4], []string{inputs.GoTool, "run", "./harness/cmd/asmprobe", "-repo"}) || check.Argv[4] != inputs.RepositoryRoot ||
		!slices.Equal(check.Argv[5:10], []string{"-goos", "darwin", "-goarch", arch, "-out"}) || !slices.Equal(check.Argv[11:], []string{"-runtime", "required"}) {
		return fmt.Errorf("evidence: verification check %q has noncanonical assembly argv", check.ID)
	}
	output := check.Argv[10]
	if !filepath.IsAbs(output) || !pathBelow(filepath.Join(inputs.RepositoryRoot, ".omx"), output) ||
		filepath.Base(output) != "darwin-"+arch || filepath.Base(filepath.Dir(output)) != "assembly" {
		return fmt.Errorf("evidence: verification check %q output path %q is not the expected assembly bundle", check.ID, output)
	}
	return nil
}

func pathBelow(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && filepath.IsLocal(relative)
}
