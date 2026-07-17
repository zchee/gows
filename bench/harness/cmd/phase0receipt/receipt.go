package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/evidence"
	"github.com/zchee/gows/bench/harness/phase0"
	"github.com/zchee/gows/bench/harness/support"
)

const (
	aaPreflightSchema      = 1
	aaPreflightVerdictKind = "gows.phase0.aa-preflight"
)

type rolePath struct {
	role string
	path string
}

type commandConfig struct {
	repoRoot           string
	verificationResult string
	outputPath         string
	aaInputs           []rolePath
	baselineInputs     []rolePath
}

type aaPreflightVerdict struct {
	SchemaVersion   int                         `json:"schema_version"`
	Kind            string                      `json:"kind"`
	Pass            bool                        `json:"pass"`
	Repository      evidence.RepositoryIdentity `json:"repository"`
	AARuns          []evidence.RunEvidence      `json:"aa_run_receipts"`
	Assemblies      []evidence.AssemblyEvidence `json:"assemblies"`
	VerificationRef artifact.Ref                `json:"verification"`
	AA              evidence.AAVerdict          `json:"aa"`
}

type operations struct {
	collectRepositoryIdentity func(string) (evidence.RepositoryIdentity, error)
	loadVerificationResult    func(string) (phase0.Result, error)
	evaluateAA                func(string, artifact.Store, evidence.RepositoryIdentity, []evidence.RunEvidence) (evidence.AAVerdict, error)
}

func productionOperations() operations {
	return operations{
		collectRepositoryIdentity: evidence.CollectRepositoryIdentity,
		loadVerificationResult:    phase0.Load,
		evaluateAA:                evidence.EvaluateAARunReceipts,
	}
}

func runAAPreflight(cfg commandConfig, ops operations) error {
	root, result, store, err := prepare(cfg, ops)
	if err != nil {
		return err
	}
	output, err := resolveOutputPath(root, cfg.outputPath)
	if err != nil {
		return err
	}
	if err := resolveVerificationArtifacts(store, result); err != nil {
		return err
	}
	aaRuns, err := ingestRoleReceipts(root, store, result.Repository, cfg.aaInputs, evidence.RequiredAARoles())
	if err != nil {
		return err
	}
	verdict, err := ops.evaluateAA(root, store, result.Repository, aaRuns)
	if err != nil {
		return fmt.Errorf("evaluate A/A receipts: %w", err)
	}
	if err := requireAAPass(verdict); err != nil {
		return err
	}
	raw, err := marshalAAPreflight(aaPreflightVerdict{
		SchemaVersion:   aaPreflightSchema,
		Kind:            aaPreflightVerdictKind,
		Pass:            true,
		Repository:      result.Repository,
		AARuns:          aaRuns,
		Assemblies:      canonicalAssemblies(result.Assemblies),
		VerificationRef: result.Verification,
		AA:              verdict,
	})
	if err != nil {
		return err
	}
	return writeNewFileAtomic(root, output, raw, 0o644)
}

func runBuild(cfg commandConfig, ops operations) error {
	root, result, store, err := prepare(cfg, ops)
	if err != nil {
		return err
	}
	output, err := resolveOutputPath(root, cfg.outputPath)
	if err != nil {
		return err
	}
	if err := resolveVerificationArtifacts(store, result); err != nil {
		return err
	}
	aaRuns, err := ingestRoleReceipts(root, store, result.Repository, cfg.aaInputs, evidence.RequiredAARoles())
	if err != nil {
		return err
	}
	aa, err := ops.evaluateAA(root, store, result.Repository, aaRuns)
	if err != nil {
		return fmt.Errorf("evaluate A/A receipts: %w", err)
	}
	if err := requireAAPass(aa); err != nil {
		return err
	}
	baselineRuns, err := ingestRoleReceipts(root, store, result.Repository, cfg.baselineInputs, evidence.RequiredBaselineRoles())
	if err != nil {
		return err
	}
	if err := ensureUniqueRunRefs(append(slices.Clone(aaRuns), baselineRuns...)); err != nil {
		return err
	}

	receipt := evidence.Receipt{
		SchemaVersion:   evidence.SchemaVersion,
		Kind:            evidence.ReceiptKind,
		Evaluator:       evidence.EvaluatorCommand,
		Contract:        evidence.Contract,
		ArtifactStore:   evidence.ArtifactStorePath,
		VerdictFile:     evidence.VerdictFile,
		Repository:      result.Repository,
		AARuns:          aaRuns,
		BaselineRuns:    baselineRuns,
		Assemblies:      canonicalAssemblies(result.Assemblies),
		VerificationRef: result.Verification,
	}
	raw, err := evidence.MarshalReceipt(receipt)
	if err != nil {
		return fmt.Errorf("marshal Phase 0 receipt: %w", err)
	}
	return writeNewFileAtomic(root, output, raw, 0o644)
}

func validateCommandConfig(cfg commandConfig, includeBaselines bool) error {
	if strings.TrimSpace(cfg.repoRoot) == "" {
		return errors.New("-repo is required")
	}
	if strings.TrimSpace(cfg.verificationResult) == "" {
		return errors.New("-verification-result is required")
	}
	if strings.TrimSpace(cfg.outputPath) == "" {
		return errors.New("-out is required")
	}
	if err := validateRolePaths(cfg.aaInputs, evidence.RequiredAARoles(), "A/A"); err != nil {
		return err
	}
	if includeBaselines {
		return validateRolePaths(cfg.baselineInputs, evidence.RequiredBaselineRoles(), "baseline")
	}
	if len(cfg.baselineInputs) != 0 {
		return errors.New("A/A preflight does not accept baseline receipts")
	}
	return nil
}

func validateRolePaths(inputs []rolePath, required []string, class string) error {
	if len(inputs) != len(required) {
		return fmt.Errorf("%s receipt count = %d, want %d", class, len(inputs), len(required))
	}
	for i, want := range required {
		if inputs[i].role != want {
			return fmt.Errorf("%s receipt role %d = %q, want %q", class, i, inputs[i].role, want)
		}
		if strings.TrimSpace(inputs[i].path) == "" {
			return fmt.Errorf("-%s is required", flagName(class, want))
		}
	}
	return nil
}

func flagName(class, role string) string {
	if class == "baseline" {
		return "baseline-" + role
	}
	return role
}

func prepare(cfg commandConfig, ops operations) (string, phase0.Result, artifact.Store, error) {
	root, err := canonicalRepositoryRoot(cfg.repoRoot)
	if err != nil {
		return "", phase0.Result{}, artifact.Store{}, err
	}
	resultPath, err := resolveInputPath(root, cfg.verificationResult, false)
	if err != nil {
		return "", phase0.Result{}, artifact.Store{}, fmt.Errorf("verification result path: %w", err)
	}
	result, err := ops.loadVerificationResult(resultPath)
	if err != nil {
		return "", phase0.Result{}, artifact.Store{}, err
	}
	if err := result.Validate(); err != nil {
		return "", phase0.Result{}, artifact.Store{}, err
	}
	live, err := ops.collectRepositoryIdentity(root)
	if err != nil {
		return "", phase0.Result{}, artifact.Store{}, err
	}
	if live != result.Repository {
		return "", phase0.Result{}, artifact.Store{}, errors.New("phase0receipt: verification result repository identity does not match the clean current source")
	}
	store, err := openFixedStore(root)
	if err != nil {
		return "", phase0.Result{}, artifact.Store{}, err
	}
	return root, result, store, nil
}

func ingestRoleReceipts(root string, store artifact.Store, repository evidence.RepositoryIdentity, inputs []rolePath, required []string) ([]evidence.RunEvidence, error) {
	if err := validateRolePaths(inputs, required, receiptClass(required)); err != nil {
		return nil, err
	}
	records := make([]evidence.RunEvidence, 0, len(inputs))
	seenPaths := make(map[string]string, len(inputs))
	seenRefs := make(map[string]string, len(inputs))
	for _, input := range inputs {
		path, err := resolveInputPath(root, input.path, true)
		if err != nil {
			return nil, fmt.Errorf("%s receipt: %w", input.role, err)
		}
		if previous, duplicate := seenPaths[path]; duplicate {
			return nil, fmt.Errorf("receipt role %q reuses path from role %q", input.role, previous)
		}
		seenPaths[path] = input.role

		runReceipt, err := artifact.LoadRunReceipt(path)
		if err != nil {
			return nil, fmt.Errorf("%s receipt: %w", input.role, err)
		}
		if err := validateRunRepositoryBinding(runReceipt, repository); err != nil {
			return nil, fmt.Errorf("%s receipt: %w", input.role, err)
		}
		ref, err := store.PutFile(path, artifact.MediaTypeRunReceipt)
		if err != nil {
			return nil, fmt.Errorf("ingest %s receipt: %w", input.role, err)
		}
		if previous, duplicate := seenRefs[ref.SHA256]; duplicate {
			return nil, fmt.Errorf("receipt role %q reuses immutable artifact from role %q", input.role, previous)
		}
		seenRefs[ref.SHA256] = input.role
		resolved, _, err := artifact.ResolveRun(store, ref)
		if err != nil {
			return nil, fmt.Errorf("resolve %s receipt: %w", input.role, err)
		}
		if err := validateRunRepositoryBinding(resolved, repository); err != nil {
			return nil, fmt.Errorf("resolved %s receipt: %w", input.role, err)
		}
		records = append(records, evidence.RunEvidence{Role: input.role, Run: ref})
	}
	return records, nil
}

func receiptClass(required []string) string {
	if slices.Equal(required, evidence.RequiredBaselineRoles()) {
		return "baseline"
	}
	return "A/A"
}

func validateRunRepositoryBinding(receipt artifact.RunReceipt, repository evidence.RepositoryIdentity) error {
	switch {
	case receipt.GitDirty || receipt.GitStatus != "":
		return errors.New("run was captured from a dirty source tree")
	case receipt.GitRemote != repository.Remote || receipt.GitBranch != repository.Branch:
		return errors.New("run repository remote or branch mismatch")
	case receipt.SourceHead != repository.SourceHead || receipt.GitTree != repository.SourceTree || receipt.SourceSHA256 != repository.SourceSHA256:
		return errors.New("run source identity mismatch")
	case receipt.ModulePath != repository.ModulePath || receipt.ModuleFilesSHA256 != repository.ModuleFilesSHA256:
		return errors.New("run module identity mismatch")
	case receipt.GoVersion != repository.GoVersion || receipt.GoBinarySHA256 != repository.GoBinarySHA256:
		return errors.New("run Go toolchain identity mismatch")
	case receipt.GOOS != repository.GOOS || receipt.GOARCH != repository.GOARCH:
		return errors.New("run host target mismatch")
	case receipt.GoExperiment != "" || receipt.ToolchainSeries != "stock":
		return errors.New("run is not in the stock Go series")
	}
	return nil
}

func ensureUniqueRunRefs(records []evidence.RunEvidence) error {
	seen := make(map[string]string, len(records))
	for _, record := range records {
		if err := record.Run.Validate(); err != nil {
			return fmt.Errorf("%s receipt reference: %w", record.Role, err)
		}
		if previous, duplicate := seen[record.Run.SHA256]; duplicate {
			return fmt.Errorf("receipt role %q reuses immutable artifact from role %q", record.Role, previous)
		}
		seen[record.Run.SHA256] = record.Role
	}
	return nil
}

func requireAAPass(verdict evidence.AAVerdict) error {
	if !verdict.Pass {
		return errors.New("A/A preflight verdict did not pass; output was not published")
	}
	return nil
}

func marshalAAPreflight(verdict aaPreflightVerdict) ([]byte, error) {
	if verdict.SchemaVersion != aaPreflightSchema || verdict.Kind != aaPreflightVerdictKind || !verdict.Pass || !verdict.AA.Pass {
		return nil, errors.New("invalid passing A/A preflight verdict")
	}
	if err := evidence.ValidateRepositoryIdentity(verdict.Repository); err != nil {
		return nil, err
	}
	if err := validateRunEvidenceRoles(verdict.AARuns, evidence.RequiredAARoles()); err != nil {
		return nil, err
	}
	verdict.Assemblies = canonicalAssemblies(verdict.Assemblies)
	verificationResult := phase0.Result{
		SchemaVersion: phase0.ResultSchemaVersion,
		Repository:    verdict.Repository,
		Verification:  verdict.VerificationRef,
		Assemblies:    verdict.Assemblies,
	}
	if err := verificationResult.Validate(); err != nil {
		return nil, err
	}
	raw, err := jsonv2.Marshal(verdict, jsonv2.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, fmt.Errorf("marshal A/A preflight verdict: %w", err)
	}
	return append(raw, '\n'), nil
}

func canonicalAssemblies(records []evidence.AssemblyEvidence) []evidence.AssemblyEvidence {
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b evidence.AssemblyEvidence) int {
		if order := strings.Compare(a.GOOS, b.GOOS); order != 0 {
			return order
		}
		return strings.Compare(a.GOARCH, b.GOARCH)
	})
	return records
}

func validateRunEvidenceRoles(records []evidence.RunEvidence, required []string) error {
	if len(records) != len(required) {
		return fmt.Errorf("run evidence count = %d, want %d", len(records), len(required))
	}
	for i, want := range required {
		if records[i].Role != want {
			return fmt.Errorf("run evidence role %d = %q, want %q", i, records[i].Role, want)
		}
		if records[i].Run.MediaType != artifact.MediaTypeRunReceipt {
			return fmt.Errorf("run evidence %q has media type %q", want, records[i].Run.MediaType)
		}
	}
	return ensureUniqueRunRefs(records)
}

func resolveVerificationArtifacts(store artifact.Store, result phase0.Result) error {
	if _, _, err := artifact.ResolveDirectory(store, result.Verification, evidence.VerificationKind); err != nil {
		return fmt.Errorf("resolve verification receipt: %w", err)
	}
	for _, assembly := range result.Assemblies {
		kind := evidence.AssemblyKindPrefix + assembly.GOOS + "-" + assembly.GOARCH
		if _, _, err := artifact.ResolveDirectory(store, assembly.Bundle, kind); err != nil {
			return fmt.Errorf("resolve %s/%s assembly receipt: %w", assembly.GOOS, assembly.GOARCH, err)
		}
	}
	return nil
}

func canonicalRepositoryRoot(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("repository root is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("absolute repository root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat repository root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("repository root %s is not a real directory", resolved)
	}
	return filepath.Clean(resolved), nil
}

func resolveInputPath(root, path string, allowReceiptDirectory bool) (string, error) {
	resolved, err := resolvePathBelowRoot(root, path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("symlink input is forbidden: %s", resolved)
	}
	if info.IsDir() && allowReceiptDirectory {
		resolved = filepath.Join(resolved, "receipt.json")
		info, err = os.Lstat(resolved)
		if err != nil {
			return "", err
		}
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("input is not a regular file: %s", resolved)
	}
	canonical, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", err
	}
	if filepath.Clean(canonical) != filepath.Clean(resolved) {
		return "", fmt.Errorf("symlinked input path is forbidden: %s", resolved)
	}
	if _, err := relativeBelowRoot(root, canonical); err != nil {
		return "", err
	}
	return canonical, nil
}

func resolveOutputPath(root, path string) (string, error) {
	resolved, err := resolvePathBelowRoot(root, path)
	if err != nil {
		return "", err
	}
	if filepath.Clean(resolved) == filepath.Clean(root) {
		return "", errors.New("output path must name a file below the repository")
	}
	if _, err := os.Lstat(resolved); err == nil {
		return "", fmt.Errorf("destination already exists: %s", resolved)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return resolved, nil
}

func resolvePathBelowRoot(root, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is required")
	}
	var absolute string
	if filepath.IsAbs(path) {
		absolute = filepath.Clean(path)
	} else {
		absolute = filepath.Join(root, path)
	}
	absolute, err := filepath.Abs(absolute)
	if err != nil {
		return "", err
	}
	if _, err := relativeBelowRoot(root, absolute); err != nil {
		return "", err
	}
	return absolute, nil
}

func relativeBelowRoot(root, path string) (string, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", err
	}
	if relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository root: %s", path)
	}
	return relative, nil
}

func openFixedStore(root string) (artifact.Store, error) {
	storeRoot := filepath.Join(root, filepath.FromSlash(evidence.ArtifactStorePath))
	for _, path := range []string{filepath.Join(root, ".omx"), storeRoot, filepath.Join(storeRoot, "sha256")} {
		if info, err := os.Lstat(path); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return artifact.Store{}, fmt.Errorf("artifact store component is not a real directory: %s", path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return artifact.Store{}, err
		}
	}
	store, err := artifact.NewStore(storeRoot)
	if err != nil {
		return artifact.Store{}, err
	}
	for _, path := range []string{store.Root(), filepath.Join(store.Root(), "sha256")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return artifact.Store{}, fmt.Errorf("artifact store component is not a real directory: %s", path)
		}
	}
	return store, nil
}

// writeNewFileAtomic publishes data without ever replacing an existing file,
// after proving path stays below root through real (non-symlink) directories.
// The atomic no-replace publication itself is [support.WriteNewFileAtomic]'s
// same-directory hard-link step.
func writeNewFileAtomic(root, path string, data []byte, mode os.FileMode) error {
	if _, err := relativeBelowRoot(root, path); err != nil {
		return err
	}
	if err := ensureRealDirectories(root, filepath.Dir(path)); err != nil {
		return err
	}
	return support.WriteNewFileAtomic(path, data, mode)
}

func ensureRealDirectories(root, directory string) error {
	relative, err := relativeBelowRoot(root, directory)
	if err != nil {
		return err
	}
	current := root
	if relative == "." {
		return nil
	}
	for part := range strings.SplitSeq(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		switch {
		case err == nil:
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("output directory component is not a real directory: %s", current)
			}
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(current, 0o755); err != nil {
				return err
			}
		default:
			return err
		}
	}
	return nil
}
