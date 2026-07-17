package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/policy"
)

type trackedPolicyRequirement struct {
	Path      string
	SeriesID  string
	Scenarios []string
}

var aaPolicyRequirement = trackedPolicyRequirement{
	Path: "bench/harness/policy/phase0/darwin-arm64-aa.json", SeriesID: "phase0-darwin-arm64-aa",
	Scenarios: []string{"binary-1k-1k", "binary-1k-200-inflight8"},
}

var baselinePolicyRequirements = map[string]trackedPolicyRequirement{
	"best-api-gows-client": {
		Path: "bench/harness/policy/darwin-arm64.json", SeriesID: "darwin-arm64",
		Scenarios: []string{
			"binary-64b-1k", "binary-1k-200", "binary-1k-1k", "binary-16k-200",
			"binary-16k-1k", "binary-1k-200-inflight8", "binary-1k-1k-inflight4",
		},
	},
	"semantic-parity-gows-client": {
		Path: "bench/harness/policy/phase0/darwin-arm64-semantic-parity.json", SeriesID: "phase0-darwin-arm64-semantic-parity",
		Scenarios: []string{"binary-1k-200-inflight8"},
	},
	"independent-gobwas-client": {
		Path: "bench/harness/policy/phase0/darwin-arm64-independent-gobwas.json", SeriesID: "phase0-darwin-arm64-independent-gobwas",
		Scenarios: []string{"binary-1k-200-inflight8"},
	},
	"independent-raw-client": {
		Path: "bench/harness/policy/phase0/darwin-arm64-independent-raw.json", SeriesID: "phase0-darwin-arm64-independent-raw",
		Scenarios: []string{"binary-1k-200-inflight8"},
	},
}

// EvaluateAARunReceipts performs the exact A/A portion of the final evaluator
// before any baseline is collected. It resolves immutable RunReceipt v2
// artifacts, revalidates the live clean implementation source, and applies the
// same statistical gates used by EvaluateDirectory.
func EvaluateAARunReceipts(root string, store artifact.Store, repository RepositoryIdentity, records []RunEvidence) (AAVerdict, error) {
	if err := repository.validate(); err != nil {
		return AAVerdict{}, err
	}
	root, err := normalizeRepositoryRoot(root)
	if err != nil {
		return AAVerdict{}, err
	}
	current, err := CollectRepositoryIdentity(root)
	if err != nil {
		return AAVerdict{}, err
	}
	if current != repository {
		return AAVerdict{}, fmt.Errorf("evidence: A/A preflight repository identity does not match the clean current source")
	}
	wantStore := filepath.Join(root, filepath.FromSlash(ArtifactStorePath))
	gotStore, err := filepath.Abs(store.Root())
	if err != nil {
		return AAVerdict{}, fmt.Errorf("evidence: absolute artifact store: %w", err)
	}
	if gotStore != wantStore {
		return AAVerdict{}, fmt.Errorf("evidence: A/A artifact store = %s, want %s", gotStore, wantStore)
	}
	if err := validateAARunRecords(records, make(map[string]string, len(records))); err != nil {
		return AAVerdict{}, err
	}
	runs, err := resolveAARuns(store, records, repository, root)
	if err != nil {
		return AAVerdict{}, err
	}
	return evaluateAA(runs)
}

// resolveAARuns resolves every A/A run record and validates it against the
// tracked A/A policy requirement, preserving record order.
func resolveAARuns(store artifact.Store, records []RunEvidence, repository RepositoryIdentity, root string) ([]resolvedRun, error) {
	runs := make([]resolvedRun, len(records))
	for i, record := range records {
		run, err := resolveRun(store, record.Run, repository, root)
		if err != nil {
			return nil, fmt.Errorf("evidence: A/A %s: %w", record.Role, err)
		}
		if err := validateTrackedRunPolicy(root, repository.SourceHead, aaPolicyRequirement, run); err != nil {
			return nil, fmt.Errorf("evidence: A/A %s: %w", record.Role, err)
		}
		runs[i] = run
	}
	return runs, nil
}

// EvaluateDirectory resolves and validates every artifact reachable from the
// tracked receipt and returns both the structured and canonical byte verdict.
// It never scans historical artifact roots or rewrites the evidence directory.
func EvaluateDirectory(evidenceDir string, requireTrackedVerdict bool) (Verdict, []byte, error) {
	receiptPath := filepath.Join(evidenceDir, "receipt.json")
	receipt, receiptRaw, err := loadReceipt(receiptPath)
	if err != nil {
		return Verdict{}, nil, err
	}
	state, err := ValidateRepository(evidenceDir, receipt.Repository, requireTrackedVerdict)
	if err != nil {
		return Verdict{}, nil, err
	}
	storeRoot := filepath.Join(state.Root, filepath.FromSlash(receipt.ArtifactStore))
	info, err := os.Lstat(storeRoot)
	if err != nil {
		return Verdict{}, nil, fmt.Errorf("evidence: immutable artifact store unavailable: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Verdict{}, nil, fmt.Errorf("evidence: artifact store %s is not a real directory", storeRoot)
	}
	store, err := artifact.NewStore(storeRoot)
	if err != nil {
		return Verdict{}, nil, err
	}

	aaRuns, err := resolveAARuns(store, receipt.AARuns, receipt.Repository, state.Root)
	if err != nil {
		return Verdict{}, nil, err
	}
	baselineRuns := make(map[string]resolvedRun, len(receipt.BaselineRuns))
	for _, record := range receipt.BaselineRuns {
		run, err := resolveRun(store, record.Run, receipt.Repository, state.Root)
		if err != nil {
			return Verdict{}, nil, fmt.Errorf("evidence: baseline %s: %w", record.Role, err)
		}
		requirement, ok := baselinePolicyRequirements[record.Role]
		if !ok {
			return Verdict{}, nil, fmt.Errorf("evidence: unknown baseline role %q", record.Role)
		}
		if err := validateTrackedRunPolicy(state.Root, receipt.Repository.SourceHead, requirement, run); err != nil {
			return Verdict{}, nil, fmt.Errorf("evidence: baseline %s: %w", record.Role, err)
		}
		baselineRuns[record.Role] = run
	}
	aa, err := evaluateAA(aaRuns)
	if err != nil {
		return Verdict{}, nil, err
	}
	baselines, err := evaluateBaselines(receipt.BaselineRuns, baselineRuns)
	if err != nil {
		return Verdict{}, nil, err
	}
	assemblies, err := resolveAssemblies(store, receipt.Assemblies, receipt.Repository, state.Root)
	if err != nil {
		return Verdict{}, nil, err
	}
	verification, err := resolveVerification(store, receipt.VerificationRef, receipt.Repository, state.Root)
	if err != nil {
		return Verdict{}, nil, err
	}

	receiptSum := sha256.Sum256(receiptRaw)
	verdict := Verdict{
		SchemaVersion: SchemaVersion,
		Kind:          ReceiptKind,
		Pass:          aa.Pass,
		SourceHead:    receipt.Repository.SourceHead,
		SourceSHA256:  receipt.Repository.SourceSHA256,
		ReceiptSHA256: hex.EncodeToString(receiptSum[:]),
		AARunRefs:     slices.Clone(receipt.AARuns),
		BaselineRefs:  canonicalBaselineRefs(receipt.BaselineRuns),
		AA:            aa,
		Baselines:     baselines,
		Assemblies:    assemblies,
		Verification:  verification,
	}
	raw, err := MarshalVerdict(verdict)
	if err != nil {
		return Verdict{}, nil, err
	}
	if requireTrackedVerdict {
		if err := CompareVerdict(filepath.Join(evidenceDir, receipt.VerdictFile), raw); err != nil {
			return Verdict{}, nil, err
		}
	}
	return verdict, raw, nil
}

func validateTrackedRunPolicy(root, sourceHead string, requirement trackedPolicyRequirement, run resolvedRun) error {
	tracked, err := gitOutputBytes(root, "show", sourceHead+":"+requirement.Path)
	if err != nil {
		return fmt.Errorf("tracked policy %s is unavailable: %w", requirement.Path, err)
	}
	if !bytes.Equal(tracked, run.PolicyRaw) || policy.Sum(tracked) != run.Receipt.PolicySHA256 {
		return fmt.Errorf("run policy bytes/hash do not match tracked source policy %s", requirement.Path)
	}
	if run.Policy.Series.ID != requirement.SeriesID {
		return fmt.Errorf("policy series ID = %q, want %q", run.Policy.Series.ID, requirement.SeriesID)
	}
	if len(run.Policy.Scenarios) != len(requirement.Scenarios) {
		return fmt.Errorf("policy scenarios = %d, want %d", len(run.Policy.Scenarios), len(requirement.Scenarios))
	}
	for i, want := range requirement.Scenarios {
		if got := run.Policy.Scenarios[i].Name; got != want {
			return fmt.Errorf("policy scenario %d = %q, want %q", i, got, want)
		}
	}
	return nil
}

func canonicalBaselineRefs(records []RunEvidence) []RunEvidence {
	byRole := make(map[string]RunEvidence, len(records))
	for _, record := range records {
		byRole[record.Role] = record
	}
	result := make([]RunEvidence, 0, len(requiredBaselineRoles))
	for _, role := range requiredBaselineRoles {
		result = append(result, byRole[role])
	}
	return result
}
