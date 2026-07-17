// Package evidence defines and evaluates the tracked Phase 0 benchmark
// receipt. The receipt contains only immutable CAS references and source
// identity; raw benchmark and verification artifacts remain outside git.
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/support"
)

const (
	// SchemaVersion is the only Phase 0 receipt and verdict schema accepted.
	// Historical or versionless evidence is never upgraded implicitly.
	SchemaVersion = 1

	ReceiptKind    = "gows.phase0.benchmark-truth"
	PlanSHA256     = "1054f4b0ba8abda6f14707d7326f2b48e37a64260c5fa11568ffb9e605a1e34f"
	PlanningHead   = "d62e1bd94fe30413cf58f704c2384252a0d7cfd5"
	ExpectedRemote = "git@github.com:zchee/gows.git"
	ExpectedBranch = "fastest-claude"

	// EvaluatorCommand is deliberately stored verbatim in the tracked receipt.
	// Changing the evaluator surface therefore invalidates existing evidence.
	EvaluatorCommand = "GOEXPERIMENT= GOFLAGS=-mod=mod go -C bench run ./harness/cmd/benchcmp -run evidence/phase0/current"

	Contract = "PASS only when the Phase 0 evaluator rejects missing, stale, dirty, invalidated, or identity-mismatched evidence; three independent same-binary A/A sessions with n>=20 each pass the preregistered equivalence, precision, order-effect, and empirical false-positive gates; a complete 5s/30s n>=20 current-implementation baseline exists without requiring quickws superiority; tracked receipts resolve immutable raw artifacts and exact source, module, binary, policy, adapter, and assembly hashes; supported amd64/arm64 assembly provenance and all required test, vet, race, build, and static gates pass; and no production hot-path, public-API, or assembly-kernel implementation was changed."

	ArtifactStorePath = ".omx/artifacts"
	EvidencePath      = "bench/evidence/phase0/current"
	VerdictFile       = "verdict.json"

	AssemblyKindPrefix = "assembly/"
	VerificationKind   = "verification/phase0"
)

// RepositoryIdentity binds every artifact to the implementation-start
// source commit. The final tracked evidence commit may descend from this
// commit only by changing EvidencePath.
type RepositoryIdentity struct {
	PlanSHA256        string `json:"plan_sha256"`
	Remote            string `json:"remote"`
	Branch            string `json:"branch"`
	SourceHead        string `json:"source_head"`
	SourceTree        string `json:"source_tree"`
	SourceSHA256      string `json:"source_sha256"`
	ModulePath        string `json:"module_path"`
	ModuleFilesSHA256 string `json:"module_files_sha256"`
	GoVersion         string `json:"go_version"`
	GoBinarySHA256    string `json:"go_binary_sha256"`
	GoBinarySizeBytes int64  `json:"go_binary_size_bytes"`
	GOOS              string `json:"goos"`
	GOARCH            string `json:"goarch"`
	EvidencePath      string `json:"evidence_path"`
}

// RunEvidence assigns a non-interchangeable semantic role to a run receipt.
// Roles prevent a receipt from satisfying multiple required series by merely
// repeating one otherwise-valid CAS reference.
type RunEvidence struct {
	Role string       `json:"role"`
	Run  artifact.Ref `json:"run"`
}

// AssemblyEvidence points at one complete DirectoryReceipt for a supported
// target. The directory kind is assembly/<goos>-<goarch>.
type AssemblyEvidence struct {
	GOOS   string       `json:"goos"`
	GOARCH string       `json:"goarch"`
	Bundle artifact.Ref `json:"bundle"`
}

// Receipt is the compact tracked root of all Phase 0 evidence.
type Receipt struct {
	SchemaVersion   int                `json:"schema_version"`
	Kind            string             `json:"kind"`
	Evaluator       string             `json:"evaluator_command"`
	Contract        string             `json:"contract"`
	ArtifactStore   string             `json:"artifact_store"`
	VerdictFile     string             `json:"verdict_file"`
	Repository      RepositoryIdentity `json:"repository"`
	AARuns          []RunEvidence      `json:"aa_runs"`
	BaselineRuns    []RunEvidence      `json:"baseline_runs"`
	Assemblies      []AssemblyEvidence `json:"assemblies"`
	VerificationRef artifact.Ref       `json:"verification"`
}

func (r Receipt) Validate() error {
	switch {
	case r.SchemaVersion != SchemaVersion:
		return fmt.Errorf("evidence: receipt schema_version = %d, want %d", r.SchemaVersion, SchemaVersion)
	case r.Kind != ReceiptKind:
		return fmt.Errorf("evidence: receipt kind = %q, want %q", r.Kind, ReceiptKind)
	case r.Evaluator != EvaluatorCommand:
		return fmt.Errorf("evidence: evaluator command mismatch")
	case r.Contract != Contract:
		return fmt.Errorf("evidence: evaluator contract mismatch")
	case r.ArtifactStore != ArtifactStorePath:
		return fmt.Errorf("evidence: artifact_store = %q, want %q", r.ArtifactStore, ArtifactStorePath)
	case r.VerdictFile != VerdictFile:
		return fmt.Errorf("evidence: verdict_file = %q, want %q", r.VerdictFile, VerdictFile)
	}
	if err := r.Repository.validate(); err != nil {
		return err
	}
	if len(r.BaselineRuns) != len(requiredBaselineRoles) {
		return fmt.Errorf("evidence: baseline_runs count = %d, want %d", len(r.BaselineRuns), len(requiredBaselineRoles))
	}
	seenRefs := make(map[string]string, len(r.AARuns)+len(r.BaselineRuns)+len(r.Assemblies)+1)
	validateRef := func(class string, ref artifact.Ref) error {
		if err := ref.Validate(); err != nil {
			return fmt.Errorf("evidence: %s: %w", class, err)
		}
		if previous, duplicate := seenRefs[ref.SHA256]; duplicate {
			return fmt.Errorf("evidence: %s reuses artifact from %s", class, previous)
		}
		seenRefs[ref.SHA256] = class
		return nil
	}
	if err := validateAARunRecords(r.AARuns, seenRefs); err != nil {
		return err
	}
	baselineRoles := make(map[string]bool, len(r.BaselineRuns))
	for i, run := range r.BaselineRuns {
		if !slices.Contains(requiredBaselineRoles, run.Role) || baselineRoles[run.Role] {
			return fmt.Errorf("evidence: baseline_runs[%d] has invalid or duplicate role %q", i, run.Role)
		}
		baselineRoles[run.Role] = true
		if run.Run.MediaType != artifact.MediaTypeRunReceipt {
			return fmt.Errorf("evidence: baseline_runs[%d] has wrong receipt media type %q", i, run.Run.MediaType)
		}
		if err := validateRef(fmt.Sprintf("baseline_runs[%d]", i), run.Run); err != nil {
			return err
		}
	}
	arches := make(map[string]bool, len(r.Assemblies))
	for i, assembly := range r.Assemblies {
		if assembly.GOOS != r.Repository.GOOS || (assembly.GOARCH != "amd64" && assembly.GOARCH != "arm64") {
			return fmt.Errorf("evidence: assemblies[%d] has unsupported target %s/%s", i, assembly.GOOS, assembly.GOARCH)
		}
		if arches[assembly.GOARCH] {
			return fmt.Errorf("evidence: duplicate assembly target %q", assembly.GOARCH)
		}
		arches[assembly.GOARCH] = true
		if assembly.Bundle.MediaType != artifact.MediaTypeDirectoryReceipt {
			return fmt.Errorf("evidence: assemblies[%d] has wrong receipt media type %q", i, assembly.Bundle.MediaType)
		}
		if err := validateRef(fmt.Sprintf("assemblies[%d]", i), assembly.Bundle); err != nil {
			return err
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if !arches[arch] {
			return fmt.Errorf("evidence: missing supported assembly target %q", arch)
		}
	}
	if r.VerificationRef.MediaType != artifact.MediaTypeDirectoryReceipt {
		return fmt.Errorf("evidence: verification has wrong receipt media type %q", r.VerificationRef.MediaType)
	}
	if err := validateRef("verification", r.VerificationRef); err != nil {
		return err
	}
	return nil
}

func validateAARunRecords(records []RunEvidence, seenRefs map[string]string) error {
	roles := RequiredAARoles()
	if len(records) != len(roles) {
		return fmt.Errorf("evidence: aa_runs count = %d, want exactly %d", len(records), len(roles))
	}
	for i, run := range records {
		wantRole := roles[i]
		if run.Role != wantRole {
			return fmt.Errorf("evidence: aa_runs[%d].role = %q, want %q", i, run.Role, wantRole)
		}
		if run.Run.MediaType != artifact.MediaTypeRunReceipt {
			return fmt.Errorf("evidence: aa_runs[%d] has wrong receipt media type %q", i, run.Run.MediaType)
		}
		if err := run.Run.Validate(); err != nil {
			return fmt.Errorf("evidence: aa_runs[%d]: %w", i, err)
		}
		class := fmt.Sprintf("aa_runs[%d]", i)
		if previous, duplicate := seenRefs[run.Run.SHA256]; duplicate {
			return fmt.Errorf("evidence: %s reuses artifact from %s", class, previous)
		}
		seenRefs[run.Run.SHA256] = class
	}
	return nil
}

func (identity RepositoryIdentity) validate() error {
	switch {
	case identity.PlanSHA256 != PlanSHA256:
		return fmt.Errorf("evidence: plan SHA-256 = %q, want %s", identity.PlanSHA256, PlanSHA256)
	case identity.Remote != ExpectedRemote:
		return fmt.Errorf("evidence: repository remote = %q, want %q", identity.Remote, ExpectedRemote)
	case identity.Branch != ExpectedBranch:
		return fmt.Errorf("evidence: repository branch = %q, want %q", identity.Branch, ExpectedBranch)
	case !support.ValidGitObjectID(identity.SourceHead):
		return errors.New("evidence: repository source_head is not a full Git object ID")
	case !support.ValidGitObjectID(identity.SourceTree):
		return errors.New("evidence: repository source_tree is not a full Git object ID")
	case !support.ValidSHA256(identity.SourceSHA256):
		return errors.New("evidence: repository source_sha256 is invalid")
	case identity.ModulePath != "github.com/zchee/gows":
		return fmt.Errorf("evidence: repository module_path = %q, want github.com/zchee/gows", identity.ModulePath)
	case !support.ValidSHA256(identity.ModuleFilesSHA256):
		return errors.New("evidence: repository module_files_sha256 is invalid")
	case identity.GoVersion == "" || strings.Contains(identity.GoVersion, "-X:"):
		return fmt.Errorf("evidence: repository Go version %q is not a stock version", identity.GoVersion)
	case !support.ValidSHA256(identity.GoBinarySHA256) || identity.GoBinarySizeBytes <= 0:
		return errors.New("evidence: repository Go binary identity is invalid")
	case identity.GOOS == "" || identity.GOARCH == "":
		return errors.New("evidence: repository GOOS/GOARCH are required")
	case identity.EvidencePath != EvidencePath:
		return fmt.Errorf("evidence: repository evidence_path = %q, want %q", identity.EvidencePath, EvidencePath)
	}
	return nil
}

// ValidateRepositoryIdentity applies the exact Phase 0 source/toolchain
// identity contract without inspecting a checkout. Producers and typed result
// consumers should call CollectRepositoryIdentity when live validation is
// required.
func ValidateRepositoryIdentity(identity RepositoryIdentity) error {
	return identity.validate()
}

var requiredBaselineRoles = []string{
	"best-api-gows-client",
	"semantic-parity-gows-client",
	"independent-gobwas-client",
	"independent-raw-client",
}

// RequiredAARoles returns the ordered, non-interchangeable A/A receipt roles.
func RequiredAARoles() []string {
	return []string{"session-1", "session-2", "session-3"}
}

// RequiredBaselineRoles returns the complete baseline receipt role set in
// canonical verdict order.
func RequiredBaselineRoles() []string {
	return slices.Clone(requiredBaselineRoles)
}

// LoadReceipt strictly decodes a receipt, rejecting unknown fields and
// trailing values before applying semantic validation.
func LoadReceipt(path string) (Receipt, error) {
	receipt, _, err := loadReceipt(path)
	return receipt, err
}

func loadReceipt(path string) (Receipt, []byte, error) {
	raw, err := readRegularFile(path, "receipt")
	if err != nil {
		return Receipt{}, nil, err
	}
	var receipt Receipt
	if err := decodeStrict(raw, &receipt); err != nil {
		return Receipt{}, nil, fmt.Errorf("evidence: parse receipt: %w", err)
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, nil, err
	}
	return receipt, raw, nil
}

// MarshalReceipt validates receipt and returns its deterministic tracked JSON
// representation. Producer commands should use this function rather than
// duplicating schema defaults or JSON encoder settings.
func MarshalReceipt(receipt Receipt) ([]byte, error) {
	if err := receipt.Validate(); err != nil {
		return nil, err
	}
	raw, err := jsonv2.Marshal(receipt, jsonv2.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal receipt: %w", err)
	}
	return append(raw, '\n'), nil
}

func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

// IntervalVerdict records one deterministic session/block-preserving ratio
// interval and, when applicable, its gate.
type IntervalVerdict struct {
	Metric           string          `json:"metric"`
	CandidateCenter  float64         `json:"candidate_center"`
	ComparatorCenter float64         `json:"comparator_center"`
	RatioAvailable   bool            `json:"ratio_available"`
	Ratio            paired.Interval `json:"ratio"`
	BandLower        float64         `json:"band_lower"`
	BandUpper        float64         `json:"band_upper"`
	Width            float64         `json:"width"`
	Pass             bool            `json:"pass"`
}

type AAScenarioVerdict struct {
	Name        string            `json:"name"`
	Sessions    int               `json:"sessions"`
	Pairs       int               `json:"pairs"`
	Throughput  IntervalVerdict   `json:"throughput"`
	P99         IntervalVerdict   `json:"p99"`
	P999        IntervalVerdict   `json:"p999"`
	OrderEffect paired.Interval   `json:"order_effect"`
	OrderPass   bool              `json:"order_pass"`
	Resources   []IntervalVerdict `json:"resources"`
	Pass        bool              `json:"pass"`
}

type AAVerdict struct {
	SessionIDs       []string            `json:"session_ids"`
	BinarySHA256     string              `json:"binary_sha256"`
	PolicySHA256     string              `json:"policy_sha256"`
	Scenarios        []AAScenarioVerdict `json:"scenarios"`
	PrimaryGeomean   paired.Interval     `json:"primary_geomean"`
	FalsePositive    float64             `json:"empirical_false_positive_rate"`
	NullIterations   int                 `json:"null_iterations"`
	FalsePositiveMax float64             `json:"false_positive_max"`
	FalsePositiveOK  bool                `json:"false_positive_pass"`
	Pass             bool                `json:"pass"`
}

type BaselineScenarioVerdict struct {
	Name      string            `json:"name"`
	Primary   bool              `json:"primary"`
	Pairs     int               `json:"pairs"`
	Metrics   []IntervalVerdict `json:"metrics"`
	CellClass string            `json:"cell_class"`
}

type BaselineRunVerdict struct {
	SessionID       string                    `json:"session_id"`
	SeriesID        string                    `json:"series_id"`
	AdapterClass    string                    `json:"adapter_class"`
	Client          string                    `json:"client"`
	PolicySHA256    string                    `json:"policy_sha256"`
	PrimaryGeomean  paired.Interval           `json:"primary_geomean"`
	Scenarios       []BaselineScenarioVerdict `json:"scenarios"`
	SuperiorityGate bool                      `json:"superiority_gate"`
}

type AssemblyVerdict struct {
	GOOS                string   `json:"goos"`
	GOARCH              string   `json:"goarch"`
	BundleSHA256        string   `json:"bundle_sha256"`
	BinarySHA256        string   `json:"binary_sha256"`
	RuntimeProfile      string   `json:"runtime_profile"`
	SourceObjectSymbols []string `json:"source_object_symbol_hashes"`
}

type VerificationVerdict struct {
	BundleSHA256 string   `json:"bundle_sha256"`
	Checks       []string `json:"checks"`
}

// Verdict is deliberately timestamp-free. The same receipt and immutable raw
// inputs must produce byte-identical JSON.
type Verdict struct {
	SchemaVersion int                  `json:"schema_version"`
	Kind          string               `json:"kind"`
	Pass          bool                 `json:"pass"`
	SourceHead    string               `json:"source_head"`
	SourceSHA256  string               `json:"source_sha256"`
	ReceiptSHA256 string               `json:"receipt_sha256"`
	AARunRefs     []RunEvidence        `json:"aa_run_receipts"`
	BaselineRefs  []RunEvidence        `json:"baseline_run_receipts"`
	AA            AAVerdict            `json:"aa"`
	Baselines     []BaselineRunVerdict `json:"baselines"`
	Assemblies    []AssemblyVerdict    `json:"assemblies"`
	Verification  VerificationVerdict  `json:"verification"`
}

// MarshalVerdict is the canonical byte representation used both when
// creating and when reproducing the tracked verdict.
func MarshalVerdict(verdict Verdict) ([]byte, error) {
	raw, err := jsonv2.Marshal(verdict, jsonv2.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal verdict: %w", err)
	}
	return append(raw, '\n'), nil
}

// CompareVerdict requires the tracked verdict to be exactly reproducible.
func CompareVerdict(path string, generated []byte) error {
	tracked, err := readRegularFile(path, "tracked verdict")
	if err != nil {
		return err
	}
	if !bytes.Equal(tracked, generated) {
		return fmt.Errorf("evidence: tracked verdict %s is stale or non-deterministic", path)
	}
	return nil
}

func readRegularFile(path, description string) (_ []byte, resultErr error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", description, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("evidence: %s %s is not a regular non-symlink file", description, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: open %s: %w", description, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
	}()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("evidence: stat opened %s: %w", description, err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("evidence: %s %s changed identity while opening", description, path)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("evidence: read %s: %w", description, err)
	}
	return raw, nil
}

func sortedUnique(values []string) ([]string, error) {
	values = slices.Clone(values)
	slices.Sort(values)
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return nil, fmt.Errorf("duplicate value %q", values[i])
		}
	}
	return values, nil
}

// IsPhase0Directory reports whether benchcmp should use the strict Phase 0
// evaluator rather than its legacy per-run comparison mode.
func IsPhase0Directory(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return clean == "evidence/phase0/current" || strings.HasSuffix(clean, "/"+EvidencePath)
}
