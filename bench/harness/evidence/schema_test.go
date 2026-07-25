package evidence

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/zchee/gows/bench/harness/artifact"
)

func TestReceiptValidateFailsClosed(t *testing.T) {
	t.Parallel()
	receipt := testReceipt()
	if err := receipt.Validate(); err != nil {
		t.Fatalf("valid receipt: %v", err)
	}
	tests := map[string]func(*Receipt){
		"wrong plan":   func(r *Receipt) { r.Repository.PlanSHA256 = strings.Repeat("0", 64) },
		"wrong remote": func(r *Receipt) { r.Repository.Remote = "git@example.invalid/other.git" },
		"reused run":   func(r *Receipt) { r.BaselineRuns[0].Run = r.AARuns[0].Run },
		"missing baseline role": func(r *Receipt) {
			r.BaselineRuns[0].Role = "best-api-gows-client"
			r.BaselineRuns[1].Role = "best-api-gows-client"
		},
		"wrong assembly OS": func(r *Receipt) { r.Assemblies[0].GOOS = "linux" },
		"wrong evaluator":   func(r *Receipt) { r.Evaluator += " --unsafe" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := testReceipt()
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid receipt was accepted")
			}
		})
	}
}

func TestLoadReceiptRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	raw, err := jsonv2.Marshal(testReceipt(), jsonv2.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"kind":`), []byte(`"unknown":true,"kind":`), 1)
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReceipt(path); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("LoadReceipt error = %v, want unknown-field rejection", err)
	}
}

func TestLoadReceiptAndVerdictRejectSymlinks(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	raw, err := MarshalReceipt(testReceipt())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "mutable-receipt.json")
	if err := os.WriteFile(target, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "receipt.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReceipt(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("LoadReceipt symlink error = %v, want fail-closed rejection", err)
	}

	verdictTarget := filepath.Join(directory, "mutable-verdict.json")
	if err := os.WriteFile(verdictTarget, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdictLink := filepath.Join(directory, VerdictFile)
	if err := os.Symlink(verdictTarget, verdictLink); err != nil {
		t.Fatal(err)
	}
	if err := CompareVerdict(verdictLink, []byte("{}\n")); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("CompareVerdict symlink error = %v, want fail-closed rejection", err)
	}
}

func TestMarshalVerdictByteStable(t *testing.T) {
	t.Parallel()
	receipt := testReceipt()
	verdict := Verdict{
		SchemaVersion: SchemaVersion, Kind: ReceiptKind, Pass: true,
		SourceHead: receipt.Repository.SourceHead, SourceSHA256: receipt.Repository.SourceSHA256,
		ReceiptSHA256: strings.Repeat("a", 64), AARunRefs: receipt.AARuns,
		BaselineRefs: canonicalBaselineRefs(receipt.BaselineRuns),
	}
	one, err := MarshalVerdict(verdict)
	if err != nil {
		t.Fatal(err)
	}
	two, err := MarshalVerdict(verdict)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatalf("verdict bytes differ:\n%s\n%s", one, two)
	}
	path := filepath.Join(t.TempDir(), "verdict.json")
	if err := os.WriteFile(path, one, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CompareVerdict(path, two); err != nil {
		t.Fatalf("CompareVerdict: %v", err)
	}
	one[len(one)-2] ^= 1
	if err := CompareVerdict(path, one); err == nil {
		t.Fatal("CompareVerdict accepted one-byte drift")
	}
}

func TestRequiredReceiptRolesAreImmutableCopies(t *testing.T) {
	aa := RequiredAARoles()
	baseline := RequiredBaselineRoles()
	aa[0] = "changed"
	baseline[0] = "changed"
	if RequiredAARoles()[0] != "session-1" || RequiredBaselineRoles()[0] != "best-api-gows-client" {
		t.Fatal("required role API exposed mutable package state")
	}
}

func testReceipt() Receipt {
	ref := func(index int, media string) artifact.Ref {
		digest := fmt.Sprintf("%064x", index+1)
		return artifact.Ref{URI: "omx-cas://sha256/" + digest, SHA256: digest, SizeBytes: int64(index + 1), MediaType: media}
	}
	const runMedia = "application/vnd.gows.bench-run-receipt+json"
	const dirMedia = "application/vnd.gows.directory-receipt+json"
	receipt := Receipt{
		SchemaVersion: SchemaVersion, Kind: ReceiptKind, Evaluator: EvaluatorCommand, Contract: Contract,
		ArtifactStore: ArtifactStorePath, VerdictFile: VerdictFile,
		Repository: RepositoryIdentity{
			PlanSHA256: PlanSHA256, Remote: ExpectedRemote, Branch: ExpectedBranch,
			SourceHead: strings.Repeat("1", 40), SourceTree: strings.Repeat("2", 40), SourceSHA256: strings.Repeat("3", 64),
			ModulePath: "github.com/zchee/gows", ModuleFilesSHA256: strings.Repeat("4", 64),
			GoVersion: "go version go1.26.5 darwin/arm64", GoBinarySHA256: strings.Repeat("5", 64), GoBinarySizeBytes: 100,
			GOOS: "darwin", GOARCH: "arm64", EvidencePath: EvidencePath,
		},
		AARuns: []RunEvidence{
			{Role: "session-1", Run: ref(1, runMedia)},
			{Role: "session-2", Run: ref(2, runMedia)},
			{Role: "session-3", Run: ref(3, runMedia)},
		},
		Assemblies: []AssemblyEvidence{
			{GOOS: "darwin", GOARCH: "amd64", Bundle: ref(20, dirMedia)},
			{GOOS: "darwin", GOARCH: "arm64", Bundle: ref(21, dirMedia)},
		},
		VerificationRef: ref(30, dirMedia),
	}
	for i, role := range requiredBaselineRoles {
		receipt.BaselineRuns = append(receipt.BaselineRuns, RunEvidence{Role: role, Run: ref(10+i, runMedia)})
	}
	return receipt
}
