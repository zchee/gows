package phase0

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/evidence"
)

func TestResultMarshalLoadRoundTripIsCanonical(t *testing.T) {
	t.Parallel()

	result := validResult()
	result.Assemblies[0], result.Assemblies[1] = result.Assemblies[1], result.Assemblies[0]
	first, err := Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("Marshal is not byte stable")
	}
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, first, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := validResult()
	if !reflect.DeepEqual(loaded, want) {
		t.Fatalf("Load mismatch\n got: %#v\nwant: %#v", loaded, want)
	}
}

func TestResultLoadRejectsUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()

	raw, err := Marshal(validResult())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"unknown member":   []byte(strings.Replace(string(raw), "{", `{"unknown":true,`, 1)),
		"trailing value":   append(append([]byte(nil), raw...), []byte("{}")...),
		"malformed suffix": append(append([]byte(nil), raw...), byte('x')),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.json")
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load accepted %s", name)
			}
		})
	}
}

func TestResultValidateRejectsIdentityAndReceiptConfusion(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"schema":             func(r *Result) { r.SchemaVersion++ },
		"repository":         func(r *Result) { r.Repository.Branch = "other" },
		"verification media": func(r *Result) { r.Verification.MediaType = "application/json" },
		"missing target":     func(r *Result) { r.Assemblies = r.Assemblies[:1] },
		"duplicate target":   func(r *Result) { r.Assemblies[1].GOARCH = r.Assemblies[0].GOARCH },
		"noncanonical order": func(r *Result) { r.Assemblies[0], r.Assemblies[1] = r.Assemblies[1], r.Assemblies[0] },
		"wrong target OS":    func(r *Result) { r.Assemblies[1].GOOS = "linux" },
		"unsupported target": func(r *Result) { r.Assemblies[1].GOARCH = "riscv64" },
		"assembly media":     func(r *Result) { r.Assemblies[1].Bundle.MediaType = "application/json" },
		"duplicate receipt":  func(r *Result) { r.Assemblies[1].Bundle = r.Verification },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := validResult()
			mutate(&result)
			if err := result.Validate(); err == nil {
				t.Fatalf("Validate accepted %s", name)
			}
		})
	}
}

func TestResultLoadRejectsInvalidatedDirectory(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	raw, err := Marshal(validResult())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "result.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "INVALIDATED.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "invalidated") {
		t.Fatalf("Load invalidated result error = %v", err)
	}
}

func validResult() Result {
	return Result{
		SchemaVersion: ResultSchemaVersion,
		Repository: evidence.RepositoryIdentity{
			PlanSHA256: evidence.PlanSHA256, Remote: evidence.ExpectedRemote,
			Branch: evidence.ExpectedBranch, SourceHead: strings.Repeat("a", 40),
			SourceTree: strings.Repeat("b", 40), SourceSHA256: strings.Repeat("c", 64),
			ModulePath: "github.com/zchee/gows", ModuleFilesSHA256: strings.Repeat("d", 64),
			GoVersion:      "go version go1.26.5 darwin/arm64",
			GoBinarySHA256: strings.Repeat("e", 64), GoBinarySizeBytes: 1,
			GOOS: "darwin", GOARCH: "arm64", EvidencePath: evidence.EvidencePath,
		},
		Verification: testRef("1"),
		Assemblies: []evidence.AssemblyEvidence{
			{GOOS: "darwin", GOARCH: "amd64", Bundle: testRef("2")},
			{GOOS: "darwin", GOARCH: "arm64", Bundle: testRef("3")},
		},
	}
}

func testRef(digit string) artifact.Ref {
	digest := strings.Repeat(digit, 64)
	return artifact.Ref{
		URI: "omx-cas://sha256/" + digest, SHA256: digest,
		SizeBytes: 1, MediaType: "application/vnd.gows.directory-receipt+json",
	}
}
