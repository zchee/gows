package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/evidence"
	"github.com/zchee/gows/bench/harness/phase0"
)

func TestValidateRolePathsRejectsCountRoleAndMissingPath(t *testing.T) {
	t.Parallel()
	required := evidence.RequiredAARoles()
	valid := roleInputs(required, "receipt")

	tests := []struct {
		name   string
		inputs []rolePath
		match  string
	}{
		{name: "count", inputs: valid[:2], match: "count = 2, want 3"},
		{name: "role", inputs: []rolePath{{role: "session-2", path: "one"}, valid[1], valid[2]}, match: `role 0 = "session-2", want "session-1"`},
		{name: "path", inputs: []rolePath{valid[0], {role: "session-2"}, valid[2]}, match: "-session-2 is required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRolePaths(test.inputs, required, "A/A")
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("validateRolePaths() error = %v, want substring %q", err, test.match)
			}
		})
	}
}

func TestEnsureUniqueRunRefsRejectsDuplicateArtifact(t *testing.T) {
	t.Parallel()
	ref := testRef("a", runReceiptMediaType)
	err := ensureUniqueRunRefs([]evidence.RunEvidence{
		{Role: "session-1", Run: ref},
		{Role: "session-2", Run: ref},
	})
	if err == nil || !strings.Contains(err.Error(), `"session-2" reuses immutable artifact from role "session-1"`) {
		t.Fatalf("ensureUniqueRunRefs() error = %v", err)
	}
}

func TestParseConfigBindsEveryExplicitRoleFlag(t *testing.T) {
	t.Parallel()
	args := []string{"-repo", "/repo", "-verification-result", "verify/result.json", "-out", "receipt.json"}
	for _, role := range evidence.RequiredAARoles() {
		args = append(args, "-"+role, "runs/"+role)
	}
	for _, role := range evidence.RequiredBaselineRoles() {
		args = append(args, "-baseline-"+role, "runs/"+role)
	}
	cfg, err := parseConfig("build", args, &bytes.Buffer{}, true)
	if err != nil {
		t.Fatalf("parseConfig(): %v", err)
	}
	if got := rolePathRoles(cfg.aaInputs); !slices.Equal(got, evidence.RequiredAARoles()) {
		t.Fatalf("A/A roles = %v", got)
	}
	if got := rolePathRoles(cfg.baselineInputs); !slices.Equal(got, evidence.RequiredBaselineRoles()) {
		t.Fatalf("baseline roles = %v", got)
	}

	missing := slices.Clone(args[:len(args)-2])
	if _, err := parseConfig("build", missing, &bytes.Buffer{}, true); err == nil || !strings.Contains(err.Error(), "baseline-independent-raw-client") {
		t.Fatalf("missing baseline error = %v", err)
	}
}

func TestValidateRunRepositoryBindingRejectsIdentityMismatch(t *testing.T) {
	t.Parallel()
	identity := testRepositoryIdentity()
	receipt := artifact.RunReceipt{
		SourceHead: identity.SourceHead, GitRemote: identity.Remote, GitBranch: identity.Branch,
		GitTree: identity.SourceTree, SourceSHA256: identity.SourceSHA256,
		ModulePath: identity.ModulePath, ModuleFilesSHA256: identity.ModuleFilesSHA256,
		GoVersion: identity.GoVersion, GoBinarySHA256: identity.GoBinarySHA256,
		GOOS: identity.GOOS, GOARCH: identity.GOARCH, ToolchainSeries: "stock",
	}
	if err := validateRunRepositoryBinding(receipt, identity); err != nil {
		t.Fatalf("matching binding: %v", err)
	}
	receipt.SourceSHA256 = strings.Repeat("f", 64)
	if err := validateRunRepositoryBinding(receipt, identity); err == nil || !strings.Contains(err.Error(), "source identity mismatch") {
		t.Fatalf("mismatched binding error = %v", err)
	}
}

func TestMarshalAAPreflightIsCanonicalAndByteStable(t *testing.T) {
	t.Parallel()
	identity := testRepositoryIdentity()
	aaRuns := []evidence.RunEvidence{
		{Role: "session-1", Run: testRef("a", runReceiptMediaType)},
		{Role: "session-2", Run: testRef("b", runReceiptMediaType)},
		{Role: "session-3", Run: testRef("c", runReceiptMediaType)},
	}
	verification := testRef("d", "application/vnd.gows.directory-receipt+json")
	assemblies := []evidence.AssemblyEvidence{
		{GOOS: identity.GOOS, GOARCH: "arm64", Bundle: testRef("e", "application/vnd.gows.directory-receipt+json")},
		{GOOS: identity.GOOS, GOARCH: "amd64", Bundle: testRef("f", "application/vnd.gows.directory-receipt+json")},
	}
	verdict := aaPreflightVerdict{
		SchemaVersion: aaPreflightSchema, Kind: aaPreflightVerdictKind, Pass: true,
		Repository: identity, AARuns: aaRuns, Assemblies: assemblies,
		VerificationRef: verification, AA: evidence.AAVerdict{Pass: true},
	}
	one, err := marshalAAPreflight(verdict)
	if err != nil {
		t.Fatal(err)
	}
	verdict.Assemblies[0], verdict.Assemblies[1] = verdict.Assemblies[1], verdict.Assemblies[0]
	two, err := marshalAAPreflight(verdict)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatalf("assembly input order changed preflight bytes:\n%s\n%s", one, two)
	}
}

func TestPrepareRejectsVerificationIdentityMismatch(t *testing.T) {
	t.Parallel()
	root := canonicalTempDir(t)
	identity := testRepositoryIdentity()
	resultPath, result := writeVerificationResult(t, root, identity)
	mismatch := identity
	mismatch.SourceHead = strings.Repeat("9", 40)
	ops := productionOperations()
	ops.collectRepositoryIdentity = func(string) (evidence.RepositoryIdentity, error) { return mismatch, nil }

	_, _, _, err := prepare(commandConfig{repoRoot: root, verificationResult: resultPath}, ops)
	if err == nil || !strings.Contains(err.Error(), "does not match the clean current source") {
		t.Fatalf("prepare() error = %v", err)
	}
	if result.Repository == mismatch {
		t.Fatal("test fixture identities unexpectedly match")
	}
}

func TestAAPreflightDoesNotPublishNonPassingVerdict(t *testing.T) {
	t.Parallel()
	root := canonicalTempDir(t)
	identity := testRepositoryIdentity()
	resultPath, _ := writeVerificationResult(t, root, identity)
	store, err := openFixedStore(root)
	if err != nil {
		t.Fatal(err)
	}
	aaInputs := makeRunInputs(t, root, store, identity, evidence.RequiredAARoles(), "aa")
	output := filepath.Join(root, ".omx", "preflight", "verdict.json")
	ops := productionOperations()
	ops.collectRepositoryIdentity = func(string) (evidence.RepositoryIdentity, error) { return identity, nil }
	ops.evaluateAA = func(string, artifact.Store, evidence.RepositoryIdentity, []evidence.RunEvidence) (evidence.AAVerdict, error) {
		return evidence.AAVerdict{Pass: false}, nil
	}

	err = runAAPreflight(commandConfig{
		repoRoot: root, verificationResult: resultPath, outputPath: output, aaInputs: aaInputs,
	}, ops)
	if err == nil || !strings.Contains(err.Error(), "did not pass") {
		t.Fatalf("runAAPreflight() error = %v", err)
	}
	if _, statErr := os.Lstat(output); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("non-passing preflight published output: %v", statErr)
	}
}

func TestBuildWritesCanonicalReceiptWithRoleBoundInputs(t *testing.T) {
	t.Parallel()
	root := canonicalTempDir(t)
	identity := testRepositoryIdentity()
	resultPath, result := writeVerificationResult(t, root, identity)
	store, err := openFixedStore(root)
	if err != nil {
		t.Fatal(err)
	}
	aaInputs := makeRunInputs(t, root, store, identity, evidence.RequiredAARoles(), "aa")
	baselineInputs := makeRunInputs(t, root, store, identity, evidence.RequiredBaselineRoles(), "baseline")
	output := filepath.Join(root, "bench", "evidence", "phase0", "current", "receipt.json")
	ops := productionOperations()
	ops.collectRepositoryIdentity = func(string) (evidence.RepositoryIdentity, error) { return identity, nil }
	ops.evaluateAA = func(_ string, gotStore artifact.Store, gotIdentity evidence.RepositoryIdentity, records []evidence.RunEvidence) (evidence.AAVerdict, error) {
		if gotStore.Root() != filepath.Join(root, filepath.FromSlash(evidence.ArtifactStorePath)) {
			t.Errorf("store root = %s", gotStore.Root())
		}
		if gotIdentity != identity {
			t.Errorf("identity mismatch")
		}
		if roles := evidenceRoles(records); !slices.Equal(roles, evidence.RequiredAARoles()) {
			t.Errorf("A/A roles = %v", roles)
		}
		return evidence.AAVerdict{Pass: true}, nil
	}

	err = runBuild(commandConfig{
		repoRoot: root, verificationResult: resultPath, outputPath: output,
		aaInputs: aaInputs, baselineInputs: baselineInputs,
	}, ops)
	if err != nil {
		t.Fatalf("runBuild(): %v", err)
	}
	receipt, err := evidence.LoadReceipt(output)
	if err != nil {
		t.Fatalf("LoadReceipt(): %v", err)
	}
	if receipt.Repository != identity || receipt.VerificationRef != result.Verification {
		t.Fatal("receipt lost verification identity")
	}
	if roles := evidenceRoles(receipt.AARuns); !slices.Equal(roles, evidence.RequiredAARoles()) {
		t.Fatalf("A/A roles = %v", roles)
	}
	if roles := evidenceRoles(receipt.BaselineRuns); !slices.Equal(roles, evidence.RequiredBaselineRoles()) {
		t.Fatalf("baseline roles = %v", roles)
	}
	if len(receipt.Assemblies) != 2 || receipt.Assemblies[0].GOARCH != "amd64" || receipt.Assemblies[1].GOARCH != "arm64" {
		t.Fatalf("assembly order = %+v", receipt.Assemblies)
	}
}

func TestWriteNewFileAtomicNeverOverwrites(t *testing.T) {
	t.Parallel()
	root := canonicalTempDir(t)
	path := filepath.Join(root, "nested", "receipt.json")
	first := []byte("first\n")
	if err := writeNewFileAtomic(root, path, first, 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeNewFileAtomic(root, path, []byte("second\n"), 0o644); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second write error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("existing output changed to %q", got)
	}
	temporaries, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".receipt.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temporaries) != 0 {
		t.Fatalf("temporary files remain: %v", temporaries)
	}
}

func TestResolvePathBelowRootRejectsEscapeAndSymlink(t *testing.T) {
	t.Parallel()
	root := canonicalTempDir(t)
	if _, err := resolvePathBelowRoot(root, filepath.Join("..", "outside")); err == nil {
		t.Fatal("path traversal was accepted")
	}
	outside := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(outside, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "receipt.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveInputPath(root, link, false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink input error = %v", err)
	}
}

func roleInputs(roles []string, path string) []rolePath {
	inputs := make([]rolePath, len(roles))
	for i, role := range roles {
		inputs[i] = rolePath{role: role, path: path}
	}
	return inputs
}

func rolePathRoles(inputs []rolePath) []string {
	roles := make([]string, len(inputs))
	for i, input := range inputs {
		roles[i] = input.role
	}
	return roles
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := canonicalRepositoryRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func evidenceRoles(records []evidence.RunEvidence) []string {
	roles := make([]string, len(records))
	for i, record := range records {
		roles[i] = record.Role
	}
	return roles
}

func testRepositoryIdentity() evidence.RepositoryIdentity {
	return evidence.RepositoryIdentity{
		PlanSHA256:        evidence.PlanSHA256,
		Remote:            evidence.ExpectedRemote,
		Branch:            evidence.ExpectedBranch,
		SourceHead:        strings.Repeat("1", 40),
		SourceTree:        strings.Repeat("2", 40),
		SourceSHA256:      strings.Repeat("3", 64),
		ModulePath:        "github.com/zchee/gows",
		ModuleFilesSHA256: strings.Repeat("4", 64),
		GoVersion:         "go version go1.26.5 darwin/arm64",
		GoBinarySHA256:    strings.Repeat("5", 64),
		GoBinarySizeBytes: 12345,
		GOOS:              "darwin",
		GOARCH:            "arm64",
		EvidencePath:      evidence.EvidencePath,
	}
}

func testRef(digit, mediaType string) artifact.Ref {
	digest := strings.Repeat(digit, 64)
	return artifact.Ref{
		URI: "omx-cas://sha256/" + digest, SHA256: digest, SizeBytes: 1, MediaType: mediaType,
	}
}

func writeVerificationResult(t *testing.T, root string, identity evidence.RepositoryIdentity) (string, phase0.Result) {
	t.Helper()
	store, err := openFixedStore(root)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(kind string) artifact.Ref {
		t.Helper()
		dir := filepath.Join(root, ".omx", "fixture-bundles", strings.ReplaceAll(kind, "/", "-"))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"kind":"`+kind+`"}`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, ref, err := artifact.SealDirectory(store, dir, kind, []string{"manifest.json"})
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	result := phase0.Result{
		SchemaVersion: phase0.ResultSchemaVersion,
		Repository:    identity,
		Verification:  seal(evidence.VerificationKind),
		Assemblies: []evidence.AssemblyEvidence{
			{GOOS: identity.GOOS, GOARCH: "arm64", Bundle: seal(evidence.AssemblyKindPrefix + identity.GOOS + "-arm64")},
			{GOOS: identity.GOOS, GOARCH: "amd64", Bundle: seal(evidence.AssemblyKindPrefix + identity.GOOS + "-amd64")},
		},
	}
	raw, err := phase0.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".omx", "verification", "result.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path, result
}

func makeRunInputs(t *testing.T, root string, store artifact.Store, identity evidence.RepositoryIdentity, roles []string, prefix string) []rolePath {
	t.Helper()
	inputs := make([]rolePath, len(roles))
	for i, role := range roles {
		directory := writeRunReceipt(t, root, store, identity, prefix+"-"+role)
		inputs[i] = rolePath{role: role, path: directory}
	}
	return inputs
}

func writeRunReceipt(t *testing.T, root string, store artifact.Store, identity evidence.RepositoryIdentity, sessionID string) string {
	t.Helper()
	put := func(data string, mediaType string) artifact.Ref {
		t.Helper()
		ref, err := store.PutBytes([]byte(data), mediaType)
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	policyRef := put(`{"fixture":"policy"}`+"\n", "application/json")
	echoRef := put("echoserver\n", "application/octet-stream")
	loadRef := put("loadgen\n", "application/octet-stream")
	adapterDigest := strings.Repeat("6", 64)
	libraryDigest := strings.Repeat("7", 64)
	meta := map[string]any{
		"session_id": sessionID, "git_commit": identity.SourceHead,
		"git_remote": identity.Remote, "git_branch": identity.Branch,
		"git_status": "", "git_dirty": false, "git_tree": identity.SourceTree,
		"source_sha256": identity.SourceSHA256, "module_path": identity.ModulePath,
		"module_files_sha256": identity.ModuleFilesSHA256,
		"go_version":          identity.GoVersion, "go_binary_sha256": identity.GoBinarySHA256,
		"goos": identity.GOOS, "goarch": identity.GOARCH, "go_experiment": "",
		"client": "gows", "echoserver_sha256": echoRef.SHA256,
		"loadgen_sha256":          loadRef.SHA256,
		"adapter_sha256":          map[string]string{"gows": adapterDigest},
		"library_binaries_sha256": map[string]string{"gows": libraryDigest},
		"policy_sha256":           policyRef.SHA256, "run_kind": "fixture",
		"evidence_class": "claim", "toolchain_series": "stock",
	}
	manifestRaw, err := jsonv2.Marshal(meta, jsonv2.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')
	files := map[string]artifact.Ref{
		"policy.json":    policyRef,
		"manifest.json":  put(string(manifestRaw), "application/json"),
		"env-start.json": put(`{"fixture":"start"}`+"\n", "application/json"),
		"env-end.json":   put(`{"fixture":"end"}`+"\n", "application/json"),
		"samples.jsonl":  put(`{"fixture":"sample"}`+"\n", "application/x-ndjson"),
		"done.json":      put(`{"fixture":"done"}`+"\n", "application/json"),
		"echoserver":     echoRef,
		"loadgen":        loadRef,
	}
	receipt := artifact.RunReceipt{
		SchemaVersion: artifact.RunReceiptSchemaVersion,
		SessionID:     sessionID, SourceHead: identity.SourceHead,
		GitRemote: identity.Remote, GitBranch: identity.Branch, GitTree: identity.SourceTree,
		SourceSHA256: identity.SourceSHA256, ModulePath: identity.ModulePath,
		ModuleFilesSHA256: identity.ModuleFilesSHA256, GoVersion: identity.GoVersion,
		GoBinarySHA256: identity.GoBinarySHA256, GOOS: identity.GOOS, GOARCH: identity.GOARCH,
		Client: "gows", EchoserverSHA256: echoRef.SHA256, LoadgenSHA256: loadRef.SHA256,
		AdapterSHA256:       map[string]string{"gows": adapterDigest},
		LibraryBinarySHA256: map[string]string{"gows": libraryDigest},
		PolicySHA256:        policyRef.SHA256, RunKind: "fixture", EvidenceClass: "claim",
		ToolchainSeries: "stock", Files: files,
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("fixture receipt: %v", err)
	}
	raw, err := jsonv2.Marshal(receipt, jsonv2.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	directory := filepath.Join(root, ".omx", "fixture-runs", sessionID)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "receipt.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return directory
}
