package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVerificationBundleRoundTripAndFailClosedMutations(t *testing.T) {
	identity := testReceipt().Repository
	dir := t.TempDir()
	inputs := validVerificationInputs(dir)
	manifest := validVerificationManifest(t, dir, identity, inputs)
	raw, err := MarshalVerificationManifest(manifest, identity, inputs)
	if err != nil {
		t.Fatalf("marshal verification manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateVerificationBundle(dir, identity, inputs); err != nil {
		t.Fatalf("validate complete verification bundle: %v", err)
	}

	stdout := filepath.Join(dir, filepath.FromSlash(manifest.Checks[0].StdoutPath))
	if err := os.WriteFile(stdout, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateVerificationBundle(dir, identity, inputs); err == nil {
		t.Fatal("verification bundle accepted a stale stdout hash")
	}
}

func TestVerificationRecordRejectsMissingOverlapAndMutableRequiredList(t *testing.T) {
	identity := testReceipt().Repository
	dir := t.TempDir()
	inputs := validVerificationInputs(dir)
	manifest := validVerificationManifest(t, dir, identity, inputs)

	missing := cloneVerificationManifest(manifest)
	missing.Checks = missing.Checks[:len(missing.Checks)-1]
	if _, err := MarshalVerificationManifest(missing, identity, inputs); err == nil {
		t.Fatal("verification manifest accepted a missing required check")
	}

	overlap := cloneVerificationManifest(manifest)
	overlap.Checks[1].StartedAt = overlap.Checks[0].StartedAt
	if _, err := MarshalVerificationManifest(overlap, identity, inputs); err == nil {
		t.Fatal("verification manifest accepted overlapping commands")
	}

	ids := RequiredVerificationChecks()
	ids[0] = "mutated"
	if RequiredVerificationChecks()[0] != "root-test" {
		t.Fatal("RequiredVerificationChecks returned mutable package state")
	}
}

func TestVerificationRecordRejectsCommandSubstitutionAndNarrowing(t *testing.T) {
	identity := testReceipt().Repository
	dir := t.TempDir()
	inputs := validVerificationInputs(dir)
	base := validVerificationManifest(t, dir, identity, inputs)

	// Resolve check positions by ID so an inserted check cannot silently
	// repoint a mutation at the wrong entry while the test keeps passing.
	buildAMD64 := slices.Index(RequiredVerificationChecks(), "build-amd64")
	assemblyAMD64 := slices.Index(RequiredVerificationChecks(), "assembly-amd64")
	formatIndex := slices.Index(RequiredVerificationChecks(), "format")
	staticIndex := slices.Index(RequiredVerificationChecks(), "static")
	diffIndex := slices.Index(RequiredVerificationChecks(), "diff-check")

	tests := map[string]func(*VerificationManifest){
		"legacy boot identity": func(m *VerificationManifest) {
			m.BootIdentity = "{ sec = 1, usec = 2 }"
		},
		"missing tool identity": func(m *VerificationManifest) {
			m.Tools = m.Tools[:len(m.Tools)-1]
		},
		"tool byte identity substitution": func(m *VerificationManifest) {
			m.Tools[2].SHA256 = strings.Repeat("f", 64)
		},
		"tool version substitution": func(m *VerificationManifest) {
			m.Tools[3].Version = "git version forged"
		},
		"true masquerades as root test": func(m *VerificationManifest) {
			m.Checks[0].Argv = []string{"/bin/true", "test", "./...", "-count=1"}
		},
		"extra test narrowing argument": func(m *VerificationManifest) {
			m.Checks[0].Argv = append(m.Checks[0].Argv, "-run", "TestSmall")
		},
		"wrong working directory": func(m *VerificationManifest) {
			m.Checks[0].WorkingDir = "bench"
		},
		"missing controlled environment": func(m *VerificationManifest) {
			m.Checks[0].Environment = m.Checks[0].Environment[1:]
		},
		"extra environment": func(m *VerificationManifest) {
			m.Checks[0].Environment = append(m.Checks[0].Environment, "SECRET=value")
			slices.Sort(m.Checks[0].Environment)
		},
		"HOME substitution": func(m *VerificationManifest) {
			m.Checks[0].Environment = replaceTestEnvironment(m.Checks[0].Environment, "HOME=/tmp/attacker-home")
		},
		"TMPDIR substitution": func(m *VerificationManifest) {
			m.Checks[0].Environment = replaceTestEnvironment(m.Checks[0].Environment, "TMPDIR=/tmp/attacker-tmp")
		},
		"wrong build architecture": func(m *VerificationManifest) {
			m.Checks[buildAMD64].Environment = verificationEnvironment(inputs, identity.GOOS, "arm64")
		},
		"build outside verification work root": func(m *VerificationManifest) {
			m.Checks[buildAMD64].Argv[4] = filepath.Join(dir, "gows-amd64.test")
		},
		"assembly outside verification output": func(m *VerificationManifest) {
			m.Checks[assemblyAMD64].Argv[10] = filepath.Join(dir, "darwin-amd64")
		},
		"format omits tracked source": func(m *VerificationManifest) {
			m.Checks[formatIndex].Argv = m.Checks[formatIndex].Argv[:len(m.Checks[formatIndex].Argv)-1]
		},
		"static executable substitution": func(m *VerificationManifest) {
			m.Checks[staticIndex].Argv[0] = "/bin/true"
		},
		"diff executable substitution": func(m *VerificationManifest) {
			m.Checks[diffIndex].Argv[0] = "/bin/true"
		},
		"noncanonical log path": func(m *VerificationManifest) {
			m.Checks[0].StdoutPath = "logs/root-test.stdout.log"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := cloneVerificationManifest(base)
			mutate(&manifest)
			if _, err := MarshalVerificationManifest(manifest, identity, inputs); err == nil {
				t.Fatal("verification manifest accepted forged command record")
			}
		})
	}
}

func validVerificationInputs(root string) VerificationCommandInputs {
	inputs := VerificationCommandInputs{
		RepositoryRoot: root,
		GoTool:         filepath.Join(root, "tools", "go"),
		Gofmt:          filepath.Join(root, "tools", "gofmt"),
		Gopls:          filepath.Join(root, "tools", "gopls"),
		Git:            filepath.Join(root, "tools", "git"),
		HomeDir:        filepath.Join(root, "home"),
		TempDir:        filepath.Join(root, "tmp"),
		TrackedGoFiles: []string{"a.go", "bench/b.go", "flatekp/c.go"},
	}
	inputs.Tools = testVerificationToolIdentities(inputs, strings.Repeat("5", 64), 100)
	return inputs
}

func testVerificationToolIdentities(inputs VerificationCommandInputs, goSHA string, goSize int64) []VerificationToolIdentity {
	return []VerificationToolIdentity{
		{Name: "go", Path: inputs.GoTool, SizeBytes: goSize, SHA256: goSHA, Version: "go build info"},
		{Name: "gofmt", Path: inputs.Gofmt, SizeBytes: 2, SHA256: strings.Repeat("6", 64), Version: "gofmt build info"},
		{Name: "gopls", Path: inputs.Gopls, SizeBytes: 3, SHA256: strings.Repeat("7", 64), Version: "gopls build info"},
		{Name: "git", Path: inputs.Git, SizeBytes: 4, SHA256: strings.Repeat("8", 64), Version: "git version test"},
	}
}

func validVerificationManifest(t *testing.T, dir string, identity RepositoryIdentity, inputs VerificationCommandInputs) VerificationManifest {
	t.Helper()
	work := filepath.Join(inputs.RepositoryRoot, ".omx", ".phase0verify-work-fixture")
	assembly := filepath.Join(inputs.RepositoryRoot, ".omx", "phase0-verification-fixture", "assembly")
	commands := map[string][]string{
		"root-test":    {inputs.GoTool, "test", "./...", "-count=1"},
		"root-vet":     {inputs.GoTool, "vet", "./..."},
		"root-race":    {inputs.GoTool, "test", "-race", "./...", "-count=1"},
		"bench-test":   {inputs.GoTool, "test", "./...", "-count=1"},
		"bench-vet":    {inputs.GoTool, "vet", "./..."},
		"flatekp-test": {inputs.GoTool, "test", "./...", "-count=1"},
		"flatekp-vet":  {inputs.GoTool, "vet", "./..."},
		"build-amd64":  {inputs.GoTool, "test", "-c", "-o", filepath.Join(work, "gows-amd64.test"), "."},
		"build-arm64":  {inputs.GoTool, "test", "-c", "-o", filepath.Join(work, "gows-arm64.test"), "."},
		"assembly-amd64": {
			inputs.GoTool, "run", "./harness/cmd/asmprobe", "-repo", inputs.RepositoryRoot,
			"-goos", "darwin", "-goarch", "amd64", "-out", filepath.Join(assembly, "darwin-amd64"), "-runtime", "required",
		},
		"assembly-arm64": {
			inputs.GoTool, "run", "./harness/cmd/asmprobe", "-repo", inputs.RepositoryRoot,
			"-goos", "darwin", "-goarch", "arm64", "-out", filepath.Join(assembly, "darwin-arm64"), "-runtime", "required",
		},
		"micro-allocations": {
			inputs.GoTool, "test", "-run", MicroAllocationTestPattern, "-count=1", ".",
			"./internal/extension", "./internal/httpx", "./internal/pool", "./internal/utf8x",
		},
		"format":     append([]string{inputs.Gofmt, "-d"}, inputs.TrackedGoFiles...),
		"static":     append([]string{inputs.Gopls, "check"}, inputs.TrackedGoFiles...),
		"diff-check": {inputs.Git, "diff", "--check"},
	}
	workingDirs := map[string]string{
		"bench-test": "bench", "bench-vet": "bench",
		"flatekp-test": "flatekp", "flatekp-vet": "flatekp",
		"assembly-amd64": "bench", "assembly-arm64": "bench",
	}
	base := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	checks := make([]VerificationCheck, 0, len(requiredVerificationChecks))
	for i, id := range RequiredVerificationChecks() {
		stdoutPath := filepath.ToSlash(filepath.Join("logs", strings.Join([]string{twoDigits(i + 1), id}, "-")+".stdout.log"))
		stderrPath := filepath.ToSlash(filepath.Join("logs", strings.Join([]string{twoDigits(i + 1), id}, "-")+".stderr.log"))
		stdout := []byte("ok " + id + "\n")
		if id == "format" {
			stdout = nil
		}
		stderr := []byte{}
		writeVerificationArtifact(t, dir, stdoutPath, stdout)
		writeVerificationArtifact(t, dir, stderrPath, stderr)
		started := base.Add(time.Duration(2*i) * time.Second)
		workingDir := workingDirs[id]
		if workingDir == "" {
			workingDir = "."
		}
		arch := identity.GOARCH
		switch id {
		case "build-amd64":
			arch = "amd64"
		case "build-arm64":
			arch = "arm64"
		}
		checks = append(checks, VerificationCheck{
			ID: id, Argv: slices.Clone(commands[id]), WorkingDir: workingDir,
			Environment: verificationEnvironment(inputs, identity.GOOS, arch),
			StartedAt:   started.Format(time.RFC3339Nano), EndedAt: started.Add(time.Second).Format(time.RFC3339Nano), ExitCode: 0,
			StdoutPath: stdoutPath, StdoutSHA256: sha256Hex(stdout), StderrPath: stderrPath, StderrSHA256: sha256Hex(stderr),
		})
	}
	return VerificationManifest{
		SchemaVersion: VerificationSchemaVersion, SourceHead: identity.SourceHead, SourceTree: identity.SourceTree,
		ModuleFilesSHA256: identity.ModuleFilesSHA256, GoVersion: identity.GoVersion, GoBinarySHA256: identity.GoBinarySHA256,
		GOOS: identity.GOOS, GOARCH: identity.GOARCH, Hostname: "host", BootIdentity: "darwin:kern.bootsessionuuid=test-boot",
		Tools: slices.Clone(inputs.Tools), Checks: checks,
	}
}

func verificationEnvironment(inputs VerificationCommandInputs, goos, goarch string) []string {
	environment := []string{
		"CGO_ENABLED=0", "GOARCH=" + goarch, "GOENV=off", "GOEXPERIMENT=", "GOFIPS140=latest",
		"GOFLAGS=-mod=mod", "GOOS=" + goos, "GOTELEMETRY=off", "GOTOOLCHAIN=local", "GOWORK=off",
		"HOME=" + inputs.HomeDir, "LANG=C", "LC_ALL=C",
		"PATH=" + strings.Join([]string{filepath.Dir(inputs.GoTool), "/usr/bin", "/bin", "/usr/sbin", "/sbin"}, string(os.PathListSeparator)),
		"TMPDIR=" + inputs.TempDir,
	}
	slices.Sort(environment)
	return environment
}

func replaceTestEnvironment(environment []string, replacement string) []string {
	key, _, _ := strings.Cut(replacement, "=")
	result := slices.Clone(environment)
	for i, assignment := range result {
		got, _, _ := strings.Cut(assignment, "=")
		if got == key {
			result[i] = replacement
			slices.Sort(result)
			return result
		}
	}
	panic("replaceTestEnvironment: environment lacks key " + key)
}

func cloneVerificationManifest(manifest VerificationManifest) VerificationManifest {
	clone := manifest
	clone.Tools = slices.Clone(manifest.Tools)
	clone.Checks = make([]VerificationCheck, len(manifest.Checks))
	for i, check := range manifest.Checks {
		clone.Checks[i] = check
		clone.Checks[i].Argv = slices.Clone(check.Argv)
		clone.Checks[i].Environment = slices.Clone(check.Environment)
	}
	return clone
}

func twoDigits(value int) string {
	return string([]byte{'0' + byte(value/10), '0' + byte(value%10)})
}

func writeVerificationArtifact(t *testing.T, dir, relative string, contents []byte) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
