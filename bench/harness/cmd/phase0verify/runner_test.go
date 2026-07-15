package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stdjson "encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows/bench/harness/evidence"
)

func TestCommandSpecsMatchEvaluatorContract(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "repo")
	output := filepath.Join(root, ".omx", "verification")
	work := filepath.Join(root, ".omx", ".phase0verify-work-test")
	tracked := []string{"a.go", "bench/b.go", "flatekp/c.go"}
	inputs := evidence.VerificationCommandInputs{
		RepositoryRoot: root,
		GoTool:         filepath.Join(runtime.GOROOT(), "bin", "go"),
		Gofmt:          filepath.Join(runtime.GOROOT(), "bin", "gofmt"),
		Gopls:          filepath.Join(root, "tools", "gopls"),
		Git:            filepath.Join(root, "tools", "git"),
		HomeDir:        filepath.Join(root, "home"),
		TempDir:        filepath.Join(root, "tmp"),
		TrackedGoFiles: tracked,
	}
	inputs.Tools = []evidence.VerificationToolIdentity{
		{Name: "go", Path: inputs.GoTool, SizeBytes: 1, SHA256: strings.Repeat("e", 64), Version: "go build info"},
		{Name: "gofmt", Path: inputs.Gofmt, SizeBytes: 2, SHA256: strings.Repeat("a", 64), Version: "gofmt build info"},
		{Name: "gopls", Path: inputs.Gopls, SizeBytes: 3, SHA256: strings.Repeat("b", 64), Version: "gopls build info"},
		{Name: "git", Path: inputs.Git, SizeBytes: 4, SHA256: strings.Repeat("c", 64), Version: "git version test"},
	}
	specs, err := buildCommandSpecs(root, output, work, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCommandOrder(specs); err != nil {
		t.Fatal(err)
	}
	gotIDs := make([]string, len(specs))
	for i, spec := range specs {
		gotIDs[i] = spec.id
		assertControlledEnvironment(t, spec.environment)
	}
	if want := evidence.RequiredVerificationChecks(); !slices.Equal(gotIDs, want) {
		t.Fatalf("check IDs = %v, want %v", gotIDs, want)
	}
	assertArgv(t, specs[0].argv, inputs.GoTool, "test", "./...", "-count=1")
	assertArgv(t, specs[1].argv, inputs.GoTool, "vet", "./...")
	assertArgv(t, specs[2].argv, inputs.GoTool, "test", "-race", "./...", "-count=1")
	assertArgv(t, specs[3].argv, inputs.GoTool, "test", "./...", "-count=1")
	assertArgv(t, specs[4].argv, inputs.GoTool, "vet", "./...")
	assertArgv(t, specs[5].argv, inputs.GoTool, "test", "./...", "-count=1")
	assertArgv(t, specs[6].argv, inputs.GoTool, "vet", "./...")
	for index, arch := range []string{"amd64", "arm64"} {
		build := specs[7+index]
		if !slices.Contains(build.environment, "GOOS=darwin") || !slices.Contains(build.environment, "GOARCH="+arch) {
			t.Fatalf("%s environment = %v", build.id, build.environment)
		}
		if !slices.Contains(build.argv, "-c") || !slices.Contains(build.argv, filepath.Join(work, "gows-"+arch+".test")) {
			t.Fatalf("%s is not a compile-link check: %v", build.id, build.argv)
		}
		assembly := specs[9+index]
		joined := strings.Join(assembly.argv, " ")
		for _, required := range []string{"./harness/cmd/asmprobe", "-goos darwin", "-goarch " + arch, "-runtime required"} {
			if !strings.Contains(joined, required) {
				t.Fatalf("%s argv lacks %q: %v", assembly.id, required, assembly.argv)
			}
		}
		if assembly.assembly == nil || assembly.assembly.goarch != arch {
			t.Fatalf("%s assembly output = %#v", assembly.id, assembly.assembly)
		}
	}
	micro := specs[11]
	if !strings.Contains(strings.Join(micro.argv, " "), "(?i)^(testappendheaderallocs") {
		t.Fatalf("micro allocation regex is not explicit: %v", micro.argv)
	}
	format := specs[12]
	if !format.requireEmptyStdout || !slices.Equal(format.argv[2:], tracked) {
		t.Fatalf("format spec = %#v", format)
	}
	static := specs[13]
	if !slices.Equal(static.argv[2:], tracked) {
		t.Fatalf("static spec = %#v", static)
	}
	checks := make([]evidence.VerificationCheck, len(specs))
	baseTime := time.Date(2026, 7, 15, 6, 0, 0, 0, time.UTC)
	for i, spec := range specs {
		checks[i] = evidence.VerificationCheck{
			ID: spec.id, Argv: spec.argv, WorkingDir: spec.workingDirectory,
			Environment: spec.environment,
			StartedAt:   baseTime.Add(time.Duration(i*2) * time.Second).Format(time.RFC3339Nano),
			EndedAt:     baseTime.Add(time.Duration(i*2+1) * time.Second).Format(time.RFC3339Nano),
			ExitCode:    0,
			StdoutPath:  fmt.Sprintf("logs/%02d-%s.stdout.log", i+1, spec.id), StdoutSHA256: strings.Repeat("a", 64),
			StderrPath: fmt.Sprintf("logs/%02d-%s.stderr.log", i+1, spec.id), StderrSHA256: strings.Repeat("b", 64),
		}
	}
	repository := validRepositoryIdentity()
	manifest := evidence.VerificationManifest{
		SchemaVersion: evidence.VerificationSchemaVersion,
		SourceHead:    repository.SourceHead, SourceTree: repository.SourceTree,
		ModuleFilesSHA256: repository.ModuleFilesSHA256,
		GoVersion:         repository.GoVersion, GoBinarySHA256: repository.GoBinarySHA256,
		GOOS: repository.GOOS, GOARCH: repository.GOARCH,
		Hostname: "test-host", BootIdentity: "test-boot",
		Tools: slices.Clone(inputs.Tools), Checks: checks,
	}
	if _, err := evidence.MarshalVerificationManifest(manifest, repository, inputs); err != nil {
		t.Fatalf("generated command specs do not satisfy evaluator schema: %v", err)
	}
}

func TestExecutePlanIsSequentialAndStopsOnFailure(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	inputs := evidence.VerificationCommandInputs{
		RepositoryRoot: root,
		GoTool:         filepath.Join(runtime.GOROOT(), "bin", "go"), Gofmt: filepath.Join(runtime.GOROOT(), "bin", "gofmt"),
		Gopls: filepath.Join(root, "gopls"), Git: filepath.Join(root, "git"),
		HomeDir: filepath.Join(root, "home"), TempDir: filepath.Join(root, "tmp"),
		TrackedGoFiles: []string{"a.go"},
	}
	specs, err := buildCommandSpecs(root, filepath.Join(root, "out"), filepath.Join(root, "work"), inputs)
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	checks, assemblies, err := executePlan(specs,
		func(index int, spec commandSpec) (evidence.VerificationCheck, error) {
			events = append(events, "execute:"+spec.id)
			return evidence.VerificationCheck{ID: spec.id}, nil
		},
		func(spec commandSpec) (evidence.AssemblyEvidence, error) {
			events = append(events, "seal:"+spec.id)
			return evidence.AssemblyEvidence{GOOS: spec.assembly.goos, GOARCH: spec.assembly.goarch}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != len(specs) || len(assemblies) != 2 {
		t.Fatalf("checks=%d assemblies=%d", len(checks), len(assemblies))
	}
	for i := 1; i < len(checks); i++ {
		if checks[i-1].ID != specs[i-1].id || checks[i].ID != specs[i].id {
			t.Fatalf("execution order changed at %d", i)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		executeIndex := slices.Index(events, "execute:assembly-"+arch)
		sealIndex := slices.Index(events, "seal:assembly-"+arch)
		if executeIndex < 0 || sealIndex != executeIndex+1 {
			t.Fatalf("assembly %s was not sealed immediately after execution: %v", arch, events)
		}
	}

	events = nil
	checks, assemblies, err = executePlan(specs,
		func(index int, spec commandSpec) (evidence.VerificationCheck, error) {
			events = append(events, spec.id)
			if spec.id == "bench-test" {
				return evidence.VerificationCheck{}, errors.New("injected failure")
			}
			return evidence.VerificationCheck{ID: spec.id}, nil
		},
		func(spec commandSpec) (evidence.AssemblyEvidence, error) {
			t.Fatal("assembly sealer called after earlier failure")
			return evidence.AssemblyEvidence{}, nil
		})
	if err == nil || len(checks) != 3 || len(assemblies) != 0 {
		t.Fatalf("failure result checks=%d assemblies=%d err=%v", len(checks), len(assemblies), err)
	}
	if got, want := events[len(events)-1], "bench-test"; got != want {
		t.Fatalf("last executed check = %q, want %q", got, want)
	}
}

func TestExecuteCommandCapturesLogsExitAndEmptyOutputGate(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("success", func(t *testing.T) {
		spec := helperSpec(executable, "success", "hello", "warning", 0)
		check, err := executeCommand(context.Background(), root, logs, 0, spec, advancingClock())
		if err != nil {
			t.Fatal(err)
		}
		if check.ExitCode != 0 || check.StdoutSHA256 != sumString("hello") || check.StderrSHA256 != sumString("warning") {
			t.Fatalf("check = %#v", check)
		}
		assertFile(t, filepath.Join(root, "logs", "01-success.stdout.log"), "hello")
		assertFile(t, filepath.Join(root, "logs", "01-success.stderr.log"), "warning")
	})

	t.Run("nonzero logs are preserved", func(t *testing.T) {
		spec := helperSpec(executable, "failure", "partial", "fatal", 7)
		check, err := executeCommand(context.Background(), root, logs, 1, spec, advancingClock())
		if err == nil || check.ExitCode != 7 {
			t.Fatalf("check=%#v err=%v", check, err)
		}
		assertFile(t, filepath.Join(root, "logs", "02-failure.stdout.log"), "partial")
		assertFile(t, filepath.Join(root, "logs", "02-failure.stderr.log"), "fatal")
	})

	t.Run("format output fails closed", func(t *testing.T) {
		spec := helperSpec(executable, "format", "diff", "", 0)
		spec.requireEmptyStdout = true
		check, err := executeCommand(context.Background(), root, logs, 2, spec, advancingClock())
		if err == nil || check.ExitCode != 0 || !strings.Contains(err.Error(), "forbidden stdout") {
			t.Fatalf("check=%#v err=%v", check, err)
		}
	})
}

func TestOutputInvalidationAndAtomicNoOverwrite(t *testing.T) {
	t.Parallel()

	parent := t.TempDir()
	fixed := time.Date(2026, 7, 15, 6, 0, 0, 0, time.UTC)
	output := filepath.Join(parent, "run")
	tx, err := beginOutput(output, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	tx.stage = "root-race"
	tx.source = strings.Repeat("a", 40)
	if err := tx.invalidate(errors.New("injected gate failure")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(output, "INVALIDATED.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record invalidation
	if err := stdjson.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Stage != "root-race" || record.Reason != "injected gate failure" || record.FailedAt != fixed.Format(time.RFC3339Nano) {
		t.Fatalf("invalidation = %#v", record)
	}
	if _, err := os.Stat(filepath.Join(output, "result.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed output published result.json: %v", err)
	}

	sentinel := filepath.Join(output, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := beginOutput(output, time.Now); err == nil {
		t.Fatal("beginOutput overwrote an existing destination")
	}
	assertFile(t, sentinel, "keep")

	atomicPath := filepath.Join(parent, "atomic.json")
	if err := writeNewFileAtomic(atomicPath, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFileAtomic(atomicPath, []byte("second"), 0o644); err == nil {
		t.Fatal("writeNewFileAtomic replaced an existing file")
	}
	assertFile(t, atomicPath, "first")
	if matches, err := filepath.Glob(filepath.Join(parent, ".atomic.json.tmp-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v err=%v", matches, err)
	}
}

func TestPhase0VerifyHelperProcess(t *testing.T) {
	if os.Getenv("GO_PHASE0VERIFY_HELPER") != "1" {
		return
	}
	separator := slices.Index(os.Args, "--")
	if separator < 0 || len(os.Args) != separator+4 {
		os.Exit(99)
	}
	_, _ = fmt.Fprint(os.Stdout, os.Args[separator+1])
	_, _ = fmt.Fprint(os.Stderr, os.Args[separator+2])
	code, err := strconv.Atoi(os.Args[separator+3])
	if err != nil {
		os.Exit(98)
	}
	os.Exit(code)
}

func helperSpec(executable, id, stdout, stderr string, exitCode int) commandSpec {
	return commandSpec{
		id:               id,
		argv:             []string{executable, "-test.run=^TestPhase0VerifyHelperProcess$", "--", stdout, stderr, strconv.Itoa(exitCode)},
		workingDirectory: ".",
		environment:      []string{"GO_PHASE0VERIFY_HELPER=1"},
	}
}

func advancingClock() func() time.Time {
	value := time.Date(2026, 7, 15, 6, 0, 0, 0, time.UTC)
	return func() time.Time {
		result := value
		value = value.Add(time.Second)
		return result
	}
}

func assertControlledEnvironment(t *testing.T, environment []string) {
	t.Helper()
	for _, required := range []string{"GOENV=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=", "GOFLAGS=-mod=mod", "GOFIPS140=latest", "CGO_ENABLED=0"} {
		if !slices.Contains(environment, required) {
			t.Fatalf("environment lacks %q: %v", required, environment)
		}
	}
	allowed := map[string]bool{
		"CGO_ENABLED": true, "GOARCH": true, "GOENV": true, "GOEXPERIMENT": true,
		"GOFIPS140": true, "GOFLAGS": true, "GOOS": true, "GOTELEMETRY": true,
		"GOTOOLCHAIN": true, "GOWORK": true, "HOME": true, "LANG": true,
		"LC_ALL": true, "PATH": true, "TMPDIR": true,
	}
	for _, value := range environment {
		key, _, ok := strings.Cut(value, "=")
		if !ok || !allowed[key] {
			t.Fatalf("environment contains unapproved field %q", value)
		}
	}
}

func assertArgv(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != want {
		t.Fatalf("%s = %q, want %q", path, raw, want)
	}
}

func sumString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validRepositoryIdentity() evidence.RepositoryIdentity {
	return evidence.RepositoryIdentity{
		PlanSHA256: evidence.PlanSHA256, Remote: evidence.ExpectedRemote,
		Branch: evidence.ExpectedBranch, SourceHead: strings.Repeat("a", 40),
		SourceTree: strings.Repeat("b", 40), SourceSHA256: strings.Repeat("c", 64),
		ModulePath: "github.com/zchee/gows", ModuleFilesSHA256: strings.Repeat("d", 64),
		GoVersion:      "go version go1.26.5 darwin/arm64",
		GoBinarySHA256: strings.Repeat("e", 64), GoBinarySizeBytes: 1,
		GOOS: "darwin", GOARCH: "arm64", EvidencePath: evidence.EvidencePath,
	}
}
