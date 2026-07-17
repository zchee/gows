// Command benchrun executes a policy's paired candidate-vs-comparator
// scenario matrix under strict host hygiene, spawning a fresh echoserver and
// loadgen process pair per repetition and recording one JSON sample line per
// (scenario, library, repetition) to samples.jsonl. Resource accounting comes
// only from each child process's rusage, never from wrapping net.Conn on a
// gating path. See bench/README.md for the full methodology.
package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

const (
	// lockPath is the exclusive whole-host benchrun lock.
	lockPath = "/tmp/gows-benchrun.lock"
	// basePort and debugPortBase are the low ends of the two ports benchrun
	// alternates across successive server starts to dodge TIME_WAIT.
	basePort      = 19301
	debugPortBase = 20301
	// dialTimeout bounds how long benchrun waits for a freshly spawned
	// echoserver to accept TCP connections.
	dialTimeout = 10 * time.Second
	// moduleImport is the bench module's import path, used to build the
	// echoserver and loadgen binaries and to locate the module root.
	moduleImport = "github.com/zchee/gows/bench"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "benchrun: %v\n", err)
		os.Exit(1)
	}
}

func run() (resultErr error) {
	policyPath := flag.String("policy", "", "path to the policy JSON file (required)")
	outFlag := flag.String("out", "", "run output directory (default .omx/bench/<toolchain>/<evidence-class>/<host-mode>/<run-kind>/<series>/<session>-<head>)")
	smoke := flag.Bool("smoke", false, "short diagnostic execution; accepted only by a diagnostic policy")
	clientOverride := flag.String("client", "", "optional client assertion; must equal policy series.client")
	sessionFlag := flag.String("session-id", "", "explicit immutable session identifier (default generated)")
	flag.Parse()

	if *policyPath == "" {
		return errors.New("-policy is required")
	}
	pol, rawPolicy, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	if pol.Series.Toolchain == policy.ToolchainStock && pol.Series.RunKind != policy.RunKindDiagnostic && strings.Contains(runtime.Version(), "-X:") {
		return fmt.Errorf("final stock evidence requires a stock benchrun controller; runtime version is %q", runtime.Version())
	}
	client := string(pol.Series.Client)
	if *clientOverride != "" && *clientOverride != client {
		return fmt.Errorf("-client %q does not match policy series.client %q", *clientOverride, client)
	}
	if *smoke && pol.Series.RunKind != policy.RunKindDiagnostic {
		return fmt.Errorf("-smoke is non-promotable and requires a diagnostic policy, got run_kind %q", pol.Series.RunKind)
	}
	sessionID := *sessionFlag
	if sessionID == "" {
		sessionID, err = newSessionID()
		if err != nil {
			return err
		}
	}
	if !validRunArtifactID(sessionID) {
		return fmt.Errorf("session ID %q is not a path-safe artifact identifier", sessionID)
	}
	policySum := policy.Sum(rawPolicy)

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}
	moduleRoot, err := findModuleRoot(cwd)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 1. Host guard: exclusive lock, load average, foreign processes.
	release, err := acquireLock(lockPath)
	if err != nil {
		return err
	}
	defer release()

	if err := checkLoad(pol.Guard.MaxLoad1); err != nil {
		return err
	}
	if err := checkProcessHygiene(pol.Guard.ForbiddenProcessPatterns, ownedPIDs(), pol.Guard.MaxForeignCPUPercent); err != nil {
		return err
	}

	// 2. Provenance.
	commit, err := gitOutput(moduleRoot, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	shortCommit, err := gitOutput(moduleRoot, "rev-parse", "--short", "HEAD")
	if err != nil {
		return err
	}
	dirty, err := gitDirty(moduleRoot)
	if err != nil {
		return err
	}
	if dirty && pol.Series.RunKind != policy.RunKindDiagnostic {
		return fmt.Errorf("final evidence requires a clean worktree; git status is dirty")
	}
	goExperiment := pol.Series.GoExperiment
	toolchainEnvironment := canonicalToolchainEnvironment(goExperiment)
	runtimeEnvironment := canonicalRuntimeEnvironment()
	childEnvironment := overrideEnvironment(os.Environ(), append(toolchainEnvironment.assignments(), runtimeEnvironment.assignments()...)...)

	out := *outFlag
	if out == "" {
		out = defaultOutDir(moduleRoot, pol, sessionID, shortCommit)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return fmt.Errorf("create out parent %s: %w", filepath.Dir(out), err)
	}
	if err := os.Mkdir(out, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output directory already exists and cannot be resumed or overwritten: %s", out)
		}
		return fmt.Errorf("create out dir %s: %w", out, err)
	}
	stage := "output-created"
	samplesWritten := 0
	completed := false
	defer func() {
		if completed {
			return
		}
		reason := "benchrun returned before completing and sealing the run"
		if resultErr != nil {
			reason = resultErr.Error()
		} else {
			resultErr = errors.New(reason)
		}
		marker := Invalidated{
			SchemaVersion: 1,
			At:            nowRFC(), Reason: reason, Stage: stage,
			SessionID: sessionID, GitCommit: commit, PolicySHA256: policySum,
			RunKind: string(pol.Series.RunKind), SamplesWritten: samplesWritten,
		}
		if err := support.WriteJSONFile(filepath.Join(out, "INVALIDATED.json"), marker); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("write invalidation marker: %w", err))
		}
	}()

	stage = "build-binaries"
	echoserverBin := filepath.Join(out, "echoserver")
	loadgenBin := filepath.Join(out, "loadgen")
	if err := buildBinaryEnv(ctx, moduleRoot, "/harness/cmd/echoserver", echoserverBin, goExperiment, nil); err != nil {
		return err
	}
	if err := buildBinaryEnv(ctx, moduleRoot, "/harness/cmd/loadgen", loadgenBin, goExperiment, nil); err != nil {
		return err
	}

	if err := support.WriteFileAtomic(filepath.Join(out, "policy.json"), rawPolicy, 0o644); err != nil {
		return fmt.Errorf("copy policy: %w", err)
	}

	echoSum, err := sha256File(echoserverBin)
	if err != nil {
		return err
	}
	loadSum, err := sha256File(loadgenBin)
	if err != nil {
		return err
	}
	goTool := goToolPath()
	goToolSum, err := sha256File(goTool)
	if err != nil {
		return err
	}
	goToolInfo, err := os.Stat(goTool)
	if err != nil {
		return fmt.Errorf("stat Go tool: %w", err)
	}

	// Resolve candidate and comparator through any library overrides, then
	// build a dedicated echoserver binary for each override that sets a build
	// environment (build_env). Overrides that only append server_args reuse the
	// shared default echoserver binary; with no overrides, resolved is the
	// identity mapping and no extra binaries are built.
	resolved := map[string]policy.Resolved{
		pol.Candidate:  pol.Resolve(pol.Candidate),
		pol.Comparator: pol.Resolve(pol.Comparator),
	}
	adapterSums := make(map[string]string, 2)
	for _, name := range []string{pol.Candidate, pol.Comparator} {
		sum, err := policy.HashAdapter(moduleRoot, pol.Adapters[name])
		if err != nil {
			return fmt.Errorf("adapter %q: %w", name, err)
		}
		adapterSums[name] = sum
	}
	binPaths := map[string]string{}
	var overrideSums map[string]string
	for _, name := range []string{pol.Candidate, pol.Comparator} {
		r := resolved[name]
		if r.Bin == "" {
			binPaths[name] = echoserverBin
			continue
		}
		bin := filepath.Join(out, "echoserver-"+r.Bin)
		if err := buildBinaryEnv(ctx, moduleRoot, "/harness/cmd/echoserver", bin, goExperiment, r.BuildEnv); err != nil {
			return err
		}
		sum, err := sha256File(bin)
		if err != nil {
			return err
		}
		binPaths[name] = bin
		if overrideSums == nil {
			overrideSums = map[string]string{}
		}
		overrideSums[r.Bin] = sum
	}
	binarySums := make(map[string]string, 2)
	for _, name := range []string{pol.Candidate, pol.Comparator} {
		sum, err := sha256File(binPaths[name])
		if err != nil {
			return err
		}
		binarySums[name] = sum
	}
	if pol.Series.RunKind == policy.RunKindAA && binarySums[pol.Candidate] != binarySums[pol.Comparator] {
		return fmt.Errorf("A/A labels resolved to different binary hashes: %s=%s %s=%s", pol.Candidate, binarySums[pol.Candidate], pol.Comparator, binarySums[pol.Comparator])
	}
	allBinaries := []string{echoserverBin, loadgenBin}
	for _, name := range []string{pol.Candidate, pol.Comparator} {
		allBinaries = append(allBinaries, binPaths[name])
	}
	for _, binary := range uniqueStrings(allBinaries) {
		if err := validateBinaryToolchain(binary, pol.Series.Toolchain, goExperiment); err != nil {
			return err
		}
	}
	provenanceBinaries := map[string]string{"echoserver": echoserverBin, "loadgen": loadgenBin}
	for _, name := range []string{pol.Candidate, pol.Comparator} {
		provenanceBinaries["library-"+name] = binPaths[name]
	}
	captured, err := captureProvenance(ctx, moduleRoot, out, goExperiment, provenanceBinaries)
	if err != nil {
		return err
	}
	remote, err := gitOutput(moduleRoot, "remote", "get-url", "origin")
	if err != nil {
		return err
	}
	branch, err := gitOutput(moduleRoot, "branch", "--show-current")
	if err != nil {
		return err
	}
	gitStatus, err := gitOutput(moduleRoot, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return err
	}
	gitTree, err := gitOutput(moduleRoot, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	stage = "pre-measurement-identity"
	if pol.Series.RunKind != policy.RunKindDiagnostic && gitStatus != "" {
		return fmt.Errorf("final evidence became dirty during build/provenance preparation: %s", gitStatus)
	}
	if err := validateRunIdentity(moduleRoot, out, commit, remote, branch, gitStatus, gitTree, captured.SourceTree.SHA256, captured.ModuleFilesSHA256, policySum, goExperiment, pol, provenanceBinaries, captured.Binaries, adapterSums); err != nil {
		return fmt.Errorf("pre-measurement identity: %w", err)
	}

	kernel, _ := commandOutput("uname", "-a")
	hostname, _ := os.Hostname()
	environmentStart := captureEnv()
	if err := validateEnvironment(environmentStart, environmentStart, pol.Guard.MaxLoad1); err != nil {
		return err
	}

	manifest := RunManifest{
		SchemaVersion:          2,
		SessionID:              sessionID,
		GitCommit:              commit,
		GitDirty:               dirty,
		GitRemote:              remote,
		GitBranch:              branch,
		GitStatus:              gitStatus,
		GitTree:                gitTree,
		SourceSHA256:           captured.SourceTree.SHA256,
		ModulePath:             "github.com/zchee/gows",
		ModuleFilesSHA256:      captured.ModuleFilesSHA256,
		GoVersion:              toolchainGoVersion(goExperiment),
		GoBinaryPath:           goTool,
		GoBinarySHA256:         goToolSum,
		GoBinarySizeBytes:      goToolInfo.Size(),
		HarnessRuntimeVersion:  runtime.Version(),
		GOOS:                   runtime.GOOS,
		GOARCH:                 runtime.GOARCH,
		GoEnv:                  captured.GoEnv,
		ModuleGraph:            captured.ModuleGraph,
		BinaryProvenance:       captured.Binaries,
		OSVersion:              captured.OSVersion,
		SystemProfile:          captured.SystemProfile,
		Limits:                 captured.Limits,
		Hostname:               hostname,
		Kernel:                 kernel,
		BootIdentityStart:      environmentStart.BootIdentity,
		Client:                 client,
		EchoserverSHA256:       echoSum,
		LoadgenSHA256:          loadSum,
		OverrideBinariesSHA256: overrideSums,
		PolicySHA256:           policySum,
		AdapterSHA256:          adapterSums,
		LibraryBinariesSHA256:  binarySums,
		RunKind:                string(pol.Series.RunKind),
		EvidenceClass:          string(pol.Series.EvidenceClass),
		ToolchainSeries:        string(pol.Series.Toolchain),
		GoExperiment:           goExperiment,
		ToolchainEnvironment:   toolchainEnvironment,
		RuntimeEnvironment:     runtimeEnvironment,
		Seed:                   pol.Seed,
		Smoke:                  *smoke,
		StartedAt:              nowRFC(),
	}
	if err := support.WriteJSONFile(filepath.Join(out, "manifest.json"), manifest); err != nil {
		return err
	}

	// 3. Environment snapshot (start).
	if err := support.WriteJSONFile(filepath.Join(out, "env-start.json"), environmentStart); err != nil {
		return err
	}

	// 4. Paired randomized execution.
	stage = "measurement"
	samplesPath := filepath.Join(out, "samples.jsonl")
	errorsPath := filepath.Join(out, "errors.log")
	var execErr error
	samplesWritten, execErr = execute(ctx, pol, *smoke, client, sessionID, policySum, childEnvironment, loadgenBin, binPaths, binarySums, adapterSums, resolved, samplesPath, errorsPath)

	// Environment snapshot (end) is captured whether or not execution failed.
	stage = "end-validation"
	environmentEnd := captureEnv()
	if err := support.WriteJSONFile(filepath.Join(out, "env-end.json"), environmentEnd); err != nil && execErr == nil {
		return err
	}
	if execErr == nil {
		execErr = validateEnvironment(environmentStart, environmentEnd, pol.Guard.MaxLoad1)
	}
	if execErr == nil {
		execErr = validateRunIdentity(moduleRoot, out, commit, remote, branch, gitStatus, gitTree, captured.SourceTree.SHA256, captured.ModuleFilesSHA256, policySum, goExperiment, pol, provenanceBinaries, captured.Binaries, adapterSums)
	}
	if execErr != nil {
		return execErr
	}
	manifest.BootIdentityEnd = environmentEnd.BootIdentity
	manifest.EndedAt = nowRFC()
	if err := support.WriteJSONFile(filepath.Join(out, "manifest.json"), manifest); err != nil {
		return err
	}

	// 5. Run-complete marker.
	done := Done{FinishedAt: nowRFC(), Samples: samplesWritten, Scenarios: len(pol.Scenarios)}
	if err := support.WriteJSONFile(filepath.Join(out, "done.json"), done); err != nil {
		return err
	}
	stage = "seal-artifacts"
	store, err := artifact.NewStore(filepath.Join(filepath.Dir(moduleRoot), ".omx", "artifacts"))
	if err != nil {
		return err
	}
	_, receiptRef, err := artifact.SealRun(store, out)
	if err != nil {
		return err
	}
	completed = true
	stage = "complete"
	fmt.Printf("benchrun: complete: %d samples across %d scenarios -> %s\n", samplesWritten, len(pol.Scenarios), out)
	fmt.Printf("benchrun: immutable receipt: %s (%s)\n", receiptRef.URI, filepath.Join(out, "receipt.json"))
	return nil
}

// RunManifest is the provenance record written before execution starts.
// OverrideBinariesSHA256 is present only when a policy's library_overrides
// force a dedicated echoserver build (a build_env override); it is omitted
// otherwise, so manifest.json stays byte-identical for override-free policies.
type RunManifest struct {
	SchemaVersion          int                         `json:"schema_version"`
	SessionID              string                      `json:"session_id"`
	GitCommit              string                      `json:"git_commit"`
	GitDirty               bool                        `json:"git_dirty"`
	GitRemote              string                      `json:"git_remote"`
	GitBranch              string                      `json:"git_branch"`
	GitStatus              string                      `json:"git_status"`
	GitTree                string                      `json:"git_tree"`
	SourceSHA256           string                      `json:"source_sha256"`
	ModulePath             string                      `json:"module_path"`
	ModuleFilesSHA256      string                      `json:"module_files_sha256"`
	GoVersion              string                      `json:"go_version"`
	GoBinaryPath           string                      `json:"go_binary_path"`
	GoBinarySHA256         string                      `json:"go_binary_sha256"`
	GoBinarySizeBytes      int64                       `json:"go_binary_size_bytes"`
	HarnessRuntimeVersion  string                      `json:"harness_runtime_version"`
	GOOS                   string                      `json:"goos"`
	GOARCH                 string                      `json:"goarch"`
	GoEnv                  ProvenanceArtifact          `json:"go_env"`
	ModuleGraph            ProvenanceArtifact          `json:"module_graph"`
	BinaryProvenance       map[string]BinaryProvenance `json:"binary_provenance"`
	OSVersion              ProvenanceArtifact          `json:"os_version"`
	SystemProfile          ProvenanceArtifact          `json:"system_profile"`
	Limits                 ProvenanceArtifact          `json:"limits"`
	Hostname               string                      `json:"hostname"`
	Kernel                 string                      `json:"kernel"`
	BootIdentityStart      string                      `json:"boot_identity_start"`
	BootIdentityEnd        string                      `json:"boot_identity_end"`
	Client                 string                      `json:"client"`
	EchoserverSHA256       string                      `json:"echoserver_sha256"`
	LoadgenSHA256          string                      `json:"loadgen_sha256"`
	OverrideBinariesSHA256 map[string]string           `json:"override_binaries_sha256,omitzero"`
	PolicySHA256           string                      `json:"policy_sha256"`
	AdapterSHA256          map[string]string           `json:"adapter_sha256"`
	LibraryBinariesSHA256  map[string]string           `json:"library_binaries_sha256"`
	RunKind                string                      `json:"run_kind"`
	EvidenceClass          string                      `json:"evidence_class"`
	ToolchainSeries        string                      `json:"toolchain_series"`
	GoExperiment           string                      `json:"go_experiment"`
	ToolchainEnvironment   ToolchainEnvironment        `json:"toolchain_environment"`
	RuntimeEnvironment     RuntimeEnvironment          `json:"runtime_environment"`
	Seed                   uint64                      `json:"seed"`
	Smoke                  bool                        `json:"smoke"`
	StartedAt              string                      `json:"started_at"`
	EndedAt                string                      `json:"ended_at"`
}

// Done is the run-complete marker written to done.json on success.
type Done struct {
	FinishedAt string `json:"finished_at"`
	Samples    int    `json:"samples"`
	Scenarios  int    `json:"scenarios"`
}

// Invalidated is the fail-closed marker written whenever a run aborts after
// creating its artifact directory. Its presence permanently prevents the
// partial samples from being promoted.
type Invalidated struct {
	SchemaVersion  int    `json:"schema_version"`
	At             string `json:"at"`
	Reason         string `json:"reason"`
	Stage          string `json:"stage"`
	SessionID      string `json:"session_id"`
	GitCommit      string `json:"git_commit"`
	PolicySHA256   string `json:"policy_sha256"`
	RunKind        string `json:"run_kind"`
	SamplesWritten int    `json:"samples_written"`
}

type ToolchainEnvironment struct {
	GOENV        string `json:"goenv"`
	GOTOOLCHAIN  string `json:"gotoolchain"`
	GOFLAGS      string `json:"goflags"`
	GOEXPERIMENT string `json:"goexperiment"`
	GOOS         string `json:"goos"`
	GOARCH       string `json:"goarch"`
	GOAMD64      string `json:"goamd64"`
	GOARM64      string `json:"goarm64"`
	GOFIPS140    string `json:"gofips140"`
	CGOEnabled   string `json:"cgo_enabled"`
}

func canonicalToolchainEnvironment(goExperiment string) ToolchainEnvironment {
	environment := ToolchainEnvironment{
		GOENV: "off", GOTOOLCHAIN: "local", GOFLAGS: "-mod=mod", GOEXPERIMENT: goExperiment,
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GOFIPS140: "latest", CGOEnabled: "0",
	}
	switch runtime.GOARCH {
	case "amd64":
		environment.GOAMD64 = "v1"
	case "arm64":
		environment.GOARM64 = "v8.0"
	}
	return environment
}

func (environment ToolchainEnvironment) assignments() []string {
	return []string{
		"GOENV=" + environment.GOENV,
		"GOTOOLCHAIN=" + environment.GOTOOLCHAIN,
		"GOFLAGS=" + environment.GOFLAGS,
		"GOEXPERIMENT=" + environment.GOEXPERIMENT,
		"GOOS=" + environment.GOOS,
		"GOARCH=" + environment.GOARCH,
		"GOAMD64=" + environment.GOAMD64,
		"GOARM64=" + environment.GOARM64,
		"GOFIPS140=" + environment.GOFIPS140,
		"CGO_ENABLED=" + environment.CGOEnabled,
	}
}

type RuntimeEnvironment struct {
	GOMAXPROCS string `json:"gomaxprocs"`
	GOGC       string `json:"gogc"`
	GOMEMLIMIT string `json:"gomemlimit"`
	GODEBUG    string `json:"godebug"`
	GOWSSIMD   string `json:"gows_simd"`
}

func canonicalRuntimeEnvironment() RuntimeEnvironment {
	return RuntimeEnvironment{
		GOMAXPROCS: strconv.Itoa(runtime.NumCPU()), GOGC: "100", GOMEMLIMIT: "off", GODEBUG: "", GOWSSIMD: "",
	}
}

func (environment RuntimeEnvironment) assignments() []string {
	return []string{
		"GOMAXPROCS=" + environment.GOMAXPROCS,
		"GOGC=" + environment.GOGC,
		"GOMEMLIMIT=" + environment.GOMEMLIMIT,
		"GODEBUG=" + environment.GODEBUG,
		"GOWS_SIMD=" + environment.GOWSSIMD,
	}
}

// EnvSnapshot is a point-in-time host environment reading written to
// env-start.json and env-end.json.
type EnvSnapshot struct {
	Load1                  float64 `json:"load1"`
	Load5                  float64 `json:"load5"`
	Load15                 float64 `json:"load15"`
	PMSetBattery           string  `json:"pmset_batt"`
	PMSetThermal           string  `json:"pmset_therm"`
	LogicalCPUs            int     `json:"logical_cpus"`
	MemoryBytes            uint64  `json:"memory_bytes"`
	BootIdentity           string  `json:"boot_identity"`
	Uptime                 string  `json:"uptime"`
	CapturedAt             string  `json:"captured_at"`
	ObservationNanoseconds int64   `json:"observation_nanoseconds"`
}

// execute runs the whole scenario matrix, appending one sample line per
// (scenario, library, repetition). It aborts (returning the count so far and
// a non-nil error) on the first child or parse failure rather than skipping.
// binPaths maps each policy library name (candidate/comparator) to the
// echoserver binary that serves it, and resolved carries each name's real
// echoserver -lib value and any appended server arguments. client is the
// loadgen -client transport used for every run in the matrix.
func execute(ctx context.Context, pol *policy.Policy, smoke bool, client, sessionID, policySum string, childEnvironment []string, loadgenBin string, binPaths, binarySums, adapterSums map[string]string, resolved map[string]policy.Resolved, samplesPath, errorsPath string) (_ int, resultErr error) {
	sf, err := os.OpenFile(samplesPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open samples file: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, sf.Close())
	}()
	logsDir := filepath.Join(filepath.Dir(samplesPath), "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return 0, fmt.Errorf("create logs directory: %w", err)
	}

	count := 0
	portToggle := 0

	for scenarioIndex, sc := range pol.Scenarios {
		warmup := sc.Warmup.Duration()
		duration := sc.Duration.Duration()
		reps := sc.Repetitions
		if smoke {
			warmup = time.Second
			duration = 3 * time.Second
			reps = 2
		}

		blocks, err := paired.BalancedBlocks(pol.Candidate, pol.Comparator, reps, pol.Seed+uint64(scenarioIndex))
		if err != nil {
			return count, err
		}
		for rep, block := range blocks {
			if err := checkProcessHygiene(pol.Guard.ForbiddenProcessPatterns, ownedPIDs(), pol.Guard.MaxForeignCPUPercent); err != nil {
				return count, fmt.Errorf("scenario %q block %q host guard: %w", sc.Name, block.ID, err)
			}
			for orderIdx, lib := range block.Libraries {
				if err := ctx.Err(); err != nil {
					return count, fmt.Errorf("aborted: %w", err)
				}
				serverPort := basePort + portToggle
				debugPort := debugPortBase + portToggle
				portToggle ^= 1

				r := resolved[lib]
				identity := sampleIdentity{
					SessionID: sessionID, BlockID: block.ID, Order: block.Pattern,
					BinarySHA256: binarySums[lib], PolicySHA256: policySum, AdapterSHA256: adapterSums[lib],
				}
				payloadSeed, err := paired.BlockPayloadSeed(pol.Seed, scenarioIndex, rep)
				if err != nil {
					return count, err
				}
				sample, err := runOne(ctx, binPaths[lib], loadgenBin, childEnvironment, client, lib, r.Lib, r.ServerArgs, identity, pol.Guard, logsDir, sc, warmup, duration, payloadSeed, rep, orderIdx, serverPort, debugPort)
				if err != nil {
					appendError(errorsPath, sc.Name, lib, rep, err)
					return count, fmt.Errorf("scenario %q lib %q rep %d: %w", sc.Name, lib, rep, err)
				}
				if err := writeJSONLine(sf, sample); err != nil {
					return count, err
				}
				count++
			}
		}
	}
	if err := sf.Sync(); err != nil {
		return count, fmt.Errorf("sync samples file: %w", err)
	}
	return count, nil
}

type sampleIdentity struct {
	SessionID     string
	BlockID       string
	Order         paired.OrderPattern
	BinarySHA256  string
	PolicySHA256  string
	AdapterSHA256 string
}

// runOne spawns one echoserver, drives one loadgen JSON run against it, then
// SIGTERMs the server and collects both children's rusage. name is the
// policy-facing library name recorded in the sample (an override name such as
// "gows-lowat" distinct from realLib); realLib is the echoserver -lib value,
// and serverArgs are appended to the echoserver command line. client is passed
// to loadgen's -client flag to select the WebSocket client transport.
func runOne(ctx context.Context, echoserverBin, loadgenBin string, childEnvironment []string, client, name, realLib string, serverArgs []string, identity sampleIdentity, guard policy.Guard, logsDir string, sc policy.Scenario, warmup, duration time.Duration, payloadSeed uint64, rep, orderIdx, serverPort, debugPort int) (paired.Sample, error) {
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	debugAddr := fmt.Sprintf("127.0.0.1:%d", debugPort)
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	immutableFiles, err := captureFileStamps(echoserverBin, loadgenBin)
	if err != nil {
		return paired.Sample{}, err
	}

	srvArgs := append([]string{"-lib", realLib, "-addr", serverAddr, "-debug-addr", debugAddr}, serverArgs...)
	srv := exec.CommandContext(runCtx, echoserverBin, srvArgs...)
	srv.Env = childEnvironment
	var srvLog bytes.Buffer
	srv.Stdout = &srvLog
	srv.Stderr = &srvLog
	if err := srv.Start(); err != nil {
		return paired.Sample{}, fmt.Errorf("start echoserver: %w", err)
	}
	serverStopped := false
	defer func() {
		if !serverStopped && srv.Process != nil {
			_ = srv.Process.Signal(syscall.SIGKILL)
			_ = srv.Wait()
		}
	}()

	if err := waitTCP(ctx, serverAddr, dialTimeout); err != nil {
		return paired.Sample{}, fmt.Errorf("echoserver ws port %s not ready: %w (server log: %s)", serverAddr, err, strings.TrimSpace(srvLog.String()))
	}
	if err := waitTCP(ctx, debugAddr, dialTimeout); err != nil {
		return paired.Sample{}, fmt.Errorf("echoserver debug port %s not ready: %w (server log: %s)", debugAddr, err, strings.TrimSpace(srvLog.String()))
	}

	lg := exec.CommandContext(runCtx, loadgenBin,
		"-addr", serverAddr,
		"-debug-addr", debugAddr,
		"-client", client,
		"-message", string(sc.MessageType),
		"-arrival", string(sc.Arrival),
		"-conns", strconv.Itoa(sc.Connections),
		"-payload", strconv.Itoa(sc.PayloadBytes),
		"-seed", strconv.FormatUint(payloadSeed, 10),
		"-inflight", strconv.Itoa(sc.Inflight),
		"-duration", duration.String(),
		"-warmup", warmup.String(),
		"-rate", strconv.Itoa(sc.OfferedRate),
		"-max-scheduler-lateness", sc.MaxSchedulerLateness.Duration().String(),
		"-json")
	lg.Env = childEnvironment
	var lgOut, lgErr bytes.Buffer
	lg.Stdout = &lgOut
	lg.Stderr = &lgErr
	if err := lg.Start(); err != nil {
		return paired.Sample{}, fmt.Errorf("start loadgen: %w", err)
	}
	guardBaseline := captureEnv()
	monitorCtx, cancelMonitor := context.WithCancel(ctx)
	guardCh := make(chan guardResult, 1)
	go func() {
		result := monitorHost(monitorCtx, guardBaseline, guard, ownedPIDs(srv.Process.Pid, lg.Process.Pid), immutableFiles)
		if result.Err != nil {
			cancelRun()
		}
		guardCh <- result
	}()
	loadgenErr := lg.Wait()
	cancelMonitor()
	guardOutcome := <-guardCh

	if srv.Process != nil {
		_ = srv.Process.Signal(syscall.SIGTERM)
	}
	// A SIGTERM-terminated echoserver may report a non-nil wait error; the
	// ProcessState (and thus its rusage) is populated regardless, so the
	// expected termination error is intentionally not treated as fatal.
	_ = srv.Wait()
	serverStopped = true
	logErr := writeRunLogs(logsDir, identity, sc.Name, name, srvLog.Bytes(), lgOut.Bytes(), lgErr.Bytes(), guardOutcome.Snapshots)
	if guardOutcome.Err != nil {
		return paired.Sample{}, errors.Join(fmt.Errorf("continuous host guard: %w", guardOutcome.Err), logErr)
	}
	if loadgenErr != nil {
		return paired.Sample{}, errors.Join(fmt.Errorf("loadgen failed: %w (stdout: %s; stderr: %s)", loadgenErr, strings.TrimSpace(lgOut.String()), strings.TrimSpace(lgErr.String())), logErr)
	}
	if logErr != nil {
		return paired.Sample{}, logErr
	}

	var result support.LoadgenResult
	if err := json.Unmarshal(bytes.TrimSpace(lgOut.Bytes()), &result, json.RejectUnknownMembers(true)); err != nil {
		return paired.Sample{}, fmt.Errorf("parse loadgen json %q: %w", strings.TrimSpace(lgOut.String()), err)
	}
	if result.PayloadSeed != payloadSeed {
		return paired.Sample{}, fmt.Errorf("loadgen payload seed = %d, want %d", result.PayloadSeed, payloadSeed)
	}
	if err := result.HardFailure(); err != nil {
		return paired.Sample{}, fmt.Errorf("loadgen hard gate: %w", err)
	}
	serverProcessUsage := support.Usage{}
	if srv.ProcessState != nil {
		serverProcessUsage = support.ProcessRusage(srv.ProcessState.SysUsage())
	}

	msgs := float64(max(result.Messages, 1))
	conns := float64(max(sc.Connections, 1))
	sample := paired.Sample{
		LoadgenResult:               result,
		SchemaVersion:               paired.SampleSchemaVersion,
		SessionID:                   identity.SessionID,
		BlockID:                     identity.BlockID,
		Order:                       string(identity.Order),
		BinarySHA256:                identity.BinarySHA256,
		PolicySHA256:                identity.PolicySHA256,
		AdapterSHA256:               identity.AdapterSHA256,
		Scenario:                    sc.Name,
		Library:                     name,
		Repetition:                  rep,
		OrderIndex:                  orderIdx,
		ServerProcessUsage:          serverProcessUsage,
		ServerCPUSeconds:            result.ServerUsage.CPUSeconds,
		ServerMaxRSSBytes:           result.ServerUsage.MaxRSSBytes,
		ServerCPUSecondsPerMessage:  result.ServerUsage.CPUSeconds / msgs,
		ServerRSSBytesPerConnection: float64(result.ServerUsage.MaxRSSBytes) / conns,
		ClientCPUSecondsPerMessage:  result.ClientCPUSeconds / msgs,
	}
	if err := sample.Validate(); err != nil {
		return paired.Sample{}, err
	}
	return sample, nil
}

func writeRunLogs(logsDir string, identity sampleIdentity, scenario, library string, serverLog, loadgenOut, loadgenErr []byte, snapshots []EnvSnapshot) error {
	prefix := safeName(scenario) + "__" + safeName(identity.BlockID) + "__" + safeName(library)
	var guardLog bytes.Buffer
	for _, snapshot := range snapshots {
		line, err := json.Marshal(snapshot, json.Deterministic(true))
		if err != nil {
			return fmt.Errorf("marshal guard snapshot: %w", err)
		}
		guardLog.Write(line)
		guardLog.WriteByte('\n')
	}
	return errors.Join(
		support.WriteFileAtomic(filepath.Join(logsDir, prefix+".server.log"), serverLog, 0o644),
		support.WriteFileAtomic(filepath.Join(logsDir, prefix+".loadgen.json"), loadgenOut, 0o644),
		support.WriteFileAtomic(filepath.Join(logsDir, prefix+".loadgen.stderr.log"), loadgenErr, 0o644),
		support.WriteFileAtomic(filepath.Join(logsDir, prefix+".guard.jsonl"), guardLog.Bytes(), 0o644),
	)
}

// waitTCP dials addr until it accepts a connection or the deadline/ctx
// expires.
func waitTCP(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no successful dial")
	}
	return fmt.Errorf("timed out after %s: %w", timeout, lastErr)
}

// findModuleRoot walks up from start until it finds the go.mod declaring the
// bench module.
func findModuleRoot(start string) (string, error) {
	if dir, ok := support.FindModuleRoot(start, moduleImport); ok {
		return dir, nil
	}
	return "", fmt.Errorf("could not locate the bench module (%s) from %s; run benchrun inside the bench module tree", moduleImport, start)
}

// defaultOutDir keeps diagnostic, self-validation, and baseline artifacts in
// disjoint roots. The .omx tree is deliberately untracked; completed runs are
// sealed into content-addressed storage before a compact receipt is tracked.
func defaultOutDir(moduleRoot string, pol *policy.Policy, sessionID, shortCommit string) string {
	return filepath.Join(
		seriesOutRoot(moduleRoot, pol),
		sessionID+"-"+shortCommit,
	)
}

func seriesOutRoot(moduleRoot string, pol *policy.Policy) string {
	return filepath.Join(
		filepath.Dir(moduleRoot), ".omx", "bench",
		string(pol.Series.Toolchain),
		string(pol.Series.EvidenceClass),
		string(pol.Series.HostMode),
		string(pol.Series.RunKind),
		pol.Series.ID,
	)
}

func newSessionID() (string, error) {
	var entropy [8]byte
	if _, err := cryptorand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return fmt.Sprintf("session-%s-%x", time.Now().UTC().Format("20060102T150405Z"), entropy[:]), nil
}

func validRunArtifactID(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func validateRunIdentity(moduleRoot, out, commit, remote, branch, status, tree, sourceSum, moduleSum, policySum, goExperiment string, pol *policy.Policy, binaries map[string]string, binaryProvenance map[string]BinaryProvenance, adapterSums map[string]string) error {
	checks := []struct {
		name string
		want string
		args []string
	}{
		{name: "HEAD", want: commit, args: []string{"rev-parse", "HEAD"}},
		{name: "origin remote", want: remote, args: []string{"remote", "get-url", "origin"}},
		{name: "branch", want: branch, args: []string{"branch", "--show-current"}},
		{name: "worktree status", want: status, args: []string{"status", "--porcelain=v1", "--untracked-files=all"}},
		{name: "git tree", want: tree, args: []string{"rev-parse", "HEAD^{tree}"}},
	}
	for _, check := range checks {
		got, err := gitOutput(moduleRoot, check.args...)
		if err != nil {
			return fmt.Errorf("end identity %s: %w", check.name, err)
		}
		if got != check.want {
			return fmt.Errorf("end identity %s changed from %q to %q", check.name, check.want, got)
		}
	}
	rawTree, err := gitRawOutput(moduleRoot, "ls-tree", "-r", "--full-tree", "HEAD")
	if err != nil {
		return err
	}
	if got := sha256Bytes(rawTree); got != sourceSum {
		return fmt.Errorf("end identity source tree SHA-256 = %s, want %s", got, sourceSum)
	}
	gotModuleSum, err := hashFileSet(filepath.Dir(moduleRoot), []string{"go.mod", "go.sum", "bench/go.mod", "bench/go.sum", "flatekp/go.mod", "flatekp/go.sum"})
	if err != nil {
		return fmt.Errorf("end identity module files: %w", err)
	}
	if gotModuleSum != moduleSum {
		return fmt.Errorf("end identity module files SHA-256 = %s, want %s", gotModuleSum, moduleSum)
	}
	gotPolicySum, err := sha256File(filepath.Join(out, "policy.json"))
	if err != nil {
		return fmt.Errorf("end identity policy: %w", err)
	}
	if gotPolicySum != policySum {
		return fmt.Errorf("end identity policy SHA-256 = %s, want %s", gotPolicySum, policySum)
	}
	for name, want := range adapterSums {
		got, err := policy.HashAdapter(moduleRoot, pol.Adapters[name])
		if err != nil {
			return fmt.Errorf("end identity adapter %q: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("end identity adapter %q SHA-256 = %s, want %s", name, got, want)
		}
	}
	for name, path := range binaries {
		want, ok := binaryProvenance[name]
		if !ok {
			return fmt.Errorf("end identity binary %q lacks start provenance", name)
		}
		got, err := sha256File(path)
		if err != nil {
			return fmt.Errorf("end identity binary %q: %w", name, err)
		}
		if got != want.SHA256 {
			return fmt.Errorf("end identity binary %q SHA-256 = %s, want %s", name, got, want.SHA256)
		}
		if err := validateBinaryToolchain(path, pol.Series.Toolchain, goExperiment); err != nil {
			return fmt.Errorf("end identity binary %q: %w", name, err)
		}
	}
	return nil
}

func gitRawOutput(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, gitCommandError(args, err)
	}
	return out, nil
}

// gitCommandError appends the stderr that exec.Cmd.Output captured on
// failure, so callers surface git's actual diagnostic instead of only the
// bare exit status.
func gitCommandError(args []string, err error) error {
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		if detail := bytes.TrimSpace(exitErr.Stderr); len(detail) > 0 {
			return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, detail)
		}
	}
	return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hashFileSet hashes a sorted path-to-content-hash table, making both the
// selected adapter files and their exact bytes part of the identity.
func hashFileSet(root string, paths []string) (string, error) {
	paths = slices.Clone(paths)
	slices.Sort(paths)
	hash := sha256.New()
	for _, relative := range paths {
		if !filepath.IsLocal(relative) {
			return "", fmt.Errorf("source path %q is not local", relative)
		}
		sum, err := sha256File(filepath.Join(root, relative))
		if err != nil {
			return "", err
		}
		if _, err := fmt.Fprintf(hash, "%d:%s:%s\n", len(relative), relative, sum); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// buildBinaryEnv compiles a bench command into outPath, using -mod=mod so the
// working-tree gows (via the module's replace directive) is linked rather than
// the vendored snapshot. The toolchain experiment set flows through the
// dedicated goExperiment parameter; extraEnv (non-reserved KEY=VALUE entries
// from a policy's library_overrides build_env, or nil) is appended on top,
// letting an override produce a distinct echoserver build without a separate
// source tree. Policy validation rejects every reserved toolchain variable
// (GOENV, GOFLAGS, GOEXPERIMENT, ...) in build_env, so extraEnv can never
// fight the canonical toolchain environment.
func buildBinaryEnv(ctx context.Context, moduleRoot, pkgSuffix, outPath, goExperiment string, extraEnv []string) error {
	cmd := exec.CommandContext(ctx, goToolPath(), "build", "-mod=mod", "-o", outPath, moduleImport+pkgSuffix)
	cmd.Dir = moduleRoot
	cmd.Env = overrideEnvironment(os.Environ(), append(canonicalToolchainEnvironment(goExperiment).assignments(), extraEnv...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build %s (env %v): %w: %s", pkgSuffix, extraEnv, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func overrideEnvironment(base []string, overrides ...string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		key, _, ok := strings.Cut(override, "=")
		if ok {
			keys[key] = struct{}{}
		}
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if _, replaced := keys[key]; ok && replaced {
			continue
		}
		result = append(result, entry)
	}
	return append(result, overrides...)
}

func validateBinaryToolchain(path string, series policy.ToolchainSeries, expectedExperiment string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read build info %s: %w", path, err)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	actualExperiment := settings["GOEXPERIMENT"]
	if canonicalExperiment(actualExperiment) != canonicalExperiment(expectedExperiment) {
		return fmt.Errorf("%s series binary %s records GOEXPERIMENT=%q, want %q", series, path, actualExperiment, expectedExperiment)
	}
	if series == policy.ToolchainStock && strings.Contains(info.GoVersion, "-X:") {
		return fmt.Errorf("stock series binary %s has custom Go version %q", path, info.GoVersion)
	}
	environment := canonicalToolchainEnvironment(expectedExperiment)
	want := map[string]string{
		"GOOS": environment.GOOS, "GOARCH": environment.GOARCH,
		"CGO_ENABLED": environment.CGOEnabled, "GOFIPS140": environment.GOFIPS140,
	}
	if environment.GOAMD64 != "" {
		want["GOAMD64"] = environment.GOAMD64
	}
	if environment.GOARM64 != "" {
		want["GOARM64"] = environment.GOARM64
	}
	for key, expected := range want {
		if settings[key] != expected {
			return fmt.Errorf("%s series binary %s records %s=%q, want %q", series, path, key, settings[key], expected)
		}
	}
	return nil
}

func canonicalExperiment(value string) string {
	parts := strings.Split(value, ",")
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

func toolchainGoVersion(goExperiment string) string {
	cmd := exec.Command(goToolPath(), "version")
	cmd.Env = overrideEnvironment(os.Environ(), canonicalToolchainEnvironment(goExperiment).assignments()...)
	out, err := cmd.Output()
	if err != nil {
		return "unavailable: " + err.Error()
	}
	return strings.TrimSpace(string(out))
}

// goToolPath binds child builds and recorded provenance to this controller's
// compiler rather than a potentially different Go launcher found through PATH.
func goToolPath() string {
	//lint:ignore SA1019 Exact build-toolchain identity is required by benchmark provenance.
	return filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // Exact build-toolchain identity is required by benchmark provenance.
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// sha256File returns the hex SHA-256 of a file's contents.
func sha256File(path string) (_ string, resultErr error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, f.Close())
	}()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// captureEnv snapshots the host environment. Best-effort: a missing tool
// yields a zero field rather than aborting the run.
func captureEnv() EnvSnapshot {
	started := time.Now()
	l1, l5, l15, _ := readLoadavg()
	batt, _ := commandOutput("pmset", "-g", "batt")
	therm, _ := commandOutput("pmset", "-g", "therm")
	mem, _ := readMemsize()
	boot, _ := support.CaptureBootIdentity()
	uptime, _ := commandOutput("uptime")
	snapshot := EnvSnapshot{
		Load1:        l1,
		Load5:        l5,
		Load15:       l15,
		PMSetBattery: batt,
		PMSetThermal: therm,
		LogicalCPUs:  runtime.NumCPU(),
		MemoryBytes:  mem,
		BootIdentity: boot,
		Uptime:       uptime,
		CapturedAt:   nowRFC(),
	}
	snapshot.ObservationNanoseconds = time.Since(started).Nanoseconds()
	return snapshot
}

// captureContinuousEnv avoids re-reading static topology and uptime on every
// poll while still observing load, power, thermal, and boot identity across
// the full measurement window. The elapsed collector time is recorded so the
// guard's scheduling cost is machine-readable rather than hidden.
func captureContinuousEnv(baseline EnvSnapshot) EnvSnapshot {
	started := time.Now()
	l1, l5, l15, _ := readLoadavg()
	batt, _ := commandOutput("pmset", "-g", "batt")
	therm, _ := commandOutput("pmset", "-g", "therm")
	boot, _ := support.CaptureBootIdentity()
	snapshot := EnvSnapshot{
		Load1: l1, Load5: l5, Load15: l15,
		PMSetBattery: batt, PMSetThermal: therm,
		LogicalCPUs: baseline.LogicalCPUs, MemoryBytes: baseline.MemoryBytes,
		BootIdentity: boot, CapturedAt: nowRFC(),
	}
	snapshot.ObservationNanoseconds = time.Since(started).Nanoseconds()
	return snapshot
}

func validateEnvironment(start, end EnvSnapshot, maxLoad1 float64) error {
	if start.BootIdentity == "" || end.BootIdentity == "" || start.Uptime == "" || end.Uptime == "" {
		return fmt.Errorf("host guard: boot identity or uptime is unavailable")
	}
	if start.BootIdentity != end.BootIdentity {
		return fmt.Errorf("host guard: boot identity changed during run")
	}
	if start.LogicalCPUs <= 0 || start.LogicalCPUs != end.LogicalCPUs || start.MemoryBytes == 0 || start.MemoryBytes != end.MemoryBytes {
		return fmt.Errorf("host guard: CPU/memory topology changed or is unavailable")
	}
	// loadavg is gated before any benchmark child starts. The benchmark's own
	// CPU demand remains in the exponentially decaying load average after a
	// block ends, so treating the end reading as foreign load would make the
	// harness invalidate itself. Continuous contamination is instead guarded by
	// boot/power/thermal identity plus forbidden-process monitoring.
	if start.Load1 > maxLoad1 {
		return fmt.Errorf("host guard: initial load1 %.2f exceeds max %.2f", start.Load1, maxLoad1)
	}
	startPower := powerSource(start.PMSetBattery)
	endPower := powerSource(end.PMSetBattery)
	if startPower == "" || endPower == "" || startPower != endPower {
		return fmt.Errorf("host guard: power source unavailable or changed from %q to %q", startPower, endPower)
	}
	if !thermalClean(start.PMSetThermal) || !thermalClean(end.PMSetThermal) {
		return fmt.Errorf("host guard: thermal or performance warning recorded")
	}
	return nil
}

func powerSource(pmset string) string {
	line, _, _ := strings.Cut(pmset, "\n")
	prefix := "Now drawing from '"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "'") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(line, prefix), "'")
}

func thermalClean(pmset string) bool {
	return strings.Contains(pmset, "No thermal warning level has been recorded") &&
		strings.Contains(pmset, "No performance warning level has been recorded")
}

// checkLoad aborts if the one-minute load average exceeds the guard maximum.
func checkLoad(maxLoad1 float64) error {
	l1, _, _, err := readLoadavg()
	if err != nil {
		return err
	}
	if l1 > maxLoad1 {
		return fmt.Errorf("host guard: load1 %.2f exceeds max_load1 %.2f; aborting", l1, maxLoad1)
	}
	return nil
}

// acquireLock takes the exclusive benchrun lockfile, containing our pid. A
// stale lock (pid no longer alive) is removed and retried once; a live holder
// aborts.
func acquireLock(path string) (release func(), err error) {
	create := func() (*os.File, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	}
	f, err := create()
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create lockfile %s: %w", path, err)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("read existing lockfile %s: %w", path, rerr)
		}
		holder, perr := strconv.Atoi(strings.TrimSpace(string(data)))
		if perr == nil && processAlive(holder) {
			return nil, fmt.Errorf("lockfile %s held by running pid %d; another benchrun is active", path, holder)
		}
		if rmErr := os.Remove(path); rmErr != nil {
			return nil, fmt.Errorf("remove stale lockfile %s: %w", path, rmErr)
		}
		f, err = create()
		if err != nil {
			return nil, fmt.Errorf("re-create lockfile %s after removing stale lock: %w", path, err)
		}
	}
	if _, werr := fmt.Fprintf(f, "%d\n", os.Getpid()); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write lockfile %s: %w", path, werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close lockfile %s: %w", path, cerr)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = os.Remove(path) }) }, nil
}

// processAlive reports whether pid names a live process, using signal 0.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}

// readLoadavg reads the three system load averages from sysctl vm.loadavg.
func readLoadavg() (l1, l5, l15 float64, err error) {
	raw, err := commandOutput("sysctl", "-n", "vm.loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	return parseLoadavg(raw)
}

// parseLoadavg extracts the three load averages from a "sysctl -n vm.loadavg"
// string such as "{ 1.23 4.56 7.89 }".
func parseLoadavg(raw string) (l1, l5, l15 float64, err error) {
	var nums []float64
	for f := range strings.FieldsSeq(raw) {
		if v, perr := strconv.ParseFloat(f, 64); perr == nil {
			nums = append(nums, v)
		}
	}
	if len(nums) < 3 {
		return 0, 0, 0, fmt.Errorf("cannot parse load average from %q", raw)
	}
	return nums[0], nums[1], nums[2], nil
}

// readMemsize reads the physical memory size in bytes from sysctl hw.memsize.
func readMemsize() (uint64, error) {
	raw, err := commandOutput("sysctl", "-n", "hw.memsize")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
}

// gitOutput runs a git command in dir and returns its trimmed stdout.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", gitCommandError(args, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitDirty reports whether the working tree has uncommitted changes.
func gitDirty(dir string) (bool, error) {
	out, err := gitOutput(dir, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return out != "", nil
}

// commandOutput runs an external command and returns its trimmed stdout.
func commandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// appendError records a run failure to errors.log with context. Logging is
// best-effort because the caller preserves the primary error and writes the
// authoritative INVALIDATED.json marker on every failed run.
func appendError(path, scenario, lib string, rep int, cause error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s scenario=%q lib=%q rep=%d: %v\n", nowRFC(), scenario, lib, rep, cause)
}

// writeJSONLine marshals v as one compact JSON line to w, with deterministic
// map ordering like every other artifact writer: samples.jsonl is sealed into
// content-addressed storage and hashed into the run receipt, so its bytes must
// stay reproducible even if a map-valued field is ever added to a sample.
func writeJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return fmt.Errorf("marshal sample: %w", err)
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write sample: %w", err)
	}
	return nil
}

// nowRFC returns the current UTC time as an RFC 3339 nanosecond string.
func nowRFC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
