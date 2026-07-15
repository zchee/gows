package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

type provenanceArtifact struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type binaryProvenance struct {
	Path       string             `json:"path"`
	SHA256     string             `json:"sha256"`
	SizeBytes  int64              `json:"size_bytes"`
	GoVersionM provenanceArtifact `json:"go_version_m"`
}

type runManifest struct {
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
	GoEnv                  provenanceArtifact          `json:"go_env"`
	ModuleGraph            provenanceArtifact          `json:"module_graph"`
	BinaryProvenance       map[string]binaryProvenance `json:"binary_provenance"`
	OSVersion              provenanceArtifact          `json:"os_version"`
	SystemProfile          provenanceArtifact          `json:"system_profile"`
	Limits                 provenanceArtifact          `json:"limits"`
	Hostname               string                      `json:"hostname"`
	Kernel                 string                      `json:"kernel"`
	BootIdentityStart      string                      `json:"boot_identity_start"`
	BootIdentityEnd        string                      `json:"boot_identity_end"`
	Client                 string                      `json:"client"`
	EchoserverSHA256       string                      `json:"echoserver_sha256"`
	LoadgenSHA256          string                      `json:"loadgen_sha256"`
	OverrideBinariesSHA256 map[string]string           `json:"override_binaries_sha256"`
	PolicySHA256           string                      `json:"policy_sha256"`
	AdapterSHA256          map[string]string           `json:"adapter_sha256"`
	LibraryBinariesSHA256  map[string]string           `json:"library_binaries_sha256"`
	RunKind                string                      `json:"run_kind"`
	EvidenceClass          string                      `json:"evidence_class"`
	ToolchainSeries        string                      `json:"toolchain_series"`
	GoExperiment           string                      `json:"go_experiment"`
	ToolchainEnvironment   toolchainEnvironment        `json:"toolchain_environment"`
	RuntimeEnvironment     runtimeEnvironment          `json:"runtime_environment"`
	Seed                   uint64                      `json:"seed"`
	Smoke                  bool                        `json:"smoke"`
	StartedAt              string                      `json:"started_at"`
	EndedAt                string                      `json:"ended_at"`
}

type toolchainEnvironment struct {
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

type runtimeEnvironment struct {
	GOMAXPROCS string `json:"gomaxprocs"`
	GOGC       string `json:"gogc"`
	GOMEMLIMIT string `json:"gomemlimit"`
	GODEBUG    string `json:"godebug"`
	GOWSSIMD   string `json:"gows_simd"`
}

type doneMarker struct {
	FinishedAt string `json:"finished_at"`
	Samples    int    `json:"samples"`
	Scenarios  int    `json:"scenarios"`
}

type envSnapshot struct {
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

type goEnvironment struct {
	CGOEnabled   string `json:"CGO_ENABLED"`
	GOARCH       string `json:"GOARCH"`
	GOAMD64      string `json:"GOAMD64"`
	GOARM64      string `json:"GOARM64"`
	GOENV        string `json:"GOENV"`
	GOEXPERIMENT string `json:"GOEXPERIMENT"`
	GOFIPS140    string `json:"GOFIPS140"`
	GOFLAGS      string `json:"GOFLAGS"`
	GOOS         string `json:"GOOS"`
	GOTOOLCHAIN  string `json:"GOTOOLCHAIN"`
	GOVERSION    string `json:"GOVERSION"`
}

type moduleRecord struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Sum     string        `json:"Sum"`
	Main    bool          `json:"Main"`
	Replace *moduleRecord `json:"Replace"`
}

type resolvedRun struct {
	Reference artifact.Ref
	Receipt   artifact.RunReceipt
	Files     map[string]string
	Manifest  runManifest
	Policy    *policy.Policy
	PolicyRaw []byte
	Samples   []paired.Sample
	Started   time.Time
	Ended     time.Time
}

func resolveRun(store artifact.Store, ref artifact.Ref, repository RepositoryIdentity, root string) (resolvedRun, error) {
	receipt, files, err := artifact.ResolveRun(store, ref)
	if err != nil {
		return resolvedRun{}, fmt.Errorf("evidence: resolve run %s: %w", ref.URI, err)
	}
	if _, invalidated := receipt.Files["INVALIDATED.json"]; invalidated {
		return resolvedRun{}, fmt.Errorf("evidence: run %s contains INVALIDATED.json", receipt.SessionID)
	}
	manifestRaw, err := os.ReadFile(files["manifest.json"])
	if err != nil {
		return resolvedRun{}, err
	}
	var manifest runManifest
	if err := decodeStrict(manifestRaw, &manifest); err != nil {
		return resolvedRun{}, fmt.Errorf("evidence: run manifest: %w", err)
	}
	policyRaw, err := os.ReadFile(files["policy.json"])
	if err != nil {
		return resolvedRun{}, err
	}
	var policyRecord policy.Policy
	if err := decodeStrict(policyRaw, &policyRecord); err != nil {
		return resolvedRun{}, fmt.Errorf("evidence: strict policy decode: %w", err)
	}
	if err := policyRecord.Validate(); err != nil {
		return resolvedRun{}, err
	}
	policyValue := &policyRecord
	policySum := policy.Sum(policyRaw)
	samples, err := loadStrictSamples(files["samples.jsonl"])
	if err != nil {
		return resolvedRun{}, err
	}
	var done doneMarker
	if raw, err := os.ReadFile(files["done.json"]); err != nil {
		return resolvedRun{}, err
	} else if err := decodeStrict(raw, &done); err != nil {
		return resolvedRun{}, fmt.Errorf("evidence: done marker: %w", err)
	}
	var envStart, envEnd envSnapshot
	for name, target := range map[string]*envSnapshot{"env-start.json": &envStart, "env-end.json": &envEnd} {
		raw, err := os.ReadFile(files[name])
		if err != nil {
			return resolvedRun{}, err
		}
		if err := decodeStrict(raw, target); err != nil {
			return resolvedRun{}, fmt.Errorf("evidence: %s: %w", name, err)
		}
		if err := validateEnvSnapshot(*target, true); err != nil {
			return resolvedRun{}, fmt.Errorf("evidence: %s: %w", name, err)
		}
	}
	started, err := time.Parse(time.RFC3339Nano, manifest.StartedAt)
	if err != nil {
		return resolvedRun{}, fmt.Errorf("evidence: run %s invalid started_at: %w", receipt.SessionID, err)
	}
	ended, err := time.Parse(time.RFC3339Nano, manifest.EndedAt)
	if err != nil {
		return resolvedRun{}, fmt.Errorf("evidence: run %s invalid ended_at: %w", receipt.SessionID, err)
	}

	run := resolvedRun{
		Reference: ref, Receipt: receipt, Files: files, Manifest: manifest,
		Policy: policyValue, PolicyRaw: append([]byte(nil), policyRaw...), Samples: samples, Started: started, Ended: ended,
	}
	if err := validateRunIdentity(run, repository, policySum, done, envStart, envEnd, root); err != nil {
		return resolvedRun{}, err
	}
	return run, nil
}

func validateRunIdentity(run resolvedRun, repository RepositoryIdentity, policySum string, done doneMarker, envStart, envEnd envSnapshot, root string) error {
	m := run.Manifest
	p := run.Policy
	r := run.Receipt
	envStarted, _ := time.Parse(time.RFC3339Nano, envStart.CapturedAt)
	envEnded, _ := time.Parse(time.RFC3339Nano, envEnd.CapturedAt)
	finished, err := time.Parse(time.RFC3339Nano, done.FinishedAt)
	if err != nil {
		return fmt.Errorf("evidence: run %s invalid done timestamp: %w", r.SessionID, err)
	}
	switch {
	case m.SchemaVersion != 2:
		return fmt.Errorf("evidence: run %s manifest schema_version = %d, want 2", r.SessionID, m.SchemaVersion)
	case m.SessionID != r.SessionID || m.SessionID == "":
		return fmt.Errorf("evidence: run session identity mismatch manifest=%q receipt=%q", m.SessionID, r.SessionID)
	case m.GitDirty || m.GitStatus != "":
		return fmt.Errorf("evidence: run %s was captured from a dirty tree", r.SessionID)
	case m.GitRemote != repository.Remote || m.GitBranch != repository.Branch:
		return fmt.Errorf("evidence: run %s repository identity mismatch", r.SessionID)
	case m.GitCommit != repository.SourceHead || r.SourceHead != repository.SourceHead:
		return fmt.Errorf("evidence: run %s source head mismatch", r.SessionID)
	case m.GitTree != repository.SourceTree || m.SourceSHA256 != repository.SourceSHA256:
		return fmt.Errorf("evidence: run %s source tree/hash mismatch", r.SessionID)
	case m.ModulePath != repository.ModulePath || m.ModuleFilesSHA256 != repository.ModuleFilesSHA256:
		return fmt.Errorf("evidence: run %s module identity mismatch", r.SessionID)
	case m.GoVersion != repository.GoVersion || strings.Contains(m.HarnessRuntimeVersion, "-X:"):
		return fmt.Errorf("evidence: run %s stock Go identity mismatch", r.SessionID)
	case m.GoBinarySHA256 != repository.GoBinarySHA256 || m.GoBinarySizeBytes != repository.GoBinarySizeBytes:
		return fmt.Errorf("evidence: run %s Go binary identity mismatch", r.SessionID)
	case m.GOOS != repository.GOOS || m.GOARCH != repository.GOARCH:
		return fmt.Errorf("evidence: run %s host target mismatch", r.SessionID)
	case m.PolicySHA256 != policySum || r.PolicySHA256 != policySum:
		return fmt.Errorf("evidence: run %s policy hash mismatch", r.SessionID)
	case m.RunKind != string(p.Series.RunKind) || r.RunKind != string(p.Series.RunKind):
		return fmt.Errorf("evidence: run %s run_kind mismatch", r.SessionID)
	case m.EvidenceClass != string(p.Series.EvidenceClass) || r.EvidenceClass != string(p.Series.EvidenceClass):
		return fmt.Errorf("evidence: run %s evidence_class mismatch", r.SessionID)
	case m.ToolchainSeries != string(p.Series.Toolchain) || r.ToolchainSeries != string(p.Series.Toolchain):
		return fmt.Errorf("evidence: run %s toolchain series mismatch", r.SessionID)
	case p.Series.Toolchain != policy.ToolchainStock || p.Series.GoExperiment != "" || m.GoExperiment != "":
		return fmt.Errorf("evidence: run %s is not in the stock Go series", r.SessionID)
	case m.Client != string(p.Series.Client):
		return fmt.Errorf("evidence: run %s client identity mismatch", r.SessionID)
	case m.Seed != p.Seed:
		return fmt.Errorf("evidence: run %s seed mismatch", r.SessionID)
	case m.Smoke:
		return fmt.Errorf("evidence: run %s is a non-promotable smoke run", r.SessionID)
	case m.Hostname == "" || m.Kernel == "":
		return fmt.Errorf("evidence: run %s host identity is incomplete", r.SessionID)
	case m.BootIdentityStart == "" || m.BootIdentityStart != m.BootIdentityEnd:
		return fmt.Errorf("evidence: run %s boot identity changed", r.SessionID)
	case envStart.BootIdentity != m.BootIdentityStart || envEnd.BootIdentity != m.BootIdentityEnd:
		return fmt.Errorf("evidence: run %s environment boot identity mismatch", r.SessionID)
	case envStart.LogicalCPUs != envEnd.LogicalCPUs || envStart.MemoryBytes != envEnd.MemoryBytes:
		return fmt.Errorf("evidence: run %s environment topology changed", r.SessionID)
	case !run.Started.Before(run.Ended):
		return fmt.Errorf("evidence: run %s has non-positive elapsed time", r.SessionID)
	case done.Samples != len(run.Samples) || done.Scenarios != len(p.Scenarios):
		return fmt.Errorf("evidence: run %s completion counts mismatch", r.SessionID)
	}
	if err := validateRunTimeline(r.SessionID, envStarted, run.Started, envEnded, run.Ended, finished); err != nil {
		return err
	}
	if err := validateRunEnvironment(envStart, envEnd, p.Guard); err != nil {
		return fmt.Errorf("evidence: run %s: %w", r.SessionID, err)
	}
	if err := validateToolchainIdentity(m); err != nil {
		return fmt.Errorf("evidence: run %s: %w", r.SessionID, err)
	}
	for _, provenance := range []provenanceArtifact{m.GoEnv, m.ModuleGraph, m.OSVersion, m.SystemProfile, m.Limits} {
		if err := validateProvenanceRef(run, provenance); err != nil {
			return err
		}
	}
	if source, ok := r.Files["provenance/source-tree.txt"]; !ok || source.SHA256 != repository.SourceSHA256 {
		return fmt.Errorf("evidence: run %s lacks exact source-tree provenance", r.SessionID)
	}
	if err := validateGoEnvironment(run); err != nil {
		return err
	}
	modules, err := validateModuleGraph(run, root)
	if err != nil {
		return err
	}
	if err := validateBinaries(run, modules); err != nil {
		return err
	}
	if err := validateAdapters(run, root); err != nil {
		return err
	}
	if err := validateSamples(run); err != nil {
		return err
	}
	if err := validateGuardEvidence(run, envStart, p.Guard); err != nil {
		return err
	}
	return nil
}

func validateRunTimeline(sessionID string, envStarted, runStarted, envEnded, runEnded, finished time.Time) error {
	if envStarted.After(runStarted) || !runStarted.Before(runEnded) || envEnded.Before(runStarted) ||
		envEnded.After(runEnded) || envStarted.After(envEnded) || runEnded.After(finished) {
		return fmt.Errorf("evidence: run %s environment/manifest/completion timestamps are out of order", sessionID)
	}
	return nil
}

func validateEnvSnapshot(snapshot envSnapshot, requireUptime bool) error {
	for _, load := range []float64{snapshot.Load1, snapshot.Load5, snapshot.Load15} {
		if load < 0 || math.IsNaN(load) || math.IsInf(load, 0) {
			return fmt.Errorf("invalid load average %g", load)
		}
	}
	if snapshot.PMSetBattery == "" || snapshot.PMSetThermal == "" || snapshot.LogicalCPUs <= 0 || snapshot.MemoryBytes == 0 ||
		snapshot.BootIdentity == "" || snapshot.CapturedAt == "" || snapshot.ObservationNanoseconds <= 0 {
		return fmt.Errorf("host snapshot identity or observation overhead is incomplete")
	}
	if requireUptime && snapshot.Uptime == "" {
		return fmt.Errorf("host snapshot uptime is unavailable")
	}
	if _, err := time.Parse(time.RFC3339Nano, snapshot.CapturedAt); err != nil {
		return fmt.Errorf("invalid captured_at: %w", err)
	}
	return nil
}

func validateRunEnvironment(start, end envSnapshot, guard policy.Guard) error {
	if guard.MaxLoad1 <= 0 || start.Load1 > guard.MaxLoad1 {
		return fmt.Errorf("initial load1 %.2f exceeds max %.2f", start.Load1, guard.MaxLoad1)
	}
	startPower, endPower := snapshotPowerSource(start.PMSetBattery), snapshotPowerSource(end.PMSetBattery)
	if startPower == "" || endPower == "" || startPower != endPower {
		return fmt.Errorf("power source unavailable or changed from %q to %q", startPower, endPower)
	}
	if !snapshotThermalClean(start.PMSetThermal) || !snapshotThermalClean(end.PMSetThermal) {
		return fmt.Errorf("thermal or performance warning recorded")
	}
	return nil
}

func validateGuardEvidence(run resolvedRun, baseline envSnapshot, guard policy.Guard) error {
	seen := make(map[string]bool, len(run.Samples))
	for _, sample := range run.Samples {
		name := filepath.ToSlash(filepath.Join("logs", guardLogPrefix(sample.Scenario, sample.BlockID, sample.Library)+".guard.jsonl"))
		if seen[name] {
			return fmt.Errorf("evidence: run %s duplicate guard log identity %q", run.Receipt.SessionID, name)
		}
		seen[name] = true
		path, ok := run.Files[name]
		if !ok {
			return fmt.Errorf("evidence: run %s lacks guard log %q", run.Receipt.SessionID, name)
		}
		if err := validateGuardLog(path, baseline, guard); err != nil {
			return fmt.Errorf("evidence: run %s guard log %q: %w", run.Receipt.SessionID, name, err)
		}
	}
	return nil
}

func guardLogPrefix(scenario, block, library string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-")
	return replacer.Replace(scenario) + "__" + replacer.Replace(block) + "__" + replacer.Replace(library)
}

func validateGuardLog(path string, baseline envSnapshot, guard policy.Guard) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	count := 0
	var previous time.Time
	for scanner.Scan() {
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			return fmt.Errorf("empty snapshot line")
		}
		var snapshot envSnapshot
		if err := decodeStrict(raw, &snapshot); err != nil {
			return fmt.Errorf("snapshot %d: %w", count+1, err)
		}
		if err := validateEnvSnapshot(snapshot, false); err != nil {
			return fmt.Errorf("snapshot %d: %w", count+1, err)
		}
		if snapshot.BootIdentity != baseline.BootIdentity || snapshot.LogicalCPUs != baseline.LogicalCPUs || snapshot.MemoryBytes != baseline.MemoryBytes {
			return fmt.Errorf("snapshot %d host identity changed", count+1)
		}
		if source := snapshotPowerSource(snapshot.PMSetBattery); source == "" || source != snapshotPowerSource(baseline.PMSetBattery) {
			return fmt.Errorf("snapshot %d power source changed or became unavailable", count+1)
		}
		if !snapshotThermalClean(snapshot.PMSetThermal) {
			return fmt.Errorf("snapshot %d thermal or performance warning recorded", count+1)
		}
		if guard.MaxLoad1Drift <= 0 || snapshot.Load1-baseline.Load1 > guard.MaxLoad1Drift {
			return fmt.Errorf("snapshot %d load1 drift %.2f exceeds %.2f", count+1, snapshot.Load1-baseline.Load1, guard.MaxLoad1Drift)
		}
		captured, _ := time.Parse(time.RFC3339Nano, snapshot.CapturedAt)
		if !previous.IsZero() && captured.Before(previous) {
			return fmt.Errorf("snapshot %d timestamp moved backwards", count+1)
		}
		previous = captured
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("guard log has no snapshots")
	}
	return nil
}

func snapshotPowerSource(pmset string) string {
	line, _, _ := strings.Cut(pmset, "\n")
	const prefix = "Now drawing from '"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "'") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(line, prefix), "'")
}

func snapshotThermalClean(pmset string) bool {
	return strings.Contains(pmset, "No thermal warning level has been recorded") &&
		strings.Contains(pmset, "No performance warning level has been recorded")
}

func validateProvenanceRef(run resolvedRun, provenance provenanceArtifact) error {
	if provenance.Path == "" || !filepath.IsLocal(filepath.FromSlash(provenance.Path)) || !validHex(provenance.SHA256, 64) || provenance.SizeBytes < 0 {
		return fmt.Errorf("evidence: run %s invalid provenance artifact %+v", run.Receipt.SessionID, provenance)
	}
	ref, ok := run.Receipt.Files[provenance.Path]
	if !ok || ref.SHA256 != provenance.SHA256 || ref.SizeBytes != provenance.SizeBytes {
		return fmt.Errorf("evidence: run %s provenance ref mismatch for %s", run.Receipt.SessionID, provenance.Path)
	}
	return nil
}

func validateGoEnvironment(run resolvedRun) error {
	raw, err := os.ReadFile(run.Files[run.Manifest.GoEnv.Path])
	if err != nil {
		return err
	}
	var environment goEnvironment
	if err := json.Unmarshal(raw, &environment); err != nil {
		return fmt.Errorf("evidence: run %s go env: %w", run.Receipt.SessionID, err)
	}
	if environment.GOEXPERIMENT != "" || environment.GOENV != "" && environment.GOENV != "off" || environment.GOTOOLCHAIN != "local" || environment.GOFLAGS != "-mod=mod" ||
		environment.CGOEnabled != "0" || environment.GOFIPS140 != "latest" ||
		environment.GOVERSION == "" || !strings.Contains(run.Manifest.GoVersion, environment.GOVERSION) ||
		environment.GOOS != run.Manifest.GOOS || environment.GOARCH != run.Manifest.GOARCH {
		return fmt.Errorf("evidence: run %s uncontrolled Go environment: %+v", run.Receipt.SessionID, environment)
	}
	if environment.GOARCH == "amd64" && (environment.GOAMD64 != "v1" || environment.GOARM64 != "") ||
		environment.GOARCH == "arm64" && (environment.GOARM64 != "v8.0" || environment.GOAMD64 != "") {
		return fmt.Errorf("evidence: run %s invalid go env architecture baseline: %+v", run.Receipt.SessionID, environment)
	}
	return nil
}

func validateToolchainIdentity(manifest runManifest) error {
	t := manifest.ToolchainEnvironment
	if t.GOENV != "off" || t.GOTOOLCHAIN != "local" || t.GOFLAGS != "-mod=mod" || t.GOEXPERIMENT != "" ||
		t.GOOS != manifest.GOOS || t.GOARCH != manifest.GOARCH || t.GOFIPS140 != "latest" || t.CGOEnabled != "0" {
		return fmt.Errorf("uncontrolled toolchain environment: %+v", t)
	}
	if manifest.GOARCH == "arm64" && (t.GOARM64 != "v8.0" || t.GOAMD64 != "") ||
		manifest.GOARCH == "amd64" && (t.GOAMD64 != "v1" || t.GOARM64 != "") {
		return fmt.Errorf("invalid architecture baseline: %+v", t)
	}
	r := manifest.RuntimeEnvironment
	if r.GOMAXPROCS == "" || r.GOGC != "100" || r.GOMEMLIMIT != "off" || r.GODEBUG != "" || r.GOWSSIMD != "" {
		return fmt.Errorf("uncontrolled runtime environment: %+v", r)
	}
	wantGoTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if filepath.Clean(manifest.GoBinaryPath) != wantGoTool {
		return fmt.Errorf("Go toolchain path = %q, want %q", manifest.GoBinaryPath, wantGoTool)
	}
	info, err := os.Lstat(wantGoTool)
	if err != nil {
		return fmt.Errorf("stat Go toolchain: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != manifest.GoBinarySizeBytes || !validHex(manifest.GoBinarySHA256, 64) {
		return fmt.Errorf("Go toolchain file identity mismatch")
	}
	raw, err := os.ReadFile(wantGoTool)
	if err != nil {
		return fmt.Errorf("read Go toolchain: %w", err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != manifest.GoBinarySHA256 {
		return fmt.Errorf("Go toolchain SHA-256 mismatch")
	}
	return nil
}

func validateModuleGraph(run resolvedRun, root string) (map[string]moduleRecord, error) {
	path := run.Files[run.Manifest.ModuleGraph.Path]
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	current, err := captureCurrentModuleGraph(root, run.Manifest)
	if err != nil {
		return nil, err
	}
	artifactSum := sha256.Sum256(raw)
	currentSum := sha256.Sum256(current)
	if artifactSum != currentSum {
		return nil, fmt.Errorf("evidence: run %s module graph differs from the clean current source graph", run.Receipt.SessionID)
	}
	file := bytes.NewReader(raw)
	decoder := json.NewDecoder(bufio.NewReader(file))
	foundRoot := false
	foundQuickWS := false
	modules := make(map[string]moduleRecord)
	for {
		var module moduleRecord
		if err := decoder.Decode(&module); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("evidence: run %s module graph: %w", run.Receipt.SessionID, err)
		}
		if module.Path == "" || modules[module.Path].Path != "" {
			return nil, fmt.Errorf("evidence: run %s module graph has empty or duplicate module %q", run.Receipt.SessionID, module.Path)
		}
		modules[module.Path] = module
		switch module.Path {
		case "github.com/zchee/gows/bench":
			foundRoot = module.Main
		case "github.com/antlabs/quickws":
			foundQuickWS = module.Version == "v0.2.2"
			if !foundQuickWS {
				return nil, fmt.Errorf("evidence: quickws version = %q, want v0.2.2", module.Version)
			}
		}
	}
	if !foundRoot || !foundQuickWS {
		return nil, fmt.Errorf("evidence: run %s module graph lacks bench root or quickws v0.2.2", run.Receipt.SessionID)
	}
	return modules, nil
}

func captureCurrentModuleGraph(root string, manifest runManifest) ([]byte, error) {
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	t := manifest.ToolchainEnvironment
	environment := overrideEnv(os.Environ(),
		"GOENV="+t.GOENV, "GOTOOLCHAIN="+t.GOTOOLCHAIN, "GOFLAGS="+t.GOFLAGS,
		"GOEXPERIMENT="+t.GOEXPERIMENT, "GOOS="+t.GOOS, "GOARCH="+t.GOARCH,
		"GOAMD64="+t.GOAMD64, "GOARM64="+t.GOARM64, "GOFIPS140="+t.GOFIPS140,
		"CGO_ENABLED="+t.CGOEnabled,
	)
	command := exec.Command(goTool, "list", "-mod=mod", "-m", "-json", "all")
	command.Dir = filepath.Join(root, "bench")
	command.Env = environment
	var stderr bytes.Buffer
	command.Stderr = &stderr
	raw, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("evidence: current module graph: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	status, err := gitOutput(root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return nil, err
	}
	if status != "" {
		return nil, fmt.Errorf("evidence: module graph query dirtied the source tree: %s", strings.ReplaceAll(status, "\n", "; "))
	}
	return raw, nil
}

func validateBinaries(run resolvedRun, modules map[string]moduleRecord) error {
	m := run.Manifest
	if ref := run.Receipt.Files["echoserver"]; ref.SHA256 != m.EchoserverSHA256 {
		return fmt.Errorf("evidence: run %s echoserver hash mismatch", run.Receipt.SessionID)
	}
	if ref := run.Receipt.Files["loadgen"]; ref.SHA256 != m.LoadgenSHA256 {
		return fmt.Errorf("evidence: run %s loadgen hash mismatch", run.Receipt.SessionID)
	}
	wantBinaryKeys := []string{"echoserver", "loadgen", "library-" + run.Policy.Candidate, "library-" + run.Policy.Comparator}
	if err := requireExactKeys("binary provenance", m.BinaryProvenance, wantBinaryKeys); err != nil {
		return fmt.Errorf("evidence: run %s: %w", run.Receipt.SessionID, err)
	}
	if err := requireExactKeys("library binary hashes", m.LibraryBinariesSHA256, []string{run.Policy.Candidate, run.Policy.Comparator}); err != nil {
		return fmt.Errorf("evidence: run %s: %w", run.Receipt.SessionID, err)
	}
	if err := requireExactKeys("adapter hashes", m.AdapterSHA256, []string{run.Policy.Candidate, run.Policy.Comparator}); err != nil {
		return fmt.Errorf("evidence: run %s: %w", run.Receipt.SessionID, err)
	}
	for _, name := range wantBinaryKeys {
		binary := m.BinaryProvenance[name]
		if binary.Path == "" || !filepath.IsLocal(filepath.FromSlash(binary.Path)) || binary.SizeBytes <= 0 || !validHex(binary.SHA256, 64) {
			return fmt.Errorf("evidence: run %s binary provenance %q is invalid", run.Receipt.SessionID, name)
		}
		ref, ok := run.Receipt.Files[binary.Path]
		if !ok || ref.SHA256 != binary.SHA256 || ref.SizeBytes != binary.SizeBytes {
			return fmt.Errorf("evidence: run %s binary %q CAS identity mismatch", run.Receipt.SessionID, name)
		}
		if err := validateProvenanceRef(run, binary.GoVersionM); err != nil {
			return err
		}
		info, err := buildinfo.ReadFile(run.Files[binary.Path])
		if err != nil {
			return fmt.Errorf("evidence: run %s binary %q build info: %w", run.Receipt.SessionID, name, err)
		}
		if !strings.Contains(m.GoVersion, info.GoVersion) || strings.Contains(info.GoVersion, "-X:") {
			return fmt.Errorf("evidence: run %s binary %q Go version mismatch", run.Receipt.SessionID, name)
		}
		settings := make(map[string]string, len(info.Settings))
		for _, setting := range info.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["GOEXPERIMENT"] != "" || settings["GOOS"] != m.GOOS || settings["GOARCH"] != m.GOARCH ||
			settings["CGO_ENABLED"] != "0" || settings["GOFIPS140"] != "latest" ||
			settings["vcs.revision"] != m.GitCommit || settings["vcs.modified"] != "false" ||
			buildSettingEnabled(settings, "-race") || buildSettingEnabled(settings, "-asan") || buildSettingEnabled(settings, "-msan") {
			return fmt.Errorf("evidence: run %s binary %q has mixed toolchain settings", run.Receipt.SessionID, name)
		}
		if m.GOARCH == "amd64" && (settings["GOAMD64"] != "v1" || settings["GOARM64"] != "") ||
			m.GOARCH == "arm64" && (settings["GOARM64"] != "v8.0" || settings["GOAMD64"] != "") {
			return fmt.Errorf("evidence: run %s binary %q has wrong architecture baseline", run.Receipt.SessionID, name)
		}
		if err := validateBinaryModules(run.Receipt.SessionID, name, info, modules); err != nil {
			return err
		}
		versionRaw, err := os.ReadFile(run.Files[binary.GoVersionM.Path])
		if err != nil {
			return err
		}
		versionText := string(versionRaw)
		if !strings.Contains(versionText, "\tbuild\tGOOS="+m.GOOS) || !strings.Contains(versionText, "\tbuild\tGOARCH="+m.GOARCH) ||
			strings.Contains(versionText, "\tbuild\tGOEXPERIMENT=") || !strings.Contains(versionText, "\tbuild\tCGO_ENABLED=0") ||
			!strings.Contains(versionText, "\tbuild\tGOFIPS140=latest") || !strings.Contains(versionText, "\tbuild\tvcs.revision="+m.GitCommit) ||
			!strings.Contains(versionText, "\tbuild\tvcs.modified=false") {
			return fmt.Errorf("evidence: run %s binary %q go version -m mismatch", run.Receipt.SessionID, name)
		}
	}
	for _, library := range []string{run.Policy.Candidate, run.Policy.Comparator} {
		want := m.LibraryBinariesSHA256[library]
		binary, ok := m.BinaryProvenance["library-"+library]
		if !ok || want == "" || binary.SHA256 != want {
			return fmt.Errorf("evidence: run %s library %q binary is unrecorded", run.Receipt.SessionID, library)
		}
	}
	if m.BinaryProvenance["echoserver"].SHA256 != m.EchoserverSHA256 || m.BinaryProvenance["loadgen"].SHA256 != m.LoadgenSHA256 {
		return fmt.Errorf("evidence: run %s named binary provenance disagrees with manifest identity", run.Receipt.SessionID)
	}
	return nil
}

func buildSettingEnabled(settings map[string]string, name string) bool {
	value := settings[name]
	return value != "" && value != "false"
}

func requireExactKeys[V any](label string, values map[string]V, want []string) error {
	if len(values) != len(want) {
		return fmt.Errorf("%s has %d keys, want %d", label, len(values), len(want))
	}
	for _, key := range want {
		if _, ok := values[key]; !ok {
			return fmt.Errorf("%s lacks key %q", label, key)
		}
	}
	return nil
}

func validateBinaryModules(sessionID, name string, info *debug.BuildInfo, modules map[string]moduleRecord) error {
	main, ok := modules[info.Main.Path]
	if info.Main.Path == "" || !ok || !main.Main {
		return fmt.Errorf("evidence: run %s binary %q main module is absent from module graph", sessionID, name)
	}
	for _, dependency := range info.Deps {
		want, ok := modules[dependency.Path]
		if !ok || dependency.Version != want.Version || dependency.Sum != want.Sum || !sameModuleReplacement(dependency.Replace, want.Replace) {
			return fmt.Errorf("evidence: run %s binary %q dependency %q disagrees with module graph", sessionID, name, dependency.Path)
		}
	}
	return nil
}

func sameModuleReplacement(got *debug.Module, want *moduleRecord) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	versionMatches := got.Version == want.Version || got.Version == "(devel)" && want.Version == ""
	return got.Path == want.Path && versionMatches && got.Sum == want.Sum && sameModuleReplacement(got.Replace, want.Replace)
}

func validateAdapters(run resolvedRun, root string) error {
	for _, library := range []string{run.Policy.Candidate, run.Policy.Comparator} {
		want, err := policy.HashAdapter(filepath.Join(root, "bench"), run.Policy.Adapters[library])
		if err != nil {
			return err
		}
		if got := run.Manifest.AdapterSHA256[library]; got != want {
			return fmt.Errorf("evidence: run %s adapter %q hash = %s, want %s", run.Receipt.SessionID, library, got, want)
		}
	}
	return nil
}

func validateSamples(run resolvedRun) error {
	p := run.Policy
	expectedCount := 0
	scenarios := make(map[string]policy.Scenario, len(p.Scenarios))
	scenarioIndexes := make(map[string]int, len(p.Scenarios))
	for scenarioIndex, scenario := range p.Scenarios {
		expectedCount += scenario.Repetitions * 2
		scenarios[scenario.Name] = scenario
		scenarioIndexes[scenario.Name] = scenarioIndex
	}
	if len(run.Samples) != expectedCount {
		return fmt.Errorf("evidence: run %s samples = %d, want %d", run.Receipt.SessionID, len(run.Samples), expectedCount)
	}
	type pair struct {
		candidate  *paired.Sample
		comparator *paired.Sample
	}
	pairs := make(map[string]*pair, expectedCount/2)
	for i := range run.Samples {
		sample := &run.Samples[i]
		scenario, ok := scenarios[sample.Scenario]
		if !ok {
			return fmt.Errorf("evidence: run %s sample has unknown scenario %q", run.Receipt.SessionID, sample.Scenario)
		}
		if sample.SessionID != run.Receipt.SessionID || sample.PolicySHA256 != run.Receipt.PolicySHA256 {
			return fmt.Errorf("evidence: run %s sample identity mismatch", run.Receipt.SessionID)
		}
		if sample.Repetition >= scenario.Repetitions {
			return fmt.Errorf("evidence: run %s scenario %s repetition %d out of range", run.Receipt.SessionID, sample.Scenario, sample.Repetition)
		}
		if sample.BlockID != fmt.Sprintf("block-%03d", sample.Repetition) {
			return fmt.Errorf("evidence: run %s scenario %s has non-canonical block %q for repetition %d", run.Receipt.SessionID, sample.Scenario, sample.BlockID, sample.Repetition)
		}
		expectedPayloadSeed, err := paired.BlockPayloadSeed(p.Seed, scenarioIndexes[sample.Scenario], sample.Repetition)
		if err != nil {
			return err
		}
		if sample.LoadgenResult.PayloadSeed != expectedPayloadSeed {
			return fmt.Errorf("evidence: run %s scenario %s repetition %d payload seed = %d, want %d", run.Receipt.SessionID, sample.Scenario, sample.Repetition, sample.LoadgenResult.PayloadSeed, expectedPayloadSeed)
		}
		if sample.LoadgenResult.Client != string(p.Series.Client) || sample.LoadgenResult.MessageType != string(scenario.MessageType) ||
			sample.LoadgenResult.Arrival != string(scenario.Arrival) || sample.LoadgenResult.Connections != scenario.Connections ||
			sample.LoadgenResult.PayloadBytes != scenario.PayloadBytes || sample.LoadgenResult.Inflight != scenario.Inflight ||
			sample.LoadgenResult.RequestedOfferedMessagesPerSecond != scenario.OfferedRate ||
			sample.LoadgenResult.SchedulerLatenessLimitNanoseconds != scenario.MaxSchedulerLateness.Duration().Nanoseconds() ||
			sample.LoadgenResult.WarmupNanoseconds != scenario.Warmup.Duration().Nanoseconds() ||
			sample.LoadgenResult.DurationNanoseconds != scenario.Duration.Duration().Nanoseconds() {
			return fmt.Errorf("evidence: run %s sample shape disagrees with policy scenario %q", run.Receipt.SessionID, scenario.Name)
		}
		wantBinary := run.Manifest.LibraryBinariesSHA256[sample.Library]
		wantAdapter := run.Manifest.AdapterSHA256[sample.Library]
		if wantBinary == "" || sample.BinarySHA256 != wantBinary || wantAdapter == "" || sample.AdapterSHA256 != wantAdapter {
			return fmt.Errorf("evidence: run %s sample binary/adapter identity mismatch", run.Receipt.SessionID)
		}
		if err := validateMeasurementConsistency(*sample); err != nil {
			return fmt.Errorf("evidence: run %s scenario %s repetition %d: %w", run.Receipt.SessionID, sample.Scenario, sample.Repetition, err)
		}
		key := fmt.Sprintf("%s\x00%09d", sample.Scenario, sample.Repetition)
		entry := pairs[key]
		if entry == nil {
			entry = &pair{}
			pairs[key] = entry
		}
		switch sample.Library {
		case p.Candidate:
			if entry.candidate != nil {
				return fmt.Errorf("evidence: duplicate candidate sample %s", key)
			}
			entry.candidate = sample
		case p.Comparator:
			if entry.comparator != nil {
				return fmt.Errorf("evidence: duplicate comparator sample %s", key)
			}
			entry.comparator = sample
		default:
			return fmt.Errorf("evidence: run %s sample uses unregistered library %q", run.Receipt.SessionID, sample.Library)
		}
	}
	orders := make(map[string]map[paired.OrderPattern]int, len(p.Scenarios))
	for key, entry := range pairs {
		if entry.candidate == nil || entry.comparator == nil {
			return fmt.Errorf("evidence: incomplete pair %s", key)
		}
		candidate, comparator := entry.candidate, entry.comparator
		if candidate.BlockID != comparator.BlockID || candidate.Order != comparator.Order {
			return fmt.Errorf("evidence: pair %s block/order mismatch", key)
		}
		order := paired.OrderPattern(candidate.Order)
		if order == paired.OrderAB && (candidate.OrderIndex != 0 || comparator.OrderIndex != 1) ||
			order == paired.OrderBA && (comparator.OrderIndex != 0 || candidate.OrderIndex != 1) {
			return fmt.Errorf("evidence: pair %s execution order mismatch", key)
		}
		if orders[candidate.Scenario] == nil {
			orders[candidate.Scenario] = make(map[paired.OrderPattern]int)
		}
		orders[candidate.Scenario][order]++
	}
	for _, scenario := range p.Scenarios {
		if orders[scenario.Name][paired.OrderAB] != scenario.Repetitions/2 || orders[scenario.Name][paired.OrderBA] != scenario.Repetitions/2 {
			return fmt.Errorf("evidence: run %s scenario %s is not balanced AB/BA", run.Receipt.SessionID, scenario.Name)
		}
	}
	return nil
}

func loadStrictSamples(path string) ([]paired.Sample, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("evidence: open samples: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
	var samples []paired.Sample
	for line := 1; scanner.Scan(); line++ {
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var sample paired.Sample
		if err := decodeStrict(raw, &sample); err != nil {
			return nil, fmt.Errorf("evidence: samples line %d: %w", line, err)
		}
		if err := sample.Validate(); err != nil {
			return nil, fmt.Errorf("evidence: samples line %d: %w", line, err)
		}
		samples = append(samples, sample)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("evidence: read samples: %w", err)
	}
	return samples, nil
}

func validateMeasurementConsistency(sample paired.Sample) error {
	r := sample.LoadgenResult
	percentiles, err := r.Latency.Corrected.Percentiles()
	if err != nil {
		return err
	}
	if r.P50Nanoseconds != percentiles.P50.Nanoseconds() || r.P90Nanoseconds != percentiles.P90.Nanoseconds() ||
		r.P99Nanoseconds != percentiles.P99.Nanoseconds() || r.P999Nanoseconds != percentiles.P999.Nanoseconds() {
		return fmt.Errorf("latency summary disagrees with corrected HDR histogram")
	}
	if r.Latency.CorrectionMethod != "scheduled-start-response-time" || r.Latency.Raw.LowestTrackableNanoseconds != r.Latency.Corrected.LowestTrackableNanoseconds ||
		r.Latency.Raw.HighestTrackableNanoseconds != r.Latency.Corrected.HighestTrackableNanoseconds ||
		r.Latency.Raw.SignificantFigures != r.Latency.Corrected.SignificantFigures {
		return fmt.Errorf("latency observation contract is inconsistent")
	}
	durationSeconds := float64(r.DurationNanoseconds) / float64(time.Second)
	if !nearlyEqual(r.OfferedMessagesPerSecond, float64(r.OfferedMessages)/durationSeconds) ||
		!nearlyEqual(r.ThroughputMessagesPerSecond, float64(r.AchievedMessages)/durationSeconds) ||
		!nearlyEqual(r.RejectedMessagesPerSecond, float64(r.RejectedMessages)/durationSeconds) {
		return fmt.Errorf("reported rates disagree with counts and duration")
	}
	if !finitePositive(r.ThroughputMessagesPerSecond) || !finitePositive(r.LatencyObservationNanoseconds) {
		return fmt.Errorf("throughput or observation overhead is not finite and positive")
	}
	if err := validateAllocation(r.ServerAllocations, r.Messages); err != nil {
		return fmt.Errorf("server allocations: %w", err)
	}
	if err := validateAllocation(r.ClientAllocations, r.Messages); err != nil {
		return fmt.Errorf("client allocations: %w", err)
	}
	for name, usage := range map[string]support.Usage{
		"server": r.ServerUsage, "client": r.ClientUsage, "server_process": sample.ServerProcessUsage,
	} {
		if !usage.Available || usage.Source == "" || math.IsNaN(usage.CPUSeconds) || math.IsInf(usage.CPUSeconds, 0) || usage.CPUSeconds <= 0 || usage.MaxRSSBytes <= 0 {
			return fmt.Errorf("%s rusage is unavailable or invalid: %+v", name, usage)
		}
	}
	messages := float64(r.Messages)
	if !nearlyEqual(sample.ServerCPUSeconds, r.ServerUsage.CPUSeconds) || sample.ServerMaxRSSBytes != r.ServerUsage.MaxRSSBytes ||
		!nearlyEqual(sample.ServerCPUSecondsPerMessage, r.ServerUsage.CPUSeconds/messages) ||
		!nearlyEqual(sample.ServerRSSBytesPerConnection, float64(r.ServerUsage.MaxRSSBytes)/float64(r.Connections)) ||
		!nearlyEqual(sample.ClientCPUSecondsPerMessage, r.ClientUsage.CPUSeconds/messages) {
		return fmt.Errorf("sample-derived CPU/RSS fields disagree with raw usage")
	}
	return nil
}

func validateAllocation(stats support.AllocationStats, messages int64) error {
	return stats.Validate(messages)
}

func nearlyEqual(left, right float64) bool {
	if left == right {
		return true
	}
	delta := math.Abs(left - right)
	scale := math.Max(1, math.Max(math.Abs(left), math.Abs(right)))
	return delta <= 1e-12*scale
}

func finitePositive(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func runPair(run resolvedRun, scenario string, repetition int) (paired.Sample, paired.Sample, error) {
	var candidate, comparator *paired.Sample
	for i := range run.Samples {
		sample := &run.Samples[i]
		if sample.Scenario != scenario || sample.Repetition != repetition {
			continue
		}
		if sample.Library == run.Policy.Candidate {
			candidate = sample
		} else if sample.Library == run.Policy.Comparator {
			comparator = sample
		}
	}
	if candidate == nil || comparator == nil {
		return paired.Sample{}, paired.Sample{}, fmt.Errorf("evidence: missing pair %s/%d", scenario, repetition)
	}
	return *candidate, *comparator, nil
}
