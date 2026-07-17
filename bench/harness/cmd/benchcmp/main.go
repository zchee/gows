// Command benchcmp evaluates a benchrun output directory: it pairs candidate
// and comparator samples per primary scenario, computes deterministic
// median-bootstrap confidence intervals for throughput and tail latency,
// applies the policy's gate thresholds, and writes verdict.json. It exits 0
// when every gate passes, 1 on a gate failure, and 2 on a usage or data
// error. See bench/README.md for the gate definitions.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	phase0 "github.com/zchee/gows/bench/harness/evidence"
	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

// exit codes.
const (
	exitPass  = 0
	exitGate  = 1
	exitUsage = 2
)

// ScenarioVerdict is one primary scenario's evaluated statistics and per-gate
// outcomes.
type ScenarioVerdict struct {
	Name                         string  `json:"name"`
	Primary                      bool    `json:"primary"`
	Repetitions                  int     `json:"repetitions"`
	ThroughputCenter             float64 `json:"throughput_center"`
	ThroughputLower              float64 `json:"throughput_lower"`
	ThroughputUpper              float64 `json:"throughput_upper"`
	ThroughputPass               bool    `json:"throughput_pass"`
	P99Center                    float64 `json:"p99_center"`
	P99Lower                     float64 `json:"p99_lower"`
	P99Upper                     float64 `json:"p99_upper"`
	P99Pass                      bool    `json:"p99_pass"`
	P999Center                   float64 `json:"p999_center"`
	P999Pass                     bool    `json:"p999_pass"`
	ServerCPUPerMessageCenter    float64 `json:"server_cpu_seconds_per_message_center"`
	ServerRSSPerConnectionCenter float64 `json:"server_rss_bytes_per_connection_center"`
	ClientCPUPerMessageCenter    float64 `json:"client_cpu_seconds_per_message_center"`
}

// Verdict is the machine-checkable comparison result written to verdict.json.
type Verdict struct {
	Pass         bool              `json:"pass"`
	Candidate    string            `json:"candidate"`
	Comparator   string            `json:"comparator"`
	Geomean      float64           `json:"geomean"`
	GeomeanPass  bool              `json:"geomean_pass"`
	Scenarios    []ScenarioVerdict `json:"scenarios"`
	Thresholds   policy.Thresholds `json:"thresholds"`
	PolicySHA256 string            `json:"policy_sha256"`
	GeneratedAt  string            `json:"generated_at"`
}

func main() {
	if delegated, code, err := delegateToStockController(); delegated {
		if err != nil {
			fmt.Fprintf(os.Stderr, "benchcmp: stock controller: %v\n", err)
			os.Exit(exitUsage)
		}
		os.Exit(code)
	}
	os.Exit(run())
}

func run() int {
	runDir := flag.String("run", "", "path to a benchrun output directory (required)")
	policyPath := flag.String("policy", "", "policy JSON path (default <run>/policy.json)")
	writeVerdict := flag.String("write-verdict", "", "write a newly generated Phase 0 verdict (must be <run>/verdict.json)")
	flag.Parse()

	if *runDir == "" {
		fmt.Fprintln(os.Stderr, "benchcmp: -run is required")
		return exitUsage
	}
	if phase0.IsPhase0Directory(*runDir) {
		return runPhase0(*runDir, *writeVerdict)
	}
	if *writeVerdict != "" {
		fmt.Fprintln(os.Stderr, "benchcmp: -write-verdict is valid only for the Phase 0 evaluator")
		return exitUsage
	}
	pp := *policyPath
	if pp == "" {
		pp = filepath.Join(*runDir, "policy.json")
	}
	pol, rawPolicy, err := policy.Load(pp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		return exitUsage
	}
	if err := validateLegacyPolicy(pol); err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		return exitUsage
	}
	samples, err := paired.LoadSamples(filepath.Join(*runDir, "samples.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		return exitUsage
	}

	verdict, err := evaluate(samples, pol, policy.Sum(rawPolicy))
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		return exitUsage
	}
	verdict.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)

	if err := support.WriteJSONFile(filepath.Join(*runDir, "verdict.json"), verdict); err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		return exitUsage
	}
	printSummary(verdict)

	if verdict.Pass {
		return exitPass
	}
	return exitGate
}

func validateLegacyPolicy(pol *policy.Policy) error {
	if pol.Series.RunKind != policy.RunKindDiagnostic || pol.Series.EvidenceClass != policy.EvidenceClassDiagnostic {
		return fmt.Errorf("legacy flat-bootstrap evaluator accepts diagnostic policies only; use the Phase 0 receipt evaluator for %s/%s evidence", pol.Series.RunKind, pol.Series.EvidenceClass)
	}
	return nil
}

func runPhase0(runDir, writeVerdict string) int {
	wantVerdict := filepath.Join(runDir, phase0.VerdictFile)
	if writeVerdict != "" {
		got, err := filepath.Abs(writeVerdict)
		if err != nil {
			fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
			return exitUsage
		}
		want, err := filepath.Abs(wantVerdict)
		if err != nil || got != want {
			fmt.Fprintf(os.Stderr, "benchcmp: -write-verdict must be %s\n", wantVerdict)
			return exitUsage
		}
	}
	verdict, raw, err := phase0.EvaluateDirectory(runDir, writeVerdict == "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
		return exitUsage
	}
	if writeVerdict != "" {
		if err := support.WriteFileAtomic(writeVerdict, raw, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "benchcmp: %v\n", err)
			return exitUsage
		}
	}
	fmt.Printf("benchcmp: Phase 0 source=%s receipt=%s\n", verdict.SourceHead, verdict.ReceiptSHA256)
	fmt.Printf("  A/A sessions=%d false-positive=%.6f pass=%s\n", len(verdict.AA.SessionIDs), verdict.AA.FalsePositive, passLabel(verdict.AA.Pass))
	fmt.Printf("  baselines=%d assemblies=%d verification-checks=%d\n", len(verdict.Baselines), len(verdict.Assemblies), len(verdict.Verification.Checks))
	fmt.Printf("VERDICT: %s\n", passLabel(verdict.Pass))
	if verdict.Pass {
		return exitPass
	}
	return exitGate
}

const stockControllerMarker = "GOWS_BENCHCMP_STOCK_CONTROLLER=1"

// delegateToStockController preserves the frozen external command without
// trusting the environment that compiled its bootstrap process. The bootstrap
// always builds and executes the same source with the controller's compiler;
// the marked child then proves its build and process controls
// before evaluating evidence.
func delegateToStockController() (delegated bool, code int, resultErr error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return true, exitUsage, fmt.Errorf("build info is unavailable")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if os.Getenv("GOWS_BENCHCMP_STOCK_CONTROLLER") == "1" {
		if err := validateControlledController(info.GoVersion, settings, os.Getenv); err != nil {
			return true, exitUsage, err
		}
		return false, 0, nil
	}
	goTool := controllerGoToolPath()
	if file, err := os.Lstat(goTool); err != nil || !file.Mode().IsRegular() {
		return true, exitUsage, fmt.Errorf("absolute Go tool %s is unavailable", goTool)
	}
	temporary, err := os.MkdirTemp("", "gows-benchcmp-stock-")
	if err != nil {
		return true, exitUsage, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, os.RemoveAll(temporary))
	}()
	binary := filepath.Join(temporary, "benchcmp")
	environment := controlledEnvironment(os.Environ())
	build := exec.Command(goTool, "build", "-mod=mod", "-o", binary, "./harness/cmd/benchcmp")
	build.Env = environment
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return true, exitUsage, fmt.Errorf("build controlled evaluator: %w", err)
	}
	child := exec.Command(binary, os.Args[1:]...)
	child.Env = append(environment, stockControllerMarker)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return true, exitErr.ExitCode(), nil
		}
		return true, exitUsage, err
	}
	return true, exitPass, nil
}

// controllerGoToolPath returns the exact compiler that built this controller,
// which is the toolchain the delegated evaluator must prove and reuse.
func controllerGoToolPath() string {
	//lint:ignore SA1019 Exact build-toolchain identity is required by evaluator delegation.
	return filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // Exact build-toolchain identity is required by evaluator delegation.
}

func controlledEnvironment(base []string) []string {
	overrides := []string{
		"GOENV=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=", "GOFLAGS=-mod=mod",
		"GOFIPS140=latest", "GOWORK=off", "CGO_ENABLED=0",
		"GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH, "GOAMD64=", "GOARM64=",
	}
	switch runtime.GOARCH {
	case "amd64":
		overrides[len(overrides)-2] = "GOAMD64=v1"
	case "arm64":
		overrides[len(overrides)-1] = "GOARM64=v8.0"
	}
	keys := map[string]bool{
		"GOENV": true, "GOTOOLCHAIN": true, "GOEXPERIMENT": true, "GOFLAGS": true,
		"GOFIPS140": true, "GOWORK": true, "CGO_ENABLED": true,
		"GOOS": true, "GOARCH": true, "GOAMD64": true, "GOARM64": true,
		"GOWS_BENCHCMP_STOCK_CONTROLLER": true,
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, value := range base {
		key, _, _ := strings.Cut(value, "=")
		if !keys[key] {
			result = append(result, value)
		}
	}
	return append(result, overrides...)
}

func validateControlledController(goVersion string, settings map[string]string, getenv func(string) string) error {
	if strings.Contains(goVersion, "-X:") || settings["GOEXPERIMENT"] != "" || settings["CGO_ENABLED"] != "0" ||
		settings["GOFIPS140"] != "latest" || settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH ||
		buildSettingEnabled(settings["-race"]) || buildSettingEnabled(settings["-asan"]) || buildSettingEnabled(settings["-msan"]) {
		return fmt.Errorf("controlled evaluator build settings are invalid: GoVersion=%q settings=%v", goVersion, settings)
	}
	if runtime.GOARCH == "amd64" && (settings["GOAMD64"] != "v1" || settings["GOARM64"] != "") ||
		runtime.GOARCH == "arm64" && (settings["GOARM64"] != "v8.0" || settings["GOAMD64"] != "") {
		return fmt.Errorf("controlled evaluator architecture baseline is invalid")
	}
	wantEnvironment := map[string]string{
		"GOENV": "off", "GOTOOLCHAIN": "local", "GOEXPERIMENT": "", "GOFLAGS": "-mod=mod",
		"GOFIPS140": "latest", "GOWORK": "off", "CGO_ENABLED": "0",
	}
	for key, want := range wantEnvironment {
		if got := getenv(key); got != want {
			return fmt.Errorf("controlled evaluator environment %s=%q, want %q", key, got, want)
		}
	}
	return nil
}

func buildSettingEnabled(value string) bool { return value != "" && value != "false" }

// evaluate computes the full verdict from samples under a policy. It is pure
// and deterministic for a fixed policy seed (GeneratedAt is left empty for the
// caller to stamp), so a verdict is exactly reproducible.
func evaluate(samples []paired.Sample, pol *policy.Policy, policySum string) (Verdict, error) {
	primaries := pol.PrimaryScenarios()
	if len(primaries) == 0 {
		return Verdict{}, errors.New("policy has no primary scenarios")
	}
	bs := pol.Bootstrap
	th := pol.Thresholds

	// Every scenario is evaluated and reported, but only primary scenarios
	// gate the verdict: the pass/fail decision and the throughput geomean are
	// folded from primaries alone, while non-primary (experimental) cells are
	// reported with their computed ratios and per-gate outcomes for context
	// without ever flipping Pass.
	scenarios := make([]ScenarioVerdict, 0, len(pol.Scenarios))
	throughputCenters := make([]float64, 0, len(primaries))
	pass := true

	for _, sc := range pol.Scenarios {
		throughput, err := paired.Ratios(samples, sc.Name, pol.Candidate, pol.Comparator, paired.MetricThroughput)
		if err != nil {
			return Verdict{}, err
		}
		tCenter, tLower, tUpper := paired.Bootstrap(throughput, bs.Replicates, bs.Confidence, pol.Seed)

		p99, err := paired.Ratios(samples, sc.Name, pol.Candidate, pol.Comparator, paired.MetricP99)
		if err != nil {
			return Verdict{}, err
		}
		p99Center, p99Lower, p99Upper := paired.Bootstrap(p99, bs.Replicates, bs.Confidence, pol.Seed)

		p999, err := paired.Ratios(samples, sc.Name, pol.Candidate, pol.Comparator, paired.MetricP999)
		if err != nil {
			return Verdict{}, err
		}
		p999Center := paired.Median(p999)

		serverCPU, err := paired.Ratios(samples, sc.Name, pol.Candidate, pol.Comparator, paired.MetricServerCPUPerMessage)
		if err != nil {
			return Verdict{}, err
		}
		serverRSS, err := paired.Ratios(samples, sc.Name, pol.Candidate, pol.Comparator, paired.MetricServerRSSPerConn)
		if err != nil {
			return Verdict{}, err
		}
		clientCPU, err := paired.Ratios(samples, sc.Name, pol.Candidate, pol.Comparator, paired.MetricClientCPUPerMessage)
		if err != nil {
			return Verdict{}, err
		}

		tPass := tLower > th.ThroughputLowerBound
		p99Pass := p99Upper <= th.P99UpperBound
		p999Pass := p999Center <= th.P999CenterUpperBound
		if sc.Primary {
			if !tPass || !p99Pass || !p999Pass {
				pass = false
			}
			throughputCenters = append(throughputCenters, tCenter)
		}

		scenarios = append(scenarios, ScenarioVerdict{
			Name:                         sc.Name,
			Primary:                      sc.Primary,
			Repetitions:                  len(throughput),
			ThroughputCenter:             tCenter,
			ThroughputLower:              tLower,
			ThroughputUpper:              tUpper,
			ThroughputPass:               tPass,
			P99Center:                    p99Center,
			P99Lower:                     p99Lower,
			P99Upper:                     p99Upper,
			P99Pass:                      p99Pass,
			P999Center:                   p999Center,
			P999Pass:                     p999Pass,
			ServerCPUPerMessageCenter:    paired.Median(serverCPU),
			ServerRSSPerConnectionCenter: paired.Median(serverRSS),
			ClientCPUPerMessageCenter:    paired.Median(clientCPU),
		})
	}

	geomean := paired.Geomean(throughputCenters)
	geomeanPass := geomean >= th.ThroughputGeomean
	if !geomeanPass {
		pass = false
	}

	return Verdict{
		Pass:         pass,
		Candidate:    pol.Candidate,
		Comparator:   pol.Comparator,
		Geomean:      geomean,
		GeomeanPass:  geomeanPass,
		Scenarios:    scenarios,
		Thresholds:   th,
		PolicySHA256: policySum,
	}, nil
}

// printSummary prints a compact human-readable verdict to stdout.
func printSummary(v Verdict) {
	fmt.Printf("benchcmp: %s vs %s\n", v.Candidate, v.Comparator)
	for _, s := range v.Scenarios {
		tag := ""
		if !s.Primary {
			tag = " (experimental, not gated)"
		}
		fmt.Printf("  %-24s throughput=%.4f [%.4f,%.4f] %s  p99=%.4f [%.4f,%.4f] %s  p999=%.4f %s (n=%d)%s\n",
			s.Name,
			s.ThroughputCenter, s.ThroughputLower, s.ThroughputUpper, passLabel(s.ThroughputPass),
			s.P99Center, s.P99Lower, s.P99Upper, passLabel(s.P99Pass),
			s.P999Center, passLabel(s.P999Pass),
			s.Repetitions, tag)
	}
	fmt.Printf("  throughput geomean=%.4f (>= %.4f) %s\n", v.Geomean, v.Thresholds.ThroughputGeomean, passLabel(v.GeomeanPass))
	fmt.Printf("VERDICT: %s\n", passLabel(v.Pass))
}

// passLabel renders a boolean gate outcome as PASS or FAIL.
func passLabel(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
