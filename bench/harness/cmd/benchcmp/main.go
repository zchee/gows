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
	"path/filepath"
	"time"

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
	os.Exit(run())
}

func run() int {
	runDir := flag.String("run", "", "path to a benchrun output directory (required)")
	policyPath := flag.String("policy", "", "policy JSON path (default <run>/policy.json)")
	flag.Parse()

	if *runDir == "" {
		fmt.Fprintln(os.Stderr, "benchcmp: -run is required")
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
