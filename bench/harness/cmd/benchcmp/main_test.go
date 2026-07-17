package main

import (
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

func TestControlledEnvironmentOverridesToolchainInputs(t *testing.T) {
	got := controlledEnvironment([]string{
		"PATH=/bin", "GOENV=/tmp/goenv", "GOTOOLCHAIN=auto", "GOEXPERIMENT=greenteagc", "GOFLAGS=-race",
		"GOFIPS140=off", "GOWORK=/tmp/go.work", "CGO_ENABLED=1", "GOWS_BENCHCMP_STOCK_CONTROLLER=stale",
	})
	for _, want := range []string{
		"PATH=/bin", "GOENV=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=", "GOFLAGS=-mod=mod",
		"GOFIPS140=latest", "GOWORK=off", "CGO_ENABLED=0",
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("controlled environment lacks %q: %v", want, got)
		}
	}
	for _, forbidden := range []string{
		"GOENV=/tmp/goenv", "GOTOOLCHAIN=auto", "GOEXPERIMENT=greenteagc", "GOFLAGS=-race",
		"GOFIPS140=off", "GOWORK=/tmp/go.work", "CGO_ENABLED=1", "GOWS_BENCHCMP_STOCK_CONTROLLER=stale",
	} {
		if slices.Contains(got, forbidden) {
			t.Fatalf("controlled environment retained %q: %v", forbidden, got)
		}
	}
	// The architecture baseline pair must always be pinned: the host arch gets
	// the exact value validateControlledController requires of the delegated
	// evaluator, and the other arch's variable is pinned empty.
	wantArch := []string{"GOAMD64=", "GOARM64="}
	switch runtime.GOARCH {
	case "amd64":
		wantArch = []string{"GOAMD64=v1", "GOARM64="}
	case "arm64":
		wantArch = []string{"GOAMD64=", "GOARM64=v8.0"}
	}
	for _, want := range wantArch {
		if !slices.Contains(got, want) {
			t.Fatalf("controlled environment lacks architecture baseline %q: %v", want, got)
		}
	}
}

func TestLegacyEvaluatorAcceptsDiagnosticPoliciesOnly(t *testing.T) {
	diagnostic := testPolicy()
	diagnostic.Series.RunKind = policy.RunKindDiagnostic
	diagnostic.Series.EvidenceClass = policy.EvidenceClassDiagnostic
	if err := validateLegacyPolicy(diagnostic); err != nil {
		t.Fatalf("diagnostic policy rejected: %v", err)
	}
	baseline := testPolicy()
	baseline.Series.RunKind = policy.RunKindBaseline
	baseline.Series.EvidenceClass = policy.EvidenceClassBaseline
	if err := validateLegacyPolicy(baseline); err == nil {
		t.Fatal("legacy flat bootstrap accepted promotable baseline evidence")
	}
}

func sample(scenario, lib string, rep int, throughput float64, p99, p999 int64) paired.Sample {
	return paired.Sample{
		LoadgenResult: support.LoadgenResult{
			Connections:                 200,
			Messages:                    1_000_000,
			ThroughputMessagesPerSecond: throughput,
			P99Nanoseconds:              p99,
			P999Nanoseconds:             p999,
		},
		Scenario:                    scenario,
		Library:                     lib,
		Repetition:                  rep,
		ServerCPUSecondsPerMessage:  1e-6,
		ServerRSSBytesPerConnection: 1000,
		ClientCPUSecondsPerMessage:  1e-6,
	}
}

// genSamples builds n paired repetitions where candidate metrics are the
// comparator metrics scaled by the given ratios (throughput higher-better,
// p99/p999 lower-better). A small deterministic per-rep wiggle on throughput
// gives the bootstrap a non-degenerate distribution.
func genSamples(scenario string, n int, tRatio, p99Ratio, p999Ratio float64) []paired.Sample {
	const (
		compThroughput = 100.0
		compP99        = int64(1000)
		compP999       = int64(2000)
	)
	var out []paired.Sample
	for i := range n {
		wiggle := 1 + 0.01*float64(i%5)
		out = append(
			out,
			sample(scenario, "cand", i, compThroughput*tRatio*wiggle, int64(float64(compP99)*p99Ratio), int64(float64(compP999)*p999Ratio)),
			sample(scenario, "comp", i, compThroughput*wiggle, compP99, compP999),
		)
	}
	return out
}

func testPolicy() *policy.Policy {
	return &policy.Policy{
		Candidate:  "cand",
		Comparator: "comp",
		Seed:       12648430,
		Bootstrap:  policy.Bootstrap{Replicates: 4000, Confidence: 0.95},
		Thresholds: policy.Thresholds{
			ThroughputLowerBound: 1.0,
			ThroughputGeomean:    1.05,
			P99UpperBound:        1.01,
			P999CenterUpperBound: 1.05,
		},
		Scenarios: []policy.Scenario{{
			Name:         "s",
			Primary:      true,
			PayloadBytes: 1024,
			Connections:  200,
			Inflight:     1,
			Warmup:       policy.Duration(5 * time.Second),
			Duration:     policy.Duration(30 * time.Second),
			Repetitions:  20,
		}},
	}
}

func TestEvaluateGates(t *testing.T) {
	tests := map[string]struct {
		tRatio    float64
		p99Ratio  float64
		p999Ratio float64
		wantPass  bool
	}{
		"pass: faster and lower tails":   {tRatio: 1.06, p99Ratio: 0.95, p999Ratio: 0.95, wantPass: true},
		"fail: candidate slower":         {tRatio: 0.95, p99Ratio: 0.95, p999Ratio: 0.95, wantPass: false},
		"fail: p99 regressed":            {tRatio: 1.06, p99Ratio: 1.02, p999Ratio: 0.95, wantPass: false},
		"fail: p999 center too high":     {tRatio: 1.06, p99Ratio: 0.95, p999Ratio: 1.10, wantPass: false},
		"fail: throughput below geomean": {tRatio: 1.02, p99Ratio: 0.95, p999Ratio: 0.95, wantPass: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			pol := testPolicy()
			samples := genSamples("s", pol.Scenarios[0].Repetitions, tc.tRatio, tc.p99Ratio, tc.p999Ratio)
			v, err := evaluate(samples, pol, "deadbeef")
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if v.Pass != tc.wantPass {
				t.Fatalf("Pass = %v, want %v (geomean=%.4f, scenario=%+v)", v.Pass, tc.wantPass, v.Geomean, v.Scenarios[0])
			}
			if len(v.Scenarios) != 1 {
				t.Fatalf("expected 1 scenario verdict, got %d", len(v.Scenarios))
			}
			if v.Scenarios[0].Repetitions != pol.Scenarios[0].Repetitions {
				t.Fatalf("scenario repetitions = %d, want %d", v.Scenarios[0].Repetitions, pol.Scenarios[0].Repetitions)
			}
		})
	}
}

func TestEvaluateDeterministic(t *testing.T) {
	pol := testPolicy()
	samples := genSamples("s", pol.Scenarios[0].Repetitions, 1.06, 0.95, 0.95)
	v1, err := evaluate(samples, pol, "deadbeef")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	v2, err := evaluate(samples, pol, "deadbeef")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	s1, s2 := v1.Scenarios[0], v2.Scenarios[0]
	if v1.Geomean != v2.Geomean || s1.ThroughputLower != s2.ThroughputLower || s1.P99Upper != s2.P99Upper {
		t.Fatalf("evaluate not deterministic:\n v1=%+v\n v2=%+v", v1, v2)
	}
}

func TestEvaluatePairingError(t *testing.T) {
	pol := testPolicy()
	// Drop one comparator repetition to force a pairing mismatch.
	samples := genSamples("s", pol.Scenarios[0].Repetitions, 1.06, 0.95, 0.95)
	trimmed := samples[:len(samples)-1]
	if _, err := evaluate(trimmed, pol, "deadbeef"); err == nil {
		t.Fatalf("expected pairing error, got nil")
	}
}

// TestEvaluateReportsNonPrimary confirms a non-primary (experimental) scenario
// is evaluated and reported in the verdict, but never gates the pass/fail
// decision or the throughput geomean: a badly failing experimental cell leaves
// an otherwise-passing verdict green.
func TestEvaluateReportsNonPrimary(t *testing.T) {
	pol := testPolicy()
	// Add a second, non-primary scenario alongside the passing primary one.
	pol.Scenarios = append(pol.Scenarios, policy.Scenario{
		Name:         "e",
		Primary:      false,
		PayloadBytes: 1024,
		Connections:  200,
		Inflight:     8,
		Warmup:       policy.Duration(5 * time.Second),
		Duration:     policy.Duration(30 * time.Second),
		Repetitions:  20,
	})

	reps := pol.Scenarios[0].Repetitions
	// Primary "s" passes; experimental "e" is far slower with worse tails.
	samples := append(
		genSamples("s", reps, 1.06, 0.95, 0.95),
		genSamples("e", reps, 0.50, 1.50, 1.50)...,
	)

	v, err := evaluate(samples, pol, "deadbeef")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !v.Pass {
		t.Fatalf("Pass = false, want true (experimental cell must not gate; geomean=%.4f)", v.Geomean)
	}
	if len(v.Scenarios) != 2 {
		t.Fatalf("verdict scenarios = %d, want 2 (primary + experimental)", len(v.Scenarios))
	}

	byName := make(map[string]ScenarioVerdict, len(v.Scenarios))
	for _, s := range v.Scenarios {
		byName[s.Name] = s
	}
	primary, ok := byName["s"]
	if !ok || !primary.Primary || !primary.ThroughputPass {
		t.Fatalf("primary scenario verdict = %+v, want Primary && ThroughputPass", primary)
	}
	exp, ok := byName["e"]
	if !ok {
		t.Fatalf("experimental scenario missing from verdict")
	}
	if exp.Primary {
		t.Fatalf("experimental scenario Primary = true, want false")
	}
	if exp.ThroughputPass {
		t.Fatalf("experimental scenario ThroughputPass = true, want false (it is slower and should still be reported)")
	}
	if exp.Repetitions != reps {
		t.Fatalf("experimental scenario repetitions = %d, want %d", exp.Repetitions, reps)
	}
}
