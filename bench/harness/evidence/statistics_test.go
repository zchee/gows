package evidence

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

func TestEvaluateAAPassesExactSameBinaryAndIsOrderStable(t *testing.T) {
	pol := aaTestPolicy()
	runs := make([]resolvedRun, 3)
	base := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	for i := range runs {
		runs[i] = statisticalRun(pol, "aa-session-"+string(rune('1'+i)), base.Add(time.Duration(i)*time.Hour), 1)
	}
	got, err := evaluateAA(runs)
	if err != nil {
		t.Fatalf("evaluateAA: %v", err)
	}
	if !got.Pass || !got.FalsePositiveOK || got.FalsePositive != 0 {
		t.Fatalf("A/A verdict = %+v, want pass with zero false positives", got)
	}
	if len(got.Scenarios) != 1 || got.Scenarios[0].Pairs != 60 || got.Scenarios[0].Throughput.Ratio.Center != 1 {
		t.Fatalf("unexpected A/A scenario verdict: %+v", got.Scenarios)
	}
	resourceMetrics := make(map[string]bool, len(got.Scenarios[0].Resources))
	for _, resource := range got.Scenarios[0].Resources {
		resourceMetrics[resource.Metric] = true
	}
	for _, metric := range []string{
		"server_raw_allocations_per_message",
		"server_raw_allocated_bytes_per_message",
		"client_raw_allocations_per_message",
		"client_raw_allocated_bytes_per_message",
	} {
		if !resourceMetrics[metric] {
			t.Fatalf("A/A verdict resource metrics %v do not include %q", resourceMetrics, metric)
		}
	}

	permuted := slices.Clone(runs)
	for i := range permuted {
		permuted[i].Samples = slices.Clone(runs[i].Samples)
		slices.Reverse(permuted[i].Samples)
	}
	again, err := evaluateAA(permuted)
	if err != nil {
		t.Fatalf("evaluateAA permuted: %v", err)
	}
	one, err := MarshalVerdict(Verdict{SchemaVersion: SchemaVersion, Kind: ReceiptKind, Pass: got.Pass, AA: got})
	if err != nil {
		t.Fatal(err)
	}
	two, err := MarshalVerdict(Verdict{SchemaVersion: SchemaVersion, Kind: ReceiptKind, Pass: again.Pass, AA: again})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one, two) {
		t.Fatalf("sample line permutation changed verdict bytes")
	}

	changedHarness := slices.Clone(runs)
	changedHarness[1].Manifest.LoadgenSHA256 = "changed"
	if _, err := evaluateAA(changedHarness); err == nil {
		t.Fatal("A/A accepted a cross-session loadgen binary identity change")
	}
}

func TestEvaluateAARejectsWidenedEquivalencePolicy(t *testing.T) {
	pol := aaTestPolicy()
	pol.AAGates.Throughput = policy.RatioBand{Lower: 0.5, Upper: 1.5}
	runs := make([]resolvedRun, 3)
	base := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	for i := range runs {
		runs[i] = statisticalRun(pol, fmt.Sprintf("aa-session-%d", i+1), base.Add(time.Duration(i)*time.Hour), 1)
	}
	if _, err := evaluateAA(runs); err == nil {
		t.Fatal("A/A accepted a widened receipt-supplied equivalence band")
	}
}

func TestEvaluateBaselineDoesNotRequireQuickWSSuperiority(t *testing.T) {
	records := make([]RunEvidence, 0, len(requiredBaselineRoles))
	runs := make(map[string]resolvedRun, len(requiredBaselineRoles))
	for i, role := range requiredBaselineRoles {
		pol := baselineTestPolicy(role, i)
		run := statisticalRun(pol, "baseline-"+role, time.Date(2026, 7, 15, 10+i, 0, 0, 0, time.UTC), 0.5)
		runs[role] = run
		records = append(records, RunEvidence{Role: role, Run: run.Reference})
	}
	verdicts, err := evaluateBaselines(records, runs)
	if err != nil {
		t.Fatalf("evaluateBaselines: %v", err)
	}
	if len(verdicts) != len(requiredBaselineRoles) {
		t.Fatalf("baseline verdict count = %d", len(verdicts))
	}
	for _, verdict := range verdicts {
		if verdict.SuperiorityGate {
			t.Fatalf("baseline %s unexpectedly has a superiority gate", verdict.SeriesID)
		}
		if got := verdict.Scenarios[0].Metrics[0].Ratio.Center; got >= 0.75 {
			t.Fatalf("fixture did not represent a losing baseline: ratio=%g", got)
		}
	}
}

func aaTestPolicy() *policy.Policy {
	pol := baseStatisticalPolicy()
	pol.Series = policy.Series{
		ID: "phase0-aa", RunKind: policy.RunKindAA, EvidenceClass: policy.EvidenceClassSelfValidation,
		HostMode: policy.HostModeSame, Toolchain: policy.ToolchainStock, AdapterClass: policy.AdapterClassAA,
		ValidationProfile: policy.ValidationStrict, Client: policy.ClientGoWS,
	}
	pol.Candidate, pol.Comparator = "gows-a", "gows-b"
	pol.LibraryOverrides = map[string]policy.LibraryOverride{
		"gows-a": {Lib: "gows"}, "gows-b": {Lib: "gows"},
	}
	adapter := policy.Adapter{ID: "gows-aa-v1", Class: policy.AdapterClassAA, SourceFiles: []string{"harness/cmd/echoserver/server_gows.go"}}
	pol.Adapters = map[string]policy.Adapter{"gows-a": adapter, "gows-b": adapter}
	if err := pol.Validate(); err != nil {
		panic(err)
	}
	return pol
}

func baselineTestPolicy(role string, index int) *policy.Policy {
	pol := baseStatisticalPolicy()
	adapterClass := policy.AdapterClassBestAPI
	client := policy.ClientGoWS
	if role == "semantic-parity-gows-client" {
		adapterClass = policy.AdapterClassSemanticParity
	}
	if role == "independent-gobwas-client" {
		client = policy.ClientGobwas
	}
	if role == "independent-raw-client" {
		client = policy.ClientRaw
	}
	pol.Series = policy.Series{
		ID: role + "-series", RunKind: policy.RunKindBaseline, EvidenceClass: policy.EvidenceClassBaseline,
		HostMode: policy.HostModeSame, Toolchain: policy.ToolchainStock, AdapterClass: adapterClass,
		ValidationProfile: policy.ValidationStrict, Client: client,
	}
	pol.Candidate, pol.Comparator = "gows-serve", "quickws"
	pol.Adapters = map[string]policy.Adapter{
		"gows-serve": {ID: role + "-gows", Class: adapterClass, SourceFiles: []string{"harness/cmd/echoserver/server_gows.go"}},
		"quickws":    {ID: role + "-quickws", Class: adapterClass, SourceFiles: []string{"harness/cmd/echoserver/server_quickws.go"}},
	}
	pol.Seed += uint64(index)
	if err := pol.Validate(); err != nil {
		panic(err)
	}
	return pol
}

func baseStatisticalPolicy() *policy.Policy {
	return &policy.Policy{
		SchemaVersion: policy.PolicySchemaVersion,
		Seed:          12648430,
		Bootstrap:     policy.Bootstrap{Replicates: 1000, Confidence: 0.95, NullIterations: 1000},
		AAGates: policy.AAGates{
			MinSessions: 3, MinPairsPerSession: 20,
			Throughput: policy.RatioBand{Lower: 0.98, Upper: 1.02},
			P99:        policy.RatioBand{Lower: 0.98, Upper: 1.02}, P999: policy.RatioBand{Lower: 0.95, Upper: 1.05},
			OrderEffect: policy.RatioBand{Lower: 0.99, Upper: 1.01}, MaxFalsePositive: 0.05,
		},
		Thresholds: policy.Thresholds{ThroughputLowerBound: 1.05, ThroughputGeomean: 1.10, P99UpperBound: 0.95, P999CenterUpperBound: 1},
		Guard:      policy.Guard{MaxLoad1: 100, MaxLoad1Drift: 100, MaxForeignCPUPercent: 100},
		Scenarios: []policy.Scenario{{
			Name: "server-sensitive", Primary: true, CellClass: policy.CellServerSensitive,
			MessageType: policy.MessageBinary, Arrival: policy.ArrivalClosedLoop,
			PayloadBytes: 1024, Connections: 20, Inflight: 1,
			Warmup: policy.Duration(5 * time.Second), Duration: policy.Duration(30 * time.Second), Repetitions: 20,
		}},
	}
}

func statisticalRun(pol *policy.Policy, session string, started time.Time, candidateThroughputRatio float64) resolvedRun {
	const binary = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const adapter = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const policySum = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	run := resolvedRun{
		Reference: artifact.Ref{URI: "omx-cas://sha256/" + sessionHash(session), SHA256: sessionHash(session), SizeBytes: 1, MediaType: "application/vnd.gows.bench-run-receipt+json"},
		Receipt:   artifact.RunReceipt{SessionID: session, PolicySHA256: policySum},
		Manifest: runManifest{
			Hostname: "host", Kernel: "kernel", BootIdentityStart: "boot", BootIdentityEnd: "boot",
			LibraryBinariesSHA256: map[string]string{pol.Candidate: binary, pol.Comparator: binary},
			AdapterSHA256:         map[string]string{pol.Candidate: adapter, pol.Comparator: adapter},
		},
		Policy: pol, Started: started, Ended: started.Add(45 * time.Minute),
	}
	for _, scenario := range pol.Scenarios {
		for repetition := range scenario.Repetitions {
			order := paired.OrderAB
			if repetition%2 == 1 {
				order = paired.OrderBA
			}
			comparator := statisticalSample(session, scenario.Name, pol.Comparator, repetition, order, 100)
			candidate := statisticalSample(session, scenario.Name, pol.Candidate, repetition, order, 100*candidateThroughputRatio)
			run.Samples = append(run.Samples, candidate, comparator)
		}
	}
	return run
}

func statisticalSample(session, scenario, library string, repetition int, order paired.OrderPattern, throughput float64) paired.Sample {
	return paired.Sample{
		SessionID: session, Scenario: scenario, Library: library, Repetition: repetition,
		BlockID: "block-" + leftPad3(repetition), Order: string(order),
		LoadgenResult: support.LoadgenResult{
			ThroughputMessagesPerSecond: throughput, P99Nanoseconds: 1_000, P999Nanoseconds: 2_000,
			Connections:       20,
			ServerUsage:       support.Usage{Available: true, CPUSeconds: 1, MaxRSSBytes: 20_000},
			ClientUsage:       support.Usage{Available: true, CPUSeconds: 1, MaxRSSBytes: 40_000},
			ServerAllocations: support.AllocationStats{Available: true, AllocationsPerMessage: 0.001, AllocatedBytesPerMessage: 1},
			ClientAllocations: support.AllocationStats{Available: true, AllocationsPerMessage: 0.002, AllocatedBytesPerMessage: 2},
		},
		ServerCPUSecondsPerMessage: 1e-6, ServerRSSBytesPerConnection: 1_000, ClientCPUSecondsPerMessage: 1e-6,
	}
}

func leftPad3(value int) string {
	if value < 10 {
		return "00" + string(rune('0'+value))
	}
	return "0" + string([]byte{byte('0' + value/10), byte('0' + value%10)})
}

func sessionHash(value string) string {
	result := []byte("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	for i := range value {
		result[i%len(result)] = "0123456789abcdef"[value[i]%16]
	}
	return string(result)
}
