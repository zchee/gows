package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"

	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

func TestValidateMeasurementConsistencyRejectsForgedDerivedFields(t *testing.T) {
	t.Parallel()
	sample := validMeasuredSample(t)
	if err := validateMeasurementConsistency(sample); err != nil {
		t.Fatalf("valid sample: %v", err)
	}

	forgedTail := sample
	forgedTail.LoadgenResult.P99Nanoseconds++
	if err := validateMeasurementConsistency(forgedTail); err == nil || !strings.Contains(err.Error(), "HDR") {
		t.Fatalf("forged percentile error = %v", err)
	}

	forgedAllocation := sample
	forgedAllocation.LoadgenResult.ServerAllocations.MallocsRawDelta++
	if err := validateMeasurementConsistency(forgedAllocation); err == nil || !strings.Contains(err.Error(), "allocation") {
		t.Fatalf("forged allocation error = %v", err)
	}

	forgedCPU := sample
	forgedCPU.ServerCPUSecondsPerMessage *= 2
	if err := validateMeasurementConsistency(forgedCPU); err == nil || !strings.Contains(err.Error(), "CPU/RSS") {
		t.Fatalf("forged CPU error = %v", err)
	}
}

func TestLoadStrictSamplesRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	sample := validMeasuredSample(t)
	raw, err := jsonv2.Marshal(sample, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"adapter_sha256":`), []byte(`"unknown":true,"adapter_sha256":`), 1)
	path := filepath.Join(t.TempDir(), "samples.jsonl")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStrictSamples(path); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("loadStrictSamples error = %v, want unknown-field rejection", err)
	}
}

func TestValidateSamplesRejectsReusedBlockIdentity(t *testing.T) {
	t.Parallel()
	pol := &policy.Policy{
		Candidate: "a", Comparator: "b",
		Series: policy.Series{Client: policy.ClientGoWS},
		Scenarios: []policy.Scenario{{
			Name: "cell", MessageType: policy.MessageBinary, Arrival: policy.ArrivalClosedLoop,
			Connections: 2, PayloadBytes: 64, Inflight: 1, Duration: policy.Duration(time.Second), Repetitions: 2,
		}},
	}
	run := resolvedRun{
		Receipt: artifact.RunReceipt{SessionID: "session", PolicySHA256: strings.Repeat("c", 64)},
		Policy:  pol,
		Manifest: runManifest{
			LibraryBinariesSHA256: map[string]string{"a": strings.Repeat("a", 64), "b": strings.Repeat("b", 64)},
			AdapterSHA256:         map[string]string{"a": strings.Repeat("d", 64), "b": strings.Repeat("e", 64)},
		},
	}
	for repetition := range 2 {
		payloadSeed, err := paired.BlockPayloadSeed(pol.Seed, 0, repetition)
		if err != nil {
			t.Fatal(err)
		}
		order := paired.OrderAB
		if repetition == 1 {
			order = paired.OrderBA
		}
		for index, library := range []string{"a", "b"} {
			if order == paired.OrderBA {
				index = 1 - index
			}
			sample := validMeasuredSample(t)
			sample.SessionID = "session"
			sample.Scenario = "cell"
			sample.Library = library
			sample.Repetition = repetition
			sample.BlockID = "block-00" + string(rune('0'+repetition))
			sample.Order = string(order)
			sample.OrderIndex = index
			sample.PolicySHA256 = strings.Repeat("c", 64)
			sample.LoadgenResult.PayloadSeed = payloadSeed
			sample.BinarySHA256 = run.Manifest.LibraryBinariesSHA256[library]
			sample.AdapterSHA256 = run.Manifest.AdapterSHA256[library]
			run.Samples = append(run.Samples, sample)
		}
	}
	if err := validateSamples(run); err != nil {
		t.Fatalf("valid matrix: %v", err)
	}
	for i := range run.Samples {
		if run.Samples[i].Repetition == 1 {
			run.Samples[i].BlockID = "block-000"
		}
	}
	if err := validateSamples(run); err == nil || !strings.Contains(err.Error(), "non-canonical block") {
		t.Fatalf("reused block error = %v", err)
	}
}

func TestValidateRunTimeline(t *testing.T) {
	base := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	valid := []time.Time{base, base.Add(time.Second), base.Add(2 * time.Second), base.Add(3 * time.Second), base.Add(4 * time.Second)}
	if err := validateRunTimeline("session", valid[0], valid[1], valid[2], valid[3], valid[4]); err != nil {
		t.Fatalf("valid run timeline: %v", err)
	}
	tests := map[string][]time.Time{
		"environment start after manifest start": {valid[2], valid[1], valid[2], valid[3], valid[4]},
		"environment end after manifest end":     {valid[0], valid[1], valid[4], valid[3], valid[4]},
		"completion before manifest end":         {valid[0], valid[1], valid[2], valid[3], valid[2]},
	}
	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateRunTimeline("session", values[0], values[1], values[2], values[3], values[4]); err == nil {
				t.Fatal("invalid run timeline was accepted")
			}
		})
	}
}

func TestValidateEnvSnapshotRequiresObservationOverhead(t *testing.T) {
	snapshot := envSnapshot{
		PMSetBattery: "Now drawing from 'AC Power'", PMSetThermal: "No thermal warning level has been recorded\nNo performance warning level has been recorded",
		LogicalCPUs: 8, MemoryBytes: 16 << 30, BootIdentity: "darwin:kern.bootsessionuuid=test-boot", Uptime: "up 1 day",
		CapturedAt: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), ObservationNanoseconds: 1,
	}
	if err := validateEnvSnapshot(snapshot, true); err != nil {
		t.Fatalf("valid environment snapshot: %v", err)
	}
	snapshot.ObservationNanoseconds = 0
	if err := validateEnvSnapshot(snapshot, true); err == nil {
		t.Fatal("environment snapshot accepted missing observation overhead")
	}
}

func TestRunEnvironmentRejectsRecordedContamination(t *testing.T) {
	cleanThermal := "No thermal warning level has been recorded\nNo performance warning level has been recorded"
	baseline := envSnapshot{
		Load1: 2, PMSetBattery: "Now drawing from 'AC Power'", PMSetThermal: cleanThermal,
		LogicalCPUs: 8, MemoryBytes: 16 << 30, BootIdentity: "darwin:kern.bootsessionuuid=test-boot",
	}
	guard := policy.Guard{MaxLoad1: 6, MaxLoad1Drift: 4}
	if err := validateRunEnvironment(baseline, baseline, guard); err != nil {
		t.Fatalf("clean run environment: %v", err)
	}
	thermal := baseline
	thermal.PMSetThermal = "Performance warning level: 1"
	if err := validateRunEnvironment(baseline, thermal, guard); err == nil {
		t.Fatal("recorded thermal contamination was accepted")
	}
	power := baseline
	power.PMSetBattery = "Now drawing from 'Battery Power'"
	if err := validateRunEnvironment(baseline, power, guard); err == nil {
		t.Fatal("recorded power-source drift was accepted")
	}
	hot := baseline
	hot.Load1 = guard.MaxLoad1 + 0.1
	if err := validateRunEnvironment(hot, hot, guard); err == nil {
		t.Fatal("recorded initial load above the guard ceiling was accepted")
	}
	load := baseline
	load.Load1 = 6.1
	load.CapturedAt = time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	load.ObservationNanoseconds = 1
	path := filepath.Join(t.TempDir(), "guard.jsonl")
	raw, err := jsonv2.Marshal(load, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateGuardLog(path, baseline, guard); err == nil || !strings.Contains(err.Error(), "load1 drift") {
		t.Fatalf("recorded load drift error = %v", err)
	}
}

func TestBinaryIdentityHelpersFailClosed(t *testing.T) {
	if err := requireExactKeys("binaries", map[string]int{"echoserver": 1}, []string{"echoserver", "loadgen"}); err == nil {
		t.Fatal("exact-key validation accepted a missing binary")
	}
	if !buildSettingEnabled(map[string]string{"-race": "true"}, "-race") || buildSettingEnabled(map[string]string{"-race": "false"}, "-race") {
		t.Fatal("race build-setting detection is incorrect")
	}
}

func validMeasuredSample(t *testing.T) paired.Sample {
	t.Helper()
	recorder, err := support.NewLatencyRecorder(support.LatencyConfig{
		Lowest: time.Microsecond, Highest: time.Second, SignificantFigures: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		recorder.Record(time.Millisecond, time.Millisecond)
	}
	latency := recorder.Snapshot()
	percentiles, err := latency.Corrected.Percentiles()
	if err != nil {
		t.Fatal(err)
	}
	serverAllocation := support.AllocationStats{
		Available: true, MallocsBefore: 100, MallocsAfter: 112, MallocsRawDelta: 12,
		MallocsObservationOverhead: 2,
		TotalAllocBytesBefore:      1000, TotalAllocBytesAfter: 1220, TotalAllocBytesRawDelta: 220,
		TotalAllocObservationBytes: 20,
		AllocationsPerMessage:      1.2, AllocatedBytesPerMessage: 22,
		RateBasis: "raw-delta-including-observation", ObservationMethod: "paired-prewindow-control",
	}
	clientAllocation := serverAllocation
	serverUsage := support.Usage{Available: true, CPUSeconds: 1, MaxRSSBytes: 20_000, Source: "test-window-delta"}
	clientUsage := support.Usage{Available: true, CPUSeconds: 2, MaxRSSBytes: 40_000, Source: "test-window-delta"}
	result := support.LoadgenResult{
		SchemaVersion: support.LoadgenSchemaVersion, Client: "gows", MessageType: "binary", Arrival: "closed_loop",
		Connections: 2, PayloadBytes: 64, PayloadSeed: 1, Inflight: 1, DurationNanoseconds: int64(time.Second),
		Messages: 10, OfferedMessages: 10, AchievedMessages: 10,
		OfferedMessagesPerSecond: 10, ThroughputMessagesPerSecond: 10,
		P50Nanoseconds: percentiles.P50.Nanoseconds(), P90Nanoseconds: percentiles.P90.Nanoseconds(),
		P99Nanoseconds: percentiles.P99.Nanoseconds(), P999Nanoseconds: percentiles.P999.Nanoseconds(),
		Latency: latency, LatencyObservationNanoseconds: 1,
		ServerAllocations: serverAllocation, ClientAllocations: clientAllocation,
		ServerUsage: serverUsage, ClientUsage: clientUsage,
		ClientCPUSeconds: clientUsage.CPUSeconds, ClientMaxRSSBytes: clientUsage.MaxRSSBytes, ClientMaxRSSAvailable: true,
	}
	return paired.Sample{
		LoadgenResult: result, SchemaVersion: paired.SampleSchemaVersion,
		SessionID: "session", BlockID: "block-000", Order: string(paired.OrderAB),
		BinarySHA256: strings.Repeat("a", 64), PolicySHA256: strings.Repeat("b", 64), AdapterSHA256: strings.Repeat("c", 64),
		Scenario: "cell", Library: "a", Repetition: 0,
		ServerProcessUsage: support.Usage{Available: true, CPUSeconds: 2, MaxRSSBytes: 20_000, Source: "test-process"},
		ServerCPUSeconds:   serverUsage.CPUSeconds, ServerMaxRSSBytes: serverUsage.MaxRSSBytes,
		ServerCPUSecondsPerMessage: 0.1, ServerRSSBytesPerConnection: 10_000, ClientCPUSecondsPerMessage: 0.2,
	}
}
