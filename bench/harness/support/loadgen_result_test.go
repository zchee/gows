package support

import (
	"testing"
	"time"
)

func TestLoadgenResultRejectsForgedAccounting(t *testing.T) {
	t.Parallel()
	if err := validLoadgenResult(t).HardFailure(); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	tests := map[string]func(*LoadgenResult){
		"old schema":             func(r *LoadgenResult) { r.SchemaVersion-- },
		"missing payload seed":   func(r *LoadgenResult) { r.PayloadSeed = 0 },
		"forged percentile":      func(r *LoadgenResult) { r.P99Nanoseconds++ },
		"forged throughput":      func(r *LoadgenResult) { r.ThroughputMessagesPerSecond++ },
		"forged allocation rate": func(r *LoadgenResult) { r.ServerAllocations.AllocationsPerMessage++ },
		"unavailable resource":   func(r *LoadgenResult) { r.ServerUsage.Available = false },
		"histogram count mismatch": func(r *LoadgenResult) {
			r.Latency.Raw.BucketCounts[0]++
		},
		"hard I/O error": func(r *LoadgenResult) { r.Errors = 1 },
		"hard queue rejection": func(r *LoadgenResult) {
			r.OfferedMessages++
			r.RejectedMessages = 1
			r.QueueOverflows = 1
			r.OfferedMessagesPerSecond++
			r.RejectedMessagesPerSecond = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := validLoadgenResult(t)
			mutate(&record)
			if err := record.HardFailure(); err == nil {
				t.Fatalf("HardFailure accepted %s", name)
			}
		})
	}
}

func TestOpenLoopAccountingIsExactAndFailClosed(t *testing.T) {
	t.Parallel()
	valid := validLoadgenResult(t)
	valid.Arrival = "open_loop"
	valid.RequestedOfferedMessagesPerSecond = 10
	valid.SchedulerLatenessLimitNanoseconds = int64(time.Millisecond)
	valid.SchedulerMaxLatenessNanoseconds = int64(100 * time.Microsecond)
	if err := valid.HardFailure(); err != nil {
		t.Fatalf("valid open-loop fixture: %v", err)
	}

	tests := map[string]func(*LoadgenResult){
		"silent schedule loss": func(r *LoadgenResult) {
			r.RequestedOfferedMessagesPerSecond = 11
		},
		"unaccounted scheduler rejection": func(r *LoadgenResult) {
			r.RequestedOfferedMessagesPerSecond = 11
			r.OfferedMessages++
			r.OfferedMessagesPerSecond++
			r.RejectedMessages++
			r.RejectedMessagesPerSecond++
		},
		"scheduler late message": func(r *LoadgenResult) {
			r.RequestedOfferedMessagesPerSecond = 11
			r.OfferedMessages++
			r.OfferedMessagesPerSecond++
			r.RejectedMessages++
			r.RejectedMessagesPerSecond++
			r.SchedulerLateMessages++
			r.SchedulerMaxLatenessNanoseconds = int64(2 * time.Millisecond)
		},
		"post-window message": func(r *LoadgenResult) {
			r.RequestedOfferedMessagesPerSecond = 11
			r.OfferedMessages++
			r.OfferedMessagesPerSecond++
			r.DroppedMessages++
			r.PostWindowMessages++
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if err := record.HardFailure(); err == nil {
				t.Fatalf("HardFailure accepted %s", name)
			}
		})
	}
}

func TestOpenLoopOfferedMessages(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		duration time.Duration
		rate     int
		want     int64
	}{
		{time.Nanosecond, 1, 1},
		{time.Second, 1_000, 1_000},
		{time.Second + time.Nanosecond, 1_000, 1_001},
		{250 * time.Millisecond, 10, 3},
	} {
		got, err := OpenLoopOfferedMessages(test.duration, test.rate)
		if err != nil {
			t.Fatalf("OpenLoopOfferedMessages(%s,%d): %v", test.duration, test.rate, err)
		}
		if got != test.want {
			t.Fatalf("OpenLoopOfferedMessages(%s,%d) = %d, want %d", test.duration, test.rate, got, test.want)
		}
	}
}

func validLoadgenResult(t *testing.T) LoadgenResult {
	t.Helper()
	recorder, err := NewLatencyRecorder(LatencyConfig{Lowest: time.Microsecond, Highest: time.Second, SignificantFigures: 2})
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
	allocations, err := AllocationDelta(
		MemSnapshot{Mallocs: 100, TotalAlloc: 1_000},
		MemSnapshot{Mallocs: 110, TotalAlloc: 2_000},
		MemSnapshotDelta{}, 10,
	)
	if err != nil {
		t.Fatal(err)
	}
	usage := Usage{Available: true, CPUSeconds: 0.1, MaxRSSBytes: 4096, Source: "getrusage-test-window-delta"}
	return LoadgenResult{
		SchemaVersion: LoadgenSchemaVersion, Client: "raw", MessageType: "binary", Arrival: "closed_loop",
		Connections: 1, PayloadBytes: 1024, PayloadSeed: 1, Inflight: 1,
		WarmupNanoseconds: int64(time.Second), DurationNanoseconds: int64(time.Second),
		Messages: 10, OfferedMessages: 10, AchievedMessages: 10,
		OfferedMessagesPerSecond: 10, ThroughputMessagesPerSecond: 10,
		P50Nanoseconds: percentiles.P50.Nanoseconds(), P90Nanoseconds: percentiles.P90.Nanoseconds(),
		P99Nanoseconds: percentiles.P99.Nanoseconds(), P999Nanoseconds: percentiles.P999.Nanoseconds(),
		Latency: latency, LatencyObservationNanoseconds: 1,
		ServerAllocations: allocations, ClientAllocations: allocations,
		ServerUsage: usage, ClientUsage: usage, ClientCPUSeconds: usage.CPUSeconds,
		ClientMaxRSSBytes: usage.MaxRSSBytes, ClientMaxRSSAvailable: true,
	}
}
