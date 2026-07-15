package paired

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/zchee/gows/bench/harness/support"
)

// TestLoadSamples covers benchcmp's only data-ingestion path: blank-line
// tolerance, field decoding, and the malformed-line error carrying the
// offending line number.
func TestLoadSamples(t *testing.T) {
	t.Parallel()

	line := func(library string, throughput float64, p99 int64) string {
		t.Helper()
		sample := validSampleFixture(t, library, throughput, p99)
		raw, err := json.Marshal(sample)
		if err != nil {
			t.Fatalf("marshal sample fixture: %v", err)
		}
		return string(raw)
	}
	gowsLine := line("gows", 100.5, 1500)
	quickwsLine := line("quickws", 90.25, 1800)
	missingIdentity := validSampleFixture(t, "gows", 100.5, 1500)
	missingIdentity.BinarySHA256 = ""
	missingIdentityRaw, err := json.Marshal(missingIdentity)
	if err != nil {
		t.Fatalf("marshal missing-identity fixture: %v", err)
	}

	tests := map[string]struct {
		content string
		wantN   int
		wantErr string
	}{
		"success: two samples separated by a blank line": {
			content: gowsLine + "\n\n" + quickwsLine + "\n",
			wantN:   2,
		},
		"success: empty file yields no samples": {
			content: "",
			wantN:   0,
		},
		"error: malformed line reports its line number": {
			content: gowsLine + "\n\n{not json}\n",
			wantErr: "line 3",
		},
		"error: legacy versionless sample is rejected": {
			content: `{"scenario":"binary-1k-200","library":"gows","repetition":0}` + "\n",
			wantErr: "schema_version",
		},
		"error: missing immutable identity is rejected": {
			content: string(missingIdentityRaw) + "\n",
			wantErr: "binary_sha256",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "samples.jsonl")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			samples, err := LoadSamples(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadSamples error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadSamples: %v", err)
			}
			if len(samples) != tt.wantN {
				t.Fatalf("len(samples) = %d, want %d", len(samples), tt.wantN)
			}
			if tt.wantN == 2 {
				if samples[0].Library != "gows" || samples[1].Library != "quickws" {
					t.Fatalf("libraries = %q, %q, want gows, quickws", samples[0].Library, samples[1].Library)
				}
				if samples[0].LoadgenResult.ThroughputMessagesPerSecond != 100.5 {
					t.Fatalf("throughput = %v, want 100.5", samples[0].LoadgenResult.ThroughputMessagesPerSecond)
				}
				if samples[1].LoadgenResult.P99Nanoseconds != 1800 {
					t.Fatalf("p99 = %d, want 1800", samples[1].LoadgenResult.P99Nanoseconds)
				}
			}
		})
	}

	t.Run("error: missing file", func(t *testing.T) {
		t.Parallel()

		if _, err := LoadSamples(filepath.Join(t.TempDir(), "absent.jsonl")); err == nil {
			t.Fatal("LoadSamples on a missing file: nil error, want non-nil")
		}
	})
}

func validSampleFixture(t *testing.T, library string, throughput float64, p99 int64) Sample {
	t.Helper()
	recorder, err := support.NewLatencyRecorder(support.LatencyConfig{
		Lowest: time.Nanosecond, Highest: time.Second, SignificantFigures: 3,
	})
	if err != nil {
		t.Fatalf("NewLatencyRecorder: %v", err)
	}
	messages := int64(throughput * 4)
	for range messages {
		recorder.Record(time.Duration(p99), time.Duration(p99))
	}
	latency := recorder.Snapshot()
	percentiles, err := latency.Corrected.Percentiles()
	if err != nil {
		t.Fatalf("Percentiles: %v", err)
	}
	usage := support.Usage{Available: true, CPUSeconds: 0.001, MaxRSSBytes: 4096, Source: "fixture"}
	allocations := support.AllocationStats{
		Available:         true,
		RateBasis:         "raw-delta-including-observation",
		ObservationMethod: "paired-prewindow-control",
	}
	duration := int64(4 * time.Second)
	loadgen := support.LoadgenResult{
		SchemaVersion: support.LoadgenSchemaVersion, Client: "raw", MessageType: "binary", Arrival: "closed_loop",
		Connections: 1, PayloadBytes: 1024, PayloadSeed: 1, Inflight: 1, DurationNanoseconds: duration,
		Messages: messages, OfferedMessages: messages, AchievedMessages: messages,
		OfferedMessagesPerSecond: throughput, ThroughputMessagesPerSecond: throughput,
		P50Nanoseconds: percentiles.P50.Nanoseconds(), P90Nanoseconds: percentiles.P90.Nanoseconds(), P99Nanoseconds: percentiles.P99.Nanoseconds(), P999Nanoseconds: percentiles.P999.Nanoseconds(),
		Latency: latency, ServerAllocations: allocations, ClientAllocations: allocations,
		LatencyObservationNanoseconds: 1,
		ServerUsage:                   usage, ClientUsage: usage, ClientCPUSeconds: usage.CPUSeconds,
		ClientMaxRSSBytes: usage.MaxRSSBytes, ClientMaxRSSAvailable: true,
	}
	sha := strings.Repeat("a", 64)
	return Sample{
		LoadgenResult: loadgen, SchemaVersion: SampleSchemaVersion, SessionID: "session-a",
		BlockID: "block-000", Order: string(OrderAB), BinarySHA256: sha, PolicySHA256: sha,
		AdapterSHA256: sha, Scenario: "binary-1k-200", Library: library,
		ServerProcessUsage: usage, ServerCPUSeconds: usage.CPUSeconds, ServerMaxRSSBytes: usage.MaxRSSBytes,
	}
}
