package support

import (
	"testing"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/google/go-cmp/cmp"
)

func TestLatencyRecorder(t *testing.T) {
	t.Parallel()

	cfg := LatencyConfig{
		Lowest:             time.Microsecond,
		Highest:            time.Second,
		SignificantFigures: 3,
	}
	tests := map[string]struct {
		records [][2]time.Duration
		want    HistogramCounts
	}{
		"success: records every observation without reservoir loss": {
			records: [][2]time.Duration{
				{100 * time.Microsecond, 120 * time.Microsecond},
				{200 * time.Microsecond, 250 * time.Microsecond},
				{300 * time.Microsecond, 400 * time.Microsecond},
			},
			want: HistogramCounts{Seen: 3, Recorded: 3},
		},
		"success: corrected latency defaults to raw latency": {
			records: [][2]time.Duration{{100 * time.Microsecond, 0}},
			want:    HistogramCounts{Seen: 1, Recorded: 1},
		},
		"success: out of range observations are explicit drops": {
			records: [][2]time.Duration{
				{100 * time.Microsecond, 100 * time.Microsecond},
				{2 * time.Second, 2 * time.Second},
			},
			want: HistogramCounts{Seen: 2, Recorded: 1, Dropped: 1, Overflow: 1},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			recorder, err := NewLatencyRecorder(cfg)
			if err != nil {
				t.Fatalf("NewLatencyRecorder: %v", err)
			}
			for _, record := range tt.records {
				recorder.Record(record[0], record[1])
			}

			snapshot := recorder.Snapshot()
			if diff := cmp.Diff(tt.want, snapshot.Raw.HistogramCounts); diff != "" {
				t.Fatalf("raw counts mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want, snapshot.Corrected.HistogramCounts); diff != "" {
				t.Fatalf("corrected counts mismatch (-want +got):\n%s", diff)
			}
			if snapshot.Raw.LowestTrackableNanoseconds != cfg.Lowest.Nanoseconds() {
				t.Fatalf("raw lowest = %d, want %d", snapshot.Raw.LowestTrackableNanoseconds, cfg.Lowest.Nanoseconds())
			}
			if snapshot.Raw.HighestTrackableNanoseconds != cfg.Highest.Nanoseconds() {
				t.Fatalf("raw highest = %d, want %d", snapshot.Raw.HighestTrackableNanoseconds, cfg.Highest.Nanoseconds())
			}
		})
	}
}

func TestMergeLatencySnapshots(t *testing.T) {
	t.Parallel()

	cfg := LatencyConfig{
		Lowest:             time.Microsecond,
		Highest:            time.Second,
		SignificantFigures: 3,
	}
	inputs := make([]LatencySnapshot, 2)
	for i := range inputs {
		r, err := NewLatencyRecorder(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for j := range 3 {
			latency := time.Duration((i*3+j+1)*100) * time.Microsecond
			r.Record(latency, latency+25*time.Microsecond)
		}
		inputs[i] = r.Snapshot()
	}

	got, err := MergeLatencySnapshots(inputs)
	if err != nil {
		t.Fatalf("MergeLatencySnapshots: %v", err)
	}
	if got.Raw.Recorded != 6 || got.Raw.Seen != 6 || got.Raw.Dropped != 0 {
		t.Fatalf("raw counts = %+v, want seen=recorded=6 dropped=0", got.Raw.HistogramCounts)
	}
	percentiles, err := got.Raw.Percentiles()
	if err != nil {
		t.Fatalf("Percentiles: %v", err)
	}
	if percentiles.N != 6 {
		t.Fatalf("percentile observation count = %d, want 6", percentiles.N)
	}
	if percentiles.P99 < 500*time.Microsecond || percentiles.P99 > 700*time.Microsecond {
		t.Fatalf("p99 = %s, want near the 600us maximum", percentiles.P99)
	}
}

func TestLatencySnapshotJSONRoundTrip(t *testing.T) {
	t.Parallel()

	recorder, err := NewLatencyRecorder(LatencyConfig{
		Lowest:             time.Microsecond,
		Highest:            10 * time.Second,
		SignificantFigures: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder.Record(123*time.Microsecond, 150*time.Microsecond)
	want := recorder.Snapshot()

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got LatencySnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("round trip mismatch (-want +got):\n%s", diff)
	}
}
