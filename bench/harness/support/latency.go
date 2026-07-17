package support

import (
	"fmt"
	"slices"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
)

// Percentiles holds the machine-readable latency tail summary reconstructed
// from an HDR histogram snapshot. N carries the reconstructed observation
// count for test assertions and diagnostics; production accounting reads the
// HistogramCounts counters instead.
type Percentiles struct {
	P50, P90, P99, P999 time.Duration
	N                   int
}

// LatencyConfig defines the fixed precision and bounds of a mergeable latency
// histogram. Bounds are part of the artifact identity: snapshots with
// different configurations cannot be merged.
type LatencyConfig struct {
	Lowest             time.Duration `json:"lowest"`
	Highest            time.Duration `json:"highest"`
	SignificantFigures int           `json:"significant_figures"`
}

// HistogramCounts makes observation loss explicit. Seen counts every value
// offered to the recorder, Recorded counts values represented in the
// histogram, Dropped counts rejected observations, and Overflow is the subset
// rejected for exceeding the configured upper bound.
type HistogramCounts struct {
	Seen     int64 `json:"seen"`
	Recorded int64 `json:"recorded"`
	Dropped  int64 `json:"dropped"`
	Overflow int64 `json:"overflow"`
}

// HistogramSnapshot is the JSON-stable form of an HDR histogram plus its
// complete observation accounting.
type HistogramSnapshot struct {
	HistogramCounts
	LowestTrackableNanoseconds  int64   `json:"lowest_trackable_nanoseconds"`
	HighestTrackableNanoseconds int64   `json:"highest_trackable_nanoseconds"`
	SignificantFigures          int64   `json:"significant_figures"`
	BucketCounts                []int64 `json:"bucket_counts"`
}

// LatencySnapshot carries both uncorrected service latency and coordinated-
// omission-corrected response latency. The correction method is recorded so
// artifacts produced under different observation contracts cannot be merged.
type LatencySnapshot struct {
	Raw              HistogramSnapshot `json:"raw"`
	Corrected        HistogramSnapshot `json:"corrected"`
	CorrectionMethod string            `json:"correction_method"`
}

// LatencyRecorder records every observation into bounded-memory HDR
// histograms. It is single-goroutine only; callers merge snapshots after the
// connection workers stop.
type LatencyRecorder struct {
	raw       *hdrhistogram.Histogram
	corrected *hdrhistogram.Histogram
	rawCounts HistogramCounts
	corCounts HistogramCounts
}

const correctionScheduledStart = "scheduled-start-response-time"

// NewLatencyRecorder returns a recorder with the requested HDR geometry.
func NewLatencyRecorder(cfg LatencyConfig) (*LatencyRecorder, error) {
	if cfg.Lowest <= 0 {
		return nil, fmt.Errorf("support: latency lowest bound must be > 0, got %s", cfg.Lowest)
	}
	if cfg.Highest < cfg.Lowest {
		return nil, fmt.Errorf("support: latency highest bound %s is below lowest %s", cfg.Highest, cfg.Lowest)
	}
	if cfg.SignificantFigures < 1 || cfg.SignificantFigures > 5 {
		return nil, fmt.Errorf("support: latency significant figures must be in [1,5], got %d", cfg.SignificantFigures)
	}
	return &LatencyRecorder{
		raw:       hdrhistogram.New(cfg.Lowest.Nanoseconds(), cfg.Highest.Nanoseconds(), cfg.SignificantFigures),
		corrected: hdrhistogram.New(cfg.Lowest.Nanoseconds(), cfg.Highest.Nanoseconds(), cfg.SignificantFigures),
	}, nil
}

// Record records one service latency and its corrected response latency. A
// non-positive corrected value means the observation was not open-loop and
// therefore uses the raw duration for both distributions.
func (r *LatencyRecorder) Record(raw, corrected time.Duration) {
	if corrected <= 0 {
		corrected = raw
	}
	recordHistogram(r.raw, raw, &r.rawCounts)
	recordHistogram(r.corrected, corrected, &r.corCounts)
}

func recordHistogram(h *hdrhistogram.Histogram, value time.Duration, counts *HistogramCounts) {
	counts.Seen++
	if value <= 0 {
		counts.Dropped++
		return
	}
	if value.Nanoseconds() > h.HighestTrackableValue() {
		counts.Dropped++
		counts.Overflow++
		return
	}
	if err := h.RecordValue(value.Nanoseconds()); err != nil {
		counts.Dropped++
		return
	}
	counts.Recorded++
}

// Snapshot exports a detached, JSON-serializable snapshot.
func (r *LatencyRecorder) Snapshot() LatencySnapshot {
	return LatencySnapshot{
		Raw:              exportHistogram(r.raw, r.rawCounts),
		Corrected:        exportHistogram(r.corrected, r.corCounts),
		CorrectionMethod: correctionScheduledStart,
	}
}

func exportHistogram(h *hdrhistogram.Histogram, counts HistogramCounts) HistogramSnapshot {
	s := h.Export()
	return HistogramSnapshot{
		HistogramCounts:             counts,
		LowestTrackableNanoseconds:  s.LowestTrackableValue,
		HighestTrackableNanoseconds: s.HighestTrackableValue,
		SignificantFigures:          s.SignificantFigures,
		BucketCounts:                slices.Clone(s.Counts),
	}
}

// MergeLatencySnapshots merges snapshots without connection-equal
// subsampling. Every recorded message retains its original histogram count.
func MergeLatencySnapshots(snapshots []LatencySnapshot) (LatencySnapshot, error) {
	if len(snapshots) == 0 {
		return LatencySnapshot{}, fmt.Errorf("support: no latency snapshots to merge")
	}
	raw, err := importHistogram(snapshots[0].Raw)
	if err != nil {
		return LatencySnapshot{}, fmt.Errorf("support: raw snapshot 0: %w", err)
	}
	corrected, err := importHistogram(snapshots[0].Corrected)
	if err != nil {
		return LatencySnapshot{}, fmt.Errorf("support: corrected snapshot 0: %w", err)
	}
	rawCounts := snapshots[0].Raw.HistogramCounts
	corCounts := snapshots[0].Corrected.HistogramCounts
	method := snapshots[0].CorrectionMethod

	for i := 1; i < len(snapshots); i++ {
		snapshot := snapshots[i]
		if snapshot.CorrectionMethod != method {
			return LatencySnapshot{}, fmt.Errorf("support: latency snapshot %d correction method %q differs from %q", i, snapshot.CorrectionMethod, method)
		}
		nextRaw, err := importHistogram(snapshot.Raw)
		if err != nil {
			return LatencySnapshot{}, fmt.Errorf("support: raw snapshot %d: %w", i, err)
		}
		if dropped := raw.Merge(nextRaw); dropped != 0 {
			return LatencySnapshot{}, fmt.Errorf("support: raw snapshot %d merge dropped %d values due to incompatible bounds", i, dropped)
		}
		nextCorrected, err := importHistogram(snapshot.Corrected)
		if err != nil {
			return LatencySnapshot{}, fmt.Errorf("support: corrected snapshot %d: %w", i, err)
		}
		if dropped := corrected.Merge(nextCorrected); dropped != 0 {
			return LatencySnapshot{}, fmt.Errorf("support: corrected snapshot %d merge dropped %d values due to incompatible bounds", i, dropped)
		}
		addCounts(&rawCounts, snapshot.Raw.HistogramCounts)
		addCounts(&corCounts, snapshot.Corrected.HistogramCounts)
	}

	return LatencySnapshot{
		Raw:              exportHistogram(raw, rawCounts),
		Corrected:        exportHistogram(corrected, corCounts),
		CorrectionMethod: method,
	}, nil
}

func addCounts(dst *HistogramCounts, src HistogramCounts) {
	dst.Seen += src.Seen
	dst.Recorded += src.Recorded
	dst.Dropped += src.Dropped
	dst.Overflow += src.Overflow
}

func importHistogram(snapshot HistogramSnapshot) (*hdrhistogram.Histogram, error) {
	if snapshot.LowestTrackableNanoseconds <= 0 || snapshot.HighestTrackableNanoseconds < snapshot.LowestTrackableNanoseconds {
		return nil, fmt.Errorf("invalid histogram bounds [%d,%d]", snapshot.LowestTrackableNanoseconds, snapshot.HighestTrackableNanoseconds)
	}
	if snapshot.SignificantFigures < 1 || snapshot.SignificantFigures > 5 {
		return nil, fmt.Errorf("invalid significant figures %d", snapshot.SignificantFigures)
	}
	expected := hdrhistogram.New(snapshot.LowestTrackableNanoseconds, snapshot.HighestTrackableNanoseconds, int(snapshot.SignificantFigures)).Export()
	if len(snapshot.BucketCounts) != len(expected.Counts) {
		return nil, fmt.Errorf("histogram count length = %d, want %d", len(snapshot.BucketCounts), len(expected.Counts))
	}
	var total int64
	for i, count := range snapshot.BucketCounts {
		if count < 0 {
			return nil, fmt.Errorf("histogram bucket %d has negative count %d", i, count)
		}
		total += count
	}
	if total != snapshot.Recorded {
		return nil, fmt.Errorf("histogram bucket total = %d, recorded = %d", total, snapshot.Recorded)
	}
	return hdrhistogram.Import(&hdrhistogram.Snapshot{
		LowestTrackableValue:  snapshot.LowestTrackableNanoseconds,
		HighestTrackableValue: snapshot.HighestTrackableNanoseconds,
		SignificantFigures:    snapshot.SignificantFigures,
		Counts:                slices.Clone(snapshot.BucketCounts),
	}), nil
}

// Percentiles reconstructs the HDR histogram and reports its machine-readable
// tail summary.
func (s HistogramSnapshot) Percentiles() (Percentiles, error) {
	h, err := importHistogram(s)
	if err != nil {
		return Percentiles{}, err
	}
	if h.TotalCount() == 0 {
		return Percentiles{}, nil
	}
	return Percentiles{
		P50:  time.Duration(h.ValueAtQuantile(50)),
		P90:  time.Duration(h.ValueAtQuantile(90)),
		P99:  time.Duration(h.ValueAtQuantile(99)),
		P999: time.Duration(h.ValueAtQuantile(99.9)),
		N:    int(h.TotalCount()),
	}, nil
}
