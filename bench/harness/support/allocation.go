package support

import (
	"fmt"
	"math"
)

// MemSnapshotDelta is the monotonic allocation-counter difference between two
// runtime snapshots.
type MemSnapshotDelta struct {
	Mallocs         uint64 `json:"mallocs"`
	TotalAllocBytes uint64 `json:"total_alloc_bytes"`
}

// AllocationStats records raw before/after counters, separately measured
// observation overhead, and conservative per-message rates derived from the
// raw deltas. The independently sampled overhead is not subtracted: its noise
// can exceed a near-zero workload delta, and clamping that difference would
// manufacture a false exact-zero macro result.
type AllocationStats struct {
	Available                  bool    `json:"available"`
	MallocsBefore              uint64  `json:"mallocs_before"`
	MallocsAfter               uint64  `json:"mallocs_after"`
	MallocsRawDelta            uint64  `json:"mallocs_raw_delta"`
	MallocsObservationOverhead uint64  `json:"mallocs_observation_overhead"`
	TotalAllocBytesBefore      uint64  `json:"total_alloc_bytes_before"`
	TotalAllocBytesAfter       uint64  `json:"total_alloc_bytes_after"`
	TotalAllocBytesRawDelta    uint64  `json:"total_alloc_bytes_raw_delta"`
	TotalAllocObservationBytes uint64  `json:"total_alloc_observation_bytes"`
	AllocationsPerMessage      float64 `json:"allocations_per_message"`
	AllocatedBytesPerMessage   float64 `json:"allocated_bytes_per_message"`
	RateBasis                  string  `json:"rate_basis"`
	ObservationMethod          string  `json:"observation_method"`
}

const (
	allocationRateBasis         = "raw-delta-including-observation"
	allocationObservationMethod = "paired-prewindow-control"
)

// SnapshotDelta validates monotonic runtime counters and returns their exact
// difference.
func SnapshotDelta(before, after MemSnapshot) (MemSnapshotDelta, error) {
	if after.Mallocs < before.Mallocs {
		return MemSnapshotDelta{}, fmt.Errorf("support: malloc counter regressed from %d to %d", before.Mallocs, after.Mallocs)
	}
	if after.TotalAlloc < before.TotalAlloc {
		return MemSnapshotDelta{}, fmt.Errorf("support: total allocation counter regressed from %d to %d", before.TotalAlloc, after.TotalAlloc)
	}
	return MemSnapshotDelta{
		Mallocs:         after.Mallocs - before.Mallocs,
		TotalAllocBytes: after.TotalAlloc - before.TotalAlloc,
	}, nil
}

// AllocationDelta computes conservative macro allocation rates from exact raw
// counter deltas and records the separately observed measurement-control
// overhead without subtracting it. Exact zero-allocation claims belong to the
// microbenchmark contract; a macro sample remains an upper bound that can be
// compared and reproduced even when the independent overhead sample is noisy.
func AllocationDelta(before, after MemSnapshot, overhead MemSnapshotDelta, messages int64) (AllocationStats, error) {
	if messages <= 0 {
		return AllocationStats{}, fmt.Errorf("support: allocation accounting requires measured messages > 0, got %d", messages)
	}
	raw, err := SnapshotDelta(before, after)
	if err != nil {
		return AllocationStats{}, err
	}
	return AllocationStats{
		Available:                  true,
		MallocsBefore:              before.Mallocs,
		MallocsAfter:               after.Mallocs,
		MallocsRawDelta:            raw.Mallocs,
		MallocsObservationOverhead: overhead.Mallocs,
		TotalAllocBytesBefore:      before.TotalAlloc,
		TotalAllocBytesAfter:       after.TotalAlloc,
		TotalAllocBytesRawDelta:    raw.TotalAllocBytes,
		TotalAllocObservationBytes: overhead.TotalAllocBytes,
		AllocationsPerMessage:      float64(raw.Mallocs) / float64(messages),
		AllocatedBytesPerMessage:   float64(raw.TotalAllocBytes) / float64(messages),
		RateBasis:                  allocationRateBasis,
		ObservationMethod:          allocationObservationMethod,
	}, nil
}

// Validate recomputes every derived allocation field from its raw counters.
func (stats AllocationStats) Validate(messages int64) error {
	if !stats.Available {
		return fmt.Errorf("support: allocation accounting is unavailable")
	}
	if messages <= 0 {
		return fmt.Errorf("support: allocation validation requires messages > 0, got %d", messages)
	}
	if stats.RateBasis != allocationRateBasis {
		return fmt.Errorf("support: allocation rate basis = %q, want %q", stats.RateBasis, allocationRateBasis)
	}
	if stats.ObservationMethod != allocationObservationMethod {
		return fmt.Errorf("support: allocation observation method = %q, want %q", stats.ObservationMethod, allocationObservationMethod)
	}
	if stats.MallocsAfter < stats.MallocsBefore || stats.TotalAllocBytesAfter < stats.TotalAllocBytesBefore {
		return fmt.Errorf("support: allocation counters regress")
	}
	rawMallocs := stats.MallocsAfter - stats.MallocsBefore
	rawBytes := stats.TotalAllocBytesAfter - stats.TotalAllocBytesBefore
	if stats.MallocsRawDelta != rawMallocs || stats.TotalAllocBytesRawDelta != rawBytes {
		return fmt.Errorf("support: allocation raw deltas disagree with before/after counters")
	}
	wantAllocations := float64(rawMallocs) / float64(messages)
	wantBytes := float64(rawBytes) / float64(messages)
	if !sameFiniteFloat(stats.AllocationsPerMessage, wantAllocations) || !sameFiniteFloat(stats.AllocatedBytesPerMessage, wantBytes) {
		return fmt.Errorf("support: allocation per-message rates disagree with counters")
	}
	return nil
}

func sameFiniteFloat(got, want float64) bool {
	if math.IsNaN(got) || math.IsInf(got, 0) || math.IsNaN(want) || math.IsInf(want, 0) {
		return false
	}
	scale := math.Max(1, math.Max(math.Abs(got), math.Abs(want)))
	return math.Abs(got-want) <= 1e-9*scale
}
