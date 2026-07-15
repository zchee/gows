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
// observation overhead, observation-adjusted deltas, and per-message rates.
type AllocationStats struct {
	Available                   bool    `json:"available"`
	MallocsBefore               uint64  `json:"mallocs_before"`
	MallocsAfter                uint64  `json:"mallocs_after"`
	MallocsRawDelta             uint64  `json:"mallocs_raw_delta"`
	MallocsObservationOverhead  uint64  `json:"mallocs_observation_overhead"`
	MallocsNetDelta             uint64  `json:"mallocs_net_delta"`
	TotalAllocBytesBefore       uint64  `json:"total_alloc_bytes_before"`
	TotalAllocBytesAfter        uint64  `json:"total_alloc_bytes_after"`
	TotalAllocBytesRawDelta     uint64  `json:"total_alloc_bytes_raw_delta"`
	TotalAllocObservationBytes  uint64  `json:"total_alloc_observation_bytes"`
	TotalAllocBytesNetDelta     uint64  `json:"total_alloc_bytes_net_delta"`
	AllocationsPerMessage       float64 `json:"allocations_per_message"`
	AllocatedBytesPerMessage    float64 `json:"allocated_bytes_per_message"`
	ObservationAdjustmentMethod string  `json:"observation_adjustment_method"`
}

const allocationObservationMethod = "paired-prewindow-snapshot"

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

// AllocationDelta computes allocation rates after subtracting the separately
// observed measurement-control overhead. Overhead larger than the raw delta
// is rejected rather than being reported as a false zero.
func AllocationDelta(before, after MemSnapshot, overhead MemSnapshotDelta, messages int64) (AllocationStats, error) {
	if messages <= 0 {
		return AllocationStats{}, fmt.Errorf("support: allocation accounting requires measured messages > 0, got %d", messages)
	}
	raw, err := SnapshotDelta(before, after)
	if err != nil {
		return AllocationStats{}, err
	}
	if overhead.Mallocs > raw.Mallocs || overhead.TotalAllocBytes > raw.TotalAllocBytes {
		return AllocationStats{}, fmt.Errorf("support: observation overhead mallocs=%d bytes=%d exceeds raw delta mallocs=%d bytes=%d", overhead.Mallocs, overhead.TotalAllocBytes, raw.Mallocs, raw.TotalAllocBytes)
	}
	netMallocs := raw.Mallocs - overhead.Mallocs
	netBytes := raw.TotalAllocBytes - overhead.TotalAllocBytes
	return AllocationStats{
		Available:                   true,
		MallocsBefore:               before.Mallocs,
		MallocsAfter:                after.Mallocs,
		MallocsRawDelta:             raw.Mallocs,
		MallocsObservationOverhead:  overhead.Mallocs,
		MallocsNetDelta:             netMallocs,
		TotalAllocBytesBefore:       before.TotalAlloc,
		TotalAllocBytesAfter:        after.TotalAlloc,
		TotalAllocBytesRawDelta:     raw.TotalAllocBytes,
		TotalAllocObservationBytes:  overhead.TotalAllocBytes,
		TotalAllocBytesNetDelta:     netBytes,
		AllocationsPerMessage:       float64(netMallocs) / float64(messages),
		AllocatedBytesPerMessage:    float64(netBytes) / float64(messages),
		ObservationAdjustmentMethod: allocationObservationMethod,
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
	if stats.ObservationAdjustmentMethod != allocationObservationMethod {
		return fmt.Errorf("support: allocation observation method = %q, want %q", stats.ObservationAdjustmentMethod, allocationObservationMethod)
	}
	if stats.MallocsAfter < stats.MallocsBefore || stats.TotalAllocBytesAfter < stats.TotalAllocBytesBefore {
		return fmt.Errorf("support: allocation counters regress")
	}
	rawMallocs := stats.MallocsAfter - stats.MallocsBefore
	rawBytes := stats.TotalAllocBytesAfter - stats.TotalAllocBytesBefore
	if stats.MallocsRawDelta != rawMallocs || stats.TotalAllocBytesRawDelta != rawBytes {
		return fmt.Errorf("support: allocation raw deltas disagree with before/after counters")
	}
	if stats.MallocsObservationOverhead > rawMallocs || stats.TotalAllocObservationBytes > rawBytes {
		return fmt.Errorf("support: allocation observation overhead exceeds raw delta")
	}
	netMallocs := rawMallocs - stats.MallocsObservationOverhead
	netBytes := rawBytes - stats.TotalAllocObservationBytes
	if stats.MallocsNetDelta != netMallocs || stats.TotalAllocBytesNetDelta != netBytes {
		return fmt.Errorf("support: allocation net deltas disagree with raw delta and overhead")
	}
	wantAllocations := float64(netMallocs) / float64(messages)
	wantBytes := float64(netBytes) / float64(messages)
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
