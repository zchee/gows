package support

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAllocationDelta(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		before   MemSnapshot
		after    MemSnapshot
		overhead MemSnapshotDelta
		messages int64
		want     AllocationStats
		wantErr  bool
	}{
		"success: raw rates and independent control overhead are explicit": {
			before:   MemSnapshot{Mallocs: 100, TotalAlloc: 1_000},
			after:    MemSnapshot{Mallocs: 125, TotalAlloc: 1_600},
			overhead: MemSnapshotDelta{Mallocs: 5, TotalAllocBytes: 100},
			messages: 10,
			want: AllocationStats{
				Available:                  true,
				MallocsBefore:              100,
				MallocsAfter:               125,
				MallocsRawDelta:            25,
				MallocsObservationOverhead: 5,
				TotalAllocBytesBefore:      1_000,
				TotalAllocBytesAfter:       1_600,
				TotalAllocBytesRawDelta:    600,
				TotalAllocObservationBytes: 100,
				AllocationsPerMessage:      2.5,
				AllocatedBytesPerMessage:   60,
				RateBasis:                  "raw-delta-including-observation",
				ObservationMethod:          "paired-prewindow-control",
			},
		},
		"error: malloc counter regression": {
			before:   MemSnapshot{Mallocs: 101},
			after:    MemSnapshot{Mallocs: 100},
			messages: 1,
			wantErr:  true,
		},
		"error: zero measured messages": {
			before:  MemSnapshot{},
			after:   MemSnapshot{},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := AllocationDelta(tt.before, tt.after, tt.overhead, tt.messages)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("AllocationDelta: nil error, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("AllocationDelta: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("allocation mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAllocationDeltaKeepsRawRateWhenCalibrationExceedsRaw(t *testing.T) {
	t.Parallel()

	stats, err := AllocationDelta(
		MemSnapshot{Mallocs: 100, TotalAlloc: 1_000},
		MemSnapshot{Mallocs: 102, TotalAlloc: 1_120},
		MemSnapshotDelta{Mallocs: 5, TotalAllocBytes: 100},
		10,
	)
	if err != nil {
		t.Fatalf("AllocationDelta: %v", err)
	}
	if stats.MallocsRawDelta != 2 || stats.TotalAllocBytesRawDelta != 120 {
		t.Fatalf("raw deltas = (%d mallocs, %d bytes), want (2, 120)", stats.MallocsRawDelta, stats.TotalAllocBytesRawDelta)
	}
	if stats.MallocsObservationOverhead != 5 || stats.TotalAllocObservationBytes != 100 {
		t.Fatalf("observation overhead = (%d mallocs, %d bytes), want (5, 100)", stats.MallocsObservationOverhead, stats.TotalAllocObservationBytes)
	}
	if stats.AllocationsPerMessage != 0.2 || stats.AllocatedBytesPerMessage != 12 {
		t.Fatalf("raw rates = (%g allocations/message, %g bytes/message), want (0.2, 12)", stats.AllocationsPerMessage, stats.AllocatedBytesPerMessage)
	}
	if err := stats.Validate(10); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestSnapshotDelta(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		before  MemSnapshot
		after   MemSnapshot
		want    MemSnapshotDelta
		wantErr bool
	}{
		"success: monotonic counters": {
			before: MemSnapshot{Mallocs: 5, TotalAlloc: 10},
			after:  MemSnapshot{Mallocs: 8, TotalAlloc: 25},
			want:   MemSnapshotDelta{Mallocs: 3, TotalAllocBytes: 15},
		},
		"error: total allocation counter regression": {
			before:  MemSnapshot{TotalAlloc: 11},
			after:   MemSnapshot{TotalAlloc: 10},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := SnapshotDelta(tt.before, tt.after)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SnapshotDelta: nil error, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("SnapshotDelta: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("delta mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
