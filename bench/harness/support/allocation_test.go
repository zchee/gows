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
		"success: raw and observation-adjusted deltas are explicit": {
			before:   MemSnapshot{Mallocs: 100, TotalAlloc: 1_000},
			after:    MemSnapshot{Mallocs: 125, TotalAlloc: 1_600},
			overhead: MemSnapshotDelta{Mallocs: 5, TotalAllocBytes: 100},
			messages: 10,
			want: AllocationStats{
				Available:                   true,
				MallocsBefore:               100,
				MallocsAfter:                125,
				MallocsRawDelta:             25,
				MallocsObservationOverhead:  5,
				MallocsNetDelta:             20,
				TotalAllocBytesBefore:       1_000,
				TotalAllocBytesAfter:        1_600,
				TotalAllocBytesRawDelta:     600,
				TotalAllocObservationBytes:  100,
				TotalAllocBytesNetDelta:     500,
				AllocationsPerMessage:       2,
				AllocatedBytesPerMessage:    50,
				ObservationAdjustmentMethod: "paired-prewindow-snapshot",
			},
		},
		"error: overhead cannot manufacture a zero allocation rate": {
			before:   MemSnapshot{Mallocs: 100, TotalAlloc: 1_000},
			after:    MemSnapshot{Mallocs: 102, TotalAlloc: 1_020},
			overhead: MemSnapshotDelta{Mallocs: 5, TotalAllocBytes: 100},
			messages: 10,
			wantErr:  true,
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
