package paired

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBalancedBlocks(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		blocks  int
		seed    uint64
		wantErr bool
	}{
		"success: twenty paired blocks are exactly balanced": {blocks: 20, seed: 0xC0FFEE},
		"success: two paired blocks are exactly balanced":    {blocks: 2, seed: 7},
		"error: odd paired block count cannot be balanced":   {blocks: 3, seed: 7, wantErr: true},
		"error: zero paired blocks":                          {blocks: 0, seed: 7, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := BalancedBlocks("candidate", "comparator", tt.blocks, tt.seed)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("BalancedBlocks: nil error, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("BalancedBlocks: %v", err)
			}
			if len(got) != tt.blocks {
				t.Fatalf("blocks = %d, want %d", len(got), tt.blocks)
			}
			patterns := map[OrderPattern]int{}
			for i, block := range got {
				patterns[block.Pattern]++
				if block.ID == "" {
					t.Fatalf("block %d has empty ID", i)
				}
				wantLibraries := [2]string{"candidate", "comparator"}
				if block.Pattern == OrderBA {
					wantLibraries = [2]string{"comparator", "candidate"}
				}
				if diff := cmp.Diff(wantLibraries, block.Libraries); diff != "" {
					t.Fatalf("block %d libraries mismatch (-want +got):\n%s", i, diff)
				}
			}
			if patterns[OrderAB] != tt.blocks/2 || patterns[OrderBA] != tt.blocks/2 {
				t.Fatalf("patterns = %v, want AB=%d BA=%d", patterns, tt.blocks/2, tt.blocks/2)
			}
		})
	}
}

func TestBalancedBlocksDeterministic(t *testing.T) {
	t.Parallel()

	a, err := BalancedBlocks("a", "b", 20, 42)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BalancedBlocks("a", "b", 20, 42)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(a, b); diff != "" {
		t.Fatalf("same seed produced different blocks (-first +second):\n%s", diff)
	}
}

func TestBlockPayloadSeed(t *testing.T) {
	t.Parallel()
	first, err := BlockPayloadSeed(123, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	again, err := BlockPayloadSeed(123, 0, 0)
	if err != nil || again != first || first == 0 {
		t.Fatalf("same identity seed = %d/%d, err=%v", first, again, err)
	}
	for _, coordinates := range [][3]int{{124, 0, 0}, {123, 1, 0}, {123, 0, 1}} {
		other, err := BlockPayloadSeed(uint64(coordinates[0]), coordinates[1], coordinates[2])
		if err != nil || other == first {
			t.Fatalf("coordinates %v seed=%d err=%v", coordinates, other, err)
		}
	}
	if _, err := BlockPayloadSeed(1, -1, 0); err == nil {
		t.Fatal("negative scenario index accepted")
	}
}
