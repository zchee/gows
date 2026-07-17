package support

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMergeEnv(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		base      []string
		overrides []string
		want      []string
	}{
		"success: override replaces matching key and moves to the tail": {
			base:      []string{"A=1", "B=2", "C=3"},
			overrides: []string{"B=20"},
			want:      []string{"A=1", "C=3", "B=20"},
		},
		"success: untouched base order is preserved": {
			base:      []string{"B=2", "A=1"},
			overrides: []string{"C=3"},
			want:      []string{"B=2", "A=1", "C=3"},
		},
		"success: repeated override keys are all appended": {
			base:      []string{"A=1"},
			overrides: []string{"A=2", "A=3"},
			want:      []string{"A=2", "A=3"},
		},
		"success: override without separator replaces nothing": {
			base:      []string{"A=1"},
			overrides: []string{"A"},
			want:      []string{"A=1", "A"},
		},
		"success: malformed base entry survives a matching override key": {
			base:      []string{"A", "A=1"},
			overrides: []string{"A=2"},
			want:      []string{"A", "A=2"},
		},
		"success: empty value override still replaces": {
			base:      []string{"A=1"},
			overrides: []string{"A="},
			want:      []string{"A="},
		},
		"success: nil base yields only overrides": {
			base:      nil,
			overrides: []string{"A=1"},
			want:      []string{"A=1"},
		},
		"success: no overrides returns base entries unchanged": {
			base:      []string{"A=1", "B=2"},
			overrides: nil,
			want:      []string{"A=1", "B=2"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := MergeEnv(tc.base, tc.overrides...)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("MergeEnv(%v, %v...) mismatch (-want +got):\n%s", tc.base, tc.overrides, diff)
			}
		})
	}
}
