package support

import "testing"

func TestPMSetPowerSource(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		pmset string
		want  string
	}{
		"success: AC power with battery details": {
			pmset: "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; charged;\n",
			want:  "AC Power",
		},
		"success: battery power without trailing newline": {
			pmset: "Now drawing from 'Battery Power'",
			want:  "Battery Power",
		},
		"error: empty output":             {pmset: "", want: ""},
		"error: source not on first line": {pmset: "\nNow drawing from 'AC Power'", want: ""},
		"error: missing closing quote":    {pmset: "Now drawing from 'AC Power\n", want: ""},
		"error: unexpected wording":       {pmset: "Currently drawing from 'AC Power'\n", want: ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := PMSetPowerSource(tt.pmset); got != tt.want {
				t.Fatalf("PMSetPowerSource(%q) = %q, want %q", tt.pmset, got, tt.want)
			}
		})
	}
}

func TestPMSetThermalClean(t *testing.T) {
	t.Parallel()

	const thermal = "Note: No thermal warning level has been recorded\n"
	const performance = "Note: No performance warning level has been recorded\n"
	tests := map[string]struct {
		pmset string
		want  bool
	}{
		"success: both levels clean":          {pmset: thermal + performance, want: true},
		"error: thermal warning recorded":     {pmset: "Thermal warning level: 1\n" + performance, want: false},
		"error: performance warning recorded": {pmset: thermal + "Performance warning level: 2\n", want: false},
		"error: empty output":                 {pmset: "", want: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := PMSetThermalClean(tt.pmset); got != tt.want {
				t.Fatalf("PMSetThermalClean(%q) = %v, want %v", tt.pmset, got, tt.want)
			}
		})
	}
}
