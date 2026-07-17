package paired

import (
	"math"
	"testing"

	"github.com/zchee/gows/bench/harness/support"
)

func mkSample(scenario, lib string, rep int, throughput float64, p99 int64) Sample {
	return Sample{
		LoadgenResult: support.LoadgenResult{
			ThroughputMessagesPerSecond: throughput,
			P99Nanoseconds:              p99,
		},
		Scenario:   scenario,
		Library:    lib,
		Repetition: rep,
	}
}

func approx(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestRatios(t *testing.T) {
	// Samples deliberately out of repetition order to prove Ratios sorts
	// before pairing.
	samples := []Sample{
		mkSample("s", "cand", 1, 120, 0),
		mkSample("s", "cand", 0, 110, 0),
		mkSample("s", "comp", 0, 100, 0),
		mkSample("s", "comp", 1, 100, 0),
	}
	got, err := Ratios(samples, "s", "cand", "comp", MetricThroughput)
	if err != nil {
		t.Fatalf("Ratios: %v", err)
	}
	want := []float64{1.1, 1.2}
	if len(got) != len(want) {
		t.Fatalf("got %d ratios, want %d", len(got), len(want))
	}
	for i := range want {
		if !approx(got[i], want[i], 1e-9) {
			t.Fatalf("ratio[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestRatiosErrors(t *testing.T) {
	tests := map[string]struct {
		samples []Sample
		metric  string
	}{
		"count mismatch": {
			samples: []Sample{
				mkSample("s", "cand", 0, 110, 0),
				mkSample("s", "cand", 1, 120, 0),
				mkSample("s", "comp", 0, 100, 0),
			},
			metric: MetricThroughput,
		},
		"missing candidate": {
			samples: []Sample{
				mkSample("s", "comp", 0, 100, 0),
			},
			metric: MetricThroughput,
		},
		"comparator zero": {
			samples: []Sample{
				mkSample("s", "cand", 0, 110, 0),
				mkSample("s", "comp", 0, 0, 0),
			},
			metric: MetricThroughput,
		},
		"unknown metric": {
			samples: []Sample{
				mkSample("s", "cand", 0, 110, 0),
				mkSample("s", "comp", 0, 100, 0),
			},
			metric: "no_such_metric",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Ratios(tc.samples, "s", "cand", "comp", tc.metric); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestBootstrapDeterminism(t *testing.T) {
	ratios := []float64{1.01, 1.03, 1.06, 1.04, 1.02, 1.08, 1.05, 1.07, 1.03, 1.05}
	// Same seed must reproduce the interval bit-for-bit across calls.
	c1, l1, u1 := Bootstrap(ratios, 5000, 0.95, 12648430)
	c2, l2, u2 := Bootstrap(ratios, 5000, 0.95, 12648430)
	if c1 != c2 || l1 != l2 || u1 != u2 {
		t.Fatalf("bootstrap not deterministic: (%v,%v,%v) vs (%v,%v,%v)", c1, l1, u1, c2, l2, u2)
	}
	// The center is the point median: seed-independent and equal to the exact
	// median of the ratios.
	if want := Median(ratios); c1 != want {
		t.Fatalf("center = %v, want point median %v", c1, want)
	}
	// A valid interval must bracket the center.
	if l1 > c1 || c1 > u1 {
		t.Fatalf("interval does not bracket center: lower=%v center=%v upper=%v", l1, c1, u1)
	}
}

func TestBootstrapCISanity(t *testing.T) {
	// Degenerate distribution: every ratio is 1.05, so every resample median
	// is exactly 1.05 and the CI collapses to a point strictly above 1.0.
	const n = 20
	ratios := make([]float64, n)
	for i := range ratios {
		ratios[i] = 1.05
	}
	center, lower, upper := Bootstrap(ratios, 10000, 0.95, 7)
	if !approx(center, 1.05, 1e-12) {
		t.Fatalf("center = %v, want 1.05", center)
	}
	if lower <= 1.0 {
		t.Fatalf("lower = %v, want > 1.0", lower)
	}
	if !approx(lower, 1.05, 1e-12) || !approx(upper, 1.05, 1e-12) {
		t.Fatalf("degenerate CI = [%v,%v], want [1.05,1.05]", lower, upper)
	}

	// A spread distribution centered near 1.05 must satisfy lower<=center<=upper.
	spread := []float64{1.00, 1.02, 1.04, 1.05, 1.06, 1.08, 1.10, 1.03, 1.05, 1.07}
	c, l, u := Bootstrap(spread, 10000, 0.95, 7)
	if l > c || c > u {
		t.Fatalf("interval ordering violated: lower=%v center=%v upper=%v", l, c, u)
	}
}

func TestMedian(t *testing.T) {
	tests := map[string]struct {
		in   []float64
		want float64
	}{
		"empty":       {in: nil, want: 0},
		"single":      {in: []float64{3}, want: 3},
		"odd":         {in: []float64{3, 1, 2}, want: 2},
		"even":        {in: []float64{4, 1, 3, 2}, want: 2.5},
		"unsorted in": {in: []float64{10, 2, 8, 4, 6}, want: 6},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Median(tc.in); !approx(got, tc.want, 1e-12) {
				t.Fatalf("Median(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestGeomean(t *testing.T) {
	tests := map[string]struct {
		in      []float64
		want    float64
		wantNaN bool
	}{
		"empty":     {in: nil, want: 0},
		"one four":  {in: []float64{1, 4}, want: 2},
		"two eight": {in: []float64{2, 8}, want: 4},
		"identity":  {in: []float64{1.05, 1.05, 1.05}, want: 1.05},
		"negative":  {in: []float64{1, -2}, wantNaN: true},
		"zero":      {in: []float64{1, 0}, wantNaN: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := Geomean(tc.in)
			if tc.wantNaN {
				if !math.IsNaN(got) {
					t.Fatalf("Geomean(%v) = %v, want NaN", tc.in, got)
				}
				return
			}
			if !approx(got, tc.want, 1e-9) {
				t.Fatalf("Geomean(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
