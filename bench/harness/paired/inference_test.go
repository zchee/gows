package paired

import (
	"math"
	"slices"
	"testing"
)

func syntheticRatios(sessions, blocks int, orderBias float64) []BlockRatio {
	ratios := make([]BlockRatio, 0, sessions*blocks)
	for session := range sessions {
		for block := range blocks {
			pattern := OrderAB
			bias := orderBias
			if block%2 == 1 {
				pattern = OrderBA
				bias = -orderBias
			}
			wiggle := float64((session+block)%5-2) * 0.0005
			ratios = append(ratios, BlockRatio{
				SessionID: "session-" + string(rune('a'+session)),
				Scenario:  "scenario-a",
				BlockID:   blockID(block),
				Order:     pattern,
				Value:     math.Exp(wiggle + bias),
			})
		}
	}
	return ratios
}

func TestHierarchicalBootstrap(t *testing.T) {
	t.Parallel()

	cfg := InferenceConfig{Replicates: 2_000, Confidence: 0.95, Seed: 0xC0FFEE}
	tests := map[string]struct {
		ratios    []BlockRatio
		wantError bool
	}{
		"success: three sessions preserve an identity ratio": {
			ratios: syntheticRatios(3, 20, 0),
		},
		"error: no ratios": {wantError: true},
		"error: duplicate session and block": {
			ratios: []BlockRatio{
				{SessionID: "s", Scenario: "scenario", BlockID: "b", Order: OrderAB, Value: 1},
				{SessionID: "s", Scenario: "scenario", BlockID: "b", Order: OrderAB, Value: 1},
			},
			wantError: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := HierarchicalBootstrap(tt.ratios, cfg)
			if tt.wantError {
				if err == nil {
					t.Fatalf("HierarchicalBootstrap: nil error, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("HierarchicalBootstrap: %v", err)
			}
			if got.Center < 0.998 || got.Center > 1.002 {
				t.Fatalf("center = %.6f, want identity", got.Center)
			}
			if got.Lower < 0.98 || got.Upper > 1.02 {
				t.Fatalf("interval = [%.6f, %.6f], want inside [0.98,1.02]", got.Lower, got.Upper)
			}
		})
	}
}

func TestHierarchicalBootstrapDeterministic(t *testing.T) {
	t.Parallel()

	ratios := syntheticRatios(3, 20, 0)
	cfg := InferenceConfig{Replicates: 2_000, Confidence: 0.95, Seed: 99}
	first, err := HierarchicalBootstrap(ratios, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HierarchicalBootstrap(ratios, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same input and seed are not deterministic: first=%+v second=%+v", first, second)
	}
}

func TestOrderEffect(t *testing.T) {
	t.Parallel()

	cfg := InferenceConfig{Replicates: 2_000, Confidence: 0.95, Seed: 123}
	tests := map[string]struct {
		orderBias float64
		wantPass  bool
	}{
		"success: no order bias stays inside one percent":  {wantPass: true},
		"failure signal: two percent log bias is detected": {orderBias: 0.02},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := OrderEffect(syntheticRatios(3, 20, tt.orderBias), cfg)
			if err != nil {
				t.Fatalf("OrderEffect: %v", err)
			}
			pass := got.Lower >= 0.99 && got.Upper <= 1.01
			if pass != tt.wantPass {
				t.Fatalf("order interval = [%.6f, %.6f], pass=%v want %v", got.Lower, got.Upper, pass, tt.wantPass)
			}
		})
	}
}

func TestEmpiricalFalsePositiveRate(t *testing.T) {
	t.Parallel()

	base := syntheticRatios(3, 20, 0)
	metrics := map[string][]BlockRatio{
		"throughput": base,
		"p99":        base,
		"p999":       base,
	}
	gates := []MetricGate{
		{Name: "throughput", Direction: HigherIsBetter, Threshold: 1.05},
		{Name: "p99", Direction: LowerIsBetter, Threshold: 0.95},
		{Name: "p999", Direction: LowerIsBetter, Threshold: 1.00},
	}
	cfg := InferenceConfig{Replicates: 200, Confidence: 0.95, Seed: 0xBAD5EED}
	got, err := EmpiricalFalsePositiveRate(metrics, cfg, 1_000, gates)
	if err != nil {
		t.Fatalf("EmpiricalFalsePositiveRate: %v", err)
	}
	if got < 0 || got > 0.05 {
		t.Fatalf("false-positive rate = %.4f, want in [0,0.05]", got)
	}
}

func TestEmpiricalFalsePositiveRateRejectsCrossMetricIdentityDrift(t *testing.T) {
	t.Parallel()
	base := syntheticRatios(3, 20, 0)
	config := InferenceConfig{Replicates: 20, Confidence: 0.95, Seed: 1}
	gates := []MetricGate{
		{Name: "throughput", Direction: HigherIsBetter, Threshold: 1.05},
		{Name: "p99", Direction: LowerIsBetter, Threshold: 0.95},
	}

	tests := map[string]func(map[string][]BlockRatio, []MetricGate){
		"order mismatch": func(metrics map[string][]BlockRatio, _ []MetricGate) {
			changed := slices.Clone(metrics["p99"])
			changed[0].Order = OrderBA
			metrics["p99"] = changed
		},
		"scenario mismatch": func(metrics map[string][]BlockRatio, _ []MetricGate) {
			changed := slices.Clone(metrics["p99"])
			changed[0].Scenario = "other"
			metrics["p99"] = changed
		},
		"duplicate gate": func(_ map[string][]BlockRatio, gates []MetricGate) {
			gates[1].Name = gates[0].Name
		},
		"extra metric": func(metrics map[string][]BlockRatio, _ []MetricGate) {
			metrics["unregistered"] = base
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			metrics := map[string][]BlockRatio{"throughput": base, "p99": base}
			caseGates := slices.Clone(gates)
			mutate(metrics, caseGates)
			if _, err := EmpiricalFalsePositiveRate(metrics, config, 1_000, caseGates); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}
