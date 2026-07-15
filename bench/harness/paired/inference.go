package paired

import (
	"cmp"
	"fmt"
	"math"
	"slices"
)

// BlockRatio is one candidate/comparator ratio attached to its independent
// session, paired block, and execution order.
type BlockRatio struct {
	SessionID string       `json:"session_id"`
	Scenario  string       `json:"scenario"`
	BlockID   string       `json:"block_id"`
	Order     OrderPattern `json:"order"`
	Value     float64      `json:"value"`
}

// InferenceConfig defines deterministic hierarchical bootstrap inference.
type InferenceConfig struct {
	Replicates int     `json:"replicates"`
	Confidence float64 `json:"confidence"`
	Seed       uint64  `json:"seed"`
}

// Interval is a ratio estimate and its confidence interval.
type Interval struct {
	Center float64 `json:"center"`
	Lower  float64 `json:"lower"`
	Upper  float64 `json:"upper"`
}

// MetricDirection defines how a superiority threshold is applied.
type MetricDirection string

const (
	// HigherIsBetter requires the confidence interval lower bound to exceed
	// the threshold.
	HigherIsBetter MetricDirection = "higher"
	// LowerIsBetter requires the confidence interval upper bound to be below
	// the threshold.
	LowerIsBetter MetricDirection = "lower"
)

// MetricGate is one component of the preregistered full superiority verdict.
type MetricGate struct {
	Name      string          `json:"name"`
	Direction MetricDirection `json:"direction"`
	Threshold float64         `json:"threshold"`
}

type sessionRatios struct {
	id     string
	blocks []BlockRatio
}

// HierarchicalBootstrap resamples sessions first and paired blocks within
// each sampled session, preserving both independence levels.
func HierarchicalBootstrap(ratios []BlockRatio, cfg InferenceConfig) (Interval, error) {
	sessions, err := groupRatios(ratios, cfg)
	if err != nil {
		return Interval{}, err
	}
	center := math.Exp(meanSessionLogRatios(sessions))
	rng := SeededRand(cfg.Seed)
	replicates := make([]float64, cfg.Replicates)
	for replicate := range cfg.Replicates {
		var sessionMeans float64
		for range len(sessions) {
			session := sessions[rng.IntN(len(sessions))]
			var blockMean float64
			for range len(session.blocks) {
				blockMean += math.Log(session.blocks[rng.IntN(len(session.blocks))].Value)
			}
			sessionMeans += blockMean / float64(len(session.blocks))
		}
		replicates[replicate] = math.Exp(sessionMeans / float64(len(sessions)))
	}
	slices.Sort(replicates)
	alpha := (1 - cfg.Confidence) / 2
	return Interval{
		Center: center,
		Lower:  percentileSorted(replicates, alpha),
		Upper:  percentileSorted(replicates, 1-alpha),
	}, nil
}

// OrderEffect estimates AB/BA as the ratio between values observed when the
// candidate ran first and values observed when the comparator ran first.
func OrderEffect(ratios []BlockRatio, cfg InferenceConfig) (Interval, error) {
	sessions, err := groupRatios(ratios, cfg)
	if err != nil {
		return Interval{}, err
	}
	center, err := meanOrderEffect(sessions)
	if err != nil {
		return Interval{}, err
	}
	rng := SeededRand(cfg.Seed ^ goldenGamma)
	replicates := make([]float64, cfg.Replicates)
	for replicate := range cfg.Replicates {
		var total float64
		for range len(sessions) {
			session := sessions[rng.IntN(len(sessions))]
			ab, ba := splitOrders(session.blocks)
			if len(ab) == 0 || len(ba) == 0 {
				return Interval{}, fmt.Errorf("paired: session %q lacks both AB and BA blocks", session.id)
			}
			var abMean, baMean float64
			for range len(ab) {
				abMean += math.Log(ab[rng.IntN(len(ab))].Value)
			}
			for range len(ba) {
				baMean += math.Log(ba[rng.IntN(len(ba))].Value)
			}
			total += abMean/float64(len(ab)) - baMean/float64(len(ba))
		}
		replicates[replicate] = math.Exp(total / float64(len(sessions)))
	}
	slices.Sort(replicates)
	alpha := (1 - cfg.Confidence) / 2
	return Interval{
		Center: center,
		Lower:  percentileSorted(replicates, alpha),
		Upper:  percentileSorted(replicates, 1-alpha),
	}, nil
}

// EmpiricalFalsePositiveRate performs deterministic session/block-preserving
// null relabeling. A single sign flip is shared across every metric for a
// block, preserving cross-metric correlation; the full verdict counts as a
// false positive only when every preregistered gate passes.
func EmpiricalFalsePositiveRate(metrics map[string][]BlockRatio, cfg InferenceConfig, iterations int, gates []MetricGate) (float64, error) {
	if iterations < 1_000 {
		return 0, fmt.Errorf("paired: null relabel iterations must be >= 1000, got %d", iterations)
	}
	if len(gates) == 0 {
		return 0, fmt.Errorf("paired: at least one superiority gate is required")
	}
	keys, indexed, err := indexMetrics(metrics, gates, cfg)
	if err != nil {
		return 0, err
	}
	const nullRelabelGamma uint64 = 0xD1B54A32D192ED03
	rng := SeededRand(cfg.Seed ^ nullRelabelGamma)
	falsePositives := 0
	for iteration := range iterations {
		flips := make(map[string]bool, len(keys))
		for _, key := range keys {
			flips[key] = rng.IntN(2) == 1
		}
		fullPass := true
		for gateIndex, gate := range gates {
			relabeled := make([]BlockRatio, 0, len(keys))
			for _, key := range keys {
				ratio := indexed[gate.Name][key]
				if flips[key] {
					ratio.Value = 1 / ratio.Value
				}
				relabeled = append(relabeled, ratio)
			}

			// A center that cannot cross the threshold cannot possibly pass its
			// one-sided confidence bound, avoiding unnecessary nested bootstrap.
			center := math.Exp(meanLogRatios(relabeled))
			if gate.Direction == HigherIsBetter && center <= gate.Threshold ||
				gate.Direction == LowerIsBetter && center >= gate.Threshold {
				fullPass = false
				break
			}
			inferenceCfg := cfg
			inferenceCfg.Seed ^= uint64(iteration+1)*goldenGamma ^ uint64(gateIndex+1)
			interval, err := HierarchicalBootstrap(relabeled, inferenceCfg)
			if err != nil {
				return 0, err
			}
			switch gate.Direction {
			case HigherIsBetter:
				fullPass = interval.Lower > gate.Threshold
			case LowerIsBetter:
				fullPass = interval.Upper < gate.Threshold
			default:
				return 0, fmt.Errorf("paired: gate %q has unknown direction %q", gate.Name, gate.Direction)
			}
			if !fullPass {
				break
			}
		}
		if fullPass {
			falsePositives++
		}
	}
	return float64(falsePositives) / float64(iterations), nil
}

func groupRatios(ratios []BlockRatio, cfg InferenceConfig) ([]sessionRatios, error) {
	if cfg.Replicates <= 0 {
		return nil, fmt.Errorf("paired: inference replicates must be > 0, got %d", cfg.Replicates)
	}
	if cfg.Confidence <= 0 || cfg.Confidence >= 1 {
		return nil, fmt.Errorf("paired: inference confidence must be in (0,1), got %g", cfg.Confidence)
	}
	if len(ratios) == 0 {
		return nil, fmt.Errorf("paired: no block ratios")
	}
	bySession := make(map[string][]BlockRatio)
	seen := make(map[string]struct{}, len(ratios))
	for _, ratio := range ratios {
		if ratio.SessionID == "" || ratio.Scenario == "" || ratio.BlockID == "" {
			return nil, fmt.Errorf("paired: ratio has empty session_id, scenario, or block_id")
		}
		if ratio.Order != OrderAB && ratio.Order != OrderBA {
			return nil, fmt.Errorf("paired: ratio %s/%s/%s has invalid order %q", ratio.SessionID, ratio.Scenario, ratio.BlockID, ratio.Order)
		}
		if ratio.Value <= 0 || math.IsNaN(ratio.Value) || math.IsInf(ratio.Value, 0) {
			return nil, fmt.Errorf("paired: ratio %s/%s/%s has invalid value %v", ratio.SessionID, ratio.Scenario, ratio.BlockID, ratio.Value)
		}
		key := blockRatioKey(ratio)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("paired: duplicate ratio for session %q scenario %q block %q", ratio.SessionID, ratio.Scenario, ratio.BlockID)
		}
		seen[key] = struct{}{}
		bySession[ratio.SessionID] = append(bySession[ratio.SessionID], ratio)
	}
	ids := make([]string, 0, len(bySession))
	for id := range bySession {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	sessions := make([]sessionRatios, 0, len(ids))
	for _, id := range ids {
		blocks := bySession[id]
		slices.SortFunc(blocks, func(a, b BlockRatio) int {
			return cmp.Or(cmp.Compare(a.Scenario, b.Scenario), cmp.Compare(a.BlockID, b.BlockID))
		})
		sessions = append(sessions, sessionRatios{id: id, blocks: blocks})
	}
	return sessions, nil
}

func meanSessionLogRatios(sessions []sessionRatios) float64 {
	var result float64
	for _, session := range sessions {
		result += meanLogRatios(session.blocks)
	}
	return result / float64(len(sessions))
}

func meanLogRatios(ratios []BlockRatio) float64 {
	var sum float64
	for _, ratio := range ratios {
		sum += math.Log(ratio.Value)
	}
	return sum / float64(len(ratios))
}

func meanOrderEffect(sessions []sessionRatios) (float64, error) {
	var total float64
	for _, session := range sessions {
		ab, ba := splitOrders(session.blocks)
		if len(ab) == 0 || len(ba) == 0 {
			return 0, fmt.Errorf("paired: session %q lacks both AB and BA blocks", session.id)
		}
		total += meanLogRatios(ab) - meanLogRatios(ba)
	}
	return math.Exp(total / float64(len(sessions))), nil
}

func splitOrders(ratios []BlockRatio) (ab, ba []BlockRatio) {
	for _, ratio := range ratios {
		if ratio.Order == OrderAB {
			ab = append(ab, ratio)
		} else {
			ba = append(ba, ratio)
		}
	}
	return ab, ba
}

func indexMetrics(metrics map[string][]BlockRatio, gates []MetricGate, cfg InferenceConfig) ([]string, map[string]map[string]BlockRatio, error) {
	if len(metrics) != len(gates) {
		return nil, nil, fmt.Errorf("paired: metric set has %d entries, want exactly %d preregistered gates", len(metrics), len(gates))
	}
	indexed := make(map[string]map[string]BlockRatio, len(gates))
	gateNames := make(map[string]struct{}, len(gates))
	var keys []string
	for gateIndex, gate := range gates {
		if gate.Name == "" {
			return nil, nil, fmt.Errorf("paired: superiority gate name is required")
		}
		if _, duplicate := gateNames[gate.Name]; duplicate {
			return nil, nil, fmt.Errorf("paired: duplicate superiority gate %q", gate.Name)
		}
		gateNames[gate.Name] = struct{}{}
		ratios, ok := metrics[gate.Name]
		if !ok {
			return nil, nil, fmt.Errorf("paired: missing ratios for gate %q", gate.Name)
		}
		if gate.Direction != HigherIsBetter && gate.Direction != LowerIsBetter {
			return nil, nil, fmt.Errorf("paired: gate %q has unknown direction %q", gate.Name, gate.Direction)
		}
		if gate.Threshold <= 0 || math.IsNaN(gate.Threshold) || math.IsInf(gate.Threshold, 0) {
			return nil, nil, fmt.Errorf("paired: gate %q has invalid threshold %v", gate.Name, gate.Threshold)
		}
		if _, err := groupRatios(ratios, cfg); err != nil {
			return nil, nil, fmt.Errorf("paired: metric %q: %w", gate.Name, err)
		}
		byKey := make(map[string]BlockRatio, len(ratios))
		for _, ratio := range ratios {
			key := blockRatioKey(ratio)
			byKey[key] = ratio
			if gateIndex == 0 {
				keys = append(keys, key)
			}
		}
		indexed[gate.Name] = byKey
	}
	slices.Sort(keys)
	for _, gate := range gates[1:] {
		if len(indexed[gate.Name]) != len(keys) {
			return nil, nil, fmt.Errorf("paired: metric %q has %d blocks, want %d", gate.Name, len(indexed[gate.Name]), len(keys))
		}
		for _, key := range keys {
			ratio, ok := indexed[gate.Name][key]
			if !ok {
				return nil, nil, fmt.Errorf("paired: metric %q is missing block %q", gate.Name, key)
			}
			first := indexed[gates[0].Name][key]
			if ratio.SessionID != first.SessionID || ratio.Scenario != first.Scenario || ratio.BlockID != first.BlockID || ratio.Order != first.Order {
				return nil, nil, fmt.Errorf("paired: metric %q block %q identity/order differs from %q", gate.Name, key, gates[0].Name)
			}
		}
	}
	return keys, indexed, nil
}

func blockRatioKey(ratio BlockRatio) string {
	return ratio.SessionID + "\x00" + ratio.Scenario + "\x00" + ratio.BlockID
}
