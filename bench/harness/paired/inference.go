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
		key := BlockKey(ratio.SessionID, ratio.Scenario, ratio.BlockID)
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

// BlockKey is the canonical composite identity of one measured block. The
// evidence evaluator's pair/flip bookkeeping and this package's duplicate
// detection key blocks identically through it, so the two sides can never
// disagree on which measurements form one block.
func BlockKey(sessionID, scenario, blockID string) string {
	return sessionID + "\x00" + scenario + "\x00" + blockID
}
