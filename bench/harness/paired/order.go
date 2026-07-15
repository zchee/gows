package paired

import "fmt"

// OrderPattern identifies which side of a paired comparison ran first.
type OrderPattern string

const (
	// OrderAB runs candidate then comparator.
	OrderAB OrderPattern = "AB"
	// OrderBA runs comparator then candidate.
	OrderBA OrderPattern = "BA"
)

// BlockOrder is one balanced paired block.
type BlockOrder struct {
	ID        string       `json:"id"`
	Pattern   OrderPattern `json:"pattern"`
	Libraries [2]string    `json:"libraries"`
}

// BalancedBlocks returns an exactly balanced AB/BA schedule. The seed chooses
// the first pattern and the remainder alternates, so every even-sized schedule
// is balanced while retaining deterministic seed-controlled order.
func BalancedBlocks(candidate, comparator string, blocks int, seed uint64) ([]BlockOrder, error) {
	if candidate == "" || comparator == "" {
		return nil, fmt.Errorf("paired: candidate and comparator are required")
	}
	if candidate == comparator {
		return nil, fmt.Errorf("paired: candidate and comparator labels must differ")
	}
	if blocks <= 0 || blocks%2 != 0 {
		return nil, fmt.Errorf("paired: balanced AB/BA blocks require a positive even count, got %d", blocks)
	}
	start := SeededRand(seed).IntN(2)
	result := make([]BlockOrder, blocks)
	for i := range blocks {
		pattern := OrderAB
		libraries := [2]string{candidate, comparator}
		if (i+start)%2 == 1 {
			pattern = OrderBA
			libraries = [2]string{comparator, candidate}
		}
		result[i] = BlockOrder{
			ID:        blockID(i),
			Pattern:   pattern,
			Libraries: libraries,
		}
	}
	return result, nil
}

func blockID(index int) string {
	return fmt.Sprintf("block-%03d", index)
}

// BlockPayloadSeed derives the replayable base payload seed for one policy
// scenario and paired repetition. Both labels in the block use this seed;
// loadgen then derives independent per-connection streams from it.
func BlockPayloadSeed(policySeed uint64, scenarioIndex, repetition int) (uint64, error) {
	if scenarioIndex < 0 || repetition < 0 {
		return 0, fmt.Errorf("paired: payload seed indices must be nonnegative, got scenario=%d repetition=%d", scenarioIndex, repetition)
	}
	z := policySeed ^ (uint64(scenarioIndex+1) * 0x9E3779B97F4A7C15) ^ (uint64(repetition+1) * 0xD1B54A32D192ED03)
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	z ^= z >> 31
	if z == 0 {
		return 0xA24BAED4963EE407, nil
	}
	return z, nil
}
