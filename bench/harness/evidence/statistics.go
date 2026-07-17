package evidence

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
)

// The first six metric names are paired's canonical sample metrics; tying
// them to those constants keeps the strings this evaluator emits into
// verdict.json from ever drifting apart from the sample schema. The rest are
// evidence-only resource metrics with no paired counterpart.
const (
	metricThroughput       = paired.MetricThroughput
	metricP99              = paired.MetricP99
	metricP999             = paired.MetricP999
	metricServerCPU        = paired.MetricServerCPUPerMessage
	metricServerRSS        = paired.MetricServerRSSPerConn
	metricClientCPU        = paired.MetricClientCPUPerMessage
	metricClientRSS        = "client_rss_bytes_per_connection"
	metricServerAllocs     = "server_raw_allocations_per_message"
	metricServerAllocBytes = "server_raw_allocated_bytes_per_message"
	metricClientAllocs     = "client_raw_allocations_per_message"
	metricClientAllocBytes = "client_raw_allocated_bytes_per_message"
)

var resourceMetrics = []string{
	metricServerCPU,
	metricServerRSS,
	metricClientCPU,
	metricClientRSS,
	metricServerAllocs,
	metricServerAllocBytes,
	metricClientAllocs,
	metricClientAllocBytes,
}

type measuredPair struct {
	SessionID  string
	Scenario   string
	BlockID    string
	Order      paired.OrderPattern
	Candidate  paired.Sample
	Comparator paired.Sample
}

func evaluateAA(runs []resolvedRun) (AAVerdict, error) {
	if len(runs) != 3 {
		return AAVerdict{}, fmt.Errorf("evidence: A/A requires exactly three runs")
	}
	first := runs[0]
	pol := first.Policy
	if pol.Series.RunKind != policy.RunKindAA || pol.Series.EvidenceClass != policy.EvidenceClassSelfValidation ||
		pol.Series.HostMode != policy.HostModeSame || pol.Series.Toolchain != policy.ToolchainStock ||
		pol.Series.AdapterClass != policy.AdapterClassAA || pol.Series.ValidationProfile != policy.ValidationStrict {
		return AAVerdict{}, fmt.Errorf("evidence: A/A policy classification is not strict stock self-validation")
	}
	if pol.AAGates.MinSessions != 3 || pol.AAGates.MinPairsPerSession != 20 || pol.Bootstrap.Confidence != 0.95 ||
		pol.Bootstrap.Replicates < 1_000 || pol.Bootstrap.NullIterations < 1_000 || pol.AAGates.MaxFalsePositive != 0.05 ||
		pol.AAGates.Throughput != (policy.RatioBand{Lower: 0.98, Upper: 1.02}) ||
		pol.AAGates.P99 != (policy.RatioBand{Lower: 0.98, Upper: 1.02}) ||
		pol.AAGates.P999 != (policy.RatioBand{Lower: 0.95, Upper: 1.05}) ||
		pol.AAGates.OrderEffect != (policy.RatioBand{Lower: 0.99, Upper: 1.01}) {
		return AAVerdict{}, fmt.Errorf("evidence: A/A preregistered inference settings are insufficient")
	}
	sessionIDs := make([]string, len(runs))
	binarySHA := first.Manifest.LibraryBinariesSHA256[pol.Candidate]
	adapterSHA := first.Manifest.AdapterSHA256[pol.Candidate]
	for i, run := range runs {
		if run.Policy.SchemaVersion != pol.SchemaVersion || run.Receipt.PolicySHA256 != first.Receipt.PolicySHA256 ||
			run.Policy.Series.ID != pol.Series.ID {
			return AAVerdict{}, fmt.Errorf("evidence: A/A session %d uses a different policy", i+1)
		}
		candidateBinary := run.Manifest.LibraryBinariesSHA256[pol.Candidate]
		comparatorBinary := run.Manifest.LibraryBinariesSHA256[pol.Comparator]
		if candidateBinary == "" || candidateBinary != comparatorBinary || candidateBinary != binarySHA {
			return AAVerdict{}, fmt.Errorf("evidence: A/A session %d is not same-binary", i+1)
		}
		if run.Manifest.AdapterSHA256[pol.Candidate] != run.Manifest.AdapterSHA256[pol.Comparator] ||
			run.Manifest.AdapterSHA256[pol.Candidate] != adapterSHA {
			return AAVerdict{}, fmt.Errorf("evidence: A/A session %d adapter identity changed", i+1)
		}
		if run.Manifest.EchoserverSHA256 != first.Manifest.EchoserverSHA256 || run.Manifest.LoadgenSHA256 != first.Manifest.LoadgenSHA256 {
			return AAVerdict{}, fmt.Errorf("evidence: A/A session %d harness binary identity changed", i+1)
		}
		if run.Manifest.Hostname != first.Manifest.Hostname || run.Manifest.Kernel != first.Manifest.Kernel ||
			run.Manifest.BootIdentityStart != first.Manifest.BootIdentityStart {
			return AAVerdict{}, fmt.Errorf("evidence: A/A session %d host/boot identity changed", i+1)
		}
		if i > 0 && run.Started.Before(runs[i-1].Ended) {
			return AAVerdict{}, fmt.Errorf("evidence: A/A sessions %d and %d overlap or are out of order", i, i+1)
		}
		sessionIDs[i] = run.Receipt.SessionID
	}
	if _, err := sortedUnique(sessionIDs); err != nil {
		return AAVerdict{}, fmt.Errorf("evidence: A/A session IDs: %w", err)
	}

	config := paired.InferenceConfig{Replicates: pol.Bootstrap.Replicates, Confidence: pol.Bootstrap.Confidence, Seed: pol.Seed}
	verdict := AAVerdict{
		SessionIDs: sessionIDs, BinarySHA256: binarySHA, PolicySHA256: first.Receipt.PolicySHA256,
		NullIterations: pol.Bootstrap.NullIterations, FalsePositiveMax: pol.AAGates.MaxFalsePositive,
		Pass: true,
	}
	var primaryThroughput []paired.BlockRatio
	for _, scenario := range pol.Scenarios {
		if scenario.Repetitions < pol.AAGates.MinPairsPerSession {
			return AAVerdict{}, fmt.Errorf("evidence: A/A scenario %s has only %d pairs per session", scenario.Name, scenario.Repetitions)
		}
		pairs, err := collectPairs(runs, scenario.Name)
		if err != nil {
			return AAVerdict{}, err
		}
		throughput, err := summarizeMetric(pairs, metricThroughput, config, pol.AAGates.Throughput)
		if err != nil {
			return AAVerdict{}, err
		}
		p99, err := summarizeMetric(pairs, metricP99, config, pol.AAGates.P99)
		if err != nil {
			return AAVerdict{}, err
		}
		p999, err := summarizeMetric(pairs, metricP999, config, pol.AAGates.P999)
		if err != nil {
			return AAVerdict{}, err
		}
		throughputRatios, _, _, err := metricRatios(pairs, metricThroughput, nil)
		if err != nil {
			return AAVerdict{}, err
		}
		order, err := paired.OrderEffect(throughputRatios, config)
		if err != nil {
			return AAVerdict{}, err
		}
		orderPass := intervalInside(order, pol.AAGates.OrderEffect)
		resources := make([]IntervalVerdict, 0, len(resourceMetrics))
		for _, metric := range resourceMetrics {
			summary, err := summarizeMetric(pairs, metric, config, policy.RatioBand{})
			if err != nil {
				return AAVerdict{}, err
			}
			resources = append(resources, summary)
		}
		pass := throughput.Pass && p99.Pass && p999.Pass && orderPass
		if !pass {
			verdict.Pass = false
		}
		verdict.Scenarios = append(verdict.Scenarios, AAScenarioVerdict{
			Name: scenario.Name, Sessions: len(runs), Pairs: len(pairs), Throughput: throughput,
			P99: p99, P999: p999, OrderEffect: order, OrderPass: orderPass, Resources: resources, Pass: pass,
		})
		if scenario.Primary {
			primaryThroughput = append(primaryThroughput, throughputRatios...)
		}
	}
	geomean, err := hierarchicalInterval(primaryThroughput, config)
	if err != nil {
		return AAVerdict{}, err
	}
	verdict.PrimaryGeomean = geomean
	fpr, err := empiricalFullVerdictFalsePositive(runs, pol)
	if err != nil {
		return AAVerdict{}, err
	}
	verdict.FalsePositive = fpr
	verdict.FalsePositiveOK = fpr <= pol.AAGates.MaxFalsePositive
	verdict.Pass = verdict.Pass && verdict.FalsePositiveOK
	return verdict, nil
}

func evaluateBaselines(records []RunEvidence, runs map[string]resolvedRun) ([]BaselineRunVerdict, error) {
	byRole := make(map[string]resolvedRun, len(records))
	series := make(map[string]bool, len(records))
	for _, record := range records {
		run := runs[record.Role]
		p := run.Policy
		if p.Series.RunKind != policy.RunKindBaseline || p.Series.EvidenceClass != policy.EvidenceClassBaseline ||
			p.Series.HostMode != policy.HostModeSame || p.Series.Toolchain != policy.ToolchainStock ||
			p.Series.ValidationProfile != policy.ValidationStrict || p.Series.GoExperiment != "" ||
			!strings.HasPrefix(p.Candidate, "gows") || p.Comparator != "quickws" {
			return nil, fmt.Errorf("evidence: baseline role %q is not a strict stock current-gows baseline", record.Role)
		}
		if series[p.Series.ID] {
			return nil, fmt.Errorf("evidence: baseline series %q is reused", p.Series.ID)
		}
		series[p.Series.ID] = true
		switch record.Role {
		case "best-api-gows-client":
			if p.Series.AdapterClass != policy.AdapterClassBestAPI || p.Series.Client != policy.ClientGoWS {
				return nil, fmt.Errorf("evidence: baseline role %q classification mismatch", record.Role)
			}
		case "semantic-parity-gows-client":
			if p.Series.AdapterClass != policy.AdapterClassSemanticParity || p.Series.Client != policy.ClientGoWS {
				return nil, fmt.Errorf("evidence: baseline role %q classification mismatch", record.Role)
			}
		case "independent-gobwas-client":
			if p.Series.Client != policy.ClientGobwas {
				return nil, fmt.Errorf("evidence: baseline role %q client mismatch", record.Role)
			}
		case "independent-raw-client":
			if p.Series.Client != policy.ClientRaw {
				return nil, fmt.Errorf("evidence: baseline role %q client mismatch", record.Role)
			}
		default:
			return nil, fmt.Errorf("evidence: unknown baseline role %q", record.Role)
		}
		byRole[record.Role] = run
	}
	verdicts := make([]BaselineRunVerdict, 0, len(requiredBaselineRoles))
	for _, role := range requiredBaselineRoles {
		run, ok := byRole[role]
		if !ok {
			return nil, fmt.Errorf("evidence: missing baseline role %q", role)
		}
		p := run.Policy
		config := paired.InferenceConfig{Replicates: p.Bootstrap.Replicates, Confidence: p.Bootstrap.Confidence, Seed: p.Seed}
		if config.Confidence != 0.95 || config.Replicates < 1_000 {
			return nil, fmt.Errorf("evidence: baseline %q inference settings are insufficient", role)
		}
		verdict := BaselineRunVerdict{
			SessionID: run.Receipt.SessionID, SeriesID: p.Series.ID, AdapterClass: string(p.Series.AdapterClass),
			Client: string(p.Series.Client), PolicySHA256: run.Receipt.PolicySHA256, SuperiorityGate: false,
		}
		var primary []paired.BlockRatio
		for _, scenario := range p.Scenarios {
			if scenario.Warmup.Duration().Seconds() < 5 || scenario.Duration.Duration().Seconds() < 30 || scenario.Repetitions < 20 {
				return nil, fmt.Errorf("evidence: baseline %q scenario %s is shorter than 5s/30s/n20", role, scenario.Name)
			}
			pairs, err := collectPairs([]resolvedRun{run}, scenario.Name)
			if err != nil {
				return nil, err
			}
			metrics := make([]IntervalVerdict, 0, 3+len(resourceMetrics))
			for _, metric := range append([]string{metricThroughput, metricP99, metricP999}, resourceMetrics...) {
				summary, err := summarizeMetric(pairs, metric, config, policy.RatioBand{})
				if err != nil {
					return nil, err
				}
				metrics = append(metrics, summary)
			}
			verdict.Scenarios = append(verdict.Scenarios, BaselineScenarioVerdict{
				Name: scenario.Name, Primary: scenario.Primary, Pairs: len(pairs), Metrics: metrics, CellClass: string(scenario.CellClass),
			})
			if scenario.Primary {
				ratios, _, _, err := metricRatios(pairs, metricThroughput, nil)
				if err != nil {
					return nil, err
				}
				primary = append(primary, ratios...)
			}
		}
		geomean, err := hierarchicalInterval(primary, config)
		if err != nil {
			return nil, err
		}
		verdict.PrimaryGeomean = geomean
		verdicts = append(verdicts, verdict)
	}
	return verdicts, nil
}

func collectPairs(runs []resolvedRun, scenario string) ([]measuredPair, error) {
	var result []measuredPair
	for _, run := range runs {
		var definition *policy.Scenario
		for i := range run.Policy.Scenarios {
			if run.Policy.Scenarios[i].Name == scenario {
				definition = &run.Policy.Scenarios[i]
				break
			}
		}
		if definition == nil {
			return nil, fmt.Errorf("evidence: run %s lacks scenario %q", run.Receipt.SessionID, scenario)
		}
		for repetition := range definition.Repetitions {
			candidate, comparator, err := runPair(run, scenario, repetition)
			if err != nil {
				return nil, err
			}
			result = append(result, measuredPair{
				SessionID: run.Receipt.SessionID, Scenario: scenario, BlockID: candidate.BlockID,
				Order: paired.OrderPattern(candidate.Order), Candidate: candidate, Comparator: comparator,
			})
		}
	}
	slices.SortFunc(result, func(a, b measuredPair) int {
		return cmp.Or(strings.Compare(a.SessionID, b.SessionID), strings.Compare(a.Scenario, b.Scenario), strings.Compare(a.BlockID, b.BlockID))
	})
	return result, nil
}

func summarizeMetric(pairs []measuredPair, metric string, config paired.InferenceConfig, band policy.RatioBand) (IntervalVerdict, error) {
	ratios, candidate, comparator, err := metricRatios(pairs, metric, nil)
	if err != nil {
		return IntervalVerdict{}, err
	}
	interval, err := hierarchicalInterval(ratios, config)
	if err != nil {
		return IntervalVerdict{}, err
	}
	result := IntervalVerdict{
		Metric: metric, CandidateCenter: paired.Median(candidate), ComparatorCenter: paired.Median(comparator),
		RatioAvailable: true, Ratio: interval, BandLower: band.Lower, BandUpper: band.Upper,
		Width: interval.Upper - interval.Lower, Pass: true,
	}
	if band.Lower != 0 || band.Upper != 0 {
		result.Pass = intervalInside(interval, band) && result.Width <= band.Upper-band.Lower
	}
	return result, nil
}

func metricRatios(pairs []measuredPair, metric string, flips map[string]bool) ([]paired.BlockRatio, []float64, []float64, error) {
	ratios := make([]paired.BlockRatio, 0, len(pairs))
	candidateValues := make([]float64, 0, len(pairs))
	comparatorValues := make([]float64, 0, len(pairs))
	for _, pair := range pairs {
		candidate, err := sampleMetric(pair.Candidate, metric)
		if err != nil {
			return nil, nil, nil, err
		}
		comparator, err := sampleMetric(pair.Comparator, metric)
		if err != nil {
			return nil, nil, nil, err
		}
		key := paired.BlockKey(pair.SessionID, pair.Scenario, pair.BlockID)
		if flips != nil && flips[key] {
			candidate, comparator = comparator, candidate
		}
		ratio, err := finiteRatio(candidate, comparator)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("evidence: metric %s block %s: %w", metric, key, err)
		}
		ratios = append(ratios, paired.BlockRatio{
			SessionID: pair.SessionID, Scenario: pair.Scenario, BlockID: pair.BlockID, Order: pair.Order, Value: ratio,
		})
		candidateValues = append(candidateValues, candidate)
		comparatorValues = append(comparatorValues, comparator)
	}
	return ratios, candidateValues, comparatorValues, nil
}

// sampleMetric returns the named metric value for the sample. The six
// canonical sample metrics delegate to paired.Sample.Metric so the two
// packages can never disagree; only the evidence-only resource metrics are
// computed here.
func sampleMetric(sample paired.Sample, metric string) (float64, error) {
	switch metric {
	case metricClientRSS:
		return float64(sample.LoadgenResult.ClientUsage.MaxRSSBytes) / float64(sample.LoadgenResult.Connections), nil
	case metricServerAllocs:
		return sample.LoadgenResult.ServerAllocations.AllocationsPerMessage, nil
	case metricServerAllocBytes:
		return sample.LoadgenResult.ServerAllocations.AllocatedBytesPerMessage, nil
	case metricClientAllocs:
		return sample.LoadgenResult.ClientAllocations.AllocationsPerMessage, nil
	case metricClientAllocBytes:
		return sample.LoadgenResult.ClientAllocations.AllocatedBytesPerMessage, nil
	default:
		return sample.Metric(metric)
	}
}

func finiteRatio(candidate, comparator float64) (float64, error) {
	if math.IsNaN(candidate) || math.IsInf(candidate, 0) || candidate < 0 || math.IsNaN(comparator) || math.IsInf(comparator, 0) || comparator < 0 {
		return 0, fmt.Errorf("invalid values candidate=%g comparator=%g", candidate, comparator)
	}
	if candidate == 0 && comparator == 0 {
		return 1, nil
	}
	if comparator == 0 {
		return 0, fmt.Errorf("undefined ratio with zero comparator")
	}
	return candidate / comparator, nil
}

func hierarchicalInterval(ratios []paired.BlockRatio, config paired.InferenceConfig) (paired.Interval, error) {
	positive := true
	for _, ratio := range ratios {
		positive = positive && ratio.Value > 0
	}
	if positive {
		return paired.HierarchicalBootstrap(ratios, config)
	}
	return hierarchicalIntervalWithZero(ratios, config)
}

func hierarchicalIntervalWithZero(ratios []paired.BlockRatio, config paired.InferenceConfig) (paired.Interval, error) {
	if len(ratios) == 0 || config.Replicates <= 0 || config.Confidence <= 0 || config.Confidence >= 1 {
		return paired.Interval{}, fmt.Errorf("evidence: invalid nonnegative hierarchical bootstrap input")
	}
	bySession := make(map[string][]paired.BlockRatio)
	seen := make(map[string]bool, len(ratios))
	for _, ratio := range ratios {
		if ratio.SessionID == "" || ratio.Scenario == "" || ratio.BlockID == "" || ratio.Value < 0 || math.IsNaN(ratio.Value) || math.IsInf(ratio.Value, 0) {
			return paired.Interval{}, fmt.Errorf("evidence: invalid nonnegative block ratio %+v", ratio)
		}
		key := paired.BlockKey(ratio.SessionID, ratio.Scenario, ratio.BlockID)
		if seen[key] {
			return paired.Interval{}, fmt.Errorf("evidence: duplicate nonnegative block ratio %q", key)
		}
		seen[key] = true
		bySession[ratio.SessionID] = append(bySession[ratio.SessionID], ratio)
	}
	ids := make([]string, 0, len(bySession))
	for id := range bySession {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	centerValues := make([]float64, 0, len(ratios))
	for _, id := range ids {
		for _, ratio := range bySession[id] {
			centerValues = append(centerValues, ratio.Value)
		}
	}
	center := geomeanNonnegative(centerValues)
	rng := paired.SeededRand(config.Seed)
	replicates := make([]float64, config.Replicates)
	for replicate := range config.Replicates {
		var values []float64
		for range len(ids) {
			blocks := bySession[ids[rng.IntN(len(ids))]]
			for range len(blocks) {
				values = append(values, blocks[rng.IntN(len(blocks))].Value)
			}
		}
		replicates[replicate] = geomeanNonnegative(values)
	}
	slices.Sort(replicates)
	alpha := (1 - config.Confidence) / 2
	return paired.Interval{Center: center, Lower: percentile(replicates, alpha), Upper: percentile(replicates, 1-alpha)}, nil
}

func geomeanNonnegative(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var logs float64
	for _, value := range values {
		if value == 0 {
			return 0
		}
		logs += math.Log(value)
	}
	return math.Exp(logs / float64(len(values)))
}

func percentile(sorted []float64, quantile float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	position := quantile * float64(len(sorted)-1)
	lower := int(position)
	if lower+1 >= len(sorted) {
		return sorted[lower]
	}
	fraction := position - float64(lower)
	return sorted[lower] + fraction*(sorted[lower+1]-sorted[lower])
}

func intervalInside(interval paired.Interval, band policy.RatioBand) bool {
	return interval.Lower >= band.Lower && interval.Upper <= band.Upper
}

// empiricalFullVerdictFalsePositive applies one deterministic label flip to
// every metric in a session/scenario/block and recomputes the complete Phase
// 0 claim predicate. The exact-zero micro allocation gate is a deterministic
// prerequisite in the verification bundle; stochastic macro gates here cover
// throughput, geomean, p99, p999, CPU/message, allocations/message, and RSS.
func empiricalFullVerdictFalsePositive(runs []resolvedRun, pol *policy.Policy) (float64, error) {
	allPairs := make(map[string][]measuredPair, len(pol.Scenarios))
	var keys []string
	for _, scenario := range pol.Scenarios {
		pairs, err := collectPairs(runs, scenario.Name)
		if err != nil {
			return 0, err
		}
		allPairs[scenario.Name] = pairs
		for _, pair := range pairs {
			keys = append(keys, paired.BlockKey(pair.SessionID, pair.Scenario, pair.BlockID))
		}
	}
	keys, err := sortedUnique(keys)
	if err != nil {
		return 0, err
	}
	const nullSeed uint64 = 0xD1B54A32D192ED03
	rng := paired.SeededRand(pol.Seed ^ nullSeed)
	falsePositives := 0
	for iteration := range pol.Bootstrap.NullIterations {
		flips := make(map[string]bool, len(keys))
		for _, key := range keys {
			flips[key] = rng.IntN(2) == 1
		}
		pass, err := fullClaimPass(allPairs, pol, flips, iteration)
		if err != nil {
			return 0, err
		}
		if pass {
			falsePositives++
		}
	}
	return float64(falsePositives) / float64(pol.Bootstrap.NullIterations), nil
}

func fullClaimPass(allPairs map[string][]measuredPair, pol *policy.Policy, flips map[string]bool, iteration int) (bool, error) {
	config := paired.InferenceConfig{
		Replicates: pol.Bootstrap.Replicates, Confidence: pol.Bootstrap.Confidence,
		Seed: pol.Seed ^ (uint64(iteration+1) * 0x9E3779B97F4A7C15),
	}
	var primaryThroughput []paired.BlockRatio
	for _, scenario := range pol.Scenarios {
		if !scenario.Primary {
			continue
		}
		ratios, _, _, err := metricRatios(allPairs[scenario.Name], metricThroughput, flips)
		if err != nil {
			return false, err
		}
		primaryThroughput = append(primaryThroughput, ratios...)
	}
	// The primary geomean threshold is the strongest early discriminator and
	// avoids unnecessary nested bootstrap work for almost all null relabels.
	centerValues := make([]float64, len(primaryThroughput))
	for i, ratio := range primaryThroughput {
		centerValues[i] = ratio.Value
	}
	if geomeanNonnegative(centerValues) < pol.Thresholds.ThroughputGeomean {
		return false, nil
	}
	geomean, err := hierarchicalInterval(primaryThroughput, config)
	if err != nil || geomean.Lower < pol.Thresholds.ThroughputGeomean {
		return false, err
	}
	for _, scenario := range pol.Scenarios {
		if !scenario.Primary {
			continue
		}
		pairs := allPairs[scenario.Name]
		throughputLower, p99Upper, cpuUpper := pol.Thresholds.ThroughputLowerBound, pol.Thresholds.P99UpperBound, 0.90
		if scenario.CellClass == policy.CellSaturated {
			throughputLower, p99Upper, cpuUpper = 0.98, 1.02, 1.00
		}
		gates := []paired.MetricGate{
			{Name: metricThroughput, Direction: paired.HigherIsBetter, Threshold: throughputLower},
			{Name: metricP99, Direction: paired.LowerIsBetter, Threshold: p99Upper},
			{Name: metricServerCPU, Direction: paired.LowerIsBetter, Threshold: cpuUpper},
		}
		if scenario.CellClass == policy.CellServerSensitive {
			gates = append(
				gates,
				paired.MetricGate{Name: metricP999, Direction: paired.LowerIsBetter, Threshold: pol.Thresholds.P999CenterUpperBound},
				paired.MetricGate{Name: metricServerAllocs, Direction: paired.LowerIsBetter, Threshold: 1.00},
				paired.MetricGate{Name: metricServerRSS, Direction: paired.LowerIsBetter, Threshold: 1.00},
			)
		}
		for gateIndex, gate := range gates {
			ratios, candidate, _, err := metricRatios(pairs, gate.Name, flips)
			if err != nil {
				return false, err
			}
			gateConfig := config
			gateConfig.Seed ^= uint64(gateIndex+1) * 0xD1B54A32D192ED03
			interval, err := hierarchicalInterval(ratios, gateConfig)
			if err != nil {
				return false, err
			}
			strictServerThroughput := scenario.CellClass == policy.CellServerSensitive && gate.Name == metricThroughput
			if gate.Direction == paired.HigherIsBetter && (interval.Lower < gate.Threshold || strictServerThroughput && interval.Lower == gate.Threshold) ||
				gate.Direction == paired.LowerIsBetter && interval.Upper > gate.Threshold {
				return false, nil
			}
			if gate.Name == metricServerAllocs {
				absolute, err := hierarchicalAbsoluteInterval(pairs, candidate, gateConfig)
				if err != nil {
					return false, err
				}
				if absolute.Upper > 0.01 {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

func hierarchicalAbsoluteInterval(pairs []measuredPair, values []float64, config paired.InferenceConfig) (paired.Interval, error) {
	if len(pairs) != len(values) || len(values) == 0 {
		return paired.Interval{}, fmt.Errorf("evidence: invalid absolute interval input")
	}
	bySession := make(map[string][]float64)
	for i, pair := range pairs {
		bySession[pair.SessionID] = append(bySession[pair.SessionID], values[i])
	}
	ids := make([]string, 0, len(bySession))
	for id := range bySession {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	rng := paired.SeededRand(config.Seed)
	replicates := make([]float64, config.Replicates)
	for replicate := range config.Replicates {
		var sample []float64
		for range len(ids) {
			blocks := bySession[ids[rng.IntN(len(ids))]]
			for range len(blocks) {
				sample = append(sample, blocks[rng.IntN(len(blocks))])
			}
		}
		replicates[replicate] = paired.Median(sample)
	}
	slices.Sort(replicates)
	alpha := (1 - config.Confidence) / 2
	return paired.Interval{Center: paired.Median(values), Lower: percentile(replicates, alpha), Upper: percentile(replicates, 1-alpha)}, nil
}
