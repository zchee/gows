// Package paired computes paired ratio statistics (candidate divided by
// comparator, repetition by repetition) with deterministic median-bootstrap
// confidence intervals for the benchmark harness. Every function here is
// pure and side-effect free apart from [LoadSamples], which reads a
// samples.jsonl file; determinism is guaranteed for a fixed seed so a verdict
// can be reproduced exactly.
package paired

import (
	"bufio"
	"bytes"
	"cmp"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"slices"

	"github.com/go-json-experiment/json"
	"github.com/zchee/gows/bench/harness/support"
)

// Metric names understood by [Ratios]. These match the JSON field names in a
// [Sample] so a policy or command can name a metric with a stable string.
const (
	MetricThroughput          = "throughput_messages_per_second"
	MetricP99                 = "p99_nanoseconds"
	MetricP999                = "p999_nanoseconds"
	MetricServerCPUPerMessage = "server_cpu_seconds_per_message"
	MetricServerRSSPerConn    = "server_rss_bytes_per_connection"
	MetricClientCPUPerMessage = "client_cpu_seconds_per_message"
)

// Sample is one measured (scenario, library, repetition) record as written to
// samples.jsonl by benchrun. It embeds the loadgen result (which already
// carries the client's self-reported CPU seconds and peak RSS) and adds the
// run context, the server's process-rusage resource metrics, and the derived
// per-message/per-connection figures. Resource accounting is taken only from
// process rusage, never by wrapping net.Conn on a gating path.
type Sample struct {
	support.LoadgenResult
	Scenario                    string  `json:"scenario"`
	Library                     string  `json:"library"`
	Repetition                  int     `json:"repetition"`
	OrderIndex                  int     `json:"order_index"`
	ServerCPUSeconds            float64 `json:"server_cpu_seconds"`
	ServerMaxRSSBytes           int64   `json:"server_maxrss_bytes"`
	ServerCPUSecondsPerMessage  float64 `json:"server_cpu_seconds_per_message"`
	ServerRSSBytesPerConnection float64 `json:"server_rss_bytes_per_connection"`
	ClientCPUSecondsPerMessage  float64 `json:"client_cpu_seconds_per_message"`
}

// Metric returns the named metric value for the sample, or an error if the
// metric name is unknown.
func (s Sample) Metric(name string) (float64, error) {
	switch name {
	case MetricThroughput:
		return s.ThroughputMessagesPerSecond, nil
	case MetricP99:
		return float64(s.P99Nanoseconds), nil
	case MetricP999:
		return float64(s.P999Nanoseconds), nil
	case MetricServerCPUPerMessage:
		return s.ServerCPUSecondsPerMessage, nil
	case MetricServerRSSPerConn:
		return s.ServerRSSBytesPerConnection, nil
	case MetricClientCPUPerMessage:
		return s.ClientCPUSecondsPerMessage, nil
	default:
		return 0, fmt.Errorf("paired: unknown metric %q", name)
	}
}

// forScenario returns the samples for one scenario and library, ordered by
// repetition so pairing is stable regardless of samples.jsonl line order.
func forScenario(samples []Sample, scenario, library string) []Sample {
	var out []Sample
	for _, s := range samples {
		if s.Scenario == scenario && s.Library == library {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b Sample) int { return cmp.Compare(a.Repetition, b.Repetition) })
	return out
}

// Ratios pairs candidate repetition i with comparator repetition i for the
// given scenario and returns the candidate/comparator ratios of the named
// metric. Both libraries must contribute the same non-zero number of
// repetitions; a missing or unequal count is an error. A comparator value of
// zero (an undefined ratio) is also an error rather than a silent infinity.
func Ratios(samples []Sample, scenario, candidate, comparator, metric string) ([]float64, error) {
	cand := forScenario(samples, scenario, candidate)
	comp := forScenario(samples, scenario, comparator)
	if len(cand) == 0 || len(comp) == 0 {
		return nil, fmt.Errorf("paired: scenario %q missing samples (candidate=%d comparator=%d)", scenario, len(cand), len(comp))
	}
	if len(cand) != len(comp) {
		return nil, fmt.Errorf("paired: scenario %q repetition count mismatch: candidate=%d comparator=%d", scenario, len(cand), len(comp))
	}
	ratios := make([]float64, len(cand))
	for i := range cand {
		cv, err := cand[i].Metric(metric)
		if err != nil {
			return nil, err
		}
		dv, err := comp[i].Metric(metric)
		if err != nil {
			return nil, err
		}
		if dv == 0 {
			return nil, fmt.Errorf("paired: scenario %q rep %d comparator metric %q is zero", scenario, i, metric)
		}
		ratios[i] = cv / dv
	}
	return ratios, nil
}

// Bootstrap computes the median of ratios and a percentile confidence interval
// for that median via nonparametric bootstrap resampling with replacement. It
// is fully deterministic: the same (ratios, replicates, confidence, seed)
// always yields the same (center, lower, upper). The interval uses the
// (1-confidence)/2 tails of the resampled median distribution. With no ratios
// or non-positive replicates it degenerates to the point median.
func Bootstrap(ratios []float64, replicates int, confidence float64, seed uint64) (center, lower, upper float64) {
	center = Median(ratios)
	if len(ratios) == 0 || replicates <= 0 {
		return center, center, center
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))
	n := len(ratios)
	resample := make([]float64, n)
	medians := make([]float64, replicates)
	for r := range replicates {
		for i := range n {
			resample[i] = ratios[rng.IntN(n)]
		}
		medians[r] = Median(resample)
	}
	slices.Sort(medians)
	alpha := (1 - confidence) / 2
	lower = percentileSorted(medians, alpha)
	upper = percentileSorted(medians, 1-alpha)
	return center, lower, upper
}

// Median returns the median of xs (the mean of the two central values for an
// even count). It returns 0 for an empty slice.
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	return percentileSorted(s, 0.5)
}

// percentileSorted returns the linearly interpolated q-quantile (0<=q<=1) of
// an ascending-sorted slice.
func percentileSorted(sorted []float64, q float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[n-1]
	}
	pos := q * float64(n-1)
	lo := int(pos)
	if lo+1 >= n {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}

// Geomean returns the geometric mean of xs. It returns 0 for an empty slice
// and NaN when any element is non-positive (the geometric mean is undefined
// there).
func Geomean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sumLog := 0.0
	for _, x := range xs {
		if x <= 0 {
			return math.NaN()
		}
		sumLog += math.Log(x)
	}
	return math.Exp(sumLog / float64(len(xs)))
}

// LoadSamples reads a samples.jsonl file, one [Sample] per non-empty line.
func LoadSamples(path string) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("paired: open %s: %w", path, err)
	}
	defer f.Close()

	var samples []Sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var s Sample
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("paired: %s line %d: %w", path, line, err)
		}
		samples = append(samples, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("paired: read %s: %w", path, err)
	}
	return samples, nil
}
