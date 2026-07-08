package support

import (
	"math/rand/v2"
	"slices"
	"time"
)

// Recorder is a single-goroutine (not concurrency-safe) latency sample
// recorder using reservoir sampling (Algorithm R) so per-connection memory
// stays bounded even under long-running, high-rate loadgen sessions.
type Recorder struct {
	cap     int
	samples []time.Duration
	seen    int64
	rng     *rand.Rand
}

// NewRecorder returns a Recorder that keeps at most capacity samples,
// replacing older samples uniformly at random once that capacity is
// exceeded.
func NewRecorder(capacity int) *Recorder {
	return &Recorder{
		cap:     capacity,
		samples: make([]time.Duration, 0, capacity),
		rng:     rand.New(rand.NewPCG(0xC0FFEE, 0x5EED)),
	}
}

// Add records one latency sample.
func (r *Recorder) Add(d time.Duration) {
	r.seen++
	if len(r.samples) < r.cap {
		r.samples = append(r.samples, d)
		return
	}
	if j := r.rng.Int64N(r.seen); j < int64(r.cap) {
		r.samples[j] = d
	}
}

// Seen reports the total number of samples ever offered to Add, including
// ones dropped by reservoir sampling.
func (r *Recorder) Seen() int64 { return r.seen }

// Samples returns the retained (possibly subsampled) latency values.
func (r *Recorder) Samples() []time.Duration { return r.samples }

// Percentiles holds latency percentiles computed from a sorted sample set.
type Percentiles struct {
	P50, P90, P99, P999 time.Duration
	Min, Max            time.Duration
	N                   int
}

// ComputePercentiles sorts a copy of samples and reports p50/p90/p99/p999.
// It returns the zero value if samples is empty.
func ComputePercentiles(samples []time.Duration) Percentiles {
	if len(samples) == 0 {
		return Percentiles{}
	}
	s := slices.Clone(samples)
	slices.Sort(s)

	pick := func(q float64) time.Duration {
		idx := int(q * float64(len(s)-1))
		return s[idx]
	}
	return Percentiles{
		P50:  pick(0.50),
		P90:  pick(0.90),
		P99:  pick(0.99),
		P999: pick(0.999),
		Min:  s[0],
		Max:  s[len(s)-1],
		N:    len(s),
	}
}
