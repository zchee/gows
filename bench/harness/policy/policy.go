// Package policy defines the benchmark comparison policy schema shared by
// benchrun (execution) and benchcmp (statistical evaluation): the candidate
// and comparator libraries, the scenario matrix, bootstrap parameters,
// decision thresholds, and the host-hygiene guard settings. Policy files are
// authored as human-readable JSON with Go duration strings (for example
// "5s") for the warmup and measurement windows.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-json-experiment/json"
)

// Duration is a [time.Duration] that marshals to and unmarshals from a Go
// duration string (for example "5s") in JSON, keeping policy files readable
// while preserving exact nanosecond semantics.
type Duration time.Duration

// MarshalJSON encodes the duration as a quoted Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(time.Duration(d).String())), nil
}

// UnmarshalJSON decodes a quoted Go duration string such as "30s".
func (d *Duration) UnmarshalJSON(data []byte) error {
	s, err := strconv.Unquote(string(data))
	if err != nil {
		return fmt.Errorf("policy: duration must be a JSON string: %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("policy: invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Duration returns the value as a [time.Duration].
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Bootstrap parameterizes the nonparametric bootstrap confidence interval.
type Bootstrap struct {
	Replicates int     `json:"replicates"`
	Confidence float64 `json:"confidence"`
}

// Thresholds are the gate boundaries benchcmp evaluates each primary scenario
// against. Throughput ratios are candidate/comparator (higher is better);
// p99 and p999 ratios are candidate/comparator (lower is better).
type Thresholds struct {
	ThroughputLowerBound float64 `json:"throughput_lower_bound"`
	ThroughputGeomean    float64 `json:"throughput_geomean"`
	P99UpperBound        float64 `json:"p99_upper_bound"`
	P999CenterUpperBound float64 `json:"p999_center_upper_bound"`
}

// Guard holds the host-hygiene preconditions benchrun enforces before it
// spawns any measurement process.
type Guard struct {
	MaxLoad1                 float64  `json:"max_load1"`
	ForbiddenProcessPatterns []string `json:"forbidden_process_patterns"`
}

// Scenario is one measurement cell: a payload size, connection count, and the
// warmup/measurement windows repeated Repetitions times.
type Scenario struct {
	Name         string   `json:"name"`
	Primary      bool     `json:"primary,omitzero"`
	PayloadBytes int      `json:"payload_bytes"`
	Connections  int      `json:"connections"`
	Inflight     int      `json:"inflight"`
	Warmup       Duration `json:"warmup"`
	Duration     Duration `json:"duration"`
	Repetitions  int      `json:"repetitions"`
}

// Policy is the complete comparison specification.
type Policy struct {
	Candidate  string     `json:"candidate"`
	Comparator string     `json:"comparator"`
	Seed       uint64     `json:"seed"`
	Bootstrap  Bootstrap  `json:"bootstrap"`
	Thresholds Thresholds `json:"thresholds"`
	Guard      Guard      `json:"guard"`
	Scenarios  []Scenario `json:"scenarios"`
}

// PrimaryScenarios returns the scenarios flagged primary, which are the ones
// benchcmp gates on.
func (p *Policy) PrimaryScenarios() []Scenario {
	var out []Scenario
	for _, s := range p.Scenarios {
		if s.Primary {
			out = append(out, s)
		}
	}
	return out
}

// Validate reports the first structural problem with the policy, failing fast
// so a malformed run never starts.
func (p *Policy) Validate() error {
	switch {
	case p.Candidate == "":
		return fmt.Errorf("policy: candidate is required")
	case p.Comparator == "":
		return fmt.Errorf("policy: comparator is required")
	case p.Candidate == p.Comparator:
		return fmt.Errorf("policy: candidate and comparator must differ (both %q)", p.Candidate)
	case p.Bootstrap.Replicates <= 0:
		return fmt.Errorf("policy: bootstrap.replicates must be > 0, got %d", p.Bootstrap.Replicates)
	case p.Bootstrap.Confidence <= 0 || p.Bootstrap.Confidence >= 1:
		return fmt.Errorf("policy: bootstrap.confidence must be in (0,1), got %g", p.Bootstrap.Confidence)
	case len(p.Scenarios) == 0:
		return fmt.Errorf("policy: at least one scenario is required")
	}

	primaries := 0
	for i := range p.Scenarios {
		s := &p.Scenarios[i]
		switch {
		case s.Name == "":
			return fmt.Errorf("policy: scenario %d: name is required", i)
		case s.PayloadBytes <= 0:
			return fmt.Errorf("policy: scenario %q: payload_bytes must be > 0, got %d", s.Name, s.PayloadBytes)
		case s.Connections <= 0:
			return fmt.Errorf("policy: scenario %q: connections must be > 0, got %d", s.Name, s.Connections)
		case s.Repetitions <= 0:
			return fmt.Errorf("policy: scenario %q: repetitions must be > 0, got %d", s.Name, s.Repetitions)
		case s.Duration.Duration() <= 0:
			return fmt.Errorf("policy: scenario %q: duration must be > 0", s.Name)
		case s.Warmup.Duration() < 0:
			return fmt.Errorf("policy: scenario %q: warmup must be >= 0", s.Name)
		}
		if s.Primary {
			primaries++
		}
	}
	if primaries == 0 {
		return fmt.Errorf("policy: at least one scenario must be primary")
	}
	return nil
}

// Load reads, parses, and validates a policy JSON file. It also returns the
// raw file bytes so callers can hash and archive the exact policy content
// that drove a run.
func Load(path string) (*Policy, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	p, err := Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	return p, raw, nil
}

// Parse unmarshals and validates policy bytes.
func Parse(raw []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Sum returns the hex-encoded SHA-256 of the raw policy bytes, used as the
// policy's content hash in run provenance and verdicts.
func Sum(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
