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
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/zchee/gows/bench/harness/support"
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

// LibraryOverride customizes how one candidate or comparator name is built and
// launched, so a policy can A/B a build-time or run-time variant of a real
// echoserver -lib backend without a bespoke server binary. Lib is the actual
// echoserver -lib value the name maps to (defaulting to the name itself when
// empty); ServerArgs are appended verbatim to the echoserver command line; and
// BuildEnv (KEY=VALUE entries) is appended to the build environment of a
// dedicated echoserver binary compiled once for this name. An override that
// sets only ServerArgs reuses the shared default binary; one that sets BuildEnv
// forces a separate build (see [Policy.Resolve]).
type LibraryOverride struct {
	Lib        string   `json:"lib,omitzero"`
	BuildEnv   []string `json:"build_env,omitzero"`
	ServerArgs []string `json:"server_args,omitzero"`
}

// Policy is the complete comparison specification.
type Policy struct {
	Candidate        string                     `json:"candidate"`
	Comparator       string                     `json:"comparator"`
	Seed             uint64                     `json:"seed"`
	Bootstrap        Bootstrap                  `json:"bootstrap"`
	Thresholds       Thresholds                 `json:"thresholds"`
	Guard            Guard                      `json:"guard"`
	Scenarios        []Scenario                 `json:"scenarios"`
	LibraryOverrides map[string]LibraryOverride `json:"library_overrides,omitzero"`
}

// Resolved describes how benchrun should build and launch one policy library
// name after applying any matching entry in LibraryOverrides. Name is the
// policy-facing library name (preserved verbatim in samples so paired analysis
// can distinguish variants); Lib is the echoserver -lib value; Bin is "" for
// the shared default echoserver binary or the override name when a dedicated
// binary must be built; BuildEnv is appended to that binary's build
// environment; and ServerArgs are appended to the echoserver command line.
type Resolved struct {
	Name       string
	Lib        string
	Bin        string
	BuildEnv   []string
	ServerArgs []string
}

// Resolve maps a policy library name to its build and launch parameters,
// applying the matching entry in LibraryOverrides when present. Without an
// override it returns the identity mapping (Lib == name, shared default binary,
// no extra args), which is exactly benchrun's historical behavior. A dedicated
// binary is requested (Bin set to name) only when the override carries a
// non-empty BuildEnv.
func (p *Policy) Resolve(name string) Resolved {
	ov, ok := p.LibraryOverrides[name]
	if !ok {
		return Resolved{Name: name, Lib: name}
	}
	lib := ov.Lib
	if lib == "" {
		lib = name
	}
	r := Resolved{Name: name, Lib: lib, BuildEnv: ov.BuildEnv, ServerArgs: ov.ServerArgs}
	if len(ov.BuildEnv) > 0 {
		r.Bin = name
	}
	return r
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
		case s.Inflight < 1:
			return fmt.Errorf("policy: scenario %q: inflight must be >= 1, got %d", s.Name, s.Inflight)
		case s.Inflight*s.PayloadBytes > support.MaxInflightBytes:
			return fmt.Errorf("policy: scenario %q: inflight*payload_bytes = %d exceeds the %d-byte pipeline cap", s.Name, s.Inflight*s.PayloadBytes, support.MaxInflightBytes)
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

	for name, ov := range p.LibraryOverrides {
		if name == "" {
			return fmt.Errorf("policy: library_overrides has an empty name key")
		}
		for _, env := range ov.BuildEnv {
			key, _, ok := strings.Cut(env, "=")
			if !ok || key == "" {
				return fmt.Errorf("policy: library_overrides %q: build_env entry %q must be KEY=VALUE", name, env)
			}
		}
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
