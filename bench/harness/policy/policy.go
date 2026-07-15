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
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/zchee/gows/bench/harness/support"
)

// PolicySchemaVersion is the only policy schema accepted by the Phase 0
// harness. Historical versionless policies must be migrated explicitly.
const PolicySchemaVersion = 3

// RunKind separates evidence purposes that must never share an artifact root.
type RunKind string

const (
	// RunKindAA is same-binary harness self-validation.
	RunKindAA RunKind = "aa"
	// RunKindBaseline records current implementation performance without a
	// superiority gate.
	RunKindBaseline RunKind = "baseline"
	// RunKindDiagnostic is non-promotable smoke, screening, or experiment data.
	RunKindDiagnostic RunKind = "diagnostic"
)

// EvidenceClass identifies how a run may be interpreted.
type EvidenceClass string

const (
	EvidenceClassSelfValidation EvidenceClass = "self_validation"
	EvidenceClassBaseline       EvidenceClass = "baseline"
	EvidenceClassDiagnostic     EvidenceClass = "diagnostic"
	EvidenceClassClaim          EvidenceClass = "claim"
)

// HostMode distinguishes same-host diagnostics from separate-host claims.
type HostMode string

const (
	HostModeSame     HostMode = "same_host"
	HostModeSeparate HostMode = "separate_host"
)

// ToolchainSeries prevents stock and custom GOEXPERIMENT artifacts from being
// combined.
type ToolchainSeries string

const (
	ToolchainStock  ToolchainSeries = "stock"
	ToolchainCustom ToolchainSeries = "custom"
)

// AdapterClass identifies the comparator architecture being measured.
type AdapterClass string

const (
	AdapterClassAA             AdapterClass = "aa"
	AdapterClassBestAPI        AdapterClass = "best_api"
	AdapterClassSemanticParity AdapterClass = "semantic_parity"
)

// ValidationProfile separates strict conformance from unsafe diagnostics.
type ValidationProfile string

const (
	ValidationStrict ValidationProfile = "strict_on"
	ValidationUnsafe ValidationProfile = "validation_off"
)

// ClientKind identifies the independent load client implementation.
type ClientKind string

const (
	ClientGoWS   ClientKind = "gows"
	ClientGobwas ClientKind = "gobwas"
	ClientRaw    ClientKind = "raw"
)

// CellClass separates server-sensitive and saturated baseline interpretation.
type CellClass string

const (
	CellServerSensitive CellClass = "server_sensitive"
	CellSaturated       CellClass = "saturated"
	CellDiagnostic      CellClass = "diagnostic"
)

// MessageType is the WebSocket data-message type used by a scenario.
type MessageType string

const (
	MessageBinary MessageType = "binary"
	MessageText   MessageType = "text"
)

// ArrivalKind defines how messages are offered to the load generator.
type ArrivalKind string

const (
	ArrivalClosedLoop ArrivalKind = "closed_loop"
	ArrivalPipelined  ArrivalKind = "pipelined"
	ArrivalOpenLoop   ArrivalKind = "open_loop"
)

// Series is the immutable interpretation identity of a policy.
type Series struct {
	ID                string            `json:"id"`
	RunKind           RunKind           `json:"run_kind"`
	EvidenceClass     EvidenceClass     `json:"evidence_class"`
	HostMode          HostMode          `json:"host_mode"`
	Toolchain         ToolchainSeries   `json:"toolchain"`
	GoExperiment      string            `json:"go_experiment,omitzero"`
	AdapterClass      AdapterClass      `json:"adapter_class"`
	ValidationProfile ValidationProfile `json:"validation_profile"`
	Client            ClientKind        `json:"client"`
}

// Adapter declares the source identity of one policy-facing library label.
type Adapter struct {
	ID          string       `json:"id"`
	Class       AdapterClass `json:"class"`
	SourceFiles []string     `json:"source_files"`
}

// RatioBand is a closed equivalence interval.
type RatioBand struct {
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

// AAGates is the preregistered self-validation contract.
type AAGates struct {
	MinSessions        int       `json:"min_sessions"`
	MinPairsPerSession int       `json:"min_pairs_per_session"`
	Throughput         RatioBand `json:"throughput"`
	P99                RatioBand `json:"p99"`
	P999               RatioBand `json:"p999"`
	OrderEffect        RatioBand `json:"order_effect"`
	MaxFalsePositive   float64   `json:"max_false_positive"`
}

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
	Replicates     int     `json:"replicates"`
	Confidence     float64 `json:"confidence"`
	NullIterations int     `json:"null_iterations"`
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
	MaxLoad1Drift            float64  `json:"max_load1_drift"`
	MaxForeignCPUPercent     float64  `json:"max_foreign_cpu_percent"`
	ForbiddenProcessPatterns []string `json:"forbidden_process_patterns"`
}

// Scenario is one measurement cell: a payload size, connection count, and the
// warmup/measurement windows repeated Repetitions times.
type Scenario struct {
	Name        string      `json:"name"`
	Primary     bool        `json:"primary,omitzero"`
	CellClass   CellClass   `json:"cell_class"`
	MessageType MessageType `json:"message_type"`
	Arrival     ArrivalKind `json:"arrival"`
	OfferedRate int         `json:"offered_rate,omitzero"`
	// MaxSchedulerLateness is required only for true open-loop scenarios and
	// is recorded verbatim in every result. It prevents scheduler stalls from
	// being silently replayed as an in-window catch-up burst.
	MaxSchedulerLateness Duration `json:"max_scheduler_lateness,omitzero"`
	PayloadBytes         int      `json:"payload_bytes"`
	Connections          int      `json:"connections"`
	Inflight             int      `json:"inflight"`
	Warmup               Duration `json:"warmup"`
	Duration             Duration `json:"duration"`
	Repetitions          int      `json:"repetitions"`
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
	SchemaVersion    int                        `json:"schema_version"`
	Series           Series                     `json:"series"`
	Candidate        string                     `json:"candidate"`
	Comparator       string                     `json:"comparator"`
	Seed             uint64                     `json:"seed"`
	Bootstrap        Bootstrap                  `json:"bootstrap"`
	AAGates          AAGates                    `json:"aa_gates"`
	Thresholds       Thresholds                 `json:"thresholds"`
	Guard            Guard                      `json:"guard"`
	Scenarios        []Scenario                 `json:"scenarios"`
	LibraryOverrides map[string]LibraryOverride `json:"library_overrides,omitzero"`
	Adapters         map[string]Adapter         `json:"adapters"`
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
	case p.SchemaVersion != PolicySchemaVersion:
		return fmt.Errorf("policy: schema_version = %d, want %d", p.SchemaVersion, PolicySchemaVersion)
	case p.Series.ID == "":
		return fmt.Errorf("policy: series.id is required")
	case !validRunKind(p.Series.RunKind):
		return fmt.Errorf("policy: unknown series.run_kind %q", p.Series.RunKind)
	case !validEvidenceClass(p.Series.EvidenceClass):
		return fmt.Errorf("policy: unknown series.evidence_class %q", p.Series.EvidenceClass)
	case p.Series.HostMode != HostModeSame && p.Series.HostMode != HostModeSeparate:
		return fmt.Errorf("policy: unknown series.host_mode %q", p.Series.HostMode)
	case p.Series.Toolchain != ToolchainStock && p.Series.Toolchain != ToolchainCustom:
		return fmt.Errorf("policy: unknown series.toolchain %q", p.Series.Toolchain)
	case p.Series.Toolchain == ToolchainStock && p.Series.GoExperiment != "":
		return fmt.Errorf("policy: stock toolchain series must not set series.go_experiment")
	case p.Series.Toolchain == ToolchainCustom && p.Series.GoExperiment == "":
		return fmt.Errorf("policy: custom toolchain series requires series.go_experiment")
	case p.Series.GoExperiment != "" && !validGoExperiment(p.Series.GoExperiment):
		return fmt.Errorf("policy: invalid series.go_experiment %q", p.Series.GoExperiment)
	case !validAdapterClass(p.Series.AdapterClass):
		return fmt.Errorf("policy: unknown series.adapter_class %q", p.Series.AdapterClass)
	case p.Series.ValidationProfile != ValidationStrict && p.Series.ValidationProfile != ValidationUnsafe:
		return fmt.Errorf("policy: unknown series.validation_profile %q", p.Series.ValidationProfile)
	case !validClient(p.Series.Client):
		return fmt.Errorf("policy: unknown series.client %q", p.Series.Client)
	case p.Series.EvidenceClass == EvidenceClassClaim && p.Series.HostMode != HostModeSeparate:
		return fmt.Errorf("policy: claim evidence requires separate_host mode")
	case p.Series.EvidenceClass == EvidenceClassClaim && p.Series.Toolchain != ToolchainStock:
		return fmt.Errorf("policy: claim evidence requires the stock toolchain series")
	case p.Series.EvidenceClass == EvidenceClassClaim && p.Series.ValidationProfile != ValidationStrict:
		return fmt.Errorf("policy: claim evidence requires strict_on validation")
	case p.Series.RunKind == RunKindAA && (p.Series.EvidenceClass != EvidenceClassSelfValidation || p.Series.HostMode != HostModeSame || p.Series.AdapterClass != AdapterClassAA):
		return fmt.Errorf("policy: aa runs require self_validation, same_host, and aa adapter class")
	case p.Series.RunKind == RunKindBaseline && !((p.Series.EvidenceClass == EvidenceClassBaseline && p.Series.HostMode == HostModeSame) || (p.Series.EvidenceClass == EvidenceClassClaim && p.Series.HostMode == HostModeSeparate)):
		return fmt.Errorf("policy: baseline runs require baseline/same_host or claim/separate_host identity")
	case p.Series.RunKind == RunKindDiagnostic && p.Series.EvidenceClass != EvidenceClassDiagnostic:
		return fmt.Errorf("policy: diagnostic runs require diagnostic evidence")
	case p.Series.ValidationProfile == ValidationUnsafe && (p.Series.RunKind != RunKindDiagnostic || p.Series.EvidenceClass != EvidenceClassDiagnostic):
		return fmt.Errorf("policy: validation_off is diagnostic-only")
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
	case p.Bootstrap.NullIterations < 1_000:
		return fmt.Errorf("policy: bootstrap.null_iterations must be >= 1000, got %d", p.Bootstrap.NullIterations)
	case len(p.Scenarios) == 0:
		return fmt.Errorf("policy: at least one scenario is required")
	case p.Guard.MaxLoad1 <= 0:
		return fmt.Errorf("policy: guard.max_load1 must be > 0, got %g", p.Guard.MaxLoad1)
	case p.Guard.MaxLoad1Drift <= 0:
		return fmt.Errorf("policy: guard.max_load1_drift must be > 0, got %g", p.Guard.MaxLoad1Drift)
	case p.Guard.MaxForeignCPUPercent <= 0 || p.Guard.MaxForeignCPUPercent > 100:
		return fmt.Errorf("policy: guard.max_foreign_cpu_percent must be in (0,100], got %g", p.Guard.MaxForeignCPUPercent)
	case !validPositiveThreshold(p.Thresholds.ThroughputLowerBound):
		return fmt.Errorf("policy: thresholds.throughput_lower_bound must be finite and > 0")
	case !validPositiveThreshold(p.Thresholds.ThroughputGeomean):
		return fmt.Errorf("policy: thresholds.throughput_geomean must be finite and > 0")
	case !validPositiveThreshold(p.Thresholds.P99UpperBound):
		return fmt.Errorf("policy: thresholds.p99_upper_bound must be finite and > 0")
	case !validPositiveThreshold(p.Thresholds.P999CenterUpperBound):
		return fmt.Errorf("policy: thresholds.p999_center_upper_bound must be finite and > 0")
	}
	for field, value := range map[string]string{"series.id": p.Series.ID, "candidate": p.Candidate, "comparator": p.Comparator} {
		if !validArtifactID(value) {
			return fmt.Errorf("policy: %s %q is not a path-safe artifact identifier", field, value)
		}
	}
	if err := p.AAGates.validate(); err != nil {
		return err
	}
	if err := p.validateAdapters(); err != nil {
		return err
	}

	primaries := 0
	names := make(map[string]struct{}, len(p.Scenarios))
	for i := range p.Scenarios {
		s := &p.Scenarios[i]
		switch {
		case !validArtifactID(s.Name):
			return fmt.Errorf("policy: scenario %d name %q is not a path-safe artifact identifier", i, s.Name)
		case !validCellClass(s.CellClass):
			return fmt.Errorf("policy: scenario %q: invalid cell_class %q", s.Name, s.CellClass)
		case s.MessageType != MessageBinary && s.MessageType != MessageText:
			return fmt.Errorf("policy: scenario %q: invalid message_type %q", s.Name, s.MessageType)
		case !validArrival(s.Arrival):
			return fmt.Errorf("policy: scenario %q: invalid arrival %q", s.Name, s.Arrival)
		case s.PayloadBytes <= 0:
			return fmt.Errorf("policy: scenario %q: payload_bytes must be > 0, got %d", s.Name, s.PayloadBytes)
		case s.Connections <= 0:
			return fmt.Errorf("policy: scenario %q: connections must be > 0, got %d", s.Name, s.Connections)
		case s.Inflight < 1:
			return fmt.Errorf("policy: scenario %q: inflight must be >= 1, got %d", s.Name, s.Inflight)
		case s.Inflight > support.MaxInflightBytes/s.PayloadBytes:
			return fmt.Errorf("policy: scenario %q: inflight*payload_bytes exceeds the %d-byte pipeline cap", s.Name, support.MaxInflightBytes)
		case s.Repetitions <= 0:
			return fmt.Errorf("policy: scenario %q: repetitions must be > 0, got %d", s.Name, s.Repetitions)
		case s.Repetitions%2 != 0:
			return fmt.Errorf("policy: scenario %q: repetitions must be even for balanced blocks, got %d", s.Name, s.Repetitions)
		case s.Duration.Duration() <= 0:
			return fmt.Errorf("policy: scenario %q: duration must be > 0", s.Name)
		case s.Warmup.Duration() < 0:
			return fmt.Errorf("policy: scenario %q: warmup must be >= 0", s.Name)
		case s.Arrival == ArrivalClosedLoop && (s.Inflight != 1 || s.OfferedRate != 0 || s.MaxSchedulerLateness.Duration() != 0):
			return fmt.Errorf("policy: scenario %q: closed_loop requires inflight=1, offered_rate=0, and no scheduler lateness limit", s.Name)
		case s.Arrival == ArrivalPipelined && (s.Inflight < 2 || s.OfferedRate != 0 || s.MaxSchedulerLateness.Duration() != 0):
			return fmt.Errorf("policy: scenario %q: pipelined requires inflight>=2, offered_rate=0, and no scheduler lateness limit", s.Name)
		case s.Arrival == ArrivalOpenLoop && (s.Inflight != 1 || s.OfferedRate <= 0 || s.OfferedRate > support.MaxOpenLoopRate):
			return fmt.Errorf("policy: scenario %q: open_loop requires inflight=1 and offered_rate in [1,%d]", s.Name, support.MaxOpenLoopRate)
		case s.Arrival == ArrivalOpenLoop && s.MaxSchedulerLateness.Duration() <= 0:
			return fmt.Errorf("policy: scenario %q: open_loop requires max_scheduler_lateness > 0", s.Name)
		case s.Arrival == ArrivalOpenLoop && s.MaxSchedulerLateness.Duration() > time.Second/time.Duration(s.OfferedRate):
			return fmt.Errorf("policy: scenario %q: max_scheduler_lateness %s exceeds one arrival interval", s.Name, s.MaxSchedulerLateness.Duration())
		}
		if _, duplicate := names[s.Name]; duplicate {
			return fmt.Errorf("policy: duplicate scenario name %q", s.Name)
		}
		names[s.Name] = struct{}{}
		if p.Series.RunKind == RunKindBaseline {
			switch {
			case s.Warmup.Duration() < 5*time.Second:
				return fmt.Errorf("policy: baseline scenario %q: warmup must be >= 5s", s.Name)
			case s.Duration.Duration() < 30*time.Second:
				return fmt.Errorf("policy: baseline scenario %q: duration must be >= 30s", s.Name)
			case s.Repetitions < 20:
				return fmt.Errorf("policy: baseline scenario %q: repetitions must be >= 20", s.Name)
			}
		}
		if p.Series.RunKind == RunKindAA && (s.Repetitions < p.AAGates.MinPairsPerSession || s.Repetitions%2 != 0) {
			return fmt.Errorf("policy: aa scenario %q: repetitions must be even and >= %d", s.Name, p.AAGates.MinPairsPerSession)
		}
		if s.Primary {
			primaries++
		}
	}
	if primaries == 0 {
		return fmt.Errorf("policy: at least one scenario must be primary")
	}

	for name, ov := range p.LibraryOverrides {
		if !validArtifactID(name) {
			return fmt.Errorf("policy: library_overrides key %q is not a path-safe artifact identifier", name)
		}
		if name != p.Candidate && name != p.Comparator {
			return fmt.Errorf("policy: library_overrides %q is unused by candidate or comparator", name)
		}
		if ov.Lib != "" && !validArtifactID(ov.Lib) {
			return fmt.Errorf("policy: library_overrides %q lib %q is not a path-safe identifier", name, ov.Lib)
		}
		if p.Series.RunKind != RunKindDiagnostic && (len(ov.BuildEnv) != 0 || len(ov.ServerArgs) != 0) {
			return fmt.Errorf("policy: final aa/baseline evidence forbids build_env and server_args overrides")
		}
		seenEnv := make(map[string]struct{}, len(ov.BuildEnv))
		for _, env := range ov.BuildEnv {
			key, _, ok := strings.Cut(env, "=")
			if !ok || !validEnvKey(key) || strings.ContainsRune(env, 0) {
				return fmt.Errorf("policy: library_overrides %q: build_env entry %q must be KEY=VALUE", name, env)
			}
			if _, duplicate := seenEnv[key]; duplicate {
				return fmt.Errorf("policy: library_overrides %q repeats build_env key %s", name, key)
			}
			seenEnv[key] = struct{}{}
			switch key {
			case "GOENV", "GOTOOLCHAIN", "GOFLAGS", "GOEXPERIMENT", "GOOS", "GOARCH", "GOAMD64", "GOARM64", "GOFIPS140", "CGO_ENABLED":
				return fmt.Errorf("policy: library_overrides %q sets reserved toolchain variable %s; use series identity", name, key)
			}
		}
		for _, arg := range ov.ServerArgs {
			if arg == "" || strings.ContainsRune(arg, 0) {
				return fmt.Errorf("policy: library_overrides %q contains an empty or NUL server argument", name)
			}
		}
	}
	if p.Series.RunKind == RunKindAA {
		candidate := p.Resolve(p.Candidate)
		comparator := p.Resolve(p.Comparator)
		if candidate.Lib != comparator.Lib || !slices.Equal(candidate.BuildEnv, comparator.BuildEnv) || !slices.Equal(candidate.ServerArgs, comparator.ServerArgs) {
			return fmt.Errorf("policy: aa labels must resolve to the same server backend, build environment, and arguments")
		}
		ca, cb := p.Adapters[p.Candidate], p.Adapters[p.Comparator]
		if ca.ID != cb.ID || !slices.Equal(ca.SourceFiles, cb.SourceFiles) {
			return fmt.Errorf("policy: aa labels must use the same adapter identity")
		}
	}
	return nil
}

func validRunKind(value RunKind) bool {
	return value == RunKindAA || value == RunKindBaseline || value == RunKindDiagnostic
}

func validEvidenceClass(value EvidenceClass) bool {
	return value == EvidenceClassSelfValidation || value == EvidenceClassBaseline || value == EvidenceClassDiagnostic || value == EvidenceClassClaim
}

func validAdapterClass(value AdapterClass) bool {
	return value == AdapterClassAA || value == AdapterClassBestAPI || value == AdapterClassSemanticParity
}

func validClient(value ClientKind) bool {
	return value == ClientGoWS || value == ClientGobwas || value == ClientRaw
}

func validCellClass(value CellClass) bool {
	return value == CellServerSensitive || value == CellSaturated || value == CellDiagnostic
}

func validArrival(value ArrivalKind) bool {
	return value == ArrivalClosedLoop || value == ArrivalPipelined || value == ArrivalOpenLoop
}

func validGoExperiment(value string) bool {
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "= \t\r\n") {
		return false
	}
	for part := range strings.SplitSeq(value, ",") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
				return false
			}
		}
	}
	return true
}

func validArtifactID(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func validEnvKey(value string) bool {
	if value == "" || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z') || value[0] == '_') {
		return false
	}
	for _, r := range value[1:] {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func validPositiveThreshold(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func (g AAGates) validate() error {
	switch {
	case g.MinSessions < 3:
		return fmt.Errorf("policy: aa_gates.min_sessions must be >= 3, got %d", g.MinSessions)
	case g.MinPairsPerSession < 20 || g.MinPairsPerSession%2 != 0:
		return fmt.Errorf("policy: aa_gates.min_pairs_per_session must be even and >= 20, got %d", g.MinPairsPerSession)
	case g.MaxFalsePositive < 0 || g.MaxFalsePositive > 0.05:
		return fmt.Errorf("policy: aa_gates.max_false_positive must be in [0,0.05], got %g", g.MaxFalsePositive)
	}
	for name, band := range map[string]RatioBand{
		"throughput":   g.Throughput,
		"p99":          g.P99,
		"p999":         g.P999,
		"order_effect": g.OrderEffect,
	} {
		if math.IsNaN(band.Lower) || math.IsNaN(band.Upper) || band.Lower <= 0 || band.Lower >= 1 || band.Upper <= 1 || band.Lower >= band.Upper {
			return fmt.Errorf("policy: aa_gates.%s must be a positive band spanning 1, got [%g,%g]", name, band.Lower, band.Upper)
		}
	}
	return nil
}

func (p *Policy) validateAdapters() error {
	if len(p.Adapters) == 0 {
		return fmt.Errorf("policy: adapters are required")
	}
	for _, name := range []string{p.Candidate, p.Comparator} {
		adapter, ok := p.Adapters[name]
		if !ok {
			return fmt.Errorf("policy: adapter for %q is required", name)
		}
		if adapter.ID == "" {
			return fmt.Errorf("policy: adapter %q: id is required", name)
		}
		if adapter.Class != p.Series.AdapterClass {
			return fmt.Errorf("policy: adapter %q class %q differs from series class %q", name, adapter.Class, p.Series.AdapterClass)
		}
		if len(adapter.SourceFiles) == 0 {
			return fmt.Errorf("policy: adapter %q: source_files are required", name)
		}
		seen := make(map[string]struct{}, len(adapter.SourceFiles))
		for _, source := range adapter.SourceFiles {
			if strings.Contains(source, `\`) || filepath.Clean(source) != source || filepath.ToSlash(source) != source || !filepath.IsLocal(source) || filepath.Ext(source) != ".go" {
				return fmt.Errorf("policy: adapter %q source %q must be a local .go path", name, source)
			}
			if _, duplicate := seen[source]; duplicate {
				return fmt.Errorf("policy: adapter %q repeats source %q", name, source)
			}
			seen[source] = struct{}{}
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
	if err := json.Unmarshal(raw, &p, json.RejectUnknownMembers(true)); err != nil {
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

// HashAdapter binds the adapter's declared identity/class and the sorted path
// plus content hash of every source file. Both benchrun and the evaluator use
// this single contract so a metadata-only adapter change cannot masquerade as
// the same benchmark implementation.
func HashAdapter(root string, adapter Adapter) (string, error) {
	paths := slices.Clone(adapter.SourceFiles)
	slices.Sort(paths)
	hash := sha256.New()
	if _, err := fmt.Fprintf(hash, "adapter-v1\n%d:%s\n%d:%s\n", len(adapter.ID), adapter.ID, len(adapter.Class), adapter.Class); err != nil {
		return "", err
	}
	for _, relative := range paths {
		if strings.Contains(relative, `\`) || filepath.Clean(relative) != relative || filepath.ToSlash(relative) != relative || !filepath.IsLocal(relative) {
			return "", fmt.Errorf("policy: adapter source path %q is not local", relative)
		}
		path := filepath.Join(root, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("policy: stat adapter source %s: %w", relative, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("policy: adapter source %s is not a regular file", relative)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("policy: read adapter source %s: %w", relative, err)
		}
		sum := sha256.Sum256(raw)
		if _, err := fmt.Fprintf(hash, "%d:%s:%s\n", len(relative), relative, hex.EncodeToString(sum[:])); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
