package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/go-json-experiment/json"
)

func TestDurationRoundTrip(t *testing.T) {
	tests := map[string]struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		"seconds":       {in: `"5s"`, want: 5 * time.Second},
		"minutes":       {in: `"2m30s"`, want: 2*time.Minute + 30*time.Second},
		"millis":        {in: `"250ms"`, want: 250 * time.Millisecond},
		"zero":          {in: `"0s"`, want: 0},
		"not a string":  {in: `5`, wantErr: true},
		"invalid units": {in: `"5parsecs"`, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var d Duration
			err := json.Unmarshal([]byte(tc.in), &d)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", d.Duration())
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal %q: %v", tc.in, err)
			}
			if d.Duration() != tc.want {
				t.Fatalf("got %v, want %v", d.Duration(), tc.want)
			}
			// Re-marshal and parse again: the value must survive a full cycle.
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var back Duration
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatalf("re-unmarshal %s: %v", raw, err)
			}
			if back != d {
				t.Fatalf("round-trip mismatch: %v -> %s -> %v", d.Duration(), raw, back.Duration())
			}
		})
	}
}

func validPolicy() Policy {
	return Policy{
		Candidate:  "gows",
		Comparator: "quickws",
		Seed:       12648430,
		Bootstrap:  Bootstrap{Replicates: 2000, Confidence: 0.95},
		Thresholds: Thresholds{
			ThroughputLowerBound: 1.0,
			ThroughputGeomean:    1.05,
			P99UpperBound:        1.01,
			P999CenterUpperBound: 1.05,
		},
		Guard: Guard{MaxLoad1: 6.0, ForbiddenProcessPatterns: []string{"echoserver", "loadgen"}},
		Scenarios: []Scenario{
			{
				Name:         "binary-1k-200",
				Primary:      true,
				PayloadBytes: 1024,
				Connections:  200,
				Inflight:     1,
				Warmup:       Duration(5 * time.Second),
				Duration:     Duration(30 * time.Second),
				Repetitions:  20,
			},
		},
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	want := validPolicy()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", *got, want)
	}
	// Duration fields must have survived as real durations, not zeroed.
	if got.Scenarios[0].Warmup.Duration() != 5*time.Second {
		t.Fatalf("warmup lost in round-trip: %v", got.Scenarios[0].Warmup.Duration())
	}
	if got.Scenarios[0].Duration.Duration() != 30*time.Second {
		t.Fatalf("duration lost in round-trip: %v", got.Scenarios[0].Duration.Duration())
	}
}

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*Policy)
		wantErr bool
	}{
		"valid":              {mutate: func(*Policy) {}},
		"empty candidate":    {mutate: func(p *Policy) { p.Candidate = "" }, wantErr: true},
		"empty comparator":   {mutate: func(p *Policy) { p.Comparator = "" }, wantErr: true},
		"same libs":          {mutate: func(p *Policy) { p.Comparator = p.Candidate }, wantErr: true},
		"zero replicates":    {mutate: func(p *Policy) { p.Bootstrap.Replicates = 0 }, wantErr: true},
		"confidence too big": {mutate: func(p *Policy) { p.Bootstrap.Confidence = 1 }, wantErr: true},
		"confidence zero":    {mutate: func(p *Policy) { p.Bootstrap.Confidence = 0 }, wantErr: true},
		"no scenarios":       {mutate: func(p *Policy) { p.Scenarios = nil }, wantErr: true},
		"scenario no name":   {mutate: func(p *Policy) { p.Scenarios[0].Name = "" }, wantErr: true},
		"zero payload":       {mutate: func(p *Policy) { p.Scenarios[0].PayloadBytes = 0 }, wantErr: true},
		"zero conns":         {mutate: func(p *Policy) { p.Scenarios[0].Connections = 0 }, wantErr: true},
		"zero reps":          {mutate: func(p *Policy) { p.Scenarios[0].Repetitions = 0 }, wantErr: true},
		"zero duration":      {mutate: func(p *Policy) { p.Scenarios[0].Duration = 0 }, wantErr: true},
		"no primary":         {mutate: func(p *Policy) { p.Scenarios[0].Primary = false }, wantErr: true},
		"zero inflight":      {mutate: func(p *Policy) { p.Scenarios[0].Inflight = 0 }, wantErr: true},
		"negative inflight":  {mutate: func(p *Policy) { p.Scenarios[0].Inflight = -1 }, wantErr: true},
		"inflight one ok":    {mutate: func(p *Policy) { p.Scenarios[0].Inflight = 1 }, wantErr: false},
		"inflight payload too big": {mutate: func(p *Policy) {
			p.Scenarios[0].Inflight = 2048
			p.Scenarios[0].PayloadBytes = 1024 // 2048*1024 = 2 MiB > 1 MiB cap
		}, wantErr: true},
		"inflight payload at cap": {mutate: func(p *Policy) {
			p.Scenarios[0].Inflight = 8
			p.Scenarios[0].PayloadBytes = 1024 // 8 KiB, well within the cap
		}, wantErr: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	overrides := map[string]LibraryOverride{
		"gows-lowat": {
			Lib:        "gows",
			ServerArgs: []string{"-notsent-lowat", "16384"},
		},
		"gows-nogtgc": {
			Lib:      "gows",
			BuildEnv: []string{"GOEXPERIMENT=nogreenteagc"},
		},
		"default-lib": {
			ServerArgs: []string{"-flag"},
		},
	}
	tests := map[string]struct {
		overrides map[string]LibraryOverride
		name      string
		want      Resolved
	}{
		"no overrides map": {
			overrides: nil,
			name:      "gows",
			want:      Resolved{Name: "gows", Lib: "gows"},
		},
		"name absent from overrides": {
			overrides: overrides,
			name:      "quickws",
			want:      Resolved{Name: "quickws", Lib: "quickws"},
		},
		"server args only reuses default binary": {
			overrides: overrides,
			name:      "gows-lowat",
			want: Resolved{
				Name:       "gows-lowat",
				Lib:        "gows",
				Bin:        "",
				ServerArgs: []string{"-notsent-lowat", "16384"},
			},
		},
		"build env forces dedicated binary": {
			overrides: overrides,
			name:      "gows-nogtgc",
			want: Resolved{
				Name:     "gows-nogtgc",
				Lib:      "gows",
				Bin:      "gows-nogtgc",
				BuildEnv: []string{"GOEXPERIMENT=nogreenteagc"},
			},
		},
		"empty lib defaults to name": {
			overrides: overrides,
			name:      "default-lib",
			want: Resolved{
				Name:       "default-lib",
				Lib:        "default-lib",
				ServerArgs: []string{"-flag"},
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := Policy{LibraryOverrides: tc.overrides}
			got := p.Resolve(tc.name)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Resolve(%q) =\n %+v\nwant\n %+v", tc.name, got, tc.want)
			}
		})
	}
}

func TestPolicyRoundTripWithOverrides(t *testing.T) {
	want := validPolicy()
	want.Candidate = "gows-nogtgc"
	want.LibraryOverrides = map[string]LibraryOverride{
		"gows-nogtgc": {
			Lib:      "gows",
			BuildEnv: []string{"GOEXPERIMENT=nogreenteagc"},
		},
		"gows-lowat": {
			Lib:        "gows",
			ServerArgs: []string{"-notsent-lowat", "16384"},
		},
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", *got, want)
	}
}

func TestValidateOverrides(t *testing.T) {
	tests := map[string]struct {
		overrides map[string]LibraryOverride
		wantErr   bool
	}{
		"nil map ok": {overrides: nil},
		"server args only ok": {
			overrides: map[string]LibraryOverride{"x": {Lib: "gows", ServerArgs: []string{"-notsent-lowat", "16384"}}},
		},
		"valid build env": {
			overrides: map[string]LibraryOverride{"x": {Lib: "gows", BuildEnv: []string{"GOEXPERIMENT=nogreenteagc"}}},
		},
		"build env missing equals": {
			overrides: map[string]LibraryOverride{"x": {Lib: "gows", BuildEnv: []string{"GOEXPERIMENT"}}},
			wantErr:   true,
		},
		"build env empty key": {
			overrides: map[string]LibraryOverride{"x": {Lib: "gows", BuildEnv: []string{"=value"}}},
			wantErr:   true,
		},
		"empty name key": {
			overrides: map[string]LibraryOverride{"": {Lib: "gows"}},
			wantErr:   true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := validPolicy()
			p.LibraryOverrides = tc.overrides
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestExperimentPolicies(t *testing.T) {
	// Every experiment isolates one variable in the binary-1k-1k causal cell,
	// so all five share the same measurement geometry and differ only in
	// candidate/comparator and any library override.
	type want struct {
		candidate  string
		comparator string
		overrideOf string   // library_overrides key expected (empty = none).
		lib        string   // override's real echoserver -lib (when overrideOf set).
		serverArgs []string // override's server_args (nil when none).
		buildEnv   []string // override's build_env (nil when none).
	}
	tests := map[string]want{
		"h1-rbuf1k.json":        {candidate: "gows-rbuf1k", comparator: "gows"},
		"h1-rbuf16k.json":       {candidate: "gows-rbuf16k", comparator: "gows"},
		"h5-lowat-gows.json":    {candidate: "gows-lowat", comparator: "gows", overrideOf: "gows-lowat", lib: "gows", serverArgs: []string{"-notsent-lowat", "16384"}},
		"h5-lowat-quickws.json": {candidate: "quickws-lowat", comparator: "quickws", overrideOf: "quickws-lowat", lib: "quickws", serverArgs: []string{"-notsent-lowat", "16384"}},
		"h2-nogreentea.json":    {candidate: "gows-nogtgc", comparator: "gows", overrideOf: "gows-nogtgc", lib: "gows", buildEnv: []string{"GOEXPERIMENT=nogreenteagc"}},
	}
	seeds := map[uint64]string{}
	for file, w := range tests {
		t.Run(file, func(t *testing.T) {
			p, raw, err := Load(filepath.Join("experiments", file))
			if err != nil {
				t.Fatalf("load %s: %v", file, err)
			}
			if p.Candidate != w.candidate {
				t.Errorf("candidate = %q, want %q", p.Candidate, w.candidate)
			}
			if p.Comparator != w.comparator {
				t.Errorf("comparator = %q, want %q", p.Comparator, w.comparator)
			}
			// The single cell must be the primary binary-1k-1k geometry.
			if len(p.Scenarios) != 1 {
				t.Fatalf("scenarios = %d, want 1", len(p.Scenarios))
			}
			s := p.Scenarios[0]
			if !s.Primary {
				t.Errorf("scenario primary = false, want true")
			}
			if s.PayloadBytes != 1024 || s.Connections != 1000 || s.Inflight != 1 {
				t.Errorf("cell = %dB x %d conns inflight %d, want 1024B x 1000 x 1", s.PayloadBytes, s.Connections, s.Inflight)
			}
			if s.Warmup.Duration() != 5*time.Second || s.Duration.Duration() != 30*time.Second || s.Repetitions != 20 {
				t.Errorf("windows = warmup %v duration %v reps %d, want 5s/30s/20", s.Warmup.Duration(), s.Duration.Duration(), s.Repetitions)
			}
			// Resolve must yield the candidate's real lib and arguments.
			r := p.Resolve(p.Candidate)
			if w.overrideOf == "" {
				if len(p.LibraryOverrides) != 0 {
					t.Errorf("library_overrides = %v, want none", p.LibraryOverrides)
				}
				if r.Lib != w.candidate || r.Bin != "" {
					t.Errorf("resolve identity = %+v, want lib %q bin \"\"", r, w.candidate)
				}
			} else {
				ov, ok := p.LibraryOverrides[w.overrideOf]
				if !ok {
					t.Fatalf("missing library_overrides[%q]", w.overrideOf)
				}
				if ov.Lib != w.lib {
					t.Errorf("override lib = %q, want %q", ov.Lib, w.lib)
				}
				if !reflect.DeepEqual(ov.ServerArgs, w.serverArgs) {
					t.Errorf("override server_args = %v, want %v", ov.ServerArgs, w.serverArgs)
				}
				if !reflect.DeepEqual(ov.BuildEnv, w.buildEnv) {
					t.Errorf("override build_env = %v, want %v", ov.BuildEnv, w.buildEnv)
				}
				if r.Lib != w.lib {
					t.Errorf("resolve lib = %q, want %q", r.Lib, w.lib)
				}
				// A build_env override needs a dedicated binary; a server_args
				// override reuses the shared default binary.
				wantBin := ""
				if len(w.buildEnv) > 0 {
					wantBin = w.candidate
				}
				if r.Bin != wantBin {
					t.Errorf("resolve bin = %q, want %q", r.Bin, wantBin)
				}
			}
			// Seeds must be distinct across the experiment set.
			if prev, dup := seeds[p.Seed]; dup {
				t.Errorf("seed %d reused by %s and %s", p.Seed, prev, file)
			}
			seeds[p.Seed] = file
			if h := Sum(raw); len(h) != 64 {
				t.Errorf("policy sum length = %d, want 64", len(h))
			}
		})
	}
}

func TestCanonicalPolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(".", "darwin-arm64.json"))
	if err != nil {
		t.Fatalf("read canonical policy: %v", err)
	}
	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse canonical policy: %v", err)
	}
	if got := len(p.PrimaryScenarios()); got != 5 {
		t.Fatalf("canonical policy primary scenarios = %d, want 5", got)
	}
	if got := len(p.Scenarios); got != 7 {
		t.Fatalf("canonical policy total scenarios = %d, want 7 (5 primary + 2 experimental)", got)
	}
	byName := make(map[string]Scenario, len(p.Scenarios))
	nonPrimary := 0
	for _, s := range p.Scenarios {
		byName[s.Name] = s
		if !s.Primary {
			nonPrimary++
		}
		if s.Warmup.Duration() != 5*time.Second {
			t.Errorf("scenario %q warmup = %v, want 5s", s.Name, s.Warmup.Duration())
		}
		if s.Duration.Duration() != 30*time.Second {
			t.Errorf("scenario %q duration = %v, want 30s", s.Name, s.Duration.Duration())
		}
		if s.Repetitions != 20 {
			t.Errorf("scenario %q repetitions = %d, want 20", s.Name, s.Repetitions)
		}
	}
	if nonPrimary != 2 {
		t.Fatalf("canonical policy non-primary scenarios = %d, want 2", nonPrimary)
	}
	// The experimental pipelined cells must carry their intended inflight
	// windows and stay off the gate (primary=false).
	experimental := map[string]int{
		"binary-1k-200-inflight8": 8,
		"binary-1k-1k-inflight4":  4,
	}
	for name, wantInflight := range experimental {
		s, ok := byName[name]
		if !ok {
			t.Fatalf("canonical policy missing experimental scenario %q", name)
		}
		if s.Primary {
			t.Errorf("scenario %q primary = true, want false (experimental, not gated)", name)
		}
		if s.Inflight != wantInflight {
			t.Errorf("scenario %q inflight = %d, want %d", name, s.Inflight, wantInflight)
		}
		if s.PayloadBytes != 1024 {
			t.Errorf("scenario %q payload_bytes = %d, want 1024", name, s.PayloadBytes)
		}
	}
	// Sum must be stable and non-empty.
	if h := Sum(raw); len(h) != 64 {
		t.Fatalf("policy sum length = %d, want 64 hex chars", len(h))
	}
}
