package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/google/go-cmp/cmp"
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
		SchemaVersion: PolicySchemaVersion,
		Series: Series{
			ID:                "phase0-baseline-best-api-gows-client",
			RunKind:           RunKindBaseline,
			EvidenceClass:     EvidenceClassBaseline,
			HostMode:          HostModeSame,
			Toolchain:         ToolchainStock,
			AdapterClass:      AdapterClassBestAPI,
			ValidationProfile: ValidationStrict,
			Client:            ClientGoWS,
		},
		Candidate:  "gows",
		Comparator: "quickws",
		Seed:       12648430,
		Bootstrap:  Bootstrap{Replicates: 2000, Confidence: 0.95, NullIterations: 1000},
		AAGates: AAGates{
			MinSessions:        3,
			MinPairsPerSession: 20,
			Throughput:         RatioBand{Lower: 0.98, Upper: 1.02},
			P99:                RatioBand{Lower: 0.98, Upper: 1.02},
			P999:               RatioBand{Lower: 0.95, Upper: 1.05},
			OrderEffect:        RatioBand{Lower: 0.99, Upper: 1.01},
			MaxFalsePositive:   0.05,
		},
		Thresholds: Thresholds{
			ThroughputLowerBound: 1.0,
			ThroughputGeomean:    1.05,
			P99UpperBound:        1.01,
			P999CenterUpperBound: 1.05,
		},
		Guard: Guard{MaxLoad1: 6.0, MaxLoad1Drift: 16.0, MaxForeignCPUPercent: 20.0, ForbiddenProcessPatterns: []string{"echoserver", "loadgen"}},
		Scenarios: []Scenario{
			{
				Name:         "binary-1k-200",
				Primary:      true,
				CellClass:    CellServerSensitive,
				MessageType:  MessageBinary,
				Arrival:      ArrivalClosedLoop,
				PayloadBytes: 1024,
				Connections:  200,
				Inflight:     1,
				Warmup:       Duration(5 * time.Second),
				Duration:     Duration(30 * time.Second),
				Repetitions:  20,
			},
		},
		Adapters: map[string]Adapter{
			"gows": {
				ID:          "gows-serve-best-api-v1",
				Class:       AdapterClassBestAPI,
				SourceFiles: []string{"harness/cmd/echoserver/server_gows.go"},
			},
			"quickws": {
				ID:          "quickws-callback-best-api-v1",
				Class:       AdapterClassBestAPI,
				SourceFiles: []string{"harness/cmd/echoserver/server_quickws.go"},
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
	if !cmp.Equal(*got, want) {
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
		"wrong schema":       {mutate: func(p *Policy) { p.SchemaVersion = 1 }, wantErr: true},
		"empty series id":    {mutate: func(p *Policy) { p.Series.ID = "" }, wantErr: true},
		"unknown run kind":   {mutate: func(p *Policy) { p.Series.RunKind = "future" }, wantErr: true},
		"unknown evidence":   {mutate: func(p *Policy) { p.Series.EvidenceClass = "future" }, wantErr: true},
		"unknown host mode":  {mutate: func(p *Policy) { p.Series.HostMode = "future" }, wantErr: true},
		"unknown toolchain":  {mutate: func(p *Policy) { p.Series.Toolchain = "future" }, wantErr: true},
		"unknown adapter":    {mutate: func(p *Policy) { p.Series.AdapterClass = "future" }, wantErr: true},
		"unknown validation": {mutate: func(p *Policy) { p.Series.ValidationProfile = "future" }, wantErr: true},
		"unknown client":     {mutate: func(p *Policy) { p.Series.Client = "future" }, wantErr: true},
		"claim same host": {
			mutate: func(p *Policy) {
				p.Series.EvidenceClass = EvidenceClassClaim
				p.Series.HostMode = HostModeSame
			},
			wantErr: true,
		},
		"baseline separate host": {
			mutate:  func(p *Policy) { p.Series.HostMode = HostModeSeparate },
			wantErr: true,
		},
		"empty candidate":    {mutate: func(p *Policy) { p.Candidate = "" }, wantErr: true},
		"empty comparator":   {mutate: func(p *Policy) { p.Comparator = "" }, wantErr: true},
		"same libs":          {mutate: func(p *Policy) { p.Comparator = p.Candidate }, wantErr: true},
		"zero replicates":    {mutate: func(p *Policy) { p.Bootstrap.Replicates = 0 }, wantErr: true},
		"confidence too big": {mutate: func(p *Policy) { p.Bootstrap.Confidence = 1 }, wantErr: true},
		"confidence zero":    {mutate: func(p *Policy) { p.Bootstrap.Confidence = 0 }, wantErr: true},
		"no scenarios":       {mutate: func(p *Policy) { p.Scenarios = nil }, wantErr: true},
		"scenario no name":   {mutate: func(p *Policy) { p.Scenarios[0].Name = "" }, wantErr: true},
		"scenario no class":  {mutate: func(p *Policy) { p.Scenarios[0].CellClass = "" }, wantErr: true},
		"scenario no message type": {
			mutate: func(p *Policy) { p.Scenarios[0].MessageType = "" }, wantErr: true,
		},
		"scenario invalid arrival": {
			mutate: func(p *Policy) { p.Scenarios[0].Arrival = "ticker" }, wantErr: true,
		},
		"open loop missing rate": {
			mutate: func(p *Policy) { p.Scenarios[0].Arrival = ArrivalOpenLoop }, wantErr: true,
		},
		"open loop with rate": {
			mutate: func(p *Policy) {
				p.Scenarios[0].Arrival = ArrivalOpenLoop
				p.Scenarios[0].OfferedRate = 10_000
				p.Scenarios[0].MaxSchedulerLateness = Duration(50 * time.Microsecond)
			},
		},
		"open loop missing lateness limit": {
			mutate: func(p *Policy) {
				p.Scenarios[0].Arrival = ArrivalOpenLoop
				p.Scenarios[0].OfferedRate = 10_000
			},
			wantErr: true,
		},
		"open loop lateness exceeds interval": {
			mutate: func(p *Policy) {
				p.Scenarios[0].Arrival = ArrivalOpenLoop
				p.Scenarios[0].OfferedRate = 10_000
				p.Scenarios[0].MaxSchedulerLateness = Duration(time.Millisecond)
			},
			wantErr: true,
		},
		"closed loop with rate": {
			mutate: func(p *Policy) { p.Scenarios[0].OfferedRate = 10_000 }, wantErr: true,
		},
		"closed loop with scheduler lateness": {
			mutate: func(p *Policy) { p.Scenarios[0].MaxSchedulerLateness = Duration(time.Microsecond) }, wantErr: true,
		},
		"zero payload":  {mutate: func(p *Policy) { p.Scenarios[0].PayloadBytes = 0 }, wantErr: true},
		"zero conns":    {mutate: func(p *Policy) { p.Scenarios[0].Connections = 0 }, wantErr: true},
		"zero reps":     {mutate: func(p *Policy) { p.Scenarios[0].Repetitions = 0 }, wantErr: true},
		"zero duration": {mutate: func(p *Policy) { p.Scenarios[0].Duration = 0 }, wantErr: true},
		"baseline short warmup": {
			mutate: func(p *Policy) { p.Scenarios[0].Warmup = Duration(time.Second) }, wantErr: true,
		},
		"baseline short duration": {
			mutate: func(p *Policy) { p.Scenarios[0].Duration = Duration(5 * time.Second) }, wantErr: true,
		},
		"baseline too few repetitions": {
			mutate: func(p *Policy) { p.Scenarios[0].Repetitions = 19 }, wantErr: true,
		},
		"no primary":        {mutate: func(p *Policy) { p.Scenarios[0].Primary = false }, wantErr: true},
		"zero inflight":     {mutate: func(p *Policy) { p.Scenarios[0].Inflight = 0 }, wantErr: true},
		"negative inflight": {mutate: func(p *Policy) { p.Scenarios[0].Inflight = -1 }, wantErr: true},
		"inflight one ok":   {mutate: func(p *Policy) { p.Scenarios[0].Inflight = 1 }, wantErr: false},
		"pipelined arrival with inflight one": {
			mutate: func(p *Policy) { p.Scenarios[0].Arrival = ArrivalPipelined }, wantErr: true,
		},
		"pipelined arrival with window": {
			mutate: func(p *Policy) {
				p.Scenarios[0].Arrival = ArrivalPipelined
				p.Scenarios[0].Inflight = 4
			},
		},
		"inflight payload too big": {mutate: func(p *Policy) {
			p.Scenarios[0].Inflight = 2048
			p.Scenarios[0].PayloadBytes = 1024 // 2048*1024 = 2 MiB > 1 MiB cap
		}, wantErr: true},
		"inflight payload multiplication cannot overflow": {mutate: func(p *Policy) {
			p.Scenarios[0].Arrival = ArrivalPipelined
			p.Scenarios[0].Inflight = int(^uint(0) >> 1)
			p.Scenarios[0].PayloadBytes = int(^uint(0) >> 1)
		}, wantErr: true},
		"inflight payload at cap": {mutate: func(p *Policy) {
			p.Scenarios[0].Inflight = 8
			p.Scenarios[0].Arrival = ArrivalPipelined
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

func TestValidateAAPolicy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*Policy)
		wantErr bool
	}{
		"success: distinct labels resolve to one binary and adapter": {
			mutate: func(*Policy) {},
		},
		"error: fewer than twenty pairs": {
			mutate:  func(p *Policy) { p.Scenarios[0].Repetitions = 18 },
			wantErr: true,
		},
		"error: odd pairs cannot balance AB and BA": {
			mutate:  func(p *Policy) { p.Scenarios[0].Repetitions = 21 },
			wantErr: true,
		},
		"error: labels resolve to different server backends": {
			mutate:  func(p *Policy) { p.LibraryOverrides[p.Comparator] = LibraryOverride{Lib: "quickws"} },
			wantErr: true,
		},
		"error: labels use different adapters": {
			mutate: func(p *Policy) {
				adapter := p.Adapters[p.Comparator]
				adapter.ID = "different"
				p.Adapters[p.Comparator] = adapter
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := validPolicy()
			p.Series = Series{
				ID:                "phase0-aa",
				RunKind:           RunKindAA,
				EvidenceClass:     EvidenceClassSelfValidation,
				HostMode:          HostModeSame,
				Toolchain:         ToolchainStock,
				AdapterClass:      AdapterClassAA,
				ValidationProfile: ValidationStrict,
				Client:            ClientGoWS,
			}
			p.Candidate = "gows-aa-a"
			p.Comparator = "gows-aa-b"
			p.LibraryOverrides = map[string]LibraryOverride{
				p.Candidate:  {Lib: "gows-serve"},
				p.Comparator: {Lib: "gows-serve"},
			}
			adapter := Adapter{
				ID:          "gows-serve-aa-v1",
				Class:       AdapterClassAA,
				SourceFiles: []string{"harness/cmd/echoserver/server_gows.go"},
			}
			p.Adapters = map[string]Adapter{p.Candidate: adapter, p.Comparator: adapter}
			tt.mutate(&p)

			err := p.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate: nil error, want non-nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate: %v", err)
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
		"gows-custom": {
			Lib:      "gows",
			BuildEnv: []string{"CUSTOM_BUILD_FLAG=enabled"},
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
		"non-toolchain build env forces dedicated binary": {
			overrides: overrides,
			name:      "gows-custom",
			want: Resolved{
				Name:     "gows-custom",
				Lib:      "gows",
				Bin:      "gows-custom",
				BuildEnv: []string{"CUSTOM_BUILD_FLAG=enabled"},
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
			if !cmp.Equal(got, tc.want) {
				t.Fatalf("Resolve(%q) =\n %+v\nwant\n %+v", tc.name, got, tc.want)
			}
		})
	}
}

func TestPolicyRoundTripWithOverrides(t *testing.T) {
	want := validPolicy()
	want.Series.RunKind = RunKindDiagnostic
	want.Series.EvidenceClass = EvidenceClassDiagnostic
	want.Series.Toolchain = ToolchainCustom
	want.Series.GoExperiment = "nogreenteagc"
	want.Candidate = "gows-nogtgc"
	want.Comparator = "gows-lowat"
	want.LibraryOverrides = map[string]LibraryOverride{
		"gows-nogtgc": {
			Lib:      "gows",
			BuildEnv: []string{"CUSTOM_BUILD_FLAG=enabled"},
		},
		"gows-lowat": {
			Lib:        "gows",
			ServerArgs: []string{"-notsent-lowat", "16384"},
		},
	}
	adapter := want.Adapters["gows"]
	want.Adapters = map[string]Adapter{}
	adapter.ID = "gows-nogtgc-best-api-v1"
	want.Adapters[want.Candidate] = adapter
	adapter.ID = "gows-lowat-best-api-v1"
	want.Adapters[want.Comparator] = adapter
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cmp.Equal(*got, want) {
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
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", ServerArgs: []string{"-notsent-lowat", "16384"}}},
		},
		"valid build env": {
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", BuildEnv: []string{"CUSTOM_BUILD_FLAG=enabled"}}},
		},
		"build env missing equals": {
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", BuildEnv: []string{"GOEXPERIMENT"}}},
			wantErr:   true,
		},
		"build env empty key": {
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", BuildEnv: []string{"=value"}}},
			wantErr:   true,
		},
		"build env duplicate key": {
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", BuildEnv: []string{"CUSTOM=x", "CUSTOM=y"}}},
			wantErr:   true,
		},
		"GOEXPERIMENT override is rejected": {
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", BuildEnv: []string{"GOEXPERIMENT=nogreenteagc"}}},
			wantErr:   true,
		},
		"GOENV override is rejected": {
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", BuildEnv: []string{"GOENV=off"}}},
			wantErr:   true,
		},
		"unused override is rejected": {
			overrides: map[string]LibraryOverride{"x": {Lib: "gows"}},
			wantErr:   true,
		},
		"empty server argument": {
			overrides: map[string]LibraryOverride{"gows": {Lib: "gows", ServerArgs: []string{""}}},
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
			p.Series.RunKind = RunKindDiagnostic
			p.Series.EvidenceClass = EvidenceClassDiagnostic
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

func TestFinalPolicyRejectsBuildAndArgumentOverrides(t *testing.T) {
	t.Parallel()
	tests := map[string]LibraryOverride{
		"build environment": {Lib: "gows", BuildEnv: []string{"CUSTOM=enabled"}},
		"server argument":   {Lib: "gows", ServerArgs: []string{"-notsent-lowat", "16384"}},
	}
	for name, override := range tests {
		t.Run(name, func(t *testing.T) {
			p := validPolicy()
			p.LibraryOverrides = map[string]LibraryOverride{p.Candidate: override}
			if err := p.Validate(); err == nil {
				t.Fatal("final policy accepted broad override")
			}
		})
	}
}

func TestParseRejectsUnknownPolicyField(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(validPolicy())
	if err != nil {
		t.Fatal(err)
	}
	raw = append([]byte(`{"unknown":true,`), raw[1:]...)
	if _, err := Parse(raw); err == nil {
		t.Fatal("Parse accepted an unknown top-level field")
	}
}

func TestExperimentPolicies(t *testing.T) {
	// Every experiment isolates one variable in the binary-1k-1k causal cell,
	// so all five share the same measurement geometry and differ only in
	// candidate/comparator and any library override.
	type want struct {
		candidate    string
		comparator   string
		overrideOf   string   // library_overrides key expected (empty = none).
		lib          string   // override's real echoserver -lib (when overrideOf set).
		serverArgs   []string // override's server_args (nil when none).
		buildEnv     []string // override's build_env (nil when none).
		goExperiment string
	}
	tests := map[string]want{
		"h1-rbuf1k.json":        {candidate: "gows-rbuf1k", comparator: "gows"},
		"h1-rbuf16k.json":       {candidate: "gows-rbuf16k", comparator: "gows"},
		"h5-lowat-gows.json":    {candidate: "gows-lowat", comparator: "gows", overrideOf: "gows-lowat", lib: "gows", serverArgs: []string{"-notsent-lowat", "16384"}},
		"h5-lowat-quickws.json": {candidate: "quickws-lowat", comparator: "quickws", overrideOf: "quickws-lowat", lib: "quickws", serverArgs: []string{"-notsent-lowat", "16384"}},
		"h2-nogreentea.json":    {candidate: "gows-nogtgc", comparator: "gows", overrideOf: "gows-nogtgc", lib: "gows", goExperiment: "nogreenteagc"},
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
			if p.SchemaVersion != PolicySchemaVersion || p.Series.RunKind != RunKindDiagnostic {
				t.Errorf("schema/run kind = %d/%q, want %d/%q", p.SchemaVersion, p.Series.RunKind, PolicySchemaVersion, RunKindDiagnostic)
			}
			if s.PayloadBytes != 1024 || s.Connections != 1000 || s.Inflight != 1 {
				t.Errorf("cell = %dB x %d conns inflight %d, want 1024B x 1000 x 1", s.PayloadBytes, s.Connections, s.Inflight)
			}
			if s.Warmup.Duration() != 5*time.Second || s.Duration.Duration() != 30*time.Second || s.Repetitions != 20 {
				t.Errorf("windows = warmup %v duration %v reps %d, want 5s/30s/20", s.Warmup.Duration(), s.Duration.Duration(), s.Repetitions)
			}
			if p.Series.GoExperiment != w.goExperiment {
				t.Errorf("series go_experiment = %q, want %q", p.Series.GoExperiment, w.goExperiment)
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
				if !cmp.Equal(ov.ServerArgs, w.serverArgs) {
					t.Errorf("override server_args = %v, want %v", ov.ServerArgs, w.serverArgs)
				}
				if !cmp.Equal(ov.BuildEnv, w.buildEnv) {
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
	if got := len(p.PrimaryScenarios()); got != 7 {
		t.Fatalf("canonical policy primary scenarios = %d, want 7", got)
	}
	if p.SchemaVersion != PolicySchemaVersion {
		t.Fatalf("canonical policy schema = %d, want %d", p.SchemaVersion, PolicySchemaVersion)
	}
	if p.Series.RunKind != RunKindBaseline || p.Series.EvidenceClass != EvidenceClassBaseline {
		t.Fatalf("canonical series = %+v, want baseline evidence", p.Series)
	}
	if got := len(p.Scenarios); got != 7 {
		t.Fatalf("canonical policy total scenarios = %d, want 7 (all primary since the Phase D pre-registration)", got)
	}
	byName := make(map[string]Scenario, len(p.Scenarios))
	for _, s := range p.Scenarios {
		byName[s.Name] = s
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
	// The pipelined cells must carry their intended inflight windows and,
	// per the 2026-07-14 Phase D pre-registration, gate as primary cells.
	experimental := map[string]int{
		"binary-1k-200-inflight8": 8,
		"binary-1k-1k-inflight4":  4,
	}
	for name, wantInflight := range experimental {
		s, ok := byName[name]
		if !ok {
			t.Fatalf("canonical policy missing experimental scenario %q", name)
		}
		if !s.Primary {
			t.Errorf("scenario %q primary = false, want true (pre-registered gating cell)", name)
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

func TestPhase0Policies(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		runKind       RunKind
		adapter       AdapterClass
		client        ClientKind
		wantScenarios int
	}{
		"darwin-arm64-aa.json":                 {runKind: RunKindAA, adapter: AdapterClassAA, client: ClientGoWS, wantScenarios: 2},
		"darwin-arm64-semantic-parity.json":    {runKind: RunKindBaseline, adapter: AdapterClassSemanticParity, client: ClientGoWS, wantScenarios: 1},
		"darwin-arm64-independent-gobwas.json": {runKind: RunKindBaseline, adapter: AdapterClassBestAPI, client: ClientGobwas, wantScenarios: 1},
		"darwin-arm64-independent-raw.json":    {runKind: RunKindBaseline, adapter: AdapterClassBestAPI, client: ClientRaw, wantScenarios: 1},
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p, _, err := Load(filepath.Join("phase0", name))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if p.Series.RunKind != want.runKind || p.Series.AdapterClass != want.adapter || p.Series.Client != want.client {
				t.Fatalf("series = %+v, want run=%s adapter=%s client=%s", p.Series, want.runKind, want.adapter, want.client)
			}
			if p.Series.Toolchain != ToolchainStock || p.Series.GoExperiment != "" || p.Series.ValidationProfile != ValidationStrict {
				t.Fatalf("Phase 0 evidence is not stock strict: %+v", p.Series)
			}
			if len(p.Scenarios) != want.wantScenarios {
				t.Fatalf("scenarios = %d, want %d", len(p.Scenarios), want.wantScenarios)
			}
			for _, scenario := range p.Scenarios {
				if scenario.Warmup.Duration() < 5*time.Second || scenario.Duration.Duration() < 30*time.Second || scenario.Repetitions < 20 {
					t.Fatalf("scenario %q is below final window: warmup=%s duration=%s reps=%d", scenario.Name, scenario.Warmup.Duration(), scenario.Duration.Duration(), scenario.Repetitions)
				}
			}
		})
	}
}

func TestPhase0AAPolicyCoversFullClaimCellClasses(t *testing.T) {
	t.Parallel()
	p, _, err := Load(filepath.Join("phase0", "darwin-arm64-aa.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[CellClass]bool{
		CellSaturated:       false,
		CellServerSensitive: false,
	}
	for _, scenario := range p.PrimaryScenarios() {
		if _, required := want[scenario.CellClass]; required {
			want[scenario.CellClass] = true
		}
	}
	for class, present := range want {
		if !present {
			t.Errorf("A/A policy has no primary %s scenario", class)
		}
	}
}
