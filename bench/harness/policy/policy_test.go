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
