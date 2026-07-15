package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zchee/gows/bench/harness/policy"
)

func TestParseLoadavg(t *testing.T) {
	tests := map[string]struct {
		raw     string
		want1   float64
		wantErr bool
	}{
		"darwin braces":   {raw: "{ 1.23 4.56 7.89 }", want1: 1.23},
		"plain triple":    {raw: "0.50 0.60 0.70", want1: 0.50},
		"trailing spaces": {raw: "  2.00 2.10 2.20 \n", want1: 2.00},
		"too few":         {raw: "{ 1.23 }", wantErr: true},
		"non numeric":     {raw: "{ a b c }", wantErr: true},
		"empty":           {raw: "", wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l1, l5, l15, err := parseLoadavg(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got (%v,%v,%v)", l1, l5, l15)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if l1 != tc.want1 {
				t.Fatalf("load1 = %v, want %v", l1, tc.want1)
			}
			if l5 == 0 && l15 == 0 {
				t.Fatalf("load5/load15 not parsed: %v %v", l5, l15)
			}
		})
	}
}

func TestForeignCPUUsageExcludesOwnedProcessTreeAndAggregates(t *testing.T) {
	processes, err := parseProcessUsage("100 1 90.0 owned root\n200 100 80.0 owned child\n201 200 70.0 owned grandchild\n300 1 12.0 foreign one\n301 1 9.0 foreign two\n")
	if err != nil {
		t.Fatal(err)
	}
	owned := ownedProcessTree(processes, map[int]struct{}{100: {}})
	total, offenders := foreignCPUUsage(processes, owned)
	if total != 21 {
		t.Fatalf("foreign CPU = %.1f, want aggregate 21.0", total)
	}
	if len(offenders) != 2 {
		t.Fatalf("foreign offenders = %v, want 2", offenders)
	}
}

func TestOwnedProcessTreeAllowsControllerAncestorsWithoutTrustingSiblings(t *testing.T) {
	processes, err := parseProcessUsage("10 1 1.0 shell\n20 10 2.0 go run benchrun\n30 20 3.0 benchrun\n40 30 4.0 loadgen\n50 20 5.0 unrelated sibling\n")
	if err != nil {
		t.Fatal(err)
	}
	owned := ownedProcessTree(processes, map[int]struct{}{30: {}})
	for _, pid := range []int{10, 20, 30, 40} {
		if _, ok := owned[pid]; !ok {
			t.Errorf("process %d is not in the benchmark process family", pid)
		}
	}
	if _, ok := owned[50]; ok {
		t.Fatal("sibling of the go controller was incorrectly trusted")
	}
	total, _ := foreignCPUUsage(processes, owned)
	if total != 5 {
		t.Fatalf("foreign CPU = %.1f, want sibling-only 5.0", total)
	}
}

func TestProcessPatternRejectsForeignAndAllowsOwned(t *testing.T) {
	processes, err := parseProcessUsage("100 1 90.0 /tmp/benchrun -policy p.json\n200 100 80.0 /tmp/loadgen\n300 1 0.0 /tmp/echoserver\n")
	if err != nil {
		t.Fatal(err)
	}
	owned := ownedProcessTree(processes, map[int]struct{}{100: {}})
	re, err := regexp.Compile(harnessProcessPattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, process := range processes {
		if _, ok := owned[process.PID]; ok && re.MatchString(process.Command) {
			continue
		}
		if process.PID == 300 && !re.MatchString(process.Command) {
			t.Fatalf("foreign echoserver did not match %q", harnessProcessPattern)
		}
	}
}

func TestOwnedPIDsDoesNotTrustParent(t *testing.T) {
	owned := ownedPIDs(1234)
	if _, ok := owned[os.Getpid()]; !ok {
		t.Fatal("benchrun process is not owned")
	}
	if _, ok := owned[1234]; !ok {
		t.Fatal("explicit child is not owned")
	}
	if os.Getppid() != os.Getpid() {
		if _, ok := owned[os.Getppid()]; ok {
			t.Fatal("parent process must remain foreign")
		}
	}
}

func TestValidateContinuousEnvironmentGatesLoadDrift(t *testing.T) {
	cleanThermal := "No thermal warning level has been recorded\nNo performance warning level has been recorded"
	baseline := EnvSnapshot{
		Load1: 2, PMSetBattery: "Now drawing from 'AC Power'", PMSetThermal: cleanThermal,
		LogicalCPUs: 16, MemoryBytes: 64 << 30, BootIdentity: "boot",
	}
	current := baseline
	current.Load1 = 17.9
	if err := validateContinuousEnvironment(baseline, current, 16); err != nil {
		t.Fatalf("load drift inside threshold was rejected: %v", err)
	}
	current.Load1 = 18.1
	err := validateContinuousEnvironment(baseline, current, 16)
	if err == nil || !strings.Contains(err.Error(), "load1 drift") {
		t.Fatalf("load drift outside threshold = %v, want load1 drift error", err)
	}
	if err := validateContinuousEnvironment(baseline, baseline, 0); err == nil {
		t.Fatal("non-positive load drift threshold was accepted")
	}
}

func TestDefaultOutDirSeparatesEvidenceIdentities(t *testing.T) {
	moduleRoot := filepath.Join(t.TempDir(), "repo", "bench")
	pol := &policy.Policy{Series: policy.Series{
		ID: "series", Toolchain: policy.ToolchainStock, EvidenceClass: policy.EvidenceClassClaim,
		HostMode: policy.HostModeSeparate, RunKind: policy.RunKindBaseline,
	}}
	want := filepath.Join(
		filepath.Dir(moduleRoot), ".omx", "bench", "stock", "claim", "separate_host",
		"baseline", "series", "session-deadbeef",
	)
	if got := defaultOutDir(moduleRoot, pol, "session", "deadbeef"); got != want {
		t.Fatalf("defaultOutDir = %q, want %q", got, want)
	}

	diagnostic := *pol
	diagnostic.Series.EvidenceClass = policy.EvidenceClassDiagnostic
	diagnostic.Series.HostMode = policy.HostModeSame
	diagnostic.Series.RunKind = policy.RunKindDiagnostic
	if seriesOutRoot(moduleRoot, &diagnostic) == seriesOutRoot(moduleRoot, pol) {
		t.Fatal("diagnostic/same-host and claim/separate-host roots collided")
	}
}
