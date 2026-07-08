// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cpu

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The kill switch is read once at init from the environment, so it can only be
// exercised by launching a child process with GOWS_SIMD set. When the child
// marker variable is present, the test binary just prints the detected feature
// line and exits, letting the parent assert on it.
const childEnv = "GOWS_CPU_CHILD_REPORT"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		fmt.Printf("NEON=%v AVX2=%v AVX512=%v\n", HasNEON, X86.HasAVX2, X86.HasAVX512)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type features struct {
	neon, avx2, avx512 bool
}

// detectWith runs the test binary in a child process with GOWS_SIMD=simd and
// returns the features it detected.
func detectWith(t *testing.T, simd string) features {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestMain")
	cmd.Env = append(os.Environ(), childEnv+"=1", "GOWS_SIMD="+simd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child (GOWS_SIMD=%q) failed: %v\n%s", simd, err, out)
	}

	var f features
	line := strings.TrimSpace(string(out))
	if _, err := fmt.Sscanf(line, "NEON=%v AVX2=%v AVX512=%v", &f.neon, &f.avx2, &f.avx512); err != nil {
		t.Fatalf("child (GOWS_SIMD=%q) unexpected output %q: %v", simd, line, err)
	}
	return f
}

// TestNativeDetection sanity-checks detection under the ambient environment.
func TestNativeDetection(t *testing.T) {
	t.Logf("GOARCH=%s HasNEON=%v X86.HasAVX2=%v X86.HasAVX512=%v",
		runtime.GOARCH, HasNEON, X86.HasAVX2, X86.HasAVX512)

	switch runtime.GOARCH {
	case "arm64":
		if !HasNEON {
			t.Error("HasNEON = false on arm64; NEON is architecturally mandatory")
		}
	default:
		if HasNEON {
			t.Errorf("HasNEON = true on %s; NEON is only expected on arm64", runtime.GOARCH)
		}
	}

	if runtime.GOARCH != "amd64" && (X86.HasAVX2 || X86.HasAVX512) {
		t.Errorf("x86 features set on non-amd64 %s: %+v", runtime.GOARCH, X86)
	}
}

// TestKillSwitchOff verifies GOWS_SIMD=off disables every SIMD feature,
// independent of architecture.
func TestKillSwitchOff(t *testing.T) {
	f := detectWith(t, "off")
	if f.neon || f.avx2 || f.avx512 {
		t.Errorf("GOWS_SIMD=off did not disable all features: %+v", f)
	}
}

// TestKillSwitchDefault verifies that with the switch unset, NEON is reported
// on arm64 (the mandatory baseline).
func TestKillSwitchDefault(t *testing.T) {
	f := detectWith(t, "")
	if runtime.GOARCH == "arm64" && !f.neon {
		t.Errorf("GOWS_SIMD unset: NEON not reported on arm64: %+v", f)
	}
}

// TestKillSwitchCaps verifies the amd64 max-level caps. It is meaningful only
// on amd64, where SSE2 remains the baseline and the named level bounds AVX use.
func TestKillSwitchCaps(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("cap levels only affect amd64; GOARCH=%s", runtime.GOARCH)
	}

	full := detectWith(t, "avx512")
	t.Logf("baseline (avx512): %+v", full)

	if got := detectWith(t, "sse2"); got.avx2 || got.avx512 {
		t.Errorf("GOWS_SIMD=sse2 must cap below AVX2: %+v", got)
	}
	if got := detectWith(t, "avx2"); got.avx512 {
		t.Errorf("GOWS_SIMD=avx2 must cap below AVX-512: %+v", got)
	}
}
