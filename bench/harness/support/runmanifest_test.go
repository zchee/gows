package support

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestRunManifestGoldenBytes pins manifest.json byte for byte as benchrun
// writes it. The evidence package hashes and strictly decodes these files, so a
// renamed tag or a dropped omitzero changes every sealed run's identity.
func TestRunManifestGoldenBytes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		overrides map[string]string
		golden    string
	}{
		"success: override-free manifest omits override_binaries_sha256": {
			golden: "run-manifest-override-free.golden.json",
		},
		"success: override build records override_binaries_sha256": {
			overrides: map[string]string{"gows-noutf8": "0e01"},
			golden:    "run-manifest-with-overrides.golden.json",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want, err := os.ReadFile(filepath.Join("testdata", tt.golden))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := WriteJSONFile(path, runManifestFixture(tt.overrides)); err != nil {
				t.Fatalf("WriteJSONFile: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(want), string(got)); diff != "" {
				t.Fatalf("manifest.json bytes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func runManifestFixture(overrides map[string]string) RunManifest {
	artifact := func(path string) ProvenanceArtifact {
		return ProvenanceArtifact{Path: path, SHA256: "ab01", SizeBytes: 42}
	}
	return RunManifest{
		SchemaVersion: 1, SessionID: "session-1", GitCommit: "c0ffee", GitDirty: true,
		GitRemote: "origin-url", GitBranch: "main", GitStatus: " M a.go", GitTree: "7ree",
		SourceSHA256: "50fc", ModulePath: "github.com/zchee/gows/bench", ModuleFilesSHA256: "m0d",
		GoVersion: "go version go1.26 darwin/arm64", GoBinaryPath: "/goroot/bin/go", GoBinarySHA256: "60b1",
		GoBinarySizeBytes: 1024, HarnessRuntimeVersion: "go1.26", GOOS: "darwin", GOARCH: "arm64",
		GoEnv: artifact("provenance/go-env.json"), ModuleGraph: artifact("provenance/modules.jsonl"),
		BinaryProvenance: map[string]BinaryProvenance{
			"loadgen":    {Path: "bin/loadgen", SHA256: "10ad", SizeBytes: 7, GoVersionM: artifact("provenance/binaries/loadgen.version-m.txt")},
			"echoserver": {Path: "bin/echoserver", SHA256: "ec40", SizeBytes: 8, GoVersionM: artifact("provenance/binaries/echoserver.version-m.txt")},
		},
		OSVersion: artifact("provenance/os-version.txt"), SystemProfile: artifact("provenance/system-profile.txt"),
		Limits: artifact("provenance/limits.txt"), Hostname: "host", Kernel: "kernel",
		BootIdentityStart: "boot-a", BootIdentityEnd: "boot-a", Client: "gows",
		EchoserverSHA256: "ec40", LoadgenSHA256: "10ad", OverrideBinariesSHA256: overrides,
		PolicySHA256: "9011", AdapterSHA256: map[string]string{"quickws": "q1", "gows": "g1"},
		LibraryBinariesSHA256: map[string]string{"quickws": "ec40", "gows": "ec40"},
		RunKind:               "comparative", EvidenceClass: "screen", ToolchainSeries: "stock", GoExperiment: "",
		ToolchainEnvironment: ToolchainEnvironment{
			GOENV: "off", GOTOOLCHAIN: "local", GOFLAGS: "-mod=mod", GOEXPERIMENT: "", GOOS: "darwin",
			GOARCH: "arm64", GOAMD64: "", GOARM64: "v8.0", GOFIPS140: "latest", CGOEnabled: "0",
		},
		RuntimeEnvironment: RuntimeEnvironment{GOMAXPROCS: "8", GOGC: "100", GOMEMLIMIT: "off", GODEBUG: "", GOWSSIMD: ""},
		Seed:               99, Smoke: false, StartedAt: "2026-07-15T00:00:00Z", EndedAt: "2026-07-15T00:45:00Z",
	}
}
