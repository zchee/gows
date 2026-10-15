package support

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCompilerGoToolPathIsTheCompilerRootGoCommand(t *testing.T) {
	t.Parallel()

	root := CompilerGoRoot()
	if !filepath.IsAbs(root) {
		t.Fatalf("CompilerGoRoot() = %q, want an absolute path", root)
	}
	tool := CompilerGoToolPath()
	if want := filepath.Join(root, "bin", "go"); tool != want {
		t.Fatalf("CompilerGoToolPath() = %q, want %q", tool, want)
	}
	info, err := os.Stat(tool)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("compiler go command %q is not a regular file: info=%v err=%v", tool, info, err)
	}
}

func TestOverrideEnvironment(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		base      []string
		overrides []string
		want      []string
	}{
		"success: overridden keys are removed and overrides appended in order": {
			base:      []string{"PATH=/bin", "GOFLAGS=-race", "HOME=/home/u", "GOENV=/tmp/env"},
			overrides: []string{"GOENV=off", "GOFLAGS=-mod=mod"},
			want:      []string{"PATH=/bin", "HOME=/home/u", "GOENV=off", "GOFLAGS=-mod=mod"},
		},
		"success: empty override value clears an inherited value": {
			base:      []string{"GOEXPERIMENT=greenteagc", "PATH=/bin"},
			overrides: []string{"GOEXPERIMENT="},
			want:      []string{"PATH=/bin", "GOEXPERIMENT="},
		},
		"success: every duplicate of an overridden key is removed": {
			base:      []string{"GOGC=50", "PATH=/bin", "GOGC=off"},
			overrides: []string{"GOGC=100"},
			want:      []string{"PATH=/bin", "GOGC=100"},
		},
		"success: key match is exact, not a prefix": {
			base:      []string{"GOOS_EXTRA=1", "GOOSX=2"},
			overrides: []string{"GOOS=linux"},
			want:      []string{"GOOS_EXTRA=1", "GOOSX=2", "GOOS=linux"},
		},
		"success: value containing '=' keeps its key": {
			base:      []string{"GOFLAGS=-ldflags=-s", "PATH=/bin"},
			overrides: []string{"GOFLAGS=-tags=x"},
			want:      []string{"PATH=/bin", "GOFLAGS=-tags=x"},
		},
		"edge: base entry without '=' is keyed by its whole text": {
			base:      []string{"GOENV", "PATH=/bin", "STRAY"},
			overrides: []string{"GOENV=off"},
			want:      []string{"PATH=/bin", "STRAY", "GOENV=off"},
		},
		"edge: override without '=' is keyed by its whole text": {
			base:      []string{"MARKER=1", "PATH=/bin"},
			overrides: []string{"MARKER"},
			want:      []string{"PATH=/bin", "MARKER"},
		},
		"success: no overrides returns base unchanged": {
			base: []string{"PATH=/bin"},
			want: []string{"PATH=/bin"},
		},
		"success: nil base returns only overrides": {
			overrides: []string{"GOENV=off"},
			want:      []string{"GOENV=off"},
		},
		"success: evidence go invocation set": {
			base:      []string{"GOENV=/x", "GOTOOLCHAIN=auto", "GOEXPERIMENT=a", "LANG=en_US.UTF-8", "PATH=/bin"},
			overrides: []string{"GOENV=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=", "LANG=C", "LC_ALL=C"},
			want:      []string{"PATH=/bin", "GOENV=off", "GOTOOLCHAIN=local", "GOEXPERIMENT=", "LANG=C", "LC_ALL=C"},
		},
		"success: benchrun toolchain and runtime set": {
			base: []string{"GOMAXPROCS=1", "PATH=/bin", "GOARM64=v9.0", "GOWS_SIMD=off"},
			overrides: slices.Concat(
				ToolchainEnvironment{GOENV: "off", GOTOOLCHAIN: "local", GOFLAGS: "-mod=mod", GOOS: "darwin", GOARCH: "arm64", GOARM64: "v8.0", GOFIPS140: "latest", CGOEnabled: "0"}.Assignments(),
				RuntimeEnvironment{GOMAXPROCS: "8", GOGC: "100", GOMEMLIMIT: "off"}.Assignments(),
			),
			want: []string{
				"PATH=/bin",
				"GOENV=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod", "GOEXPERIMENT=", "GOOS=darwin", "GOARCH=arm64",
				"GOAMD64=", "GOARM64=v8.0", "GOFIPS140=latest", "CGO_ENABLED=0",
				"GOMAXPROCS=8", "GOGC=100", "GOMEMLIMIT=off", "GODEBUG=", "GOWS_SIMD=",
			},
		},
		"success: doccheck controlled set": {
			base:      []string{"CGO_ENABLED=1", "GOFLAGS=-race", "PATH=/bin"},
			overrides: []string{"CGO_ENABLED=0", "GOENV=off", "GOEXPERIMENT=", "GOFIPS140=latest", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local"},
			want:      []string{"PATH=/bin", "CGO_ENABLED=0", "GOENV=off", "GOEXPERIMENT=", "GOFIPS140=latest", "GOFLAGS=-mod=mod", "GOTOOLCHAIN=local"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			base := slices.Clone(tt.base)
			got := OverrideEnvironment(base, tt.overrides)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("OverrideEnvironment(%q, %q) mismatch (-want +got):\n%s", tt.base, tt.overrides, diff)
			}
			if diff := cmp.Diff(tt.base, base); diff != "" {
				t.Fatalf("OverrideEnvironment modified base (-before +after):\n%s", diff)
			}
		})
	}
}

func TestModuleIdentityPathsReturnsIndependentCopies(t *testing.T) {
	t.Parallel()

	want := []string{"go.mod", "go.sum", "bench/go.mod", "bench/go.sum", "flatekp/go.mod", "flatekp/go.sum"}
	first := ModuleIdentityPaths()
	if diff := cmp.Diff(want, first); diff != "" {
		t.Fatalf("ModuleIdentityPaths() mismatch (-want +got):\n%s", diff)
	}
	first[0] = "mutated"
	slices.Sort(first)
	if diff := cmp.Diff(want, ModuleIdentityPaths()); diff != "" {
		t.Fatalf("mutating a returned slice changed later results (-want +got):\n%s", diff)
	}
}
