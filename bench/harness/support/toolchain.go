package support

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// CompilerGoRoot returns the GOROOT of the toolchain that compiled the running
// binary. Benchmark provenance, evaluator delegation and the evidence contract
// all bind that exact compiler, never a possibly different go launcher found
// through PATH, so runtime.GOROOT's build-time value is the point here.
func CompilerGoRoot() string {
	//lint:ignore SA1019 Exact build-toolchain identity is required by benchmark provenance and evidence.
	return runtime.GOROOT() //nolint:staticcheck // Exact build-toolchain identity is required by benchmark provenance and evidence.
}

// CompilerGoToolPath returns the go command of the toolchain reported by
// [CompilerGoRoot].
func CompilerGoToolPath() string {
	return filepath.Join(CompilerGoRoot(), "bin", "go")
}

// OverrideEnvironment returns base with every entry whose key matches an
// override's key removed, followed by overrides in their given order. A key is
// the text before the first '=', or the whole entry when it has none. base is
// not modified.
func OverrideEnvironment(base, overrides []string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		key, _, _ := strings.Cut(override, "=")
		keys[key] = struct{}{}
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, overridden := keys[key]; overridden {
			continue
		}
		result = append(result, entry)
	}
	return append(result, overrides...)
}

// moduleIdentityPaths are the repository-relative module files whose contents
// make up a run's module_files_sha256.
var moduleIdentityPaths = []string{
	"go.mod", "go.sum", "bench/go.mod", "bench/go.sum", "flatekp/go.mod", "flatekp/go.sum",
}

// ModuleIdentityPaths returns a fresh copy of the repository-relative module
// files hashed into a run's module_files_sha256, so the recording and the
// validating side hash the same set.
func ModuleIdentityPaths() []string {
	return slices.Clone(moduleIdentityPaths)
}
