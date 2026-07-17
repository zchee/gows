package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/zchee/gows/bench/harness/evidence"
	"github.com/zchee/gows/bench/harness/support"
)

func buildCommandSpecs(root, output, work string, inputs evidence.VerificationCommandInputs) []commandSpec {
	baseEnv := controlledEnvironment(runtime.GOOS, runtime.GOARCH, inputs)
	archEnv := func(arch string) []string { return replaceEnvironment(baseEnv, "GOOS=darwin", "GOARCH="+arch) }
	assemblyRoot := filepath.Join(output, "assembly")
	specs := []commandSpec{
		{id: "root-test", argv: []string{inputs.GoTool, "test", "./...", "-count=1"}, workingDirectory: ".", environment: baseEnv},
		{id: "root-vet", argv: []string{inputs.GoTool, "vet", "./..."}, workingDirectory: ".", environment: baseEnv},
		{id: "root-race", argv: []string{inputs.GoTool, "test", "-race", "./...", "-count=1"}, workingDirectory: ".", environment: baseEnv},
		{id: "bench-test", argv: []string{inputs.GoTool, "test", "./...", "-count=1"}, workingDirectory: "bench", environment: baseEnv},
		{id: "bench-vet", argv: []string{inputs.GoTool, "vet", "./..."}, workingDirectory: "bench", environment: baseEnv},
		{id: "flatekp-test", argv: []string{inputs.GoTool, "test", "./...", "-count=1"}, workingDirectory: "flatekp", environment: baseEnv},
		{id: "flatekp-vet", argv: []string{inputs.GoTool, "vet", "./..."}, workingDirectory: "flatekp", environment: baseEnv},
		{id: "build-amd64", argv: []string{inputs.GoTool, "test", "-c", "-o", filepath.Join(work, "gows-amd64.test"), "."}, workingDirectory: ".", environment: archEnv("amd64")},
		{id: "build-arm64", argv: []string{inputs.GoTool, "test", "-c", "-o", filepath.Join(work, "gows-arm64.test"), "."}, workingDirectory: ".", environment: archEnv("arm64")},
	}
	for _, arch := range []string{"amd64", "arm64"} {
		bundle := filepath.Join(assemblyRoot, "darwin-"+arch)
		specs = append(specs, commandSpec{
			id:               "assembly-" + arch,
			argv:             []string{inputs.GoTool, "run", "./harness/cmd/asmprobe", "-repo", root, "-goos", "darwin", "-goarch", arch, "-out", bundle, "-runtime", "required"},
			workingDirectory: "bench", environment: baseEnv,
			assembly: &assemblyOutput{goos: "darwin", goarch: arch, directory: bundle},
		})
	}
	specs = append(
		specs,
		commandSpec{
			id:               "micro-allocations",
			argv:             []string{inputs.GoTool, "test", "-run", evidence.MicroAllocationTestPattern, "-count=1", ".", "./internal/extension", "./internal/httpx", "./internal/pool", "./internal/utf8x"},
			workingDirectory: ".", environment: baseEnv,
		},
		commandSpec{id: "format", argv: append([]string{inputs.Gofmt, "-d"}, inputs.TrackedGoFiles...), workingDirectory: ".", environment: baseEnv, requireEmptyStdout: true},
		commandSpec{id: "static", argv: append([]string{inputs.Gopls, "check"}, inputs.TrackedGoFiles...), workingDirectory: ".", environment: baseEnv},
		commandSpec{id: "diff-check", argv: []string{inputs.Git, "diff", "--check"}, workingDirectory: ".", environment: baseEnv},
	)
	for i := range specs {
		specs[i].argv = slices.Clone(specs[i].argv)
		specs[i].environment = slices.Clone(specs[i].environment)
	}
	return specs
}

func controlledEnvironment(goos, goarch string, inputs evidence.VerificationCommandInputs) []string {
	path := strings.Join([]string{filepath.Dir(inputs.GoTool), "/usr/bin", "/bin", "/usr/sbin", "/sbin"}, string(os.PathListSeparator))
	environment := []string{
		"CGO_ENABLED=0",
		"GOARCH=" + goarch,
		"GOENV=off",
		"GOEXPERIMENT=",
		"GOFIPS140=latest",
		"GOFLAGS=-mod=mod",
		"GOOS=" + goos,
		"GOTELEMETRY=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"HOME=" + inputs.HomeDir,
		"LANG=C",
		"LC_ALL=C",
		"PATH=" + path,
		"TMPDIR=" + inputs.TempDir,
	}
	slices.Sort(environment)
	return environment
}

// replaceEnvironment merges replacements over base and sorts the result so
// recorded spec environments stay deterministic.
func replaceEnvironment(base []string, replacements ...string) []string {
	result := support.MergeEnv(base, replacements...)
	slices.Sort(result)
	return result
}
