// Package doccheck generates and verifies the benchmark metadata tables in
// bench/README.md from the live module graph and the validated Phase 0 policy
// files. Keeping the generator in the benchmark module prevents documentation
// drift without adding dependencies to the production gows module.
package doccheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

const (
	moduleSection = "module-metadata"
	policySection = "phase0-policy-metadata"
)

type moduleRecord struct {
	Path    string
	Version string
}

type serverModule struct {
	flag        string
	path        string
	integration func(map[string]string) (string, error)
}

var serverModules = []serverModule{
	{flag: "latency histogram", path: "github.com/HdrHistogram/hdrhistogram-go", integration: literal("mergeable HDR observations (MIT)")},
	{flag: "gorilla", path: "github.com/gorilla/websocket", integration: literal("`net/http` upgrader")},
	{flag: "coder", path: "github.com/coder/websocket", integration: literal("`Accept` / `Read` / `Write`")},
	{flag: "gobwas", path: "github.com/gobwas/ws", integration: literal("raw `net.Conn` upgrade")},
	{flag: "gws", path: "github.com/lxzan/gws", integration: literal("callback server API")},
	{flag: "quickws", path: "github.com/antlabs/quickws", integration: literal("callback API over `net/http` hijack")},
	{
		flag: "fasthttp", path: "github.com/fasthttp/websocket",
		integration: func(versions map[string]string) (string, error) {
			version, ok := versions["github.com/valyala/fasthttp"]
			if !ok || version == "" {
				return "", errors.New("doccheck: module graph lacks github.com/valyala/fasthttp")
			}
			return fmt.Sprintf("`fasthttp` upgrader (`fasthttp %s`)", version), nil
		},
	},
	{flag: "nbio", path: "github.com/lesismal/nbio", integration: literal("`nbhttp` reactor engine")},
	{flag: "gows` / `gows-serve", path: "github.com/zchee/gows", integration: literal("raw upgrade / drain-and-coalesce server")},
}

type policyRow struct {
	role       string
	path       string
	windowUnit string
}

var phase0Policies = []policyRow{
	{role: "A/A sessions 1-3", path: "harness/policy/phase0/darwin-arm64-aa.json", windowUnit: "session"},
	{role: "Best API baseline", path: "harness/policy/darwin-arm64.json", windowUnit: "cell"},
	{role: "Semantic parity", path: "harness/policy/phase0/darwin-arm64-semantic-parity.json"},
	{role: "Independent client", path: "harness/policy/phase0/darwin-arm64-independent-gobwas.json"},
	{role: "Independent raw client", path: "harness/policy/phase0/darwin-arm64-independent-raw.json"},
}

func literal(value string) func(map[string]string) (string, error) {
	return func(map[string]string) (string, error) { return value, nil }
}

// Generate returns the complete generated README sections for benchRoot.
func Generate(benchRoot string) (map[string]string, error) {
	benchRoot, err := filepath.Abs(benchRoot)
	if err != nil {
		return nil, fmt.Errorf("doccheck: absolute bench root: %w", err)
	}
	versions, err := moduleVersions(benchRoot)
	if err != nil {
		return nil, err
	}
	modules, err := generateModuleTable(versions)
	if err != nil {
		return nil, err
	}
	policies, err := generatePolicyTable(benchRoot)
	if err != nil {
		return nil, err
	}
	return map[string]string{moduleSection: modules, policySection: policies}, nil
}

// CheckREADME fails when a generated section is missing or differs byte for
// byte from the live module and policy metadata.
func CheckREADME(benchRoot, readmePath string) error {
	sections, err := Generate(benchRoot)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(readmePath)
	if err != nil {
		return fmt.Errorf("doccheck: read README: %w", err)
	}
	for _, name := range []string{moduleSection, policySection} {
		got, err := section(raw, name)
		if err != nil {
			return err
		}
		if got != sections[name] {
			return fmt.Errorf("doccheck: generated README section %q is stale; run benchdoc -write", name)
		}
	}
	return nil
}

// WriteREADME atomically replaces only the generated sections. All prose
// outside the markers remains author-owned.
func WriteREADME(benchRoot, readmePath string) error {
	sections, err := Generate(benchRoot)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(readmePath)
	if err != nil {
		return fmt.Errorf("doccheck: read README: %w", err)
	}
	updated := raw
	for _, name := range []string{moduleSection, policySection} {
		updated, err = replaceSection(updated, name, sections[name])
		if err != nil {
			return err
		}
	}
	if bytes.Equal(raw, updated) {
		return nil
	}
	return support.WriteFileAtomic(readmePath, updated, 0o644)
}

func moduleVersions(benchRoot string) (map[string]string, error) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("doccheck: resolve go executable: %w", err)
	}
	command := exec.Command(goTool, "list", "-m", "-json", "all")
	command.Dir = benchRoot
	command.Env = controlledEnvironment(os.Environ())
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("doccheck: module graph stdout: %w", err)
	}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("doccheck: start module graph: %w", err)
	}
	versions := make(map[string]string)
	decoder := json.NewDecoder(stdout)
	for {
		var module moduleRecord
		err := decoder.Decode(&module)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, fmt.Errorf("doccheck: decode module graph: %w", err)
		}
		if module.Path == "" {
			_ = command.Process.Kill()
			_ = command.Wait()
			return nil, errors.New("doccheck: module graph contains an empty path")
		}
		versions[module.Path] = module.Version
	}
	if err := command.Wait(); err != nil {
		return nil, fmt.Errorf("doccheck: go list -m: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return versions, nil
}

func generateModuleTable(versions map[string]string) (string, error) {
	var output strings.Builder
	output.WriteString("| Harness role | Module | Version | Integration |\n")
	output.WriteString("| --- | --- | ---: | --- |\n")
	for _, server := range serverModules {
		version, ok := versions[server.path]
		if !ok {
			return "", fmt.Errorf("doccheck: module graph lacks %s", server.path)
		}
		if server.path == "github.com/zchee/gows" {
			version = "working tree"
		} else if version == "" {
			return "", fmt.Errorf("doccheck: module %s has no version", server.path)
		}
		integration, err := server.integration(versions)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&output, "| `%s` | `%s` | `%s` | %s |\n", server.flag, server.path, version, integration)
	}
	return output.String(), nil
}

func generatePolicyTable(benchRoot string) (string, error) {
	var output strings.Builder
	output.WriteString("| Evidence role | Policy | Client | Adapter | Window |\n")
	output.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, row := range phase0Policies {
		pol, _, err := policy.Load(filepath.Join(benchRoot, filepath.FromSlash(row.path)))
		if err != nil {
			return "", fmt.Errorf("doccheck: %s: %w", row.path, err)
		}
		if len(pol.Scenarios) == 0 {
			return "", fmt.Errorf("doccheck: %s has no scenarios", row.path)
		}
		first := pol.Scenarios[0]
		for _, scenario := range pol.Scenarios[1:] {
			if scenario.Warmup != first.Warmup || scenario.Duration != first.Duration || scenario.Repetitions != first.Repetitions {
				return "", fmt.Errorf("doccheck: %s has nonuniform measurement windows", row.path)
			}
		}
		adapter := string(pol.Series.AdapterClass)
		if pol.Series.RunKind == policy.RunKindAA {
			adapter = "same binary, `" + adapter + "`"
		} else {
			adapter = "`" + adapter + "`"
		}
		window := fmt.Sprintf("%s/%s, n=%d", first.Warmup.Duration(), first.Duration.Duration(), first.Repetitions)
		if pol.Series.RunKind == policy.RunKindAA {
			window = fmt.Sprintf("%s warmup, %s measure, n=%d", first.Warmup.Duration(), first.Duration.Duration(), first.Repetitions)
		}
		if row.windowUnit != "" {
			window += "/" + row.windowUnit
		}
		fmt.Fprintf(&output, "| %s | `%s` | `%s` | %s | %s |\n", row.role, row.path, pol.Series.Client, adapter, window)
	}
	return output.String(), nil
}

func controlledEnvironment(base []string) []string {
	overrides := []string{
		"CGO_ENABLED=0",
		"GOENV=off",
		"GOEXPERIMENT=",
		"GOFIPS140=latest",
		"GOFLAGS=-mod=mod",
		"GOTOOLCHAIN=local",
	}
	keys := make(map[string]bool, len(overrides))
	for _, value := range overrides {
		key, _, _ := strings.Cut(value, "=")
		keys[key] = true
	}
	environment := make([]string, 0, len(base)+len(overrides))
	for _, value := range base {
		key, _, _ := strings.Cut(value, "=")
		if !keys[key] {
			environment = append(environment, value)
		}
	}
	return append(environment, overrides...)
}

func markers(name string) (string, string) {
	return "<!-- BEGIN GENERATED: " + name + " -->", "<!-- END GENERATED: " + name + " -->"
}

func section(raw []byte, name string) (string, error) {
	begin, end := markers(name)
	start := bytes.Index(raw, []byte(begin+"\n"))
	if start < 0 {
		return "", fmt.Errorf("doccheck: missing begin marker for %q", name)
	}
	start += len(begin) + 1
	finish := bytes.Index(raw[start:], []byte(end))
	if finish < 0 {
		return "", fmt.Errorf("doccheck: missing end marker for %q", name)
	}
	if bytes.Contains(raw[start+finish+len(end):], []byte(end)) || bytes.Contains(raw[start:], []byte(begin)) {
		return "", fmt.Errorf("doccheck: duplicate marker for %q", name)
	}
	return string(raw[start : start+finish]), nil
}

func replaceSection(raw []byte, name, content string) ([]byte, error) {
	begin, end := markers(name)
	current, err := section(raw, name)
	if err != nil {
		return nil, err
	}
	want := begin + "\n" + content + end
	got := begin + "\n" + current + end
	if bytes.Count(raw, []byte(got)) != 1 {
		return nil, fmt.Errorf("doccheck: generated section %q is ambiguous", name)
	}
	return bytes.Replace(raw, []byte(got), []byte(want), 1), nil
}
