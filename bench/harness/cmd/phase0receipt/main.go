// Command phase0receipt validates and assembles immutable Phase 0 evidence.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/zchee/gows/bench/harness/evidence"
)

const (
	exitSuccess = 0
	exitFailure = 1
	exitUsage   = 2
)

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if err := printUsage(stderr); err != nil {
			return exitFailure
		}
		return exitUsage
	}

	var err error
	switch args[0] {
	case "aa-preflight":
		var cfg commandConfig
		cfg, err = parseConfig("aa-preflight", args[1:], stderr, false)
		if err == nil {
			err = runAAPreflight(cfg, productionOperations())
		}
		if err == nil {
			_, err = fmt.Fprintf(stdout, "phase0receipt: A/A preflight PASS -> %s\n", cfg.outputPath)
		}
	case "build":
		var cfg commandConfig
		cfg, err = parseConfig("build", args[1:], stderr, true)
		if err == nil {
			err = runBuild(cfg, productionOperations())
		}
		if err == nil {
			_, err = fmt.Fprintf(stdout, "phase0receipt: receipt created -> %s\n", cfg.outputPath)
		}
	case "help", "-h", "--help":
		if err := printUsage(stdout); err != nil {
			return exitFailure
		}
		return exitSuccess
	default:
		if _, err := fmt.Fprintf(stderr, "phase0receipt: unknown mode %q\n", args[0]); err != nil {
			return exitFailure
		}
		if err := printUsage(stderr); err != nil {
			return exitFailure
		}
		return exitUsage
	}
	if err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "phase0receipt: %v\n", err); writeErr != nil {
			return exitFailure
		}
		if isUsageError(err) {
			return exitUsage
		}
		return exitFailure
	}
	return exitSuccess
}

func parseConfig(name string, args []string, output io.Writer, includeBaselines bool) (commandConfig, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(output)
	cfg := commandConfig{}
	fs.StringVar(&cfg.repoRoot, "repo", "", "absolute or current-directory-relative repository root")
	fs.StringVar(&cfg.verificationResult, "verification-result", "", "phase0verify result.json path below the repository")
	fs.StringVar(&cfg.outputPath, "out", "", "new output JSON path below the repository")

	aaRoles := evidence.RequiredAARoles()
	cfg.aaInputs = make([]rolePath, len(aaRoles))
	for i, role := range aaRoles {
		cfg.aaInputs[i].role = role
		fs.StringVar(&cfg.aaInputs[i].path, role, "", "run receipt file or directory for "+role)
	}
	if includeBaselines {
		roles := evidence.RequiredBaselineRoles()
		cfg.baselineInputs = make([]rolePath, len(roles))
		for i, role := range roles {
			cfg.baselineInputs[i].role = role
			fs.StringVar(&cfg.baselineInputs[i].path, "baseline-"+role, "", "baseline run receipt file or directory for "+role)
		}
	}
	if err := fs.Parse(args); err != nil {
		return commandConfig{}, usageError{err}
	}
	if fs.NArg() != 0 {
		return commandConfig{}, usageError{fmt.Errorf("unexpected positional arguments: %v", fs.Args())}
	}
	if err := validateCommandConfig(cfg, includeBaselines); err != nil {
		return commandConfig{}, usageError{err}
	}
	return cfg, nil
}

func printUsage(output io.Writer) error {
	lines := []string{
		"usage:",
		"  phase0receipt aa-preflight -repo ROOT -verification-result RESULT -session-1 RECEIPT -session-2 RECEIPT -session-3 RECEIPT -out VERDICT",
		"  phase0receipt build -repo ROOT -verification-result RESULT -session-1 RECEIPT -session-2 RECEIPT -session-3 RECEIPT -baseline-best-api-gows-client RECEIPT -baseline-semantic-parity-gows-client RECEIPT -baseline-independent-gobwas-client RECEIPT -baseline-independent-raw-client RECEIPT -out RECEIPT",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
	}
	return nil
}

type usageError struct{ error }

func isUsageError(err error) bool {
	_, ok := err.(usageError)
	return ok
}
