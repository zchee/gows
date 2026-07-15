// Command phase0verify runs and seals the complete Phase 0 verification gate.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.repoRoot, "repo", "", "gows repository root (auto-detected when empty)")
	flag.StringVar(&cfg.outputRoot, "out", "", "new output directory below the repository .omx directory")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "phase0verify: positional arguments are not supported")
		os.Exit(2)
	}
	if cfg.outputRoot == "" {
		fmt.Fprintln(os.Stderr, "phase0verify: -out is required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, err := run(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "phase0verify:", err)
		os.Exit(1)
	}
	fmt.Printf("phase0verify: verification=%s\n", result.Verification.URI)
	for _, assembly := range result.Assemblies {
		fmt.Printf("phase0verify: assembly %s/%s=%s\n", assembly.GOOS, assembly.GOARCH, assembly.Bundle.URI)
	}
}
