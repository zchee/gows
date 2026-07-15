// Command asmprobe creates one immutable supported-target assembly provenance
// bundle and immediately revalidates it from disk.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zchee/gows/bench/harness/assembly"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "asmprobe:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		repoRoot    = flag.String("repo", "", "gows repository root (auto-detected when empty)")
		goos        = flag.String("goos", runtime.GOOS, "supported target GOOS")
		goarch      = flag.String("goarch", runtime.GOARCH, "supported target GOARCH: amd64 or arm64")
		output      = flag.String("out", "", "new immutable bundle directory")
		runtimeMode = flag.String("runtime", "required", "runtime dispatch evidence: required or skip")
		allowDirty  = flag.Bool("allow-dirty", false, "emit explicitly diagnostic evidence from a dirty source tree")
	)
	flag.Parse()
	if *output == "" {
		return errors.New("-out is required")
	}
	runRuntime, err := parseRuntimeMode(*runtimeMode)
	if err != nil {
		return err
	}
	root := *repoRoot
	if root == "" {
		root, err = findRepoRoot()
		if err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	bundle, err := assembly.Collect(ctx, assembly.Config{
		RepoRoot:   root,
		GOOS:       *goos,
		GOARCH:     *goarch,
		RunRuntime: runRuntime,
		AllowDirty: *allowDirty,
	})
	if err != nil {
		return err
	}
	requireFinal := runRuntime && !*allowDirty
	if err := assembly.WriteBundle(*output, bundle, requireFinal); err != nil {
		return err
	}
	verified, err := assembly.ReadBundle(*output, requireFinal)
	if err != nil {
		return fmt.Errorf("revalidate published bundle: %w", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join(*output, "manifest.json"))
	if err != nil {
		return fmt.Errorf("read published manifest digest: %w", err)
	}
	sum := sha256.Sum256(manifestBytes)
	result := struct {
		Bundle          string `json:"bundle"`
		GOOS            string `json:"goos"`
		GOARCH          string `json:"goarch"`
		RuntimeVerified bool   `json:"runtime_verified"`
		Final           bool   `json:"final"`
		BinarySHA256    string `json:"binary_sha256"`
		ManifestSHA256  string `json:"manifest_sha256"`
	}{
		Bundle:          *output,
		GOOS:            verified.Manifest.Target.GOOS,
		GOARCH:          verified.Manifest.Target.GOARCH,
		RuntimeVerified: verified.Manifest.CPU.Runtime.Available,
		Final:           requireFinal,
		BinarySHA256:    verified.Manifest.Binary.SHA256,
		ManifestSHA256:  hex.EncodeToString(sum[:]),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func parseRuntimeMode(value string) (bool, error) {
	switch value {
	case "required":
		return true, nil
	case "skip":
		return false, nil
	default:
		return false, fmt.Errorf("invalid -runtime %q: want required or skip", value)
	}
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		modBytes, readErr := os.ReadFile(filepath.Join(dir, "go.mod"))
		if readErr == nil && strings.HasPrefix(string(modBytes), "module github.com/zchee/gows\n") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find github.com/zchee/gows repository root")
		}
		dir = parent
	}
}
