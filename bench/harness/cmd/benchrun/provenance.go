package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zchee/gows/bench/harness/support"
)

type ProvenanceArtifact struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type BinaryProvenance struct {
	Path       string             `json:"path"`
	SHA256     string             `json:"sha256"`
	SizeBytes  int64              `json:"size_bytes"`
	GoVersionM ProvenanceArtifact `json:"go_version_m"`
}

type CapturedProvenance struct {
	SourceTree        ProvenanceArtifact          `json:"source_tree"`
	GoEnv             ProvenanceArtifact          `json:"go_env"`
	ModuleGraph       ProvenanceArtifact          `json:"module_graph"`
	OSVersion         ProvenanceArtifact          `json:"os_version"`
	SystemProfile     ProvenanceArtifact          `json:"system_profile"`
	Limits            ProvenanceArtifact          `json:"limits"`
	Binaries          map[string]BinaryProvenance `json:"binaries"`
	ModuleFilesSHA256 string                      `json:"module_files_sha256"`
}

func captureProvenance(ctx context.Context, moduleRoot, out, goExperiment string, binaries map[string]string) (CapturedProvenance, error) {
	toolchainEnv := overrideEnvironment(os.Environ(), canonicalToolchainEnvironment(goExperiment).assignments()...)
	goTool := goToolPath()
	sourceTree, err := captureCommandArtifact(ctx, out, "provenance/source-tree.txt", moduleRoot, nil, "git", "ls-tree", "-r", "--full-tree", "HEAD")
	if err != nil {
		return CapturedProvenance{}, err
	}
	goEnv, err := captureCommandArtifact(ctx, out, "provenance/go-env.json", moduleRoot, toolchainEnv, goTool, "env", "-json")
	if err != nil {
		return CapturedProvenance{}, err
	}
	modules, err := captureCommandArtifact(ctx, out, "provenance/modules.jsonl", moduleRoot, toolchainEnv, goTool, "list", "-mod=mod", "-m", "-json", "all")
	if err != nil {
		return CapturedProvenance{}, err
	}
	osVersion, err := captureShellArtifact(ctx, out, "provenance/os-version.txt", moduleRoot, "sw_vers; uname -a")
	if err != nil {
		return CapturedProvenance{}, err
	}
	system, err := captureShellArtifact(ctx, out, "provenance/system-profile.txt", moduleRoot, "/usr/sbin/sysctl -a")
	if err != nil {
		return CapturedProvenance{}, err
	}
	limits, err := captureShellArtifact(ctx, out, "provenance/limits.txt", moduleRoot, "launchctl limit; ulimit -a")
	if err != nil {
		return CapturedProvenance{}, err
	}

	names := make([]string, 0, len(binaries))
	for name := range binaries {
		names = append(names, name)
	}
	slices.Sort(names)
	binaryProvenance := make(map[string]BinaryProvenance, len(names))
	for _, name := range names {
		path := binaries[name]
		info, err := os.Lstat(path)
		if err != nil {
			return CapturedProvenance{}, fmt.Errorf("provenance: stat binary %s: %w", name, err)
		}
		if !info.Mode().IsRegular() {
			return CapturedProvenance{}, fmt.Errorf("provenance: binary %s is not regular", name)
		}
		sum, err := sha256File(path)
		if err != nil {
			return CapturedProvenance{}, err
		}
		version, err := captureCommandArtifact(ctx, out, filepath.ToSlash(filepath.Join("provenance", "binaries", safeName(name)+".version-m.txt")), moduleRoot, toolchainEnv, goTool, "version", "-m", path)
		if err != nil {
			return CapturedProvenance{}, err
		}
		relative, err := filepath.Rel(out, path)
		if err != nil || !filepath.IsLocal(relative) {
			return CapturedProvenance{}, fmt.Errorf("provenance: binary %s path %s is outside output root %s", name, path, out)
		}
		binaryProvenance[name] = BinaryProvenance{Path: filepath.ToSlash(relative), SHA256: sum, SizeBytes: info.Size(), GoVersionM: version}
	}
	moduleSum, err := hashFileSet(filepath.Dir(moduleRoot), []string{"go.mod", "go.sum", "bench/go.mod", "bench/go.sum", "flatekp/go.mod", "flatekp/go.sum"})
	if err != nil {
		return CapturedProvenance{}, fmt.Errorf("provenance: module files: %w", err)
	}
	return CapturedProvenance{
		SourceTree: sourceTree, GoEnv: goEnv, ModuleGraph: modules, OSVersion: osVersion,
		SystemProfile: system, Limits: limits, Binaries: binaryProvenance, ModuleFilesSHA256: moduleSum,
	}, nil
}

func captureShellArtifact(ctx context.Context, out, relative, dir, script string) (ProvenanceArtifact, error) {
	return captureCommandArtifact(ctx, out, relative, dir, nil, "/bin/sh", "-c", script)
}

func captureCommandArtifact(ctx context.Context, out, relative, dir string, env []string, name string, args ...string) (ProvenanceArtifact, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	if env != nil {
		command.Env = env
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	raw, err := command.Output()
	if err != nil {
		return ProvenanceArtifact{}, fmt.Errorf("provenance: %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	path := filepath.Join(out, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return ProvenanceArtifact{}, err
	}
	if err := support.WriteFileAtomic(path, raw, 0o644); err != nil {
		return ProvenanceArtifact{}, err
	}
	hash := sha256.Sum256(raw)
	return ProvenanceArtifact{Path: relative, SHA256: hex.EncodeToString(hash[:]), SizeBytes: int64(len(raw))}, nil
}

func safeName(value string) string {
	return strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-").Replace(value)
}
