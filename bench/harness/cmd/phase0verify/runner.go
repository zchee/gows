package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/zchee/gows/bench/harness/artifact"
	"github.com/zchee/gows/bench/harness/assembly"
	"github.com/zchee/gows/bench/harness/evidence"
	"github.com/zchee/gows/bench/harness/phase0"
	"github.com/zchee/gows/bench/harness/support"
)

const invalidationSchemaVersion = 1

type config struct {
	repoRoot   string
	outputRoot string
}

type assemblyOutput struct {
	goos, goarch string
	directory    string
}

type commandSpec struct {
	id                 string
	argv               []string
	workingDirectory   string
	environment        []string
	requireEmptyStdout bool
	assembly           *assemblyOutput
}

type hostIdentity struct {
	hostname string
	boot     string
}

type invalidation struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Stage         string `json:"stage"`
	Reason        string `json:"reason"`
	SourceHead    string `json:"source_head,omitempty"`
	FailedAt      string `json:"failed_at"`
}

type outputTransaction struct {
	root      string
	stage     string
	source    string
	committed bool
	now       func() time.Time
}

func run(ctx context.Context, cfg config) (_ phase0.Result, resultErr error) {
	root, err := resolveRepositoryRoot(cfg.repoRoot)
	if err != nil {
		return phase0.Result{}, err
	}
	if runtime.GOOS != "darwin" {
		return phase0.Result{}, fmt.Errorf("phase 0 verification requires a Darwin controller, got %s", runtime.GOOS)
	}
	output, err := resolveOutputRoot(root, cfg.outputRoot)
	if err != nil {
		return phase0.Result{}, err
	}
	identity, err := evidence.CollectRepositoryIdentity(root)
	if err != nil {
		return phase0.Result{}, err
	}
	host, err := captureHostIdentity()
	if err != nil {
		return phase0.Result{}, err
	}
	commandInputs, err := evidence.CollectVerificationCommandInputs(root, identity.SourceHead)
	if err != nil {
		return phase0.Result{}, err
	}
	store, err := artifact.NewStore(filepath.Join(root, filepath.FromSlash(evidence.ArtifactStorePath)))
	if err != nil {
		return phase0.Result{}, err
	}

	tx, err := beginOutput(output, time.Now)
	if err != nil {
		return phase0.Result{}, err
	}
	tx.source = identity.SourceHead
	defer func() {
		if resultErr != nil && !tx.committed {
			resultErr = errors.Join(resultErr, tx.invalidate(resultErr))
		}
	}()

	verificationDir := filepath.Join(output, "verification")
	logsDir := filepath.Join(verificationDir, "logs")
	assemblyDir := filepath.Join(output, "assembly")
	for _, directory := range []string{logsDir, assemblyDir} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return phase0.Result{}, fmt.Errorf("create output directory %s: %w", directory, err)
		}
	}
	workDir, err := os.MkdirTemp(filepath.Join(root, ".omx"), ".phase0verify-work-*")
	if err != nil {
		return phase0.Result{}, fmt.Errorf("create verification work directory: %w", err)
	}
	workRemoved := false
	defer func() {
		if !workRemoved {
			resultErr = errors.Join(resultErr, os.RemoveAll(workDir))
		}
	}()

	specs := buildCommandSpecs(root, output, workDir, commandInputs)
	checks, assemblies, err := executePlan(
		specs,
		func(index int, spec commandSpec) (evidence.VerificationCheck, error) {
			tx.stage = spec.id
			return executeCommand(ctx, root, logsDir, index, spec, time.Now)
		},
		func(spec commandSpec) (evidence.AssemblyEvidence, error) {
			if _, err := assembly.ReadBundle(spec.assembly.directory, true); err != nil {
				return evidence.AssemblyEvidence{}, fmt.Errorf("revalidate %s: %w", spec.id, err)
			}
			kind := evidence.AssemblyKindPrefix + spec.assembly.goos + "-" + spec.assembly.goarch
			_, ref, err := artifact.SealDirectory(store, spec.assembly.directory, kind, []string{"manifest.json"})
			if err != nil {
				return evidence.AssemblyEvidence{}, fmt.Errorf("seal %s: %w", spec.id, err)
			}
			return evidence.AssemblyEvidence{
				GOOS: spec.assembly.goos, GOARCH: spec.assembly.goarch, Bundle: ref,
			}, nil
		},
	)
	if err != nil {
		return phase0.Result{}, err
	}

	tx.stage = "work-cleanup"
	if err := os.RemoveAll(workDir); err != nil {
		return phase0.Result{}, fmt.Errorf("remove verification work directory: %w", err)
	}
	workRemoved = true
	if _, err := os.Lstat(workDir); !errors.Is(err, os.ErrNotExist) {
		return phase0.Result{}, fmt.Errorf("verification work directory still exists: %s", workDir)
	}

	tx.stage = "source-revalidation"
	finalIdentity, err := evidence.CollectRepositoryIdentity(root)
	if err != nil {
		return phase0.Result{}, err
	}
	if !reflect.DeepEqual(identity, finalIdentity) {
		return phase0.Result{}, errors.New("repository identity changed during verification")
	}
	finalCommandInputs, err := evidence.CollectVerificationCommandInputs(root, identity.SourceHead)
	if err != nil {
		return phase0.Result{}, err
	}
	if !reflect.DeepEqual(commandInputs, finalCommandInputs) {
		return phase0.Result{}, errors.New("verification tool or command input identity changed during verification")
	}
	finalHost, err := captureHostIdentity()
	if err != nil {
		return phase0.Result{}, err
	}
	if host != finalHost {
		return phase0.Result{}, errors.New("host or boot identity changed during verification")
	}

	manifest := evidence.VerificationManifest{
		SchemaVersion: evidence.VerificationSchemaVersion,
		SourceHead:    identity.SourceHead, SourceTree: identity.SourceTree,
		ModuleFilesSHA256: identity.ModuleFilesSHA256,
		GoVersion:         identity.GoVersion, GoBinarySHA256: identity.GoBinarySHA256,
		GOOS: identity.GOOS, GOARCH: identity.GOARCH,
		Hostname: host.hostname, BootIdentity: host.boot,
		Tools: slices.Clone(commandInputs.Tools), Checks: checks,
	}
	tx.stage = "verification-manifest"
	manifestRaw, err := evidence.MarshalVerificationManifest(manifest, identity, commandInputs)
	if err != nil {
		return phase0.Result{}, err
	}
	if err := support.WriteNewFileAtomic(filepath.Join(verificationDir, "manifest.json"), manifestRaw, 0o644); err != nil {
		return phase0.Result{}, err
	}
	if err := evidence.ValidateVerificationBundle(verificationDir, identity, commandInputs); err != nil {
		return phase0.Result{}, err
	}
	tx.stage = "verification-seal"
	_, verificationRef, err := artifact.SealDirectory(store, verificationDir, evidence.VerificationKind, []string{"manifest.json"})
	if err != nil {
		return phase0.Result{}, err
	}

	result := phase0.Result{
		SchemaVersion: phase0.ResultSchemaVersion,
		Repository:    identity,
		Verification:  verificationRef,
		Assemblies:    assemblies,
	}
	resultRaw, err := phase0.Marshal(result)
	if err != nil {
		return phase0.Result{}, err
	}
	tx.stage = "final-source-revalidation"
	finalIdentity, err = evidence.CollectRepositoryIdentity(root)
	if err != nil {
		return phase0.Result{}, err
	}
	if !reflect.DeepEqual(identity, finalIdentity) {
		return phase0.Result{}, errors.New("repository identity changed before result publication")
	}
	finalCommandInputs, err = evidence.CollectVerificationCommandInputs(root, identity.SourceHead)
	if err != nil {
		return phase0.Result{}, err
	}
	if !reflect.DeepEqual(commandInputs, finalCommandInputs) {
		return phase0.Result{}, errors.New("verification tool or command input identity changed before result publication")
	}
	finalHost, err = captureHostIdentity()
	if err != nil {
		return phase0.Result{}, err
	}
	if host != finalHost {
		return phase0.Result{}, errors.New("host or boot identity changed before result publication")
	}
	tx.stage = "result-publication"
	resultPath := filepath.Join(output, phase0.ResultFile)
	if err := support.WriteNewFileAtomic(resultPath, resultRaw, 0o644); err != nil {
		return phase0.Result{}, err
	}
	loaded, err := phase0.Load(resultPath)
	if err != nil {
		return phase0.Result{}, err
	}
	tx.committed = true
	return loaded, nil
}

func beginOutput(path string, now func() time.Time) (*outputTransaction, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create output parent: %w", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("output destination already exists: %s", path)
		}
		return nil, fmt.Errorf("create output destination: %w", err)
	}
	tx := &outputTransaction{root: path, stage: "initialization", now: now}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, errors.Join(err, tx.invalidate(err))
	}
	return tx, nil
}

func (tx *outputTransaction) invalidate(cause error) error {
	record := invalidation{
		SchemaVersion: invalidationSchemaVersion,
		Kind:          "gows.phase0.verification.invalidated", Stage: tx.stage,
		Reason: cause.Error(), SourceHead: tx.source,
		FailedAt: tx.now().UTC().Format(time.RFC3339Nano),
	}
	raw, err := marshalJSON(record)
	if err != nil {
		return err
	}
	if err := support.WriteNewFileAtomic(filepath.Join(tx.root, "INVALIDATED.json"), raw, 0o644); err != nil {
		return fmt.Errorf("write verification invalidation: %w", err)
	}
	return nil
}

func executeCommand(ctx context.Context, root, logsDir string, index int, spec commandSpec, now func() time.Time) (evidence.VerificationCheck, error) {
	base := fmt.Sprintf("%02d-%s", index+1, spec.id)
	stdoutRelative := filepath.ToSlash(filepath.Join("logs", base+".stdout.log"))
	stderrRelative := filepath.ToSlash(filepath.Join("logs", base+".stderr.log"))
	stdoutPath := filepath.Join(logsDir, base+".stdout.log")
	stderrPath := filepath.Join(logsDir, base+".stderr.log")
	stdoutFile, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return evidence.VerificationCheck{}, fmt.Errorf("create %s stdout: %w", spec.id, err)
	}
	stdoutHash := sha256.New()
	stderrFile, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return evidence.VerificationCheck{}, errors.Join(
			fmt.Errorf("create %s stderr: %w", spec.id, err),
			syncAndClose(stdoutFile),
		)
	}
	stderrHash := sha256.New()

	command := exec.CommandContext(ctx, spec.argv[0], spec.argv[1:]...)
	command.Dir = filepath.Join(root, filepath.FromSlash(spec.workingDirectory))
	command.Env = slices.Clone(spec.environment)
	command.Stdout = io.MultiWriter(stdoutFile, stdoutHash)
	command.Stderr = io.MultiWriter(stderrFile, stderrHash)
	started := now().UTC()
	runErr := command.Run()
	ended := now().UTC()
	if !started.Before(ended) {
		ended = started.Add(time.Nanosecond)
	}
	exitCode := 0
	if runErr != nil {
		exitCode = -1
		if exitErr, ok := errors.AsType[*exec.ExitError](runErr); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	closeErr := errors.Join(syncAndClose(stdoutFile), syncAndClose(stderrFile))
	check := evidence.VerificationCheck{
		ID: spec.id, Argv: slices.Clone(spec.argv), WorkingDir: spec.workingDirectory,
		Environment: slices.Clone(spec.environment),
		StartedAt:   started.Format(time.RFC3339Nano), EndedAt: ended.Format(time.RFC3339Nano),
		ExitCode:   exitCode,
		StdoutPath: stdoutRelative, StdoutSHA256: hex.EncodeToString(stdoutHash.Sum(nil)),
		StderrPath: stderrRelative, StderrSHA256: hex.EncodeToString(stderrHash.Sum(nil)),
	}
	if closeErr != nil {
		return check, fmt.Errorf("close %s logs: %w", spec.id, closeErr)
	}
	if runErr != nil {
		return check, fmt.Errorf("verification check %s exited %d: %w", spec.id, exitCode, runErr)
	}
	if spec.requireEmptyStdout {
		info, err := os.Stat(stdoutPath)
		if err != nil {
			return check, err
		}
		if info.Size() != 0 {
			return check, fmt.Errorf("verification check %s produced %d bytes of forbidden stdout", spec.id, info.Size())
		}
	}
	return check, nil
}

type (
	commandExecutor func(index int, spec commandSpec) (evidence.VerificationCheck, error)
	assemblySealer  func(spec commandSpec) (evidence.AssemblyEvidence, error)
)

func executePlan(specs []commandSpec, execute commandExecutor, seal assemblySealer) ([]evidence.VerificationCheck, []evidence.AssemblyEvidence, error) {
	if err := validateCommandOrder(specs); err != nil {
		return nil, nil, err
	}
	checks := make([]evidence.VerificationCheck, 0, len(specs))
	assemblies := make([]evidence.AssemblyEvidence, 0, 2)
	for index, spec := range specs {
		check, err := execute(index, spec)
		if err != nil {
			return checks, assemblies, err
		}
		checks = append(checks, check)
		if spec.assembly != nil {
			assembly, err := seal(spec)
			if err != nil {
				return checks, assemblies, err
			}
			assemblies = append(assemblies, assembly)
		}
	}
	return checks, assemblies, nil
}

func syncAndClose(file *os.File) error {
	return errors.Join(file.Sync(), file.Close())
}

func validateCommandOrder(specs []commandSpec) error {
	want := evidence.RequiredVerificationChecks()
	if len(specs) != len(want) {
		return fmt.Errorf("verification command count = %d, want %d", len(specs), len(want))
	}
	for i := range specs {
		if specs[i].id != want[i] {
			return fmt.Errorf("verification command %d = %q, want %q", i, specs[i].id, want[i])
		}
		if len(specs[i].argv) == 0 || !filepath.IsAbs(specs[i].argv[0]) {
			return fmt.Errorf("verification command %q executable is not absolute", specs[i].id)
		}
	}
	return nil
}

func resolveRepositoryRoot(value string) (string, error) {
	if value == "" {
		output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
		if err != nil {
			return "", fmt.Errorf("resolve repository root: %w", err)
		}
		value = strings.TrimSpace(string(output))
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func resolveOutputRoot(root, value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve output root: %w", err)
	}
	omxRoot := filepath.Join(root, ".omx")
	relative, err := filepath.Rel(omxRoot, absolute)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("output must be a new child of %s", omxRoot)
	}
	artifactRoot := filepath.Join(root, filepath.FromSlash(evidence.ArtifactStorePath))
	if relativeToStore, err := filepath.Rel(artifactRoot, absolute); err == nil && (relativeToStore == "." || filepath.IsLocal(relativeToStore)) {
		return "", errors.New("output cannot be inside the immutable artifact store")
	}
	return absolute, nil
}

func captureHostIdentity() (hostIdentity, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return hostIdentity{}, fmt.Errorf("capture hostname: %w", err)
	}
	if hostname == "" {
		return hostIdentity{}, errors.New("capture hostname: empty hostname")
	}
	boot, err := support.CaptureBootIdentity()
	if err != nil {
		return hostIdentity{}, err
	}
	return hostIdentity{hostname: hostname, boot: boot}, nil
}

func marshalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
