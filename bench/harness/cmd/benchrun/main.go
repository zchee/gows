// Command benchrun executes a policy's paired candidate-vs-comparator
// scenario matrix under strict host hygiene, spawning a fresh echoserver and
// loadgen process pair per repetition and recording one JSON sample line per
// (scenario, library, repetition) to samples.jsonl. Resource accounting comes
// only from each child process's rusage, never from wrapping net.Conn on a
// gating path. See bench/README.md for the full methodology.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/zchee/gows/bench/harness/paired"
	"github.com/zchee/gows/bench/harness/policy"
	"github.com/zchee/gows/bench/harness/support"
)

const (
	// lockPath is the exclusive whole-host benchrun lock.
	lockPath = "/tmp/gows-benchrun.lock"
	// basePort and debugPortBase are the low ends of the two ports benchrun
	// alternates across successive server starts to dodge TIME_WAIT.
	basePort      = 19301
	debugPortBase = 20301
	// dialTimeout bounds how long benchrun waits for a freshly spawned
	// echoserver to accept TCP connections.
	dialTimeout = 10 * time.Second
	// moduleImport is the bench module's import path, used to build the
	// echoserver and loadgen binaries and to locate the module root.
	moduleImport = "github.com/zchee/gows/bench"
	// goldenGamma is an odd-constant PCG stream separator (golden ratio).
	goldenGamma = 0x9E3779B97F4A7C15
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "benchrun: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	policyPath := flag.String("policy", "", "path to the policy JSON file (required)")
	outFlag := flag.String("out", "", "run output directory (default results/v-next/darwin-arm64/claude-run-<UTCstamp>-<gitshort>)")
	smoke := flag.Bool("smoke", false, "override every scenario to warmup 1s / measure 3s / 2 reps for an end-to-end sanity pass")
	flag.Parse()

	if *policyPath == "" {
		return errors.New("-policy is required")
	}
	pol, rawPolicy, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}
	moduleRoot, err := findModuleRoot(cwd)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 1. Host guard: exclusive lock, load average, foreign processes.
	release, err := acquireLock(lockPath)
	if err != nil {
		return err
	}
	defer release()

	if err := checkLoad(pol.Guard.MaxLoad1); err != nil {
		return err
	}
	if err := checkForeignProcesses(pol.Guard.ForbiddenProcessPatterns); err != nil {
		return err
	}

	// 2. Provenance.
	commit, err := gitOutput(moduleRoot, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	shortCommit, err := gitOutput(moduleRoot, "rev-parse", "--short", "HEAD")
	if err != nil {
		return err
	}
	dirty, err := gitDirty(moduleRoot)
	if err != nil {
		return err
	}

	out := *outFlag
	if out == "" {
		out = defaultOutDir(moduleRoot, shortCommit)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create out dir %s: %w", out, err)
	}

	echoserverBin := filepath.Join(out, "echoserver")
	loadgenBin := filepath.Join(out, "loadgen")
	if err := buildBinary(ctx, moduleRoot, "/harness/cmd/echoserver", echoserverBin); err != nil {
		return err
	}
	if err := buildBinary(ctx, moduleRoot, "/harness/cmd/loadgen", loadgenBin); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(out, "policy.json"), rawPolicy, 0o644); err != nil {
		return fmt.Errorf("copy policy: %w", err)
	}

	echoSum, err := sha256File(echoserverBin)
	if err != nil {
		return err
	}
	loadSum, err := sha256File(loadgenBin)
	if err != nil {
		return err
	}

	// Resolve candidate and comparator through any library overrides, then
	// build a dedicated echoserver binary for each override that sets a build
	// environment (build_env). Overrides that only append server_args reuse the
	// shared default echoserver binary. With no overrides, resolved is the
	// identity mapping and no extra binaries are built, so meta.json is
	// byte-identical to a pre-override run apart from the omitted schema field.
	resolved := map[string]policy.Resolved{
		pol.Candidate:  pol.Resolve(pol.Candidate),
		pol.Comparator: pol.Resolve(pol.Comparator),
	}
	binPaths := map[string]string{}
	var overrideSums map[string]string
	for _, name := range []string{pol.Candidate, pol.Comparator} {
		r := resolved[name]
		if r.Bin == "" {
			binPaths[name] = echoserverBin
			continue
		}
		bin := filepath.Join(out, "echoserver-"+r.Bin)
		if err := buildBinaryEnv(ctx, moduleRoot, "/harness/cmd/echoserver", bin, r.BuildEnv); err != nil {
			return err
		}
		sum, err := sha256File(bin)
		if err != nil {
			return err
		}
		binPaths[name] = bin
		if overrideSums == nil {
			overrideSums = map[string]string{}
		}
		overrideSums[r.Bin] = sum
	}

	kernel, _ := commandOutput("uname", "-a")
	hostname, _ := os.Hostname()

	meta := Meta{
		GitCommit:              commit,
		GitDirty:               dirty,
		GoVersion:              runtime.Version(),
		Hostname:               hostname,
		Kernel:                 kernel,
		EchoserverSHA256:       echoSum,
		LoadgenSHA256:          loadSum,
		OverrideBinariesSHA256: overrideSums,
		PolicySHA256:           policy.Sum(rawPolicy),
		Seed:                   pol.Seed,
		Smoke:                  *smoke,
		StartedAt:              nowRFC(),
	}
	if err := writeJSONFile(filepath.Join(out, "meta.json"), meta); err != nil {
		return err
	}

	// 3. Environment snapshot (start).
	if err := writeJSONFile(filepath.Join(out, "env-start.json"), captureEnv()); err != nil {
		return err
	}

	// 4. Paired randomized execution.
	samplesPath := filepath.Join(out, "samples.jsonl")
	errorsPath := filepath.Join(out, "errors.log")
	count, execErr := execute(ctx, pol, *smoke, loadgenBin, binPaths, resolved, samplesPath, errorsPath)

	// Environment snapshot (end) is captured whether or not execution failed.
	if err := writeJSONFile(filepath.Join(out, "env-end.json"), captureEnv()); err != nil && execErr == nil {
		return err
	}
	if execErr != nil {
		return execErr
	}

	// 5. Run-complete marker.
	done := Done{FinishedAt: nowRFC(), Samples: count, Scenarios: len(pol.Scenarios)}
	if err := writeJSONFile(filepath.Join(out, "done.json"), done); err != nil {
		return err
	}
	fmt.Printf("benchrun: complete: %d samples across %d scenarios -> %s\n", count, len(pol.Scenarios), out)
	return nil
}

// Meta is the provenance record written to meta.json before execution starts.
// OverrideBinariesSHA256 is present only when a policy's library_overrides
// force a dedicated echoserver build (a build_env override); it is omitted
// otherwise, so meta.json stays byte-identical for override-free policies.
type Meta struct {
	GitCommit              string            `json:"git_commit"`
	GitDirty               bool              `json:"git_dirty"`
	GoVersion              string            `json:"go_version"`
	Hostname               string            `json:"hostname"`
	Kernel                 string            `json:"kernel"`
	EchoserverSHA256       string            `json:"echoserver_sha256"`
	LoadgenSHA256          string            `json:"loadgen_sha256"`
	OverrideBinariesSHA256 map[string]string `json:"override_binaries_sha256,omitzero"`
	PolicySHA256           string            `json:"policy_sha256"`
	Seed                   uint64            `json:"seed"`
	Smoke                  bool              `json:"smoke"`
	StartedAt              string            `json:"started_at"`
}

// Done is the run-complete marker written to done.json on success.
type Done struct {
	FinishedAt string `json:"finished_at"`
	Samples    int    `json:"samples"`
	Scenarios  int    `json:"scenarios"`
}

// EnvSnapshot is a point-in-time host environment reading written to
// env-start.json and env-end.json.
type EnvSnapshot struct {
	Load1        float64 `json:"load1"`
	Load5        float64 `json:"load5"`
	Load15       float64 `json:"load15"`
	PMSetBattery string  `json:"pmset_batt"`
	PMSetThermal string  `json:"pmset_therm"`
	LogicalCPUs  int     `json:"logical_cpus"`
	MemoryBytes  uint64  `json:"memory_bytes"`
	CapturedAt   string  `json:"captured_at"`
}

// execute runs the whole scenario matrix, appending one sample line per
// (scenario, library, repetition). It aborts (returning the count so far and
// a non-nil error) on the first child or parse failure rather than skipping.
// binPaths maps each policy library name (candidate/comparator) to the
// echoserver binary that serves it, and resolved carries each name's real
// echoserver -lib value and any appended server arguments.
func execute(ctx context.Context, pol *policy.Policy, smoke bool, loadgenBin string, binPaths map[string]string, resolved map[string]policy.Resolved, samplesPath, errorsPath string) (int, error) {
	sf, err := os.OpenFile(samplesPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open samples file: %w", err)
	}
	defer sf.Close()

	rng := rand.New(rand.NewPCG(pol.Seed, pol.Seed^goldenGamma))
	order := []string{pol.Candidate, pol.Comparator}
	count := 0
	portToggle := 0

	for _, sc := range pol.Scenarios {
		warmup := sc.Warmup.Duration()
		duration := sc.Duration.Duration()
		reps := sc.Repetitions
		if smoke {
			warmup = time.Second
			duration = 3 * time.Second
			reps = 2
		}

		for rep := range reps {
			order[0], order[1] = pol.Candidate, pol.Comparator
			rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })

			for orderIdx, lib := range order {
				if err := ctx.Err(); err != nil {
					return count, fmt.Errorf("aborted: %w", err)
				}
				serverPort := basePort + portToggle
				debugPort := debugPortBase + portToggle
				portToggle ^= 1

				r := resolved[lib]
				sample, err := runOne(ctx, binPaths[lib], loadgenBin, lib, r.Lib, r.ServerArgs, sc, warmup, duration, rep, orderIdx, serverPort, debugPort)
				if err != nil {
					appendError(errorsPath, sc.Name, lib, rep, err)
					return count, fmt.Errorf("scenario %q lib %q rep %d: %w", sc.Name, lib, rep, err)
				}
				if err := writeJSONLine(sf, sample); err != nil {
					return count, err
				}
				count++
			}
		}
	}
	return count, nil
}

// runOne spawns one echoserver, drives one loadgen JSON run against it, then
// SIGTERMs the server and collects both children's rusage. name is the
// policy-facing library name recorded in the sample (an override name such as
// "gows-lowat" distinct from realLib); realLib is the echoserver -lib value,
// and serverArgs are appended to the echoserver command line.
func runOne(ctx context.Context, echoserverBin, loadgenBin, name, realLib string, serverArgs []string, sc policy.Scenario, warmup, duration time.Duration, rep, orderIdx, serverPort, debugPort int) (paired.Sample, error) {
	serverAddr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	debugAddr := fmt.Sprintf("127.0.0.1:%d", debugPort)

	srvArgs := append([]string{"-lib", realLib, "-addr", serverAddr, "-debug-addr", debugAddr}, serverArgs...)
	srv := exec.CommandContext(ctx, echoserverBin, srvArgs...)
	var srvLog bytes.Buffer
	srv.Stdout = &srvLog
	srv.Stderr = &srvLog
	if err := srv.Start(); err != nil {
		return paired.Sample{}, fmt.Errorf("start echoserver: %w", err)
	}
	serverStopped := false
	defer func() {
		if !serverStopped && srv.Process != nil {
			_ = srv.Process.Signal(syscall.SIGKILL)
			_ = srv.Wait()
		}
	}()

	if err := waitTCP(ctx, serverAddr, dialTimeout); err != nil {
		return paired.Sample{}, fmt.Errorf("echoserver ws port %s not ready: %w (server log: %s)", serverAddr, err, strings.TrimSpace(srvLog.String()))
	}
	if err := waitTCP(ctx, debugAddr, dialTimeout); err != nil {
		return paired.Sample{}, fmt.Errorf("echoserver debug port %s not ready: %w (server log: %s)", debugAddr, err, strings.TrimSpace(srvLog.String()))
	}

	lg := exec.CommandContext(ctx, loadgenBin,
		"-addr", serverAddr,
		"-debug-addr", debugAddr,
		"-conns", strconv.Itoa(sc.Connections),
		"-payload", strconv.Itoa(sc.PayloadBytes),
		"-inflight", strconv.Itoa(sc.Inflight),
		"-duration", duration.String(),
		"-warmup", warmup.String(),
		"-rate", "0",
		"-json")
	var lgOut, lgErr bytes.Buffer
	lg.Stdout = &lgOut
	lg.Stderr = &lgErr
	if err := lg.Run(); err != nil {
		return paired.Sample{}, fmt.Errorf("loadgen failed: %w (stderr: %s)", err, strings.TrimSpace(lgErr.String()))
	}

	var result support.LoadgenResult
	if err := json.Unmarshal(bytes.TrimSpace(lgOut.Bytes()), &result); err != nil {
		return paired.Sample{}, fmt.Errorf("parse loadgen json %q: %w", strings.TrimSpace(lgOut.String()), err)
	}

	if srv.Process != nil {
		_ = srv.Process.Signal(syscall.SIGTERM)
	}
	// A SIGTERM-terminated echoserver may report a non-nil wait error; the
	// ProcessState (and thus its rusage) is populated regardless, so the
	// expected termination error is intentionally not treated as fatal.
	_ = srv.Wait()
	serverStopped = true
	serverCPU, serverRSS := rusage(srv.ProcessState)

	// The server's resources come from its process rusage here; the client's
	// come from loadgen's own getrusage(RUSAGE_SELF), already in result. Both
	// are process rusage, never a net.Conn counting wrapper.
	msgs := float64(max(result.Messages, 1))
	conns := float64(max(sc.Connections, 1))
	return paired.Sample{
		LoadgenResult:               result,
		Scenario:                    sc.Name,
		Library:                     name,
		Repetition:                  rep,
		OrderIndex:                  orderIdx,
		ServerCPUSeconds:            serverCPU,
		ServerMaxRSSBytes:           serverRSS,
		ServerCPUSecondsPerMessage:  serverCPU / msgs,
		ServerRSSBytesPerConnection: float64(serverRSS) / conns,
		ClientCPUSecondsPerMessage:  result.ClientCPUSeconds / msgs,
	}, nil
}

// rusage extracts total CPU seconds (user+system) and peak resident set size
// from a finished process's rusage. Maxrss is bytes on darwin, the harness's
// target platform.
func rusage(ps *os.ProcessState) (cpuSeconds float64, maxRSSBytes int64) {
	if ps == nil {
		return 0, 0
	}
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0, 0
	}
	cpuSeconds = timevalSeconds(ru.Utime) + timevalSeconds(ru.Stime)
	maxRSSBytes = int64(ru.Maxrss)
	return cpuSeconds, maxRSSBytes
}

// timevalSeconds converts a syscall.Timeval to fractional seconds.
func timevalSeconds(t syscall.Timeval) float64 {
	return float64(t.Sec) + float64(t.Usec)/1e6
}

// waitTCP dials addr until it accepts a connection or the deadline/ctx
// expires.
func waitTCP(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no successful dial")
	}
	return fmt.Errorf("timed out after %s: %w", timeout, lastErr)
}

// findModuleRoot walks up from start until it finds the go.mod declaring the
// bench module.
func findModuleRoot(start string) (string, error) {
	dir := start
	for {
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for line := range strings.Lines(string(data)) {
				line = strings.TrimSpace(line)
				if rest, ok := strings.CutPrefix(line, "module "); ok {
					if strings.TrimSpace(rest) == moduleImport {
						return dir, nil
					}
					break
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate the bench module (%s) from %s; run benchrun inside the bench module tree", moduleImport, start)
		}
		dir = parent
	}
}

// defaultOutDir builds the default run directory under the module's results
// tree.
func defaultOutDir(moduleRoot, shortCommit string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	name := fmt.Sprintf("claude-run-%s-%s", stamp, shortCommit)
	return filepath.Join(moduleRoot, "results", "v-next", "darwin-arm64", name)
}

// buildBinary compiles a bench command into outPath, using -mod=mod so the
// working-tree gows (via the module's replace directive) is linked rather than
// the vendored snapshot.
func buildBinary(ctx context.Context, moduleRoot, pkgSuffix, outPath string) error {
	return buildBinaryEnv(ctx, moduleRoot, pkgSuffix, outPath, nil)
}

// buildBinaryEnv compiles a bench command into outPath like buildBinary, but
// appends extraEnv (KEY=VALUE entries, for example a GOEXPERIMENT setting) to
// the build environment. This lets a policy's library_overrides produce a
// distinct echoserver build (hypothesis H2) without a separate source tree.
func buildBinaryEnv(ctx context.Context, moduleRoot, pkgSuffix, outPath string, extraEnv []string) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=mod", "-o", outPath, moduleImport+pkgSuffix)
	cmd.Dir = moduleRoot
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	cmd.Env = append(cmd.Env, extraEnv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build %s (env %v): %w: %s", pkgSuffix, extraEnv, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// sha256File returns the hex SHA-256 of a file's contents.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// captureEnv snapshots the host environment. Best-effort: a missing tool
// yields a zero field rather than aborting the run.
func captureEnv() EnvSnapshot {
	l1, l5, l15, _ := readLoadavg()
	batt, _ := commandOutput("pmset", "-g", "batt")
	therm, _ := commandOutput("pmset", "-g", "therm")
	mem, _ := readMemsize()
	return EnvSnapshot{
		Load1:        l1,
		Load5:        l5,
		Load15:       l15,
		PMSetBattery: batt,
		PMSetThermal: therm,
		LogicalCPUs:  runtime.NumCPU(),
		MemoryBytes:  mem,
		CapturedAt:   nowRFC(),
	}
}

// checkLoad aborts if the one-minute load average exceeds the guard maximum.
func checkLoad(maxLoad1 float64) error {
	l1, _, _, err := readLoadavg()
	if err != nil {
		return err
	}
	if l1 > maxLoad1 {
		return fmt.Errorf("host guard: load1 %.2f exceeds max_load1 %.2f; aborting", l1, maxLoad1)
	}
	return nil
}

// checkForeignProcesses aborts if any already-running process matches a
// forbidden pattern. It runs before any child is spawned, and never matches
// benchrun's own pid.
func checkForeignProcesses(patterns []string) error {
	self := os.Getpid()
	for _, pat := range patterns {
		out, err := exec.Command("pgrep", "-fl", pat).Output()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 1 {
				continue // pgrep exits 1 when nothing matches.
			}
			return fmt.Errorf("host guard: pgrep -fl %q: %w", pat, err)
		}
		if offenders := offendersFromPgrep(string(out), self); len(offenders) > 0 {
			return fmt.Errorf("host guard: process matching %q already running: %s", pat, strings.Join(offenders, "; "))
		}
	}
	return nil
}

// offendersFromPgrep parses "pgrep -fl" output into matching lines, excluding
// benchrun's own pid.
func offendersFromPgrep(out string, self int) []string {
	var offenders []string
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pidField, _, _ := strings.Cut(line, " ")
		if pid, err := strconv.Atoi(pidField); err == nil && pid == self {
			continue
		}
		offenders = append(offenders, line)
	}
	return offenders
}

// acquireLock takes the exclusive benchrun lockfile, containing our pid. A
// stale lock (pid no longer alive) is removed and retried once; a live holder
// aborts.
func acquireLock(path string) (release func(), err error) {
	create := func() (*os.File, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	}
	f, err := create()
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create lockfile %s: %w", path, err)
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("read existing lockfile %s: %w", path, rerr)
		}
		holder, perr := strconv.Atoi(strings.TrimSpace(string(data)))
		if perr == nil && processAlive(holder) {
			return nil, fmt.Errorf("lockfile %s held by running pid %d; another benchrun is active", path, holder)
		}
		if rmErr := os.Remove(path); rmErr != nil {
			return nil, fmt.Errorf("remove stale lockfile %s: %w", path, rmErr)
		}
		f, err = create()
		if err != nil {
			return nil, fmt.Errorf("re-create lockfile %s after removing stale lock: %w", path, err)
		}
	}
	if _, werr := fmt.Fprintf(f, "%d\n", os.Getpid()); werr != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write lockfile %s: %w", path, werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close lockfile %s: %w", path, cerr)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = os.Remove(path) }) }, nil
}

// processAlive reports whether pid names a live process, using signal 0.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}

// readLoadavg reads the three system load averages from sysctl vm.loadavg.
func readLoadavg() (l1, l5, l15 float64, err error) {
	raw, err := commandOutput("sysctl", "-n", "vm.loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	return parseLoadavg(raw)
}

// parseLoadavg extracts the three load averages from a "sysctl -n vm.loadavg"
// string such as "{ 1.23 4.56 7.89 }".
func parseLoadavg(raw string) (l1, l5, l15 float64, err error) {
	var nums []float64
	for f := range strings.FieldsSeq(raw) {
		if v, perr := strconv.ParseFloat(f, 64); perr == nil {
			nums = append(nums, v)
		}
	}
	if len(nums) < 3 {
		return 0, 0, 0, fmt.Errorf("cannot parse load average from %q", raw)
	}
	return nums[0], nums[1], nums[2], nil
}

// readMemsize reads the physical memory size in bytes from sysctl hw.memsize.
func readMemsize() (uint64, error) {
	raw, err := commandOutput("sysctl", "-n", "hw.memsize")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
}

// gitOutput runs a git command in dir and returns its trimmed stdout.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitDirty reports whether the working tree has uncommitted changes.
func gitDirty(dir string) (bool, error) {
	out, err := gitOutput(dir, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return out != "", nil
}

// commandOutput runs an external command and returns its trimmed stdout.
func commandOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// appendError records a run failure to errors.log with context.
func appendError(path, scenario, lib string, rep int, cause error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s scenario=%q lib=%q rep=%d: %v\n", nowRFC(), scenario, lib, rep, cause)
}

// writeJSONLine marshals v as one compact JSON line to w.
func writeJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal sample: %w", err)
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write sample: %w", err)
	}
	return nil
}

// writeJSONFile marshals v as indented JSON to path.
func writeJSONFile(path string, v any) error {
	b, err := json.Marshal(v, jsontext.WithIndent("  "))
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// nowRFC returns the current UTC time as an RFC 3339 nanosecond string.
func nowRFC() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
