package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/gows/bench/harness/policy"
)

const harnessProcessPattern = `(^|/)(go|compile|link|asm|gows[.]test|benchrun|echoserver|loadgen)( |$)`

const hostGuardInterval = 5 * time.Second

type guardResult struct {
	Snapshots []EnvSnapshot
	Err       error
}

type fileStamp struct {
	Size           int64
	Mode           os.FileMode
	ModificationNS int64
}

type processUsage struct {
	PID, PPID int
	CPU       float64
	Command   string
}

func monitorHost(ctx context.Context, baseline EnvSnapshot, guard policy.Guard, excludedPIDs map[int]struct{}, immutableFiles map[string]fileStamp) guardResult {
	patterns := append([]string{}, guard.ForbiddenProcessPatterns...)
	patterns = append(patterns, harnessProcessPattern)
	ticker := time.NewTicker(hostGuardInterval)
	defer ticker.Stop()
	result := guardResult{}
	for {
		current := captureContinuousEnv(baseline)
		result.Snapshots = append(result.Snapshots, current)
		if err := validateContinuousEnvironment(baseline, current, guard.MaxLoad1Drift); err != nil {
			result.Err = err
			return result
		}
		if err := checkProcessHygiene(patterns, excludedPIDs, guard.MaxForeignCPUPercent); err != nil {
			result.Err = err
			return result
		}
		if err := validateFileStamps(immutableFiles); err != nil {
			result.Err = err
			return result
		}
		select {
		case <-ctx.Done():
			return result
		case <-ticker.C:
		}
	}
}

func captureFileStamps(paths ...string) (map[string]fileStamp, error) {
	result := make(map[string]fileStamp, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("host guard: stat immutable file %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("host guard: immutable file %s is not regular", path)
		}
		result[path] = fileStamp{Size: info.Size(), Mode: info.Mode(), ModificationNS: info.ModTime().UnixNano()}
	}
	return result, nil
}

func validateFileStamps(want map[string]fileStamp) error {
	for path, stamp := range want {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("host guard: immutable file %s became unavailable: %w", path, err)
		}
		got := fileStamp{Size: info.Size(), Mode: info.Mode(), ModificationNS: info.ModTime().UnixNano()}
		if got != stamp {
			return fmt.Errorf("host guard: immutable file identity changed for %s", path)
		}
	}
	return nil
}

func checkProcessHygiene(patterns []string, excluded map[int]struct{}, cpuLimit float64) error {
	output, err := exec.Command("ps", "-Ao", "pid=,ppid=,%cpu=,command=").Output()
	if err != nil {
		return fmt.Errorf("host guard: ps process usage: %w", err)
	}
	processes, err := parseProcessUsage(string(output))
	if err != nil {
		return err
	}
	owned, err := ownedProcessTree(processes, excluded)
	if err != nil {
		return err
	}
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("host guard: compile process pattern %q: %w", pattern, err)
		}
		var offenders []string
		for _, process := range processes {
			if _, ok := owned[process.PID]; !ok && re.MatchString(process.Command) {
				offenders = append(offenders, formatProcessUsage(process))
			}
		}
		if len(offenders) != 0 {
			return fmt.Errorf("host guard: process matching %q already running: %s", pattern, strings.Join(offenders, "; "))
		}
	}
	total, offenders := foreignCPUUsage(processes, owned)
	if total > cpuLimit {
		return fmt.Errorf("host guard: aggregate foreign process CPU %.1f%% exceeds %.1f%%: %s", total, cpuLimit, strings.Join(offenders, "; "))
	}
	return nil
}

func parseProcessUsage(output string) ([]processUsage, error) {
	var result []processUsage
	for line := range strings.Lines(output) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("host guard: parse ps pid in %q: %w", line, err)
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("host guard: parse ps ppid in %q: %w", line, err)
		}
		cpu, err := strconv.ParseFloat(strings.TrimSuffix(fields[2], "%"), 64)
		if err != nil {
			return nil, fmt.Errorf("host guard: parse ps CPU in %q: %w", line, err)
		}
		if cpu < 0 || math.IsNaN(cpu) || math.IsInf(cpu, 0) {
			return nil, fmt.Errorf("host guard: invalid ps CPU %.3f in %q", cpu, line)
		}
		result = append(result, processUsage{PID: pid, PPID: ppid, CPU: cpu, Command: strings.Join(fields[3:], " ")})
	}
	return result, nil
}

func ownedProcessTree(processes []processUsage, roots map[int]struct{}) (map[int]struct{}, error) {
	byPID := make(map[int]processUsage, len(processes))
	for _, process := range processes {
		byPID[process.PID] = process
	}
	owned := make(map[int]struct{}, len(roots)+8)
	for pid := range roots {
		if _, present := byPID[pid]; present {
			owned[pid] = struct{}{}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, process := range processes {
			if _, ok := owned[process.PID]; ok {
				continue
			}
			if _, ok := owned[process.PPID]; ok {
				owned[process.PID] = struct{}{}
				changed = true
			}
		}
	}
	// A `go run` controller remains the direct parent of the compiled
	// benchrun process while measurements execute. Trust that exact ancestor
	// chain, but add it only after expanding descendants so siblings of the
	// controller (other builds, agents, or benchmark processes) remain foreign.
	controllers := make(map[int]processUsage)
	for root := range roots {
		process, ok := byPID[root]
		if !ok || process.PPID <= 1 {
			continue
		}
		if _, alreadyOwned := owned[process.PPID]; alreadyOwned {
			continue
		}
		parent, ok := byPID[process.PPID]
		if ok {
			controllers[parent.PID] = parent
		}
	}
	for root := range roots {
		seen := make(map[int]struct{})
		for pid := root; pid > 1; {
			if _, duplicate := seen[pid]; duplicate {
				break
			}
			seen[pid] = struct{}{}
			process, ok := byPID[pid]
			if !ok || process.PPID <= 1 {
				break
			}
			owned[process.PPID] = struct{}{}
			pid = process.PPID
		}
	}
	// On Darwin, `caffeinate utility ...` execs the utility in the original
	// process and leaves an assertion-holder child whose command line retains
	// the original caffeinate invocation. It is therefore a sibling of the
	// benchmark below a controller ancestor, not a benchmark descendant. Trust
	// only that exact stock sidecar. Phase 0 fixes the launcher spelling to
	// `/usr/bin/caffeinate -dimsu`; accepting any other option set requires an
	// explicit code and policy review. Do not expand descendants again, or a
	// child of the assertion helper could become owned without proof.
	controllerPIDs := make([]int, 0, len(controllers))
	for pid := range controllers {
		controllerPIDs = append(controllerPIDs, pid)
	}
	sort.Ints(controllerPIDs)
	for _, controllerPID := range controllerPIDs {
		controller := controllers[controllerPID]
		want := "/usr/bin/caffeinate -dimsu " + controller.Command
		var match int
		for _, process := range processes {
			if _, alreadyOwned := owned[process.PID]; alreadyOwned {
				continue
			}
			if process.PPID != controllerPID || process.Command != want {
				continue
			}
			if match != 0 {
				return nil, fmt.Errorf("host guard: ambiguous caffeinate sidecars for controller PID %d", controllerPID)
			}
			match = process.PID
		}
		if match != 0 {
			owned[match] = struct{}{}
		}
	}
	return owned, nil
}

func foreignCPUUsage(processes []processUsage, owned map[int]struct{}) (float64, []string) {
	var total float64
	var foreign []processUsage
	for _, process := range processes {
		if _, ok := owned[process.PID]; ok {
			continue
		}
		total += process.CPU
		if process.CPU > 0 {
			foreign = append(foreign, process)
		}
	}
	sort.Slice(foreign, func(i, j int) bool {
		if foreign[i].CPU != foreign[j].CPU {
			return foreign[i].CPU > foreign[j].CPU
		}
		return foreign[i].PID < foreign[j].PID
	})
	if len(foreign) > 8 {
		foreign = foreign[:8]
	}
	offenders := make([]string, 0, len(foreign))
	for _, process := range foreign {
		offenders = append(offenders, formatProcessUsage(process))
	}
	return total, offenders
}

func formatProcessUsage(process processUsage) string {
	return fmt.Sprintf("pid=%d cpu=%.1f%% command=%s", process.PID, process.CPU, process.Command)
}

func validateContinuousEnvironment(baseline, current EnvSnapshot, maxLoad1Drift float64) error {
	if baseline.BootIdentity == "" || current.BootIdentity != baseline.BootIdentity {
		return fmt.Errorf("host guard: boot identity changed or became unavailable")
	}
	if current.LogicalCPUs != baseline.LogicalCPUs || current.MemoryBytes != baseline.MemoryBytes {
		return fmt.Errorf("host guard: CPU/memory topology changed")
	}
	if source := powerSource(current.PMSetBattery); source == "" || source != powerSource(baseline.PMSetBattery) {
		return fmt.Errorf("host guard: power source changed or became unavailable")
	}
	if !thermalClean(current.PMSetThermal) {
		return fmt.Errorf("host guard: thermal or performance warning recorded")
	}
	if maxLoad1Drift <= 0 || current.Load1-baseline.Load1 > maxLoad1Drift {
		return fmt.Errorf("host guard: load1 drift %.2f exceeds %.2f (baseline %.2f, current %.2f)", current.Load1-baseline.Load1, maxLoad1Drift, baseline.Load1, current.Load1)
	}
	return nil
}

func ownedPIDs(values ...int) map[int]struct{} {
	result := make(map[int]struct{}, len(values)+1)
	result[os.Getpid()] = struct{}{}
	for _, value := range values {
		if value > 0 {
			result[value] = struct{}{}
		}
	}
	return result
}
