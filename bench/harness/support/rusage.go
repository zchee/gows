package support

import "fmt"

// Usage is normalized process resource usage. Available distinguishes a real
// zero measurement from an unsupported or unavailable collector.
type Usage struct {
	Available   bool    `json:"available"`
	CPUSeconds  float64 `json:"cpu_seconds"`
	MaxRSSBytes int64   `json:"maxrss_bytes"`
	Source      string  `json:"source"`
}

// ProcessRusage normalizes an os.ProcessState.SysUsage value for the current
// operating system.
func ProcessRusage(raw any) Usage {
	return processRusage(raw)
}

// SelfRusage returns normalized usage for the calling process.
func SelfRusage() Usage {
	return selfRusage()
}

// UsageDelta converts cumulative getrusage readings into a measurement-window
// CPU delta while retaining the after-reading peak RSS. Availability remains
// explicit: incomparable or regressing readings are rejected rather than
// encoded as plausible zeroes.
func UsageDelta(before, after Usage) (Usage, error) {
	if !before.Available || !after.Available {
		return Usage{}, fmt.Errorf("support: rusage is unavailable before or after the measurement window")
	}
	if before.Source == "" || after.Source != before.Source {
		return Usage{}, fmt.Errorf("support: rusage source changed from %q to %q", before.Source, after.Source)
	}
	if after.CPUSeconds < before.CPUSeconds {
		return Usage{}, fmt.Errorf("support: cumulative CPU seconds regressed from %g to %g", before.CPUSeconds, after.CPUSeconds)
	}
	if after.MaxRSSBytes < 0 {
		return Usage{}, fmt.Errorf("support: negative MaxRSS %d", after.MaxRSSBytes)
	}
	return Usage{
		Available:   true,
		CPUSeconds:  after.CPUSeconds - before.CPUSeconds,
		MaxRSSBytes: after.MaxRSSBytes,
		Source:      before.Source + "-window-delta",
	}, nil
}
