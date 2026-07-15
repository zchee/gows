package support

import "syscall"

// RusageStats extracts total CPU seconds (user+system) and peak resident set
// size from ru. It is the one conversion point shared by loadgen (its own
// getrusage(RUSAGE_SELF)) and benchrun (the echoserver child's post-wait
// rusage), so both sides of a resource ratio use identical arithmetic.
// Maxrss is bytes on darwin, the harness's target platform.
func RusageStats(ru *syscall.Rusage) (cpuSeconds float64, maxRSSBytes int64) {
	if ru == nil {
		return 0, 0
	}
	return timevalSeconds(ru.Utime) + timevalSeconds(ru.Stime), int64(ru.Maxrss)
}

// timevalSeconds converts a syscall.Timeval to fractional seconds.
func timevalSeconds(t syscall.Timeval) float64 {
	return float64(t.Sec) + float64(t.Usec)/1e6
}
