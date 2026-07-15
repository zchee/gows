//go:build darwin || linux

package support

import "syscall"

func processRusage(raw any) Usage {
	ru, ok := raw.(*syscall.Rusage)
	if !ok || ru == nil {
		return Usage{}
	}
	rss, ok := normalizeMaxRSS(int64(ru.Maxrss))
	if !ok {
		return Usage{}
	}
	return Usage{
		Available:   true,
		CPUSeconds:  timevalSeconds(ru.Utime) + timevalSeconds(ru.Stime),
		MaxRSSBytes: rss,
		Source:      "getrusage",
	}
}

func selfRusage() Usage {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return Usage{}
	}
	return processRusage(&ru)
}

func timevalSeconds(value syscall.Timeval) float64 {
	return float64(value.Sec) + float64(value.Usec)/1e6
}
