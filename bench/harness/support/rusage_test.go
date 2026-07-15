package support

import (
	"syscall"
	"testing"
)

func TestRusageStats(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ru      *syscall.Rusage
		wantCPU float64
		wantRSS int64
	}{
		"nil rusage": {},
		"user plus system with fractional seconds": {
			ru: &syscall.Rusage{
				Utime:  syscall.Timeval{Sec: 1, Usec: 500000},
				Stime:  syscall.Timeval{Sec: 2, Usec: 250000},
				Maxrss: 1 << 20,
			},
			wantCPU: 3.75,
			wantRSS: 1 << 20,
		},
		"zero rusage": {
			ru: &syscall.Rusage{},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cpu, rss := RusageStats(tt.ru)
			if cpu != tt.wantCPU {
				t.Errorf("cpuSeconds = %v, want %v", cpu, tt.wantCPU)
			}
			if rss != tt.wantRSS {
				t.Errorf("maxRSSBytes = %d, want %d", rss, tt.wantRSS)
			}
		})
	}
}
