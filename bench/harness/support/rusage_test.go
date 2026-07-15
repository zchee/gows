package support

import (
	"runtime"
	"syscall"
	"testing"
)

func TestRusageStats(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ru   any
		want Usage
	}{
		"nil rusage is unavailable rather than a fake zero": {},
		"user plus system with fractional seconds": {
			ru: &syscall.Rusage{
				Utime:  syscall.Timeval{Sec: 1, Usec: 500000},
				Stime:  syscall.Timeval{Sec: 2, Usec: 250000},
				Maxrss: 1 << 20,
			},
			want: Usage{
				Available:   true,
				CPUSeconds:  3.75,
				MaxRSSBytes: 1 << 20,
				Source:      "getrusage",
			},
		},
		"zero rusage": {
			ru: &syscall.Rusage{},
			want: Usage{
				Available: true,
				Source:    "getrusage",
			},
		},
	}
	if runtime.GOOS == "linux" {
		tt := tests["user plus system with fractional seconds"]
		tt.want.MaxRSSBytes *= 1024
		tests["user plus system with fractional seconds"] = tt
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := ProcessRusage(tt.ru)
			if got != tt.want {
				t.Errorf("ProcessRusage = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestUsageDelta(t *testing.T) {
	t.Parallel()

	got, err := UsageDelta(
		Usage{Available: true, CPUSeconds: 1.25, MaxRSSBytes: 1_000, Source: "getrusage"},
		Usage{Available: true, CPUSeconds: 3.5, MaxRSSBytes: 4_096, Source: "getrusage"},
	)
	if err != nil {
		t.Fatalf("UsageDelta: %v", err)
	}
	if !got.Available || got.CPUSeconds != 2.25 || got.MaxRSSBytes != 4_096 || got.Source != "getrusage-window-delta" {
		t.Fatalf("UsageDelta = %+v", got)
	}

	if _, err := UsageDelta(Usage{}, Usage{}); err == nil {
		t.Fatal("UsageDelta accepted unavailable readings")
	}
	if _, err := UsageDelta(
		Usage{Available: true, CPUSeconds: 2, Source: "getrusage"},
		Usage{Available: true, CPUSeconds: 1, Source: "getrusage"},
	); err == nil {
		t.Fatal("UsageDelta accepted regressing CPU time")
	}
}
