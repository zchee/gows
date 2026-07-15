package main

import (
	"testing"
	"time"

	"github.com/zchee/gows"
)

// TestGowsVariants verifies that every gows -lib variant is registered in the
// runners map and resolves to the read-buffer size, UTF-8 setting, and echo
// loop the experiments depend on. The read-buffer geometry is hypothesis H1's
// manipulated variable, and useServe selects the drain-and-coalesce loop that
// the paired final gate measures as gows-serve, so a wrong value in either
// would silently invalidate its experiment.
func TestGowsVariants(t *testing.T) {
	tests := map[string]struct {
		wantReadBuf  int
		wantSkipUTF8 bool
		wantUseServe bool
	}{
		"gows":         {wantReadBuf: bufferSize},
		"gows-noutf8":  {wantReadBuf: bufferSize, wantSkipUTF8: true},
		"gows-rbuf1k":  {wantReadBuf: 1024 + gows.MaxHeaderSize},
		"gows-rbuf16k": {wantReadBuf: 16 * 1024},
		"gows-serve":   {wantReadBuf: bufferSize, wantUseServe: true},
	}
	if got, want := len(gowsVariants), len(tests); got != want {
		t.Errorf("gowsVariants has %d entries, want %d (update this test when adding a variant)", got, want)
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := runners[name]; !ok {
				t.Fatalf("variant %q is not registered in runners", name)
			}
			v, ok := gowsVariants[name]
			if !ok {
				t.Fatalf("variant %q is missing from gowsVariants", name)
			}
			if v.readBufSize != tc.wantReadBuf {
				t.Errorf("readBufSize = %d, want %d", v.readBufSize, tc.wantReadBuf)
			}
			if v.skipUTF8 != tc.wantSkipUTF8 {
				t.Errorf("skipUTF8 = %v, want %v", v.skipUTF8, tc.wantSkipUTF8)
			}
			if v.useServe != tc.wantUseServe {
				t.Errorf("useServe = %v, want %v", v.useServe, tc.wantUseServe)
			}
		})
	}
}

// TestGowsRbuf1kFitsFrame guards the rbuf1kSize invariant: a 1 KiB payload plus
// a maximum frame header must fit in the read buffer, and the buffer must not
// exceed the 16 KiB adaptive ceiling that the stock and 16k variants bracket.
func TestGowsRbuf1kFitsFrame(t *testing.T) {
	if rbuf1kSize < 1024+gows.MaxHeaderSize {
		t.Fatalf("rbuf1kSize = %d is too small to hold a 1 KiB frame + %d-byte header", rbuf1kSize, gows.MaxHeaderSize)
	}
	if rbuf1kSize >= bufferSize {
		t.Fatalf("rbuf1kSize = %d should be smaller than the stock buffer %d for H1 to sweep downward", rbuf1kSize, bufferSize)
	}
}

// TestValidateFlags covers the new flag combinations. Actual socket options and
// trace capture are exercised only through their platform seams, never here, so
// this test stays privilege- and timing-free.
func TestValidateFlags(t *testing.T) {
	tests := map[string]struct {
		fc      flagConfig
		wantErr bool
	}{
		"defaults": {
			fc: flagConfig{traceDelay: 10 * time.Second, traceDuration: 5 * time.Second},
		},
		"lowat off unsupported ok": {
			fc: flagConfig{notsentLowat: 0, lowatSupported: false},
		},
		"lowat on supported": {
			fc: flagConfig{notsentLowat: 16384, lowatSupported: true},
		},
		"lowat on unsupported": {
			fc:      flagConfig{notsentLowat: 16384, lowatSupported: false},
			wantErr: true,
		},
		"lowat negative": {
			fc:      flagConfig{notsentLowat: -1, lowatSupported: true},
			wantErr: true,
		},
		"trace valid": {
			fc: flagConfig{traceFile: "/tmp/t.out", traceDelay: 0, traceDuration: time.Second},
		},
		"trace zero duration": {
			fc:      flagConfig{traceFile: "/tmp/t.out", traceDelay: time.Second, traceDuration: 0},
			wantErr: true,
		},
		"trace negative duration": {
			fc:      flagConfig{traceFile: "/tmp/t.out", traceDelay: 0, traceDuration: -time.Second},
			wantErr: true,
		},
		"trace negative delay": {
			fc:      flagConfig{traceFile: "/tmp/t.out", traceDelay: -time.Second, traceDuration: time.Second},
			wantErr: true,
		},
		"trace unset ignores bad windows": {
			fc: flagConfig{traceFile: "", traceDelay: -time.Second, traceDuration: 0},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateFlags(tc.fc)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
