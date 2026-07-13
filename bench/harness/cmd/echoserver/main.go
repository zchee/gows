// Command echoserver runs a plain WebSocket echo server (read message, write
// same opcode+payload back) using one of several third-party libraries,
// under an identical configuration, for cross-library throughput/latency/
// allocation comparison. See bench/README.md for the fairness rules.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/zchee/gows/bench/harness/support"
)

// bufferSize is the shared read/write buffer size (bytes) applied to every
// library that exposes such a knob, per plan §8 fairness rules. It is also the
// read-buffer size of the stock "gows" and "gows-noutf8" variants.
const bufferSize = 4096

// runner starts a blocking echo server on addr and returns when ctx is
// canceled (or immediately on a fatal startup error). cfg carries the
// flag-derived configuration (gows read buffer, TCP_NOTSENT_LOWAT, trace
// capture); backends that cannot honor a given field document that they ignore
// it.
type runner func(ctx context.Context, addr string, cfg serverConfig) error

var runners = map[string]runner{
	"gorilla":  runGorilla,
	"coder":    runCoder,
	"gobwas":   runGobwas,
	"gws":      runGWS,
	"quickws":  runQuickWS,
	"fasthttp": runFastHTTP,
	"nbio":     runNBIO,
	// The four gows variants share runGows; their read-buffer size and UTF-8
	// setting come from gowsVariants, applied to cfg before dispatch.
	"gows":         runGows,
	"gows-noutf8":  runGows,
	"gows-rbuf1k":  runGows,
	"gows-rbuf16k": runGows,
	"gows-serve":   runGows,
}

// knownLibs returns the registered -lib names in sorted order, so the flag
// usage text and the unknown-lib error stay in sync with the runners map.
func knownLibs() []string {
	libs := make([]string, 0, len(runners))
	for name := range runners {
		libs = append(libs, name)
	}
	slices.Sort(libs)
	return libs
}

func main() {
	libList := strings.Join(knownLibs(), "|")
	lib := flag.String("lib", "", "websocket library to serve with: "+libList)
	addr := flag.String("addr", ":9001", "websocket listen address")
	debugAddr := flag.String("debug-addr", ":9101", "HTTP address exposing GET /debug/memstats (out of the hot path)")
	notsentLowat := flag.Int("notsent-lowat", 0, "TCP_NOTSENT_LOWAT bytes applied to every accepted connection before upgrade (0 = off; darwin only)")
	traceFile := flag.String("trace-file", "", "capture runtime/trace to this path once, starting after the first connection plus -trace-delay (empty = off)")
	traceDelay := flag.Duration("trace-delay", 10*time.Second, "delay after the first accepted connection before runtime/trace capture starts")
	traceDuration := flag.Duration("trace-duration", 5*time.Second, "runtime/trace capture window length")
	flag.Parse()

	run, ok := runners[*lib]
	if !ok {
		fmt.Fprintf(os.Stderr, "echoserver: unknown -lib %q (want one of %s)\n", *lib, libList)
		os.Exit(2)
	}

	if err := validateFlags(flagConfig{
		notsentLowat:   *notsentLowat,
		lowatSupported: notsentLowatSupported,
		traceFile:      *traceFile,
		traceDelay:     *traceDelay,
		traceDuration:  *traceDuration,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "echoserver: %v\n", err)
		os.Exit(2)
	}

	cfg := serverConfig{notsentLowat: *notsentLowat}
	if v, ok := gowsVariants[*lib]; ok {
		cfg.readBufSize = v.readBufSize
		cfg.skipUTF8 = v.skipUTF8
		cfg.useServe = v.useServe
	}
	if *traceFile != "" {
		cfg.tracer = newTraceController(*traceFile, *traceDelay, *traceDuration)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	debugSrv, debugErrCh := support.StartDebugServer(*debugAddr)
	defer debugSrv.Close()

	log.Printf("echoserver: lib=%s addr=%s debug-addr=%s buffer=%dB", *lib, *addr, *debugAddr, bufferSize)
	if v, ok := gowsVariants[*lib]; ok && v.readBufSize != bufferSize {
		log.Printf("echoserver: gows read buffer=%dB", v.readBufSize)
	}
	if cfg.notsentLowat > 0 {
		log.Printf("echoserver: TCP_NOTSENT_LOWAT=%d bytes per accepted connection", cfg.notsentLowat)
	}
	if cfg.tracer != nil {
		log.Printf("echoserver: trace capture armed: file=%s delay=%s duration=%s", *traceFile, *traceDelay, *traceDuration)
	}

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- run(ctx, *addr, cfg) }()

	select {
	case err := <-runErrCh:
		if err != nil {
			log.Fatalf("echoserver: %s: %v", *lib, err)
		}
	case err := <-debugErrCh:
		log.Fatalf("echoserver: debug server: %v", err)
	case <-ctx.Done():
		<-runErrCh
	}
}

// flagConfig is the subset of parsed flags that validateFlags checks.
type flagConfig struct {
	notsentLowat   int
	lowatSupported bool
	traceFile      string
	traceDelay     time.Duration
	traceDuration  time.Duration
}

// validateFlags reports the first problem with the new echoserver flag
// combination, or nil when the configuration is runnable. It is pure so the
// flag rules are unit testable without binding a socket or starting a trace.
func validateFlags(fc flagConfig) error {
	if fc.notsentLowat < 0 {
		return fmt.Errorf("-notsent-lowat must be >= 0, got %d", fc.notsentLowat)
	}
	if fc.notsentLowat > 0 && !fc.lowatSupported {
		return fmt.Errorf("-notsent-lowat is unsupported on GOOS %s", runtime.GOOS)
	}
	if fc.traceFile != "" {
		if fc.traceDelay < 0 {
			return fmt.Errorf("-trace-delay must be >= 0, got %s", fc.traceDelay)
		}
		if fc.traceDuration <= 0 {
			return fmt.Errorf("-trace-duration must be > 0, got %s", fc.traceDuration)
		}
	}
	return nil
}
