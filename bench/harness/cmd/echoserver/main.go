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
	"syscall"

	"github.com/zchee/gows/bench/harness/support"
)

// bufferSize is the shared read/write buffer size (bytes) applied to every
// library that exposes such a knob, per plan §8 fairness rules.
const bufferSize = 4096

// runner starts a blocking echo server on addr and returns when ctx is
// canceled (or immediately on a fatal startup error).
type runner func(ctx context.Context, addr string) error

var runners = map[string]runner{
	"gorilla":     runGorilla,
	"coder":       runCoder,
	"gobwas":      runGobwas,
	"gws":         runGWS,
	"quickws":     runQuickWS,
	"fasthttp":    runFastHTTP,
	"nbio":        runNBIO,
	"gows":        runGows,
	"gows-noutf8": runGowsNoUTF8,
}

func main() {
	lib := flag.String("lib", "", "websocket library to serve with: gorilla|coder|gobwas|gws|quickws|fasthttp|nbio|gows|gows-noutf8")
	addr := flag.String("addr", ":9001", "websocket listen address")
	debugAddr := flag.String("debug-addr", ":9101", "HTTP address exposing GET /debug/memstats (out of the hot path)")
	flag.Parse()

	run, ok := runners[*lib]
	if !ok {
		fmt.Fprintf(os.Stderr, "echoserver: unknown -lib %q (want one of gorilla|coder|gobwas|gws|quickws|fasthttp|nbio|gows|gows-noutf8)\n", *lib)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	debugSrv, debugErrCh := support.StartDebugServer(*debugAddr)
	defer debugSrv.Close()

	log.Printf("echoserver: lib=%s addr=%s debug-addr=%s buffer=%dB", *lib, *addr, *debugAddr, bufferSize)

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- run(ctx, *addr) }()

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
