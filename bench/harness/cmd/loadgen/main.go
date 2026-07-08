// Command loadgen drives WebSocket load against an echoserver instance
// (any -lib backend) using a single fast, low-level client implementation
// (gobwas/ws) so every server-side comparison is measured through an
// identical client. See bench/README.md for methodology.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/zchee/gows/bench/harness/support"
)

// reservoirCap bounds per-connection latency sample memory; see
// support.Recorder.
const reservoirCap = 20_000

// connRW adapts the (net.Conn, *bufio.Reader) pair returned by ws.Dial into
// a single io.ReadWriter, since ws.Dial's bufio.Reader may hold bytes
// buffered during the HTTP handshake that a raw conn.Read would skip. ws.Dial
// returns a nil *bufio.Reader when nothing was buffered, in which case reads
// go straight to the net.Conn.
type connRW struct {
	r *bufio.Reader
	net.Conn
}

func (c *connRW) Read(p []byte) (int, error) {
	if c.r != nil {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9001", "echoserver websocket address (host:port)")
	debugAddr := flag.String("debug-addr", "127.0.0.1:9101", "echoserver /debug/memstats address")
	conns := flag.Int("conns", 200, "number of concurrent connections")
	payloadSize := flag.Int("payload", 1024, "message payload size in bytes")
	duration := flag.Duration("duration", 15*time.Second, "measurement duration")
	warmup := flag.Duration("warmup", 3*time.Second, "warmup duration before measurement starts")
	rate := flag.Int("rate", 0, "target aggregate messages/sec across all connections (0 = saturate)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := support.WaitForDebugServer(ctx, *debugAddr); err != nil {
		log.Fatalf("loadgen: server not reachable at %s: %v", *debugAddr, err)
	}

	payload := support.DeterministicPayload(*payloadSize)

	clients := make([]*connRW, *conns)
	url := "ws://" + *addr + "/"
	for i := range clients {
		nc, br, _, err := ws.Dial(ctx, url)
		if err != nil {
			log.Fatalf("loadgen: dial %d/%d failed: %v", i+1, *conns, err)
		}
		clients[i] = &connRW{r: br, Conn: nc}
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()

	var (
		phase      atomic.Int32 // 0=warmup, 1=measure, 2=done
		totalMsgs  atomic.Int64
		totalBytes atomic.Int64
	)

	var perConnInterval time.Duration
	if *rate > 0 {
		perConnInterval = max(time.Duration(int64(len(clients))*int64(time.Second)/int64(*rate)), time.Microsecond)
	}

	stopCh := make(chan struct{})
	recorders := make([]*support.Recorder, len(clients))
	var wg sync.WaitGroup
	for i, c := range clients {
		rec := support.NewRecorder(reservoirCap)
		recorders[i] = rec
		wg.Add(1)
		go func(c *connRW, rec *support.Recorder) {
			defer wg.Done()
			runConn(c, payload, perConnInterval, stopCh, &phase, rec, &totalMsgs, &totalBytes)
		}(c, rec)
	}

	log.Printf("loadgen: dialed %d conns to %s, warming up for %s", *conns, *addr, *warmup)
	select {
	case <-time.After(*warmup):
	case <-ctx.Done():
	}

	before, err := support.FetchMemSnapshot(ctx, *debugAddr)
	if err != nil {
		log.Fatalf("loadgen: fetch pre-measurement memstats: %v", err)
	}
	// Warmup samples were never recorded: runConn only calls rec.Add and
	// bumps the counters once phase reaches 1, so nothing further needs
	// resetting here beyond a defensive counter zeroing.
	totalMsgs.Store(0)
	totalBytes.Store(0)
	phase.Store(1)
	measureStart := time.Now()
	log.Printf("loadgen: measuring for %s", *duration)

	select {
	case <-time.After(*duration):
	case <-ctx.Done():
	}
	measureElapsed := time.Since(measureStart)
	phase.Store(2)
	close(stopCh)
	wg.Wait()

	after, err := support.FetchMemSnapshot(ctx, *debugAddr)
	if err != nil {
		log.Fatalf("loadgen: fetch post-measurement memstats: %v", err)
	}

	var allSamples []time.Duration
	for _, rec := range recorders {
		allSamples = append(allSamples, rec.Samples()...)
	}
	pct := support.ComputePercentiles(allSamples)

	msgs := totalMsgs.Load()
	bytes := totalBytes.Load()
	msgsPerSec := float64(msgs) / measureElapsed.Seconds()
	mbPerSec := float64(bytes) / measureElapsed.Seconds() / (1024 * 1024)

	fmt.Printf("addr=%s conns=%d payload=%dB duration=%s\n", *addr, *conns, *payloadSize, measureElapsed)
	fmt.Printf("throughput: %.0f msg/s, %.2f MB/s\n", msgsPerSec, mbPerSec)
	fmt.Printf("latency: p50=%s p90=%s p99=%s p999=%s min=%s max=%s (n=%d)\n",
		pct.P50, pct.P90, pct.P99, pct.P999, pct.Min, pct.Max, pct.N)
	fmt.Printf("server mallocs delta: %d (%.2f/msg), total_alloc delta: %d bytes\n",
		after.Mallocs-before.Mallocs, float64(after.Mallocs-before.Mallocs)/float64(max(msgs, 1)),
		after.TotalAlloc-before.TotalAlloc)
}

// runConn drives one connection's request/response loop until stopCh
// closes. During phase==0 (warmup) it still sends traffic but does not
// record latency samples or contribute to the throughput counters, which
// are reset by main right before phase flips to 1 (measure).
func runConn(
	c *connRW,
	payloadTemplate []byte,
	interval time.Duration,
	stopCh <-chan struct{},
	phase *atomic.Int32,
	rec *support.Recorder,
	totalMsgs, totalBytes *atomic.Int64,
) {
	buf := make([]byte, len(payloadTemplate))
	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for {
		select {
		case <-stopCh:
			return
		default:
		}
		if ticker != nil {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
			}
		}

		copy(buf, payloadTemplate)
		start := time.Now()
		if err := wsutil.WriteClientMessage(c, ws.OpBinary, buf); err != nil {
			return
		}
		resp, _, err := wsutil.ReadServerData(c)
		if err != nil {
			return
		}
		latency := time.Since(start)

		if phase.Load() == 1 {
			rec.Add(latency)
			totalMsgs.Add(1)
			totalBytes.Add(int64(len(resp)) * 2) // request + echoed response
		}
	}
}
