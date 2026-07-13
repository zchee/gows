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

	"github.com/go-json-experiment/json"
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
	inflight := flag.Int("inflight", 1, "messages kept outstanding per connection (1 = closed request/response loop, >1 = pipelined)")
	duration := flag.Duration("duration", 15*time.Second, "measurement duration")
	warmup := flag.Duration("warmup", 3*time.Second, "warmup duration before measurement starts")
	rate := flag.Int("rate", 0, "target aggregate messages/sec across all connections (0 = saturate)")
	jsonOut := flag.Bool("json", false, "emit one machine-readable JSON result line to stdout and suppress the human summary")
	flag.Parse()

	if *inflight < 1 {
		log.Fatalf("loadgen: -inflight must be >= 1, got %d", *inflight)
	}
	if *inflight**payloadSize > support.MaxInflightBytes {
		log.Fatalf("loadgen: -inflight (%d) * -payload (%d) = %d exceeds the %d-byte pipeline cap; a larger window risks deadlocking the synchronous write path against unread echoes",
			*inflight, *payloadSize, *inflight**payloadSize, support.MaxInflightBytes)
	}
	if *inflight > 1 && *rate > 0 {
		log.Fatalf("loadgen: -rate %d with -inflight %d is unsupported: open-loop rate pacing and multi-inflight pipelining measure different things; use one or the other", *rate, *inflight)
	}

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
		phase       atomic.Int32 // 0=warmup, 1=measure, 2=done
		totalMsgs   atomic.Int64
		totalBytes  atomic.Int64
		totalErrs   atomic.Int64
		sawMismatch atomic.Bool // set if any echo failed byte-for-byte verification
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
			if *inflight <= 1 {
				runConn(c, payload, perConnInterval, stopCh, &phase, rec, &totalMsgs, &totalBytes, &totalErrs, &sawMismatch)
				return
			}
			runConnPipelined(c, payload, *inflight, stopCh, &phase, rec, &totalMsgs, &totalBytes, &totalErrs, &sawMismatch)
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

	// A verification mismatch means the server echoed corrupt bytes: the
	// throughput figure would be meaningless, so abort the run instead of
	// emitting a result. Transient I/O errors remain counted (Errors) but
	// non-fatal, matching the prior behavior.
	if sawMismatch.Load() {
		log.Fatalf("loadgen: echo verification failed (%d errors recorded); aborting run", totalErrs.Load())
	}

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

	clientCPUSeconds, clientMaxRSSBytes := selfRusage()

	if *jsonOut {
		result := support.LoadgenResult{
			Connections:                 *conns,
			PayloadBytes:                *payloadSize,
			Inflight:                    *inflight,
			WarmupNanoseconds:           warmup.Nanoseconds(),
			DurationNanoseconds:         measureElapsed.Nanoseconds(),
			Messages:                    msgs,
			ThroughputMessagesPerSecond: msgsPerSec,
			P50Nanoseconds:              pct.P50.Nanoseconds(),
			P90Nanoseconds:              pct.P90.Nanoseconds(),
			P99Nanoseconds:              pct.P99.Nanoseconds(),
			P999Nanoseconds:             pct.P999.Nanoseconds(),
			Errors:                      int(totalErrs.Load()),
			ClientCPUSeconds:            clientCPUSeconds,
			ClientMaxRSSBytes:           clientMaxRSSBytes,
		}
		line, err := json.Marshal(result)
		if err != nil {
			log.Fatalf("loadgen: marshal json result: %v", err)
		}
		fmt.Printf("%s\n", line)
		return
	}

	fmt.Printf("addr=%s conns=%d payload=%dB duration=%s\n", *addr, *conns, *payloadSize, measureElapsed)
	fmt.Printf("throughput: %.0f msg/s, %.2f MB/s\n", msgsPerSec, mbPerSec)
	fmt.Printf("latency: p50=%s p90=%s p99=%s p999=%s min=%s max=%s (n=%d)\n",
		pct.P50, pct.P90, pct.P99, pct.P999, pct.Min, pct.Max, pct.N)
	fmt.Printf("server mallocs delta: %d (%.2f/msg), total_alloc delta: %d bytes\n",
		after.Mallocs-before.Mallocs, float64(after.Mallocs-before.Mallocs)/float64(max(msgs, 1)),
		after.TotalAlloc-before.TotalAlloc)
}

// selfRusage reports this loadgen process's total CPU seconds (user+system)
// and peak resident set size from getrusage(RUSAGE_SELF). Maxrss is bytes on
// darwin, the harness's target platform. Resource accounting comes from
// process rusage, never from a net.Conn counting wrapper on the message path.
func selfRusage() (cpuSeconds float64, maxRSSBytes int64) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, 0
	}
	timeval := func(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
	return timeval(ru.Utime) + timeval(ru.Stime), int64(ru.Maxrss)
}

// runConn drives one connection's closed request/response loop (one message
// outstanding at a time) until stopCh closes. During phase==0 (warmup) it
// still sends traffic but does not record latency samples or contribute to the
// throughput counters, which are reset by main right before phase flips to 1
// (measure). Every echo is verified byte-for-byte against the sent payload; a
// mismatch sets sawMismatch so main can abort the run.
func runConn(
	c *connRW,
	payloadTemplate []byte,
	interval time.Duration,
	stopCh <-chan struct{},
	phase *atomic.Int32,
	rec *support.Recorder,
	totalMsgs, totalBytes, totalErrs *atomic.Int64,
	sawMismatch *atomic.Bool,
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
			if phase.Load() == 1 {
				totalErrs.Add(1)
			}
			return
		}
		resp, _, err := wsutil.ReadServerData(c)
		if err != nil {
			if phase.Load() == 1 {
				totalErrs.Add(1)
			}
			return
		}
		if verr := support.VerifyEcho(payloadTemplate, resp); verr != nil {
			if phase.Load() == 1 {
				totalErrs.Add(1)
			}
			sawMismatch.Store(true)
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

// runConnPipelined drives one connection with up to inflight messages
// outstanding at once. A dedicated writer goroutine keeps the window primed
// while this goroutine reads and verifies echoes. Splitting the synchronous
// gobwas read and write onto two goroutines is what makes multi-inflight safe:
// a single interleaved goroutine that primed k writes before reading could
// deadlock once k*payload filled the socket buffers (the server blocks writing
// echoes we are not reading, so our next write blocks too). Here the reader
// drains continuously, so the writer only ever blocks acquiring a window
// credit, which the reader returns on every echo. The window caps the number
// of in-flight messages and preserves FIFO echo attribution (a single
// connection echoes in send order).
func runConnPipelined(
	c *connRW,
	payloadTemplate []byte,
	inflight int,
	stopCh <-chan struct{},
	phase *atomic.Int32,
	rec *support.Recorder,
	totalMsgs, totalBytes, totalErrs *atomic.Int64,
	sawMismatch *atomic.Bool,
) {
	win := support.NewPipelineWindow(inflight, payloadTemplate)
	connDone := make(chan struct{}) // closed by the reader when this connection stops
	writerStop := make(chan struct{})

	// One supervisor goroutine reconciles the two shutdown signals and then
	// sets a past deadline on the connection so neither peer goroutine can stay
	// parked in a blocking read or write. On stopCh (normal end) this unblocks
	// the reader, which is otherwise waiting in ReadServerData for an echo the
	// stopped writer will never trigger; phase is already 2 by then, so the
	// deadline error is not counted. On connDone (the reader stopped first,
	// e.g. a mismatch on a still-open connection) it unblocks a writer that
	// could otherwise wedge on a full send buffer once the reader stops
	// draining.
	go func() {
		select {
		case <-stopCh:
		case <-connDone:
		}
		_ = c.SetDeadline(time.Now())
		close(writerStop)
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(payloadTemplate))
		copy(buf, payloadTemplate)
		for {
			select {
			case <-writerStop:
				return
			default:
			}
			// Wait for a free credit first, then stamp the send time at the
			// actual hand-off to the write path (never counting the credit
			// wait as latency), then transmit.
			if !win.Acquire(writerStop) {
				return
			}
			win.Record(time.Now())
			if err := wsutil.WriteClientMessage(c, ws.OpBinary, buf); err != nil {
				if phase.Load() == 1 {
					totalErrs.Add(1)
				}
				return
			}
		}
	}()

	for {
		echo, _, err := wsutil.ReadServerData(c)
		recvAt := time.Now()
		if err != nil {
			if phase.Load() == 1 {
				totalErrs.Add(1)
			}
			break
		}
		latency, _, verr := win.Receive(echo, recvAt)
		if verr != nil {
			if phase.Load() == 1 {
				totalErrs.Add(1)
			}
			sawMismatch.Store(true)
			break
		}
		if phase.Load() == 1 {
			rec.Add(latency)
			totalMsgs.Add(1)
			totalBytes.Add(int64(len(echo)) * 2) // request + echoed response
		}
	}
	close(connDone)
	wg.Wait()
}
