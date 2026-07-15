// Command loadgen drives WebSocket load against an echoserver instance
// (any -lib backend) using a single fast, low-level client implementation so
// every server-side comparison is measured through an identical client. The
// client transport is selectable with -client={gows,gobwas}: "gows" (default)
// drives gows's own client stack, whose NEON masking kernel and copy-free write
// path make the client far cheaper than the scalar gobwas path it replaced;
// "gobwas" keeps the original gobwas/ws client so the prior configuration stays
// reproducible. See bench/README.md for methodology.
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
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/zchee/gows"
	"github.com/zchee/gows/bench/harness/support"
)

// reservoirCap bounds per-connection latency sample memory; see
// support.Recorder.
const reservoirCap = 20_000

// clientKind selects the WebSocket client transport loadgen uses to drive load.
// The client is identical for every server under test, so switching it changes
// only the client-side cost, never the fairness of a server-vs-server
// comparison.
type clientKind string

const (
	// clientGows drives load through gows's own client stack (Dial +
	// NewClientConn + WriteMessage/ReadMessage). Its NEON masking kernel and
	// copy-free write path are the point of this transport.
	clientGows clientKind = "gows"
	// clientGobwas drives load through the original gobwas/ws client, kept so
	// the pre-A2c configuration remains reproducible and any client-bias
	// question stays testable.
	clientGobwas clientKind = "gobwas"
)

// parseClientKind validates the -client flag value, returning the resolved
// clientKind or a descriptive error naming the accepted values. It is pure so
// the resolution logic is unit-testable without a network.
func parseClientKind(s string) (clientKind, error) {
	switch clientKind(s) {
	case clientGows, clientGobwas:
		return clientKind(s), nil
	default:
		return "", fmt.Errorf("loadgen: -client must be %q or %q, got %q", clientGows, clientGobwas, s)
	}
}

// wsClient is the transport contract the connection loops drive: a single
// binary WriteMessage, a single ReadMessage returning the next data payload,
// plus the deadline and close controls the pipelined shutdown path needs. The
// payload passed to WriteMessage is read-only and must not be mutated by the
// implementation (gobwas, which masks in place, copies into its own scratch to
// honor this; gows never mutates the caller's slice), so a single shared
// payload template can back every connection without per-message copying in the
// loops.
type wsClient interface {
	WriteMessage(p []byte) error
	ReadMessage() ([]byte, error)
	SetDeadline(t time.Time) error
	Close() error
}

// connRW adapts the (net.Conn, *bufio.Reader) pair returned by ws.Dial into a
// single io.ReadWriter, since ws.Dial's bufio.Reader may hold bytes buffered
// during the HTTP handshake that a raw conn.Read would skip. ws.Dial returns a
// nil *bufio.Reader when nothing was buffered, in which case reads go straight
// to the net.Conn.
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

// gobwasClient drives load through gobwas/ws's wsutil frame helpers.
// wsutil.WriteClientMessage masks the payload in place, so the read-only
// template is first copied into a per-connection scratch buffer; that copy
// preserves the historical behavior of the gobwas path exactly.
type gobwasClient struct {
	*connRW
	scratch []byte
}

func newGobwasClient(c *connRW, payloadLen int) *gobwasClient {
	return &gobwasClient{connRW: c, scratch: make([]byte, payloadLen)}
}

func (g *gobwasClient) WriteMessage(p []byte) error {
	n := copy(g.scratch, p)
	return wsutil.WriteClientMessage(g.connRW, ws.OpBinary, g.scratch[:n])
}

func (g *gobwasClient) ReadMessage() ([]byte, error) {
	resp, _, err := wsutil.ReadServerData(g.connRW)
	return resp, err
}

// gowsClient drives load through gows's own client Conn. The raw net.Conn is
// retained so Close and SetDeadline act directly on the socket (matching the
// gobwas path's ungraceful teardown) rather than triggering gows's WebSocket
// closing handshake, which would read from a connection whose peer goroutines
// have already stopped.
type gowsClient struct {
	conn net.Conn
	ws   *gows.Conn
}

func (g *gowsClient) WriteMessage(p []byte) error {
	return g.ws.WriteMessage(gows.OpcodeBinary, p)
}

func (g *gowsClient) ReadMessage() ([]byte, error) {
	_, msg, err := g.ws.ReadMessage()
	return msg, err
}

func (g *gowsClient) SetDeadline(t time.Time) error { return g.conn.SetDeadline(t) }

func (g *gowsClient) Close() error { return g.conn.Close() }

// dialClient opens one connection to url with the selected client transport.
// payloadLen sizes the gobwas scratch buffer and is ignored by the gows client.
func dialClient(ctx context.Context, kind clientKind, url string, payloadLen int) (wsClient, error) {
	switch kind {
	case clientGows:
		conn, hs, err := gows.Dial(ctx, url)
		if err != nil {
			return nil, err
		}
		c := gows.NewClientConn(conn, gows.WithBuffered(hs.Buffered))
		return &gowsClient{conn: conn, ws: c}, nil
	default: // clientGobwas
		nc, br, _, err := ws.Dial(ctx, url)
		if err != nil {
			return nil, err
		}
		return newGobwasClient(&connRW{r: br, Conn: nc}, payloadLen), nil
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9001", "echoserver websocket address (host:port)")
	debugAddr := flag.String("debug-addr", "127.0.0.1:9101", "echoserver /debug/memstats address")
	client := flag.String("client", string(clientGows), "client transport: gows (NEON-masking gows client stack) or gobwas (original gobwas/ws client)")
	conns := flag.Int("conns", 200, "number of concurrent connections")
	payloadSize := flag.Int("payload", 1024, "message payload size in bytes")
	inflight := flag.Int("inflight", 1, "messages kept outstanding per connection (1 = closed request/response loop, >1 = pipelined)")
	duration := flag.Duration("duration", 15*time.Second, "measurement duration")
	warmup := flag.Duration("warmup", 3*time.Second, "warmup duration before measurement starts")
	rate := flag.Int("rate", 0, "target aggregate messages/sec across all connections (0 = saturate)")
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile of the measurement window (not warmup or dialing) to this path")
	jsonOut := flag.Bool("json", false, "emit one machine-readable JSON result line to stdout and suppress the human summary")
	flag.Parse()

	kind, err := parseClientKind(*client)
	if err != nil {
		log.Fatalf("%v", err)
	}
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

	clients := make([]wsClient, *conns)
	url := "ws://" + *addr + "/"
	for i := range clients {
		c, err := dialClient(ctx, kind, url, *payloadSize)
		if err != nil {
			log.Fatalf("loadgen: dial %d/%d failed: %v", i+1, *conns, err)
		}
		clients[i] = c
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
		wg.Go(func() {
			if *inflight <= 1 {
				runConn(c, payload, perConnInterval, stopCh, &phase, rec, &totalMsgs, &totalBytes, &totalErrs, &sawMismatch)
				return
			}
			runConnPipelined(c, payload, *inflight, stopCh, &phase, rec, &totalMsgs, &totalBytes, &totalErrs, &sawMismatch)
		})
	}

	log.Printf("loadgen: dialed %d conns to %s with -client %s, warming up for %s", *conns, *addr, kind, *warmup)
	select {
	case <-time.After(*warmup):
	case <-ctx.Done():
	}

	before, err := support.FetchMemSnapshot(ctx, *debugAddr)
	if err != nil {
		log.Fatalf("loadgen: fetch pre-measurement memstats: %v", err)
	}

	// Profile only the measurement window: start after warmup and dialing, stop
	// before teardown, so the profile isolates steady-state per-message client
	// cost from one-time handshake and ramp costs.
	stopProfile := startCPUProfile(*cpuProfile)

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
	stopProfile()
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
			Client:                      string(kind),
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

	fmt.Printf("client=%s addr=%s conns=%d payload=%dB duration=%s\n", kind, *addr, *conns, *payloadSize, measureElapsed)
	fmt.Printf("throughput: %.0f msg/s, %.2f MB/s\n", msgsPerSec, mbPerSec)
	fmt.Printf("latency: p50=%s p90=%s p99=%s p999=%s min=%s max=%s (n=%d)\n",
		pct.P50, pct.P90, pct.P99, pct.P999, pct.Min, pct.Max, pct.N)
	fmt.Printf("server mallocs delta: %d (%.2f/msg), total_alloc delta: %d bytes\n",
		after.Mallocs-before.Mallocs, float64(after.Mallocs-before.Mallocs)/float64(max(msgs, 1)),
		after.TotalAlloc-before.TotalAlloc)
}

// startCPUProfile begins a CPU profile at path and returns a stop function. An
// empty path disables profiling and returns a no-op stop, so callers can always
// invoke the returned function unconditionally. A profile that cannot be
// created or started is fatal: a benchmark asked to profile that silently
// produced no profile would waste an exclusive run.
func startCPUProfile(path string) (stop func()) {
	if path == "" {
		return func() {}
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("loadgen: create cpu profile %s: %v", path, err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		log.Fatalf("loadgen: start cpu profile: %v", err)
	}
	return func() {
		pprof.StopCPUProfile()
		_ = f.Close()
	}
}

// selfRusage reports this loadgen process's total CPU seconds (user+system)
// and peak resident set size from getrusage(RUSAGE_SELF). Resource accounting
// comes from process rusage, never from a net.Conn counting wrapper on the
// message path.
func selfRusage() (cpuSeconds float64, maxRSSBytes int64) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, 0
	}
	return support.RusageStats(&ru)
}

// runConn drives one connection's closed request/response loop (one message
// outstanding at a time) until stopCh closes. During phase==0 (warmup) it
// still sends traffic but does not record latency samples or contribute to the
// throughput counters, which are reset by main right before phase flips to 1
// (measure). Every echo is verified byte-for-byte against the sent payload; a
// mismatch sets sawMismatch so main can abort the run. The payload template is
// read-only and shared across connections: the client transport never mutates
// it (gobwas copies into private scratch, gows masks in a private buffer), so
// no per-message copy is needed here.
func runConn(
	c wsClient,
	payloadTemplate []byte,
	interval time.Duration,
	stopCh <-chan struct{},
	phase *atomic.Int32,
	rec *support.Recorder,
	totalMsgs, totalBytes, totalErrs *atomic.Int64,
	sawMismatch *atomic.Bool,
) {
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

		start := time.Now()
		if err := c.WriteMessage(payloadTemplate); err != nil {
			if phase.Load() == 1 {
				totalErrs.Add(1)
			}
			return
		}
		resp, err := c.ReadMessage()
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
// read and write onto two goroutines is what makes multi-inflight safe: a
// single interleaved goroutine that primed k writes before reading could
// deadlock once k*payload filled the socket buffers (the server blocks writing
// echoes we are not reading, so our next write blocks too). Here the reader
// drains continuously, so the writer only ever blocks acquiring a window
// credit, which the reader returns on every echo. The window caps the number
// of in-flight messages and preserves FIFO echo attribution (a single
// connection echoes in send order).
func runConnPipelined(
	c wsClient,
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
	// the reader, which is otherwise waiting in ReadMessage for an echo the
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
	wg.Go(func() {
		for {
			select {
			case <-writerStop:
				return
			default:
			}
			// Wait for a free credit first, then stamp the send time at the
			// actual hand-off to the write path (never counting the credit
			// wait as latency), then transmit. The payload template is
			// read-only; the client transport never mutates it.
			if !win.Acquire(writerStop) {
				return
			}
			win.Record(time.Now())
			if err := c.WriteMessage(payloadTemplate); err != nil {
				if phase.Load() == 1 {
					totalErrs.Add(1)
				}
				return
			}
		}
	})

	for {
		echo, err := c.ReadMessage()
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
