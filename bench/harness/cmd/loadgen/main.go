// Command loadgen drives reproducible WebSocket echo workloads and emits a
// strict machine-readable measurement record. Closed-loop, pipelined, and
// true open-loop arrivals are separate contracts; every accepted message is
// verified, every latency observation is represented in mergeable HDR
// histograms, and all loss/resource accounting is explicit.
package main

import (
	"bufio"
	"context"
	"errors"
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

const (
	drainTimeout                   = 5 * time.Second
	latencyLowest                  = time.Microsecond
	latencyHighest                 = 60 * time.Second
	latencySignificantFigures      = 2
	latencyCalibrationObservations = 4_096
)

var errVerificationMismatch = errors.New("verification mismatch")

type clientKind string

const (
	clientGoWS   clientKind = "gows"
	clientGobwas clientKind = "gobwas"
	clientRaw    clientKind = "raw"
)

func parseClientKind(value string) (clientKind, error) {
	switch clientKind(value) {
	case clientGoWS, clientGobwas, clientRaw:
		return clientKind(value), nil
	default:
		return "", fmt.Errorf("loadgen: -client must be %q, %q, or %q, got %q", clientGoWS, clientGobwas, clientRaw, value)
	}
}

type messageKind string

const (
	messageBinary messageKind = "binary"
	messageText   messageKind = "text"
)

func parseMessageKind(value string) (messageKind, error) {
	switch messageKind(value) {
	case messageBinary, messageText:
		return messageKind(value), nil
	default:
		return "", fmt.Errorf("loadgen: -message must be %q or %q, got %q", messageBinary, messageText, value)
	}
}

type arrivalKind string

const (
	arrivalClosedLoop arrivalKind = "closed_loop"
	arrivalPipelined  arrivalKind = "pipelined"
	arrivalOpenLoop   arrivalKind = "open_loop"
)

func parseArrivalKind(value string) (arrivalKind, error) {
	switch arrivalKind(value) {
	case arrivalClosedLoop, arrivalPipelined, arrivalOpenLoop:
		return arrivalKind(value), nil
	default:
		return "", fmt.Errorf("loadgen: -arrival must be %q, %q, or %q, got %q", arrivalClosedLoop, arrivalPipelined, arrivalOpenLoop, value)
	}
}

type wsClient interface {
	WriteMessage([]byte) error
	ReadMessage() ([]byte, error)
	SetDeadline(time.Time) error
	Close() error
}

type connRW struct {
	r *bufio.Reader
	net.Conn
}

func (c *connRW) Read(payload []byte) (int, error) {
	if c.r != nil {
		return c.r.Read(payload)
	}
	return c.Conn.Read(payload)
}

type gobwasClient struct {
	*connRW
	opcode  ws.OpCode
	scratch []byte
}

func newGobwasClient(conn *connRW, kind messageKind, payloadLen int) (*gobwasClient, error) {
	opcode, err := gobwasOpcode(kind)
	if err != nil {
		return nil, err
	}
	return &gobwasClient{connRW: conn, opcode: opcode, scratch: make([]byte, payloadLen)}, nil
}

func gobwasOpcode(kind messageKind) (ws.OpCode, error) {
	switch kind {
	case messageBinary:
		return ws.OpBinary, nil
	case messageText:
		return ws.OpText, nil
	default:
		return 0, fmt.Errorf("loadgen: unsupported message type %q", kind)
	}
}

func (client *gobwasClient) WriteMessage(payload []byte) error {
	n := copy(client.scratch, payload)
	return wsutil.WriteClientMessage(client.connRW, client.opcode, client.scratch[:n])
}

func (client *gobwasClient) ReadMessage() ([]byte, error) {
	payload, opcode, err := wsutil.ReadServerData(client.connRW)
	if err != nil {
		return nil, err
	}
	if opcode != client.opcode {
		return nil, fmt.Errorf("loadgen: gobwas received opcode %#x, want %#x", opcode, client.opcode)
	}
	return payload, nil
}

type gowsClient struct {
	conn   net.Conn
	ws     *gows.Conn
	opcode gows.Opcode
}

func (client *gowsClient) WriteMessage(payload []byte) error {
	return client.ws.WriteMessage(client.opcode, payload)
}

func (client *gowsClient) ReadMessage() ([]byte, error) {
	opcode, payload, err := client.ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	if opcode != client.opcode {
		return nil, fmt.Errorf("loadgen: gows received opcode %#x, want %#x", opcode, client.opcode)
	}
	return payload, nil
}

func (client *gowsClient) SetDeadline(deadline time.Time) error {
	return client.conn.SetDeadline(deadline)
}

func (client *gowsClient) Close() error { return client.conn.Close() }

func gowsOpcode(kind messageKind) (gows.Opcode, error) {
	switch kind {
	case messageBinary:
		return gows.OpcodeBinary, nil
	case messageText:
		return gows.OpcodeText, nil
	default:
		return 0, fmt.Errorf("loadgen: unsupported message type %q", kind)
	}
}

func dialClient(ctx context.Context, client clientKind, rawURL string, message messageKind, payloadLen int) (wsClient, error) {
	switch client {
	case clientGoWS:
		conn, handshake, err := gows.Dial(ctx, rawURL)
		if err != nil {
			return nil, err
		}
		opcode, err := gowsOpcode(message)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return &gowsClient{conn: conn, ws: gows.NewClientConn(conn, gows.WithBuffered(handshake.Buffered)), opcode: opcode}, nil
	case clientGobwas:
		conn, reader, _, err := ws.Dial(ctx, rawURL)
		if err != nil {
			return nil, err
		}
		resolved, err := newGobwasClient(&connRW{r: reader, Conn: conn}, message, payloadLen)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return resolved, nil
	case clientRaw:
		return dialRawClient(ctx, rawURL, message, payloadLen)
	default:
		return nil, fmt.Errorf("loadgen: unsupported client %q", client)
	}
}

func main() {
	if err := run(); err != nil {
		log.Printf("loadgen: %v", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:9001", "echoserver websocket address (host:port)")
	debugAddr := flag.String("debug-addr", "127.0.0.1:9101", "echoserver /debug/memstats address")
	clientFlag := flag.String("client", string(clientGoWS), "client transport: gows, gobwas, or independent raw RFC 6455")
	messageFlag := flag.String("message", string(messageBinary), "WebSocket data message type: binary or text")
	arrivalFlag := flag.String("arrival", string(arrivalClosedLoop), "arrival contract: closed_loop, pipelined, or open_loop")
	conns := flag.Int("conns", 200, "number of concurrent connections")
	payloadSize := flag.Int("payload", 1024, "message payload size in bytes")
	payloadSeed := flag.Uint64("seed", 0xC0FFEE, "base seed for deterministic per-connection payload streams")
	inflight := flag.Int("inflight", 1, "messages kept outstanding per connection")
	duration := flag.Duration("duration", 15*time.Second, "measurement duration")
	warmup := flag.Duration("warmup", 3*time.Second, "warmup duration before measurement starts")
	rate := flag.Int("rate", 0, "aggregate open-loop offered messages/sec; required only for open_loop")
	maxSchedulerLateness := flag.Duration("max-scheduler-lateness", 0, "maximum dispatch lateness for open_loop; must be positive and no more than one arrival interval")
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile for the measurement window")
	jsonOut := flag.Bool("json", false, "emit one machine-readable JSON result line")
	flag.Parse()

	client, err := parseClientKind(*clientFlag)
	if err != nil {
		return err
	}
	message, err := parseMessageKind(*messageFlag)
	if err != nil {
		return err
	}
	arrival, err := parseArrivalKind(*arrivalFlag)
	if err != nil {
		return err
	}
	if err := validateShape(arrival, *conns, *payloadSize, *inflight, *rate, *maxSchedulerLateness, *warmup, *duration); err != nil {
		return err
	}
	if *payloadSeed == 0 {
		return fmt.Errorf("loadgen: -seed must be nonzero")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := support.WaitForDebugServer(ctx, *debugAddr); err != nil {
		return fmt.Errorf("server not reachable at %s: %w", *debugAddr, err)
	}

	payloads := make([][]byte, *conns)
	for index := range payloads {
		seed := connectionPayloadSeed(*payloadSeed, index)
		if message == messageText {
			payloads[index] = support.DeterministicTextPayloadSeed(*payloadSize, seed)
		} else {
			payloads[index] = support.DeterministicPayloadSeed(*payloadSize, seed)
		}
	}
	clients := make([]wsClient, *conns)
	defer func() {
		for _, conn := range clients {
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	rawURL := "ws://" + *addr + "/"
	for index := range clients {
		conn, err := dialClient(ctx, client, rawURL, message, *payloadSize)
		if err != nil {
			return fmt.Errorf("dial %d/%d: %w", index+1, *conns, err)
		}
		clients[index] = conn
	}

	log.Printf("dialed %d connections to %s with client=%s message=%s; warming for %s", *conns, *addr, client, message, *warmup)
	if err := warmConnections(clients, payloads, *warmup); err != nil {
		return fmt.Errorf("warmup: %w", err)
	}

	latencyObservation, err := calibrateLatencyObservation()
	if err != nil {
		return err
	}
	serverOverheadStart, err := support.FetchMemSnapshot(ctx, *debugAddr)
	if err != nil {
		return fmt.Errorf("fetch server allocation calibration start: %w", err)
	}
	// Match the measurement control sequence exactly. The allocation window
	// includes both rusage requests between its two memstats snapshots, so a
	// shorter calibration would falsely charge observer allocations to the
	// WebSocket server.
	if _, err := support.FetchUsage(ctx, *debugAddr); err != nil {
		return fmt.Errorf("fetch server allocation calibration rusage start: %w", err)
	}
	if _, err := support.FetchUsage(ctx, *debugAddr); err != nil {
		return fmt.Errorf("fetch server allocation calibration rusage end: %w", err)
	}
	serverOverheadEnd, err := support.FetchMemSnapshot(ctx, *debugAddr)
	if err != nil {
		return fmt.Errorf("fetch server allocation calibration end: %w", err)
	}
	serverOverhead, err := support.SnapshotDelta(serverOverheadStart, serverOverheadEnd)
	if err != nil {
		return fmt.Errorf("server allocation calibration: %w", err)
	}
	clientOverheadStart := support.ReadMemSnapshot()
	_ = support.SelfRusage()
	_ = support.SelfRusage()
	clientOverheadEnd := support.ReadMemSnapshot()
	clientOverhead, err := support.SnapshotDelta(clientOverheadStart, clientOverheadEnd)
	if err != nil {
		return fmt.Errorf("client allocation calibration: %w", err)
	}
	recorders, err := newLatencyRecorders(len(clients))
	if err != nil {
		return err
	}

	stopProfile, err := startCPUProfile(*cpuProfile)
	if err != nil {
		return err
	}
	serverBefore, err := support.FetchMemSnapshot(ctx, *debugAddr)
	if err != nil {
		_ = stopProfile()
		return fmt.Errorf("fetch pre-measurement server memstats: %w", err)
	}
	serverUsageBefore, err := support.FetchUsage(ctx, *debugAddr)
	if err != nil {
		_ = stopProfile()
		return fmt.Errorf("fetch pre-measurement server rusage: %w", err)
	}
	clientBefore := support.ReadMemSnapshot()
	usageBefore := support.SelfRusage()

	log.Printf("measuring arrival=%s for %s", arrival, *duration)
	result, err := measure(clients, recorders, payloads, arrival, *inflight, *rate, *maxSchedulerLateness, *duration)
	usageAfter := support.SelfRusage()
	clientAfter := support.ReadMemSnapshot()
	serverUsageAfter, serverUsageAfterErr := support.FetchUsage(ctx, *debugAddr)
	serverAfter, serverAfterErr := support.FetchMemSnapshot(ctx, *debugAddr)
	profileErr := stopProfile()
	if err != nil {
		return err
	}
	if serverAfterErr != nil {
		return fmt.Errorf("fetch post-measurement server memstats: %w", serverAfterErr)
	}
	if serverUsageAfterErr != nil {
		return fmt.Errorf("fetch post-measurement server rusage: %w", serverUsageAfterErr)
	}
	if profileErr != nil {
		return profileErr
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("interrupted: %w", err)
	}

	serverAllocations, err := support.AllocationDelta(serverBefore, serverAfter, serverOverhead, result.achieved)
	if err != nil {
		return fmt.Errorf("server allocations: %w", err)
	}
	clientAllocations, err := support.AllocationDelta(clientBefore, clientAfter, clientOverhead, result.achieved)
	if err != nil {
		return fmt.Errorf("client allocations: %w", err)
	}
	clientUsage, err := support.UsageDelta(usageBefore, usageAfter)
	if err != nil {
		return fmt.Errorf("client rusage: %w", err)
	}
	serverUsage, err := support.UsageDelta(serverUsageBefore, serverUsageAfter)
	if err != nil {
		return fmt.Errorf("server rusage: %w", err)
	}
	pct, err := result.latency.Corrected.Percentiles()
	if err != nil {
		return fmt.Errorf("corrected latency percentiles: %w", err)
	}
	dropped, err := result.dropped()
	if err != nil {
		return err
	}
	durationSeconds := duration.Seconds()
	record := support.LoadgenResult{
		SchemaVersion:                     support.LoadgenSchemaVersion,
		Client:                            string(client),
		MessageType:                       string(message),
		Arrival:                           string(arrival),
		Connections:                       *conns,
		PayloadBytes:                      *payloadSize,
		PayloadSeed:                       *payloadSeed,
		Inflight:                          *inflight,
		WarmupNanoseconds:                 warmup.Nanoseconds(),
		DurationNanoseconds:               duration.Nanoseconds(),
		Messages:                          result.achieved,
		OfferedMessages:                   result.offered,
		RequestedOfferedMessagesPerSecond: *rate,
		AchievedMessages:                  result.achieved,
		RejectedMessages:                  result.rejected,
		DroppedMessages:                   dropped,
		QueueOverflows:                    result.queueOverflows,
		SchedulerLateMessages:             result.schedulerLate,
		PostWindowMessages:                result.postWindow,
		SchedulerLatenessLimitNanoseconds: maxSchedulerLateness.Nanoseconds(),
		SchedulerMaxLatenessNanoseconds:   result.schedulerMaxLateness,
		MeasurementDrainNanoseconds:       result.drainNanoseconds,
		VerificationMismatches:            result.mismatches,
		OfferedMessagesPerSecond:          float64(result.offered) / durationSeconds,
		ThroughputMessagesPerSecond:       float64(result.achieved) / durationSeconds,
		RejectedMessagesPerSecond:         float64(result.rejected) / durationSeconds,
		P50Nanoseconds:                    pct.P50.Nanoseconds(),
		P90Nanoseconds:                    pct.P90.Nanoseconds(),
		P99Nanoseconds:                    pct.P99.Nanoseconds(),
		P999Nanoseconds:                   pct.P999.Nanoseconds(),
		Errors:                            result.errors,
		Latency:                           result.latency,
		LatencyObservationNanoseconds:     latencyObservation,
		ServerAllocations:                 serverAllocations,
		ClientAllocations:                 clientAllocations,
		ServerUsage:                       serverUsage,
		ClientUsage:                       clientUsage,
		ClientCPUSeconds:                  clientUsage.CPUSeconds,
		ClientMaxRSSBytes:                 clientUsage.MaxRSSBytes,
		ClientMaxRSSAvailable:             clientUsage.Available,
	}
	if err := record.Validate(); err != nil {
		return err
	}
	if *jsonOut {
		line, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal JSON result: %w", err)
		}
		fmt.Printf("%s\n", line)
	} else {
		printHuman(record)
	}
	return record.HardFailure()
}

func validateShape(arrival arrivalKind, connections, payload, inflight, rate int, maxSchedulerLateness, warmup, duration time.Duration) error {
	switch {
	case connections <= 0:
		return fmt.Errorf("loadgen: -conns must be > 0, got %d", connections)
	case payload <= 0:
		return fmt.Errorf("loadgen: -payload must be > 0, got %d", payload)
	case inflight < 1:
		return fmt.Errorf("loadgen: -inflight must be >= 1, got %d", inflight)
	case inflight > support.MaxInflightBytes/payload:
		return fmt.Errorf("loadgen: inflight*payload exceeds %d", support.MaxInflightBytes)
	case warmup < 0:
		return fmt.Errorf("loadgen: -warmup must be >= 0, got %s", warmup)
	case duration <= 0:
		return fmt.Errorf("loadgen: -duration must be > 0, got %s", duration)
	case arrival == arrivalClosedLoop && (inflight != 1 || rate != 0 || maxSchedulerLateness != 0):
		return fmt.Errorf("loadgen: closed_loop requires inflight=1, rate=0, and max-scheduler-lateness=0")
	case arrival == arrivalPipelined && (inflight < 2 || rate != 0 || maxSchedulerLateness != 0):
		return fmt.Errorf("loadgen: pipelined requires inflight>=2, rate=0, and max-scheduler-lateness=0")
	case arrival == arrivalOpenLoop && (inflight != 1 || rate <= 0 || rate > support.MaxOpenLoopRate):
		return fmt.Errorf("loadgen: open_loop requires inflight=1 and rate in [1,%d]", support.MaxOpenLoopRate)
	case arrival == arrivalOpenLoop && maxSchedulerLateness <= 0:
		return fmt.Errorf("loadgen: open_loop requires max-scheduler-lateness > 0")
	case arrival == arrivalOpenLoop && maxSchedulerLateness > time.Second/time.Duration(rate):
		return fmt.Errorf("loadgen: max-scheduler-lateness %s exceeds one arrival interval", maxSchedulerLateness)
	}
	return nil
}

func warmConnections(clients []wsClient, payloads [][]byte, duration time.Duration) error {
	if len(payloads) != len(clients) {
		return fmt.Errorf("loadgen: warmup payload count %d != client count %d", len(payloads), len(clients))
	}
	if duration == 0 {
		return nil
	}
	end := time.Now().Add(duration)
	for _, client := range clients {
		if err := client.SetDeadline(end.Add(drainTimeout)); err != nil {
			return err
		}
	}
	errorsCh := make(chan error, len(clients))
	var wg sync.WaitGroup
	for index, client := range clients {
		payload := payloads[index]
		wg.Go(func() {
			for {
				started := time.Now()
				if !started.Before(end) {
					return
				}
				if _, err := exchange(client, payload, started); err != nil {
					errorsCh <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errorsCh)
	for _, client := range clients {
		if err := client.SetDeadline(time.Time{}); err != nil {
			return err
		}
	}
	return errors.Join(collectErrors(errorsCh)...)
}

func collectErrors(errorsCh <-chan error) []error {
	var collected []error
	for err := range errorsCh {
		collected = append(collected, err)
	}
	return collected
}

type measurementCounters struct {
	offered              atomic.Int64
	achieved             atomic.Int64
	rejected             atomic.Int64
	queueOverflows       atomic.Int64
	schedulerLate        atomic.Int64
	postWindow           atomic.Int64
	schedulerMaxLateness atomic.Int64
	errors               atomic.Int64
	mismatches           atomic.Int64
}

type measurementResult struct {
	offered, achieved, rejected, queueOverflows, schedulerLate int64
	postWindow, schedulerMaxLateness, drainNanoseconds         int64
	errors, mismatches                                         int64
	latency                                                    support.LatencySnapshot
}

func (result measurementResult) dropped() (int64, error) {
	accepted := result.offered - result.rejected
	if accepted < result.achieved {
		return 0, fmt.Errorf("loadgen: achieved %d exceeds accepted %d", result.achieved, accepted)
	}
	return accepted - result.achieved, nil
}

func newLatencyRecorders(count int) ([]*support.LatencyRecorder, error) {
	recorders := make([]*support.LatencyRecorder, count)
	for index := range recorders {
		recorder, err := support.NewLatencyRecorder(support.LatencyConfig{
			Lowest: latencyLowest, Highest: latencyHighest, SignificantFigures: latencySignificantFigures,
		})
		if err != nil {
			return nil, err
		}
		recorders[index] = recorder
	}
	return recorders, nil
}

func measure(clients []wsClient, recorders []*support.LatencyRecorder, payloads [][]byte, arrival arrivalKind, inflight, rate int, maxSchedulerLateness, duration time.Duration) (measurementResult, error) {
	if len(recorders) != len(clients) {
		return measurementResult{}, fmt.Errorf("loadgen: latency recorder count %d != client count %d", len(recorders), len(clients))
	}
	if len(payloads) != len(clients) {
		return measurementResult{}, fmt.Errorf("loadgen: payload count %d != client count %d", len(payloads), len(clients))
	}
	for _, client := range clients {
		if err := client.SetDeadline(time.Time{}); err != nil {
			return measurementResult{}, err
		}
	}
	start := time.Now()
	end := start.Add(duration)
	deadlineResult := make(chan error, 1)
	deadlineTimer := time.AfterFunc(time.Until(end), func() {
		deadlineResult <- setClientDeadlines(clients, end.Add(drainTimeout))
	})
	counters := &measurementCounters{}
	var measurementErr error
	switch arrival {
	case arrivalClosedLoop:
		measureClosedLoop(clients, recorders, payloads, end, counters)
	case arrivalPipelined:
		measurePipelined(clients, recorders, payloads, inflight, end, counters)
	case arrivalOpenLoop:
		measurementErr = measureOpenLoop(clients, recorders, payloads, start, end, rate, maxSchedulerLateness, counters)
	default:
		measurementErr = fmt.Errorf("loadgen: unsupported arrival %q", arrival)
	}
	if measurementErr != nil && deadlineTimer.Stop() {
		return measurementResult{}, measurementErr
	}
	if deadlineErr := <-deadlineResult; deadlineErr != nil {
		measurementErr = errors.Join(measurementErr, deadlineErr)
	}
	if measurementErr != nil {
		return measurementResult{}, measurementErr
	}

	snapshots := make([]support.LatencySnapshot, len(recorders))
	for index, recorder := range recorders {
		snapshots[index] = recorder.Snapshot()
	}
	merged, err := support.MergeLatencySnapshots(snapshots)
	if err != nil {
		return measurementResult{}, err
	}
	return measurementResult{
		offered: counters.offered.Load(), achieved: counters.achieved.Load(),
		rejected: counters.rejected.Load(), queueOverflows: counters.queueOverflows.Load(),
		schedulerLate: counters.schedulerLate.Load(), postWindow: counters.postWindow.Load(),
		schedulerMaxLateness: counters.schedulerMaxLateness.Load(),
		drainNanoseconds:     max(int64(0), time.Since(end).Nanoseconds()),
		errors:               counters.errors.Load(), mismatches: counters.mismatches.Load(), latency: merged,
	}, nil
}

func setClientDeadlines(clients []wsClient, deadline time.Time) error {
	var result error
	for index, client := range clients {
		if err := client.SetDeadline(deadline); err != nil {
			failure := fmt.Errorf("loadgen: set client %d deadline: %w", index, err)
			// A client that cannot accept the bounded drain deadline could
			// otherwise leave its worker blocked forever. Closing that client is
			// the only fail-closed way to unblock its I/O and join the worker.
			if closeErr := client.Close(); closeErr != nil {
				failure = errors.Join(failure, fmt.Errorf("loadgen: close client %d after deadline failure: %w", index, closeErr))
			}
			result = errors.Join(result, failure)
		}
	}
	return result
}

func measureClosedLoop(clients []wsClient, recorders []*support.LatencyRecorder, payloads [][]byte, end time.Time, counters *measurementCounters) {
	var wg sync.WaitGroup
	for index, client := range clients {
		recorder := recorders[index]
		payload := payloads[index]
		wg.Go(func() {
			for {
				started := time.Now()
				if !started.Before(end) {
					return
				}
				counters.offered.Add(1)
				latency, err := exchange(client, payload, started)
				if err != nil {
					recordExchangeError(err, counters)
					return
				}
				recorder.Record(latency, latency)
				counters.achieved.Add(1)
			}
		})
	}
	wg.Wait()
}

type arrival struct {
	Sequence  int64
	Scheduled time.Time
}

func scheduledArrival(start time.Time, sequence int64, rate int) (time.Time, error) {
	if sequence < 0 {
		return time.Time{}, fmt.Errorf("loadgen: arrival sequence must be >= 0, got %d", sequence)
	}
	if rate <= 0 {
		return time.Time{}, fmt.Errorf("loadgen: arrival rate must be > 0, got %d", rate)
	}
	seconds := sequence / int64(rate)
	remainder := sequence % int64(rate)
	if seconds > int64(^uint64(0)>>1)/int64(time.Second) {
		return time.Time{}, fmt.Errorf("loadgen: arrival sequence %d overflows duration", sequence)
	}
	offset := time.Duration(seconds)*time.Second + time.Duration(remainder)*time.Second/time.Duration(rate)
	return start.Add(offset), nil
}

func offerArrival(queues []chan arrival, next int, offered arrival) (int, bool) {
	if len(queues) == 0 {
		return 0, false
	}
	if next < 0 || next >= len(queues) {
		next = 0
	}
	queue := queues[next]
	next = (next + 1) % len(queues)
	select {
	case queue <- offered:
		return next, true
	default:
		return next, false
	}
}

func measureOpenLoop(clients []wsClient, recorders []*support.LatencyRecorder, payloads [][]byte, start, end time.Time, rate int, maxSchedulerLateness time.Duration, counters *measurementCounters) error {
	if !time.Now().Before(end) {
		return fmt.Errorf("loadgen: open-loop measurement window expired before scheduler start")
	}
	queues := make([]chan arrival, len(clients))
	var wg sync.WaitGroup
	for index, client := range clients {
		queue := make(chan arrival, 1)
		queues[index] = queue
		recorder := recorders[index]
		payload := payloads[index]
		wg.Go(func() {
			for offered := range queue {
				started := time.Now()
				if !started.Before(end) {
					counters.postWindow.Add(1)
					continue
				}
				latency, err := exchange(client, payload, started)
				if err != nil {
					recordExchangeError(err, counters)
					continue
				}
				received := started.Add(latency)
				recorder.Record(latency, received.Sub(offered.Scheduled))
				counters.achieved.Add(1)
			}
		})
	}
	dispatchErr := dispatchOpenLoop(queues, start, end, rate, maxSchedulerLateness, counters, openLoopClock{
		now: time.Now,
		waitUntil: func(deadline time.Time) {
			if delay := time.Until(deadline); delay > 0 {
				time.Sleep(delay)
			}
		},
	})
	for _, queue := range queues {
		close(queue)
	}
	wg.Wait()
	return dispatchErr
}

type openLoopClock struct {
	now       func() time.Time
	waitUntil func(time.Time)
}

func dispatchOpenLoop(queues []chan arrival, start, end time.Time, rate int, maxSchedulerLateness time.Duration, counters *measurementCounters, clock openLoopClock) error {
	if len(queues) == 0 {
		return fmt.Errorf("loadgen: open-loop scheduler requires at least one queue")
	}
	if counters == nil || clock.now == nil || clock.waitUntil == nil {
		return fmt.Errorf("loadgen: open-loop scheduler is incompletely configured")
	}
	if !start.Before(end) {
		return fmt.Errorf("loadgen: open-loop window start must precede end")
	}
	if maxSchedulerLateness <= 0 || rate <= 0 || rate > support.MaxOpenLoopRate || maxSchedulerLateness > time.Second/time.Duration(rate) {
		return fmt.Errorf("loadgen: invalid open-loop rate/lateness contract rate=%d max_lateness=%s", rate, maxSchedulerLateness)
	}
	if now := clock.now(); !now.Before(end) {
		return fmt.Errorf("loadgen: open-loop measurement window expired before dispatch")
	}
	total, err := support.OpenLoopOfferedMessages(end.Sub(start), rate)
	if err != nil {
		return err
	}
	nextQueue := 0
	for sequence := int64(0); sequence < total; {
		scheduled, err := scheduledArrival(start, sequence, rate)
		if err != nil {
			return err
		}
		now := clock.now()
		if now.Before(scheduled) {
			clock.waitUntil(scheduled)
			now = clock.now()
		}
		if !now.Before(end) {
			remaining := total - sequence
			counters.offered.Add(remaining)
			rejectSchedulerLate(counters, remaining, now.Sub(scheduled))
			break
		}

		due, err := scheduledArrivalsThrough(start, now, rate)
		if err != nil {
			return err
		}
		due = min(due, total)
		if due <= sequence {
			return fmt.Errorf("loadgen: scheduler clock did not reach arrival %d", sequence)
		}
		latestSequence := due - 1
		latestScheduled, err := scheduledArrival(start, latestSequence, rate)
		if err != nil {
			return err
		}
		missed := latestSequence - sequence
		if missed > 0 {
			counters.offered.Add(missed)
			rejectSchedulerLate(counters, missed, now.Sub(scheduled))
		}

		lateness := now.Sub(latestScheduled)
		recordSchedulerMaxLateness(counters, lateness)
		counters.offered.Add(1)
		if lateness > maxSchedulerLateness {
			rejectSchedulerLate(counters, 1, lateness)
		} else {
			var accepted bool
			nextQueue, accepted = offerArrival(queues, nextQueue, arrival{Sequence: latestSequence, Scheduled: latestScheduled})
			if !accepted {
				counters.rejected.Add(1)
				counters.queueOverflows.Add(1)
			}
		}
		sequence = due
	}
	return nil
}

func scheduledArrivalsThrough(start, now time.Time, rate int) (int64, error) {
	if now.Before(start) {
		return 0, nil
	}
	elapsed := now.Sub(start)
	if elapsed == time.Duration(1<<63-1) {
		return 0, fmt.Errorf("loadgen: scheduler elapsed time overflows arrival count")
	}
	return support.OpenLoopOfferedMessages(elapsed+time.Nanosecond, rate)
}

func rejectSchedulerLate(counters *measurementCounters, count int64, lateness time.Duration) {
	if count <= 0 {
		return
	}
	counters.rejected.Add(count)
	counters.schedulerLate.Add(count)
	recordSchedulerMaxLateness(counters, lateness)
}

func recordSchedulerMaxLateness(counters *measurementCounters, lateness time.Duration) {
	value := max(int64(0), lateness.Nanoseconds())
	for current := counters.schedulerMaxLateness.Load(); value > current; current = counters.schedulerMaxLateness.Load() {
		if counters.schedulerMaxLateness.CompareAndSwap(current, value) {
			return
		}
	}
}

func measurePipelined(clients []wsClient, recorders []*support.LatencyRecorder, payloads [][]byte, inflight int, end time.Time, counters *measurementCounters) {
	var wg sync.WaitGroup
	for index, client := range clients {
		recorder := recorders[index]
		payload := payloads[index]
		wg.Go(func() {
			measurePipelineConnection(client, recorder, payload, inflight, end, counters)
		})
	}
	wg.Wait()
}

func connectionPayloadSeed(base uint64, index int) uint64 {
	z := base + uint64(index+1)*0x9E3779B97F4A7C15
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	z ^= z >> 31
	if z == 0 {
		return 0xD1B54A32D192ED03
	}
	return z
}

func measurePipelineConnection(client wsClient, recorder *support.LatencyRecorder, payload []byte, inflight int, end time.Time, counters *measurementCounters) {
	credits := make(chan struct{}, inflight)
	for range inflight {
		credits <- struct{}{}
	}
	sent := make(chan time.Time, inflight)
	stopWriter := make(chan struct{})
	stop := sync.OnceFunc(func() { close(stopWriter) })
	endCh := make(chan struct{})
	endTimer := time.AfterFunc(time.Until(end), func() { close(endCh) })
	defer endTimer.Stop()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer close(sent)
		for {
			select {
			case <-stopWriter:
				return
			case <-endCh:
				return
			case <-credits:
			}
			started := time.Now()
			if !started.Before(end) {
				credits <- struct{}{}
				return
			}
			counters.offered.Add(1)
			if err := client.WriteMessage(payload); err != nil {
				recordExchangeError(err, counters)
				return
			}
			select {
			case sent <- started:
			case <-stopWriter:
				return
			}
		}
	}()

	for started := range sent {
		echo, err := client.ReadMessage()
		received := time.Now()
		if err != nil {
			recordExchangeError(err, counters)
			stop()
			_ = client.SetDeadline(time.Now())
			break
		}
		if err := support.VerifyEcho(payload, echo); err != nil {
			recordExchangeError(err, counters)
			stop()
			_ = client.SetDeadline(time.Now())
			break
		}
		latency := received.Sub(started)
		recorder.Record(latency, latency)
		counters.achieved.Add(1)
		credits <- struct{}{}
	}
	stop()
	<-writerDone
}

func exchange(client wsClient, payload []byte, started time.Time) (time.Duration, error) {
	if err := client.WriteMessage(payload); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	echo, err := client.ReadMessage()
	received := time.Now()
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	if err := support.VerifyEcho(payload, echo); err != nil {
		return 0, fmt.Errorf("%w: %v", errVerificationMismatch, err)
	}
	return received.Sub(started), nil
}

func recordExchangeError(err error, counters *measurementCounters) {
	counters.errors.Add(1)
	if errors.Is(err, errVerificationMismatch) {
		counters.mismatches.Add(1)
	}
}

func calibrateLatencyObservation() (float64, error) {
	recorder, err := support.NewLatencyRecorder(support.LatencyConfig{
		Lowest: latencyLowest, Highest: latencyHighest, SignificantFigures: latencySignificantFigures,
	})
	if err != nil {
		return 0, err
	}
	started := time.Now()
	for range latencyCalibrationObservations {
		recorder.Record(100*time.Microsecond, 100*time.Microsecond)
	}
	return float64(time.Since(started).Nanoseconds()) / latencyCalibrationObservations, nil
}

func startCPUProfile(path string) (func() error, error) {
	if path == "" {
		return func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create CPU profile %s: %w", path, err)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("start CPU profile: %w", err)
	}
	return func() error {
		pprof.StopCPUProfile()
		return file.Close()
	}, nil
}

func printHuman(result support.LoadgenResult) {
	megabytesPerSecond := result.ThroughputMessagesPerSecond * float64(result.PayloadBytes*2) / (1024 * 1024)
	fmt.Printf("client=%s message=%s arrival=%s conns=%d payload=%dB duration=%s\n", result.Client, result.MessageType, result.Arrival, result.Connections, result.PayloadBytes, time.Duration(result.DurationNanoseconds))
	fmt.Printf("offered=%.0f achieved=%.0f rejected=%.0f msg/s throughput=%.2f MiB/s\n", result.OfferedMessagesPerSecond, result.ThroughputMessagesPerSecond, result.RejectedMessagesPerSecond, megabytesPerSecond)
	fmt.Printf("latency corrected p50=%s p90=%s p99=%s p999=%s seen=%d recorded=%d dropped=%d overflow=%d\n", time.Duration(result.P50Nanoseconds), time.Duration(result.P90Nanoseconds), time.Duration(result.P99Nanoseconds), time.Duration(result.P999Nanoseconds), result.Latency.Corrected.Seen, result.Latency.Corrected.Recorded, result.Latency.Corrected.Dropped, result.Latency.Corrected.Overflow)
	fmt.Printf("errors=%d mismatches=%d dropped=%d queue_overflows=%d client_cpu=%.3fs client_maxrss=%dB\n", result.Errors, result.VerificationMismatches, result.DroppedMessages, result.QueueOverflows, result.ClientCPUSeconds, result.ClientMaxRSSBytes)
}
