package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zchee/gows/bench/harness/support"
)

func TestParseClientKind(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    clientKind
		wantErr bool
	}{
		"success: gows":            {input: "gows", want: clientGoWS},
		"success: gobwas":          {input: "gobwas", want: clientGobwas},
		"success: raw":             {input: "raw", want: clientRaw},
		"error: empty":             {input: "", wantErr: true},
		"error: unknown value":     {input: "coder", wantErr: true},
		"error: wrong case":        {input: "GOWS", wantErr: true},
		"error: leading space":     {input: " gows", wantErr: true},
		"error: trailing newline":  {input: "gobwas\n", wantErr: true},
		"error: superset misspell": {input: "gowss", wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseClientKind(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseClientKind(%q): got nil error, want error", tt.input)
				}
				if got != "" {
					t.Fatalf("parseClientKind(%q): got kind %q on error, want empty", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseClientKind(%q): unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseClientKind(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateShapeRejectsInflightPayloadOverflow(t *testing.T) {
	t.Parallel()
	maxInt := int(^uint(0) >> 1)
	if err := validateShape(arrivalPipelined, 1, maxInt, maxInt, 0, 0, time.Second, time.Second); err == nil {
		t.Fatal("validateShape accepted overflowing inflight*payload")
	}
}

func TestValidateShapeRequiresPreregisteredOpenLoopLateness(t *testing.T) {
	t.Parallel()
	if err := validateShape(arrivalOpenLoop, 1, 1024, 1, 1_000, time.Millisecond, time.Second, time.Second); err != nil {
		t.Fatalf("valid open-loop shape: %v", err)
	}
	for name, lateness := range map[string]time.Duration{
		"missing":                0,
		"above arrival interval": 2 * time.Millisecond,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateShape(arrivalOpenLoop, 1, 1024, 1, 1_000, lateness, time.Second, time.Second); err == nil {
				t.Fatal("validateShape accepted invalid open-loop lateness contract")
			}
		})
	}
}

func TestConnectionPayloadSeedIsStableAndDistinct(t *testing.T) {
	t.Parallel()
	first := connectionPayloadSeed(42, 0)
	if first != connectionPayloadSeed(42, 0) {
		t.Fatal("connection payload seed is not deterministic")
	}
	if first == connectionPayloadSeed(42, 1) || first == connectionPayloadSeed(43, 0) {
		t.Fatal("distinct connection/base identities reused a payload seed")
	}
}

func TestScheduledArrival(t *testing.T) {
	t.Parallel()

	start := time.Unix(100, 0)
	tests := map[string]struct {
		sequence int64
		rate     int
		want     time.Time
		wantErr  bool
	}{
		"success: first arrival is at the start": {
			sequence: 0,
			rate:     1_000,
			want:     start,
		},
		"success: schedule is absolute and drift free": {
			sequence: 250,
			rate:     1_000,
			want:     start.Add(250 * time.Millisecond),
		},
		"error: non-positive rate": {rate: 0, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := scheduledArrival(start, tt.sequence, tt.rate)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("scheduledArrival: nil error, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("scheduledArrival: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Fatalf("arrival = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestOfferArrival(t *testing.T) {
	t.Parallel()

	queues := []chan arrival{
		make(chan arrival, 1),
		make(chan arrival, 1),
	}
	first := arrival{Sequence: 1}
	second := arrival{Sequence: 2}
	third := arrival{Sequence: 3}

	next, accepted := offerArrival(queues, 0, first)
	if !accepted || next != 1 {
		t.Fatalf("first offer = next %d accepted %v, want 1/true", next, accepted)
	}
	next, accepted = offerArrival(queues, next, second)
	if !accepted || next != 0 {
		t.Fatalf("second offer = next %d accepted %v, want 0/true", next, accepted)
	}
	// Both queues are full. The offer is rejected explicitly instead of a
	// ticker channel silently coalescing it.
	next, accepted = offerArrival(queues, next, third)
	if accepted || next != 1 {
		t.Fatalf("third offer = next %d accepted %v, want 1/false", next, accepted)
	}
}

func TestDispatchOpenLoopRejectsMissedSlotsInsteadOfBursting(t *testing.T) {
	t.Parallel()
	start := time.Unix(100, 0)
	end := start.Add(time.Second)
	current := start.Add(250 * time.Millisecond)
	queue := make(chan arrival, 20)
	counters := &measurementCounters{}
	err := dispatchOpenLoop(
		[]chan arrival{queue}, start, end, 10, 5*time.Millisecond, counters,
		openLoopClock{
			now: func() time.Time { return current },
			waitUntil: func(deadline time.Time) {
				if deadline.After(current) {
					current = deadline
				}
			},
		},
	)
	if err != nil {
		t.Fatalf("dispatchOpenLoop: %v", err)
	}
	if got := counters.offered.Load(); got != 10 {
		t.Fatalf("offered = %d, want exact schedule count 10", got)
	}
	if got := counters.schedulerLate.Load(); got != 3 {
		t.Fatalf("scheduler late = %d, want 3 missed/stale slots", got)
	}
	if got := counters.rejected.Load(); got != 3 {
		t.Fatalf("rejected = %d, want 3", got)
	}
	if got := counters.queueOverflows.Load(); got != 0 {
		t.Fatalf("queue overflows = %d, want 0", got)
	}
	if got := counters.schedulerMaxLateness.Load(); got != int64(250*time.Millisecond) {
		t.Fatalf("max scheduler lateness = %s, want 250ms", time.Duration(got))
	}
	if got := len(queue); got != 7 {
		t.Fatalf("dispatched arrivals = %d, want 7 without catch-up burst", got)
	}
	for want := int64(3); want < 10; want++ {
		got := <-queue
		if got.Sequence != want {
			t.Fatalf("dispatched sequence = %d, want %d", got.Sequence, want)
		}
	}
}

func TestMeasureOpenLoopRejectsExpiredWindowBeforeExchange(t *testing.T) {
	t.Parallel()
	now := time.Now()
	counters := &measurementCounters{}
	err := measureOpenLoop(
		[]wsClient{expiredWindowClient{}},
		[]*support.LatencyRecorder{nil},
		[][]byte{{1}},
		now.Add(-2*time.Second), now.Add(-time.Second), 1, time.Millisecond, counters,
	)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired open-loop window error = %v, want explicit rejection", err)
	}
	if counters.offered.Load() != 0 || counters.achieved.Load() != 0 {
		t.Fatalf("expired window exchanged traffic: offered=%d achieved=%d", counters.offered.Load(), counters.achieved.Load())
	}
}

func TestMeasureOpenLoopAcceptsPreEndDispatchCompletedDuringDrain(t *testing.T) {
	t.Parallel()

	recorder, err := support.NewLatencyRecorder(support.LatencyConfig{
		Lowest: time.Microsecond, Highest: time.Second, SignificantFigures: 2,
	})
	if err != nil {
		t.Fatalf("new latency recorder: %v", err)
	}
	client := &drainingEchoClient{
		written: make(chan struct{}),
		release: make(chan struct{}),
	}
	start := time.Now().Add(50 * time.Millisecond)
	end := start.Add(500 * time.Millisecond)
	counters := &measurementCounters{}
	done := make(chan error, 1)
	go func() {
		done <- measureOpenLoop(
			[]wsClient{client},
			[]*support.LatencyRecorder{recorder},
			[][]byte{{1, 2, 3}},
			start, end, 1, time.Second, counters,
		)
	}()

	select {
	case <-client.written:
		// WriteMessage is called only after the worker's end-boundary check,
		// proving that this exchange was dispatched inside the window.
	case err := <-done:
		t.Fatalf("measureOpenLoop returned before dispatch: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pre-end open-loop dispatch")
	}
	if wait := time.Until(end.Add(10 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	close(client.release)
	if err := <-done; err != nil {
		t.Fatalf("measureOpenLoop: %v", err)
	}

	if got := counters.offered.Load(); got != 1 {
		t.Fatalf("offered = %d, want 1", got)
	}
	if got := counters.achieved.Load(); got != 1 {
		t.Fatalf("achieved = %d, want the drained response", got)
	}
	if got := counters.postWindow.Load(); got != 0 {
		t.Fatalf("post-window = %d, want 0 for a pre-end dispatch", got)
	}
	if got := counters.errors.Load(); got != 0 {
		t.Fatalf("errors = %d, want 0", got)
	}
	snapshot := recorder.Snapshot()
	if snapshot.Raw.Seen != 1 || snapshot.Corrected.Seen != 1 {
		t.Fatalf("latency observations raw=%d corrected=%d, want 1/1", snapshot.Raw.Seen, snapshot.Corrected.Seen)
	}
}

func TestMeasureClosesClientWhenDrainDeadlineCannotBeSet(t *testing.T) {
	t.Parallel()

	recorder, err := support.NewLatencyRecorder(support.LatencyConfig{
		Lowest: time.Microsecond, Highest: time.Second, SignificantFigures: 2,
	})
	if err != nil {
		t.Fatalf("new latency recorder: %v", err)
	}
	client := &deadlineFailureClient{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := measure(
			[]wsClient{client},
			[]*support.LatencyRecorder{recorder},
			[][]byte{{1}},
			arrivalClosedLoop, 1, 0, 0, 10*time.Millisecond,
		)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "set client 0 deadline") {
			t.Fatalf("measurement error = %v, want drain-deadline failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("measurement remained blocked after drain-deadline failure")
	}
	select {
	case <-client.closed:
	default:
		t.Fatal("client was not closed after drain-deadline failure")
	}
}

type expiredWindowClient struct{}

func (expiredWindowClient) WriteMessage([]byte) error    { return nil }
func (expiredWindowClient) ReadMessage() ([]byte, error) { return []byte{1}, nil }
func (expiredWindowClient) SetDeadline(time.Time) error  { return nil }
func (expiredWindowClient) Close() error                 { return nil }

type drainingEchoClient struct {
	written chan struct{}
	release chan struct{}
	payload []byte
}

func (c *drainingEchoClient) WriteMessage(payload []byte) error {
	c.payload = append([]byte(nil), payload...)
	close(c.written)
	return nil
}

func (c *drainingEchoClient) ReadMessage() ([]byte, error) {
	<-c.release
	return append([]byte(nil), c.payload...), nil
}

func (*drainingEchoClient) SetDeadline(time.Time) error { return nil }
func (*drainingEchoClient) Close() error                { return nil }

type deadlineFailureClient struct {
	closed chan struct{}
}

func (*deadlineFailureClient) WriteMessage([]byte) error { return nil }

func (c *deadlineFailureClient) ReadMessage() ([]byte, error) {
	<-c.closed
	return nil, errors.New("closed after deadline failure")
}

func (*deadlineFailureClient) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		return nil
	}
	return errors.New("deadline rejected")
}

func (c *deadlineFailureClient) Close() error {
	close(c.closed)
	return nil
}
