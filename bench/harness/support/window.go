package support

import (
	"bytes"
	"fmt"
	"time"
)

// MaxInflightBytes bounds capacity*payload for a pipelined loadgen connection.
// Priming k messages back-to-back pushes up to k*payload bytes toward the
// server before the client reads a single echo; keeping that product well
// under a megabyte stays comfortably inside typical loopback socket buffers so
// the synchronous gobwas write path can never silently deadlock against an
// unread echo stream. Both loadgen and the policy schema reject configurations
// above it.
const MaxInflightBytes = 1 << 20

// VerifyEcho reports a descriptive error when got is not byte-for-byte equal to
// expected. The loadgen payload is deterministic and identical for every
// message, so a correct echo server always returns expected exactly; any
// difference in length or content is a server- or transport-level corruption
// that must fail the run rather than be silently counted as throughput.
//
// The common case (a correct echo) is decided by a single [bytes.Equal], which
// dispatches to the runtime's SIMD memequal and is far cheaper than a scalar
// byte loop on the per-message hot path. Only a genuine mismatch pays for the
// descriptive length/content diagnosis.
func VerifyEcho(expected, got []byte) error {
	if bytes.Equal(expected, got) {
		return nil
	}
	if len(got) != len(expected) {
		return fmt.Errorf("echo length mismatch: got %d bytes, want %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			return fmt.Errorf("echo content mismatch at byte %d: got 0x%02x, want 0x%02x", i, got[i], expected[i])
		}
	}
	return nil
}

// inflightMessage records one sent-but-not-yet-echoed message: its monotonic
// sequence number and the instant it was handed to the send path.
type inflightMessage struct {
	seq    int64
	sentAt time.Time
}

// PipelineWindow bounds the number of messages one loadgen connection keeps
// outstanding to a fixed capacity and attributes each echo to the matching
// send in FIFO order.
//
// A PipelineWindow is driven by exactly one writer goroutine (Acquire then
// Record) and one reader goroutine (Receive). Two bounded
// channels do all the coordination, so no lock is required: a credit channel
// (pre-filled with capacity tokens) supplies backpressure — the writer blocks
// in Acquire once capacity messages are outstanding — and a FIFO channel holds
// the outstanding messages in send order. Each Receive pops one message and
// returns one credit. A single connection's echoes arrive in the order its
// messages were sent, which makes the FIFO attribution exact.
//
// The split of Acquire (wait for a credit) from Record (stamp the send) is
// deliberate: the caller stamps the send time only after a credit is in hand,
// i.e. at the instant the message is actually handed to the write path. In
// this saturation model there is no external arrival schedule, so that instant
// is both the intended and the actual send time; the recorded latency is an
// honest round-trip and needs no coordinated-omission correction. (Stamping
// before Acquire would instead fold the credit wait into the latency.)
// Capacity 1 degenerates to a closed request/response loop: the second Acquire
// blocks until the first echo is received, matching the send-wait-send
// accounting of the non-pipelined path.
type PipelineWindow struct {
	capacity int
	expected []byte
	credits  chan struct{}        // available send credits; pre-filled to capacity
	fifo     chan inflightMessage // outstanding messages in send order
	nextSeq  int64
}

// NewPipelineWindow returns a window that keeps at most capacity messages
// outstanding and verifies every echo against expected. A capacity below 1 is
// clamped to 1 so the window always admits at least one message.
func NewPipelineWindow(capacity int, expected []byte) *PipelineWindow {
	capacity = max(capacity, 1)
	w := &PipelineWindow{
		capacity: capacity,
		expected: expected,
		credits:  make(chan struct{}, capacity),
		fifo:     make(chan inflightMessage, capacity),
	}
	for range capacity {
		w.credits <- struct{}{}
	}
	return w
}

// tryAcquire takes a send credit without blocking, returning true when one was
// free or false when the window is already full. It exists so tests can assert
// window-full refusal deterministically, without goroutines; the live writer
// uses Acquire.
func (w *PipelineWindow) tryAcquire() bool {
	select {
	case <-w.credits:
		return true
	default:
		return false
	}
}

// Acquire takes a send credit, blocking until one is free or stop is closed. It
// returns true on success, or false when stop fired before a credit became
// available.
func (w *PipelineWindow) Acquire(stop <-chan struct{}) bool {
	select {
	case <-w.credits:
		return true
	case <-stop:
		return false
	}
}

// Record registers a message as sent at sentAt and returns its sequence
// number. The caller must already hold a credit from Acquire;
// pairing every acquired credit with exactly one Record keeps the window
// bounded and the FIFO push non-blocking. sentAt is captured by the caller
// after acquiring the credit, i.e. at the actual send instant.
func (w *PipelineWindow) Record(sentAt time.Time) (seq int64) {
	seq = w.nextSeq
	w.nextSeq++
	w.fifo <- inflightMessage{seq: seq, sentAt: sentAt}
	return seq
}

// Receive pops the oldest outstanding message, returns its credit, verifies
// echo against the expected payload, and returns the message's latency (recvAt
// minus its send time) and sequence number. A length or content mismatch
// returns a non-nil error together with the offending message's sequence
// number. Receive must be called only after a corresponding Record; with no
// message outstanding it blocks until one is recorded.
func (w *PipelineWindow) Receive(echo []byte, recvAt time.Time) (latency time.Duration, seq int64, err error) {
	msg := <-w.fifo
	w.credits <- struct{}{} // return the credit; the just-freed slot guarantees room
	if verr := VerifyEcho(w.expected, echo); verr != nil {
		return 0, msg.seq, verr
	}
	return recvAt.Sub(msg.sentAt), msg.seq, nil
}
