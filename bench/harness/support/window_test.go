package support

import (
	"slices"
	"testing"
	"time"
)

func TestVerifyEcho(t *testing.T) {
	pay := DeterministicPayload(64)
	corrupt := slices.Clone(pay)
	corrupt[32] ^= 0xFF

	tests := map[string]struct {
		expected []byte
		got      []byte
		wantErr  bool
	}{
		"match":            {expected: pay, got: slices.Clone(pay), wantErr: false},
		"length short":     {expected: pay, got: pay[:len(pay)-1], wantErr: true},
		"length long":      {expected: pay, got: append(slices.Clone(pay), 0x00), wantErr: true},
		"content mismatch": {expected: pay, got: corrupt, wantErr: true},
		"both empty":       {expected: nil, got: nil, wantErr: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := VerifyEcho(tc.expected, tc.got)
			if tc.wantErr && err == nil {
				t.Fatalf("VerifyEcho(%d bytes, %d bytes) = nil, want error", len(tc.expected), len(tc.got))
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("VerifyEcho: unexpected error: %v", err)
			}
		})
	}
}

// send is a test helper that performs one full send (acquire a credit, then
// record the send at sentAt), failing if no credit was available.
func send(t *testing.T, w *PipelineWindow, sentAt time.Time) int64 {
	t.Helper()
	if !w.tryAcquire() {
		t.Fatalf("tryAcquire: false, want true (a credit should be available)")
	}
	return w.Record(sentAt)
}

// TestPipelineWindowCredits exercises the credit bookkeeping for a k>3 window:
// a send is admitted only while credits remain, refused when the window is
// full, and a Receive frees exactly one credit.
func TestPipelineWindowCredits(t *testing.T) {
	pay := DeterministicPayload(32)
	const capacity = 4
	w := NewPipelineWindow(capacity, pay)
	if w.capacity != capacity {
		t.Fatalf("capacity = %d, want %d", w.capacity, capacity)
	}

	base := time.Unix(0, 0)
	for i := range capacity {
		if seq := send(t, w, base); seq != int64(i) {
			t.Fatalf("send %d: seq = %d, want %d", i, seq, i)
		}
		if len(w.fifo) != i+1 {
			t.Fatalf("after send %d: outstanding = %d, want %d", i, len(w.fifo), i+1)
		}
	}

	// Window is full: the next acquire must be refused.
	if w.tryAcquire() {
		t.Fatalf("tryAcquire on full window: true, want false")
	}

	// Receiving one echo frees exactly one credit.
	if _, _, err := w.Receive(pay, base); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(w.fifo) != capacity-1 {
		t.Fatalf("after Receive: outstanding = %d, want %d", len(w.fifo), capacity-1)
	}
	if seq := send(t, w, base); seq != capacity {
		t.Fatalf("send after freeing a credit: seq = %d, want %d", seq, capacity)
	}
}

// TestPipelineWindowClosedLoopEquivalence shows a capacity-1 window enforces
// exactly one message outstanding at a time (send, wait, send), which is the
// closed request/response accounting of the non-pipelined path.
func TestPipelineWindowClosedLoopEquivalence(t *testing.T) {
	pay := DeterministicPayload(16)
	w := NewPipelineWindow(1, pay)
	base := time.Unix(0, 0)

	if seq := send(t, w, base); seq != 0 {
		t.Fatalf("first send seq = %d, want 0", seq)
	}
	// With one message in flight the window is full: no second send may start
	// until the outstanding echo is received.
	if w.tryAcquire() {
		t.Fatalf("second tryAcquire before receive: true, want false (closed loop keeps one in flight)")
	}
	if _, _, err := w.Receive(pay, base); err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if seq := send(t, w, base); seq != 1 {
		t.Fatalf("send after receive seq = %d, want 1", seq)
	}
}

// TestPipelineWindowLatencyAttribution verifies each echo's latency is measured
// against the send timestamp of the matching (FIFO-oldest) message, not any
// later in-flight message.
func TestPipelineWindowLatencyAttribution(t *testing.T) {
	pay := DeterministicPayload(48)
	w := NewPipelineWindow(4, pay)
	base := time.Unix(100, 0)

	// Three messages sent at spaced-out times while all stay in flight.
	sendOffsets := []time.Duration{0, 3 * time.Millisecond, 11 * time.Millisecond}
	for i, off := range sendOffsets {
		if seq := send(t, w, base.Add(off)); seq != int64(i) {
			t.Fatalf("send %d: seq = %d, want %d", i, seq, i)
		}
	}

	// Echoes arrive in send order at distinct receive times; each latency must
	// pair with its own message's send time.
	recvOffsets := []time.Duration{5 * time.Millisecond, 9 * time.Millisecond, 40 * time.Millisecond}
	for i, roff := range recvOffsets {
		latency, seq, err := w.Receive(pay, base.Add(roff))
		if err != nil {
			t.Fatalf("Receive %d: %v", i, err)
		}
		if seq != int64(i) {
			t.Fatalf("Receive %d: seq = %d, want %d (FIFO attribution)", i, seq, i)
		}
		want := roff - sendOffsets[i]
		if latency != want {
			t.Fatalf("Receive %d: latency = %v, want %v (recv %v - send %v)", i, latency, want, roff, sendOffsets[i])
		}
	}
}

// TestPipelineWindowReceiveMismatch confirms a length or content mismatch on an
// echo raises an error and reports the offending message's sequence number.
func TestPipelineWindowReceiveMismatch(t *testing.T) {
	pay := DeterministicPayload(64)
	corrupt := slices.Clone(pay)
	corrupt[10] ^= 0x01

	tests := map[string]struct {
		echo    []byte
		wantErr bool
	}{
		"good echo":        {echo: slices.Clone(pay), wantErr: false},
		"short echo":       {echo: pay[:len(pay)-1], wantErr: true},
		"content mismatch": {echo: corrupt, wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			w := NewPipelineWindow(2, pay)
			base := time.Unix(0, 0)
			send(t, w, base)
			_, seq, err := w.Receive(tc.echo, base.Add(time.Millisecond))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Receive with bad echo: err = nil, want error")
				}
				if seq != 0 {
					t.Fatalf("Receive mismatch: seq = %d, want 0 (offending message)", seq)
				}
				return
			}
			if err != nil {
				t.Fatalf("Receive with good echo: unexpected error: %v", err)
			}
		})
	}
}

// TestPipelineWindowAcquireStop verifies the blocking Acquire returns false once
// its stop channel is closed on a full window rather than blocking forever.
func TestPipelineWindowAcquireStop(t *testing.T) {
	pay := DeterministicPayload(8)
	w := NewPipelineWindow(1, pay)
	base := time.Unix(0, 0)

	// A nil stop never fires, so Acquire returns as soon as the single credit
	// is available.
	if !w.Acquire(nil) {
		t.Fatalf("first Acquire on empty window: false, want true")
	}
	w.Record(base)
	stop := make(chan struct{})
	close(stop)
	if w.Acquire(stop) {
		t.Fatalf("Acquire on full window with closed stop: true, want false")
	}
}
