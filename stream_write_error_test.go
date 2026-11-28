// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gows

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// The backend can produce a whole fragment or buffer its input. No message
// finishes successfully, so the peer never needs to inflate the test bytes.
type streamFaultCompressor struct {
	dst                io.Writer
	emit               bool
	writeErr, flushErr error
}

func (w *streamFaultCompressor) Reset(dst io.Writer) { w.dst = dst }

func (w *streamFaultCompressor) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if w.emit {
		return w.dst.Write(p)
	}
	return len(p), nil
}

func (w *streamFaultCompressor) Flush() error { return w.flushErr }

func installStreamCompressor(t *testing.T, emit bool) *streamFaultCompressor {
	t.Helper()
	w := &streamFaultCompressor{emit: emit}
	backend := *defaultDeflateBackend
	backend.NewWriter = func(int, int) (DeflateWriter, error) { return w, nil }
	withDeflateBackend(t, &backend, defaultDeflateLevel, deflateWindowBits)
	return w
}

func TestStreamFailureAfterFragmentRetained(t *testing.T) {
	const frag = defaultWriteBufferSize
	cause := errors.New("stream failure")
	tests := map[string]struct {
		firstSize int
		started   bool
		transport bool
		failures  []string
	}{
		"second fragment transport failure":             {firstSize: frag, started: true, transport: true, failures: []string{"write"}},
		"compressor failure after first fragment":       {firstSize: frag, started: true, failures: []string{"write"}},
		"final fragment flush failure":                  {firstSize: frag, started: true, failures: []string{"flush", "short marker"}},
		"compressor failure before first fragment":      {failures: []string{"write"}},
		"compressed mode failure before first fragment": {firstSize: frag, failures: []string{"write", "flush", "short marker"}},
		"closeLargeLocked compressor failure":           {firstSize: defaultCompressMinSize, failures: []string{"close write"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for _, failure := range tt.failures {
				var compressor *streamFaultCompressor
				if !tt.transport {
					compressor = installStreamCompressor(t, tt.started)
				}
				writes := 0
				wire := &scriptConn{}
				probe := &writeProbe{Conn: wire, write: func(p []byte) (int, error) {
					writes++
					if tt.transport && writes == 2 {
						return 0, cause
					}
					return wire.Write(p)
				}}
				c := NewServerConn(probe, WithCompression(!tt.transport))
				w, err := c.NextWriter(OpcodeBinary)
				if err != nil {
					t.Fatal(err)
				}
				if n, err := w.Write(make([]byte, tt.firstSize)); n != tt.firstSize || err != nil {
					t.Fatalf("%s: first write = %d, %v", failure, n, err)
				}
				if tt.started {
					frames := parseFrames(t, wire.out.Bytes())
					if len(frames) != 1 || frames[0].h.Fin || frames[0].h.Opcode != OpcodeBinary || (!tt.transport && frames[0].h.Rsv != RSV1) {
						t.Fatalf("%s: want one initial non-final fragment, got %d frames", failure, len(frames))
					}
				} else if writes != 0 {
					t.Fatalf("%s: first write sent %d fragments, want none", failure, writes)
				}
				switch failure {
				case "write":
					if compressor != nil {
						compressor.writeErr = cause
					}
					_, err = w.Write(make([]byte, frag))
				case "close write":
					compressor.writeErr = cause
					err = w.Close()
				case "flush":
					compressor.flushErr = cause
					err = w.Close()
				case "short marker":
					err = w.Close()
				}
				if failure == "short marker" {
					if err == nil || !strings.Contains(err.Error(), "shorter than the sync-flush marker") {
						t.Fatalf("%s: got %v, want framing error", failure, err)
					}
				} else if !errors.Is(err, cause) {
					t.Fatalf("%s: got %v, want error matching %v", failure, err, cause)
				}
				before := writes
				if tt.started {
					wantWrites := 1
					if tt.transport {
						wantWrites++
					}
					if writes != wantWrites {
						t.Fatalf("%s: transport writes = %d, want %d", failure, writes, wantWrites)
					}
					requireWriteFailure(t, err, nil)
					later := asyncResult(func() error { return c.WriteMessage(OpcodeText, nil) })
					if got := awaitResult(t, "concurrent writer", later); got != err {
						t.Fatalf("%s: concurrent WriteMessage = %v, want same error as stream (%v)", failure, got, err)
					}
				} else if _, retained := errors.AsType[*writeError](err); retained || before != 0 {
					t.Fatalf("%s: retained = %t, writes = %d; want neither", failure, retained, before)
				}
				if n, got := w.Write(nil); n != 0 || got != err {
					t.Fatalf("%s: subsequent stream write = %d, %v; want 0, %v", failure, n, got, err)
				}
				if got := w.Close(); got != err || writes != before {
					t.Fatalf("%s: stream Close = %v, writes = %d; want %v, %d", failure, got, writes, err, before)
				}
				if !tt.started {
					if got := c.WriteMessage(OpcodeText, []byte("next")); got != nil || writes != 1 {
						t.Fatalf("%s: following WriteMessage = %v, writes = %d; want nil, 1", failure, got, writes)
					}
				}
			}
		})
	}
}

func TestStreamCloseSentNotRetained(t *testing.T) {
	tests := map[string]struct{ handshake bool }{
		"WriteClose from another goroutine":       {},
		"graceful close on the reading goroutine": {handshake: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			deadline := time.Now().Add(5 * time.Second)
			if err := a.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := b.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			spy := newCloseCountConn(a)
			c := NewServerConn(spy)
			w, err := c.NextWriter(OpcodeText)
			if err != nil {
				t.Fatal(err)
			}
			closing := asyncResult(func() error {
				if tt.handshake {
					return c.Close(t.Context(), CloseNormalClosure, "local")
				}
				if err := c.WriteClose(CloseNormalClosure, "local"); err != nil {
					return err
				}
				_, _, err := c.ReadMessage()
				return err
			})
			if f := readWireFrame(t, b); f.h.Opcode != OpcodeClose {
				t.Fatalf("first frame = %v, want Close", f.h.Opcode)
			}
			awaitEntered(t, "peer Close read", spy.readEntered, closing)
			if _, err := w.Write(make([]byte, defaultWriteBufferSize)); err != errWriteClosed {
				t.Fatalf("fragment after Close = %v, want errWriteClosed", err)
			}
			if err := w.Close(); err != errWriteClosed || spy.closes.Load() != 0 {
				t.Fatalf("stream Close = %v, transport closes = %d; want errWriteClosed, 0", err, spy.closes.Load())
			}
			if err := NewClientConn(b).WriteClose(CloseGoingAway, "peer"); err != nil {
				t.Fatalf("peer WriteClose: %v", err)
			}
			err = awaitResult(t, "close handshake", closing)
			if tt.handshake {
				if err != nil {
					t.Fatalf("close handshake: %v", err)
				}
			} else if ce, ok := errors.AsType[*CloseError](err); !ok || ce.Code != CloseGoingAway || ce.Reason != "peer" {
				t.Fatalf("ReadMessage = %v, want peer Close", err)
			}
			if err := c.WriteMessage(OpcodeText, nil); err != errWriteClosed {
				t.Fatalf("later WriteMessage = %v, want errWriteClosed", err)
			}
		})
	}
}

func TestStreamCompressorFailureAfterCloseNotRetained(t *testing.T) {
	compressor := installStreamCompressor(t, true)
	wire := &scriptConn{}
	spy := newCloseCountConn(wire)
	c := NewServerConn(spy, WithCompression(true))
	w, err := c.NextWriter(OpcodeBinary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, defaultWriteBufferSize)); err != nil {
		t.Fatal(err)
	}
	if err := awaitResult(t, "WriteClose", asyncResult(func() error { return c.WriteClose(CloseNormalClosure, "local") })); err != nil {
		t.Fatal(err)
	}
	frames := parseFrames(t, wire.out.Bytes())
	if len(frames) != 2 || frames[0].h.Opcode != OpcodeBinary || frames[0].h.Fin || frames[0].h.Rsv != RSV1 || frames[1].h.Opcode != OpcodeClose {
		t.Fatalf("want compressed non-final fragment followed by Close, got %d frames", len(frames))
	}
	compressor.writeErr = errors.New("compression interrupted")
	_, err = w.Write([]byte("more"))
	if !errors.Is(err, compressor.writeErr) || errors.Is(err, net.ErrClosed) {
		t.Fatalf("stream Write = %v, want only the compressor error", err)
	}
	if got := w.Close(); got != err || spy.closes.Load() != 0 {
		t.Fatalf("stream Close = %v, transport closes = %d; want %v, 0", got, spy.closes.Load(), err)
	}
	if err := c.WriteMessage(OpcodeText, nil); err != errWriteClosed {
		t.Fatalf("later WriteMessage = %v, want errWriteClosed", err)
	}
	wire.in = clientFrame(true, OpcodeClose, AppendCloseBody(nil, CloseGoingAway, []byte("peer")))
	_, _, err = c.ReadMessage()
	if ce, ok := errors.AsType[*CloseError](err); !ok || ce.Code != CloseGoingAway || ce.Reason != "peer" {
		t.Fatalf("ReadMessage = %v, want peer Close", err)
	}
}
