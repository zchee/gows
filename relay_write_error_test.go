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
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFrameWriteErrorRetained(t *testing.T) {
	boom := errors.New("frame write failed")

	t.Run("transport failure", func(t *testing.T) {
		tests := map[string]struct {
			client    bool
			afterSent bool
			op        Opcode
			cause     error
		}{
			"server data":           {op: OpcodeText, cause: boom},
			"client data":           {client: true, op: OpcodeBinary, cause: boom},
			"short write":           {op: OpcodeBinary},
			"deadline":              {op: OpcodeText, cause: os.ErrDeadlineExceeded},
			"Ping after sent Close": {afterSent: true, op: OpcodePing, cause: boom},
			"Pong after sent Close": {afterSent: true, op: OpcodePong, cause: boom},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				writes := 0
				failAt := 1
				if tt.afterSent {
					failAt = 2
				}
				wire := &scriptConn{}
				probe := &writeProbe{Conn: wire, write: func(p []byte) (int, error) {
					writes++
					if writes == failAt {
						if tt.cause == nil {
							return len(p) - 1, nil
						}
						return 0, tt.cause
					}
					return wire.Write(p)
				}}
				spy := newCloseCountConn(probe)
				c := newConn(spy, tt.client, nil)
				defer c.teardown()

				if tt.afterSent {
					body := AppendCloseBody(nil, CloseNormalClosure, nil)
					if err := c.WriteFrame(OpcodeClose, true, body, false); err != nil {
						t.Fatal(err)
					}
				}

				want := tt.cause
				if want == nil {
					want = io.ErrShortWrite
				}
				e := c.WriteFrame(tt.op, true, []byte("payload"), false)
				requireWriteFailure(t, e, want)

				followUps := map[string]func() error{
					"data":          func() error { return c.WriteFrame(OpcodeText, true, nil, false) },
					"Ping":          func() error { return c.WriteFrame(OpcodePing, true, nil, false) },
					"Close":         func() error { return c.WriteFrame(OpcodeClose, true, nil, false) },
					"invalid frame": func() error { return c.WriteFrame(Opcode(3), false, nil, false) },
				}
				for followName, call := range followUps {
					if got := call(); got != e {
						t.Fatalf("%s follow-up = %v, want %v (identity)", followName, got, e)
					}
				}
				if writes != failAt {
					t.Fatalf("transport writes = %d, want %d", writes, failAt)
				}
				c.teardown()
				if got := spy.closes.Load(); got != 1 {
					t.Fatalf("transport closes = %d, want 1", got)
				}
				if got := c.WriteFrame(OpcodeText, true, nil, false); got != e {
					t.Fatalf("after teardown = %v, want %v (identity)", got, e)
				}
			})
		}

		t.Run("vectored TCP deadline", func(t *testing.T) {
			raw, peer := loopbackPair(t)
			defer peer.Close()
			c := NewServerConn(raw)
			defer c.teardown()
			if err := raw.(*net.TCPConn).SetWriteBuffer(4096); err != nil {
				t.Fatal(err)
			}
			if err := c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 16<<10)
			var e error
			for e == nil {
				e = c.WriteFrame(OpcodeBinary, true, payload, false)
			}
			requireWriteFailure(t, e, os.ErrDeadlineExceeded)
			if got := c.WriteFrame(OpcodeBinary, true, payload, false); got != e {
				t.Fatalf("follow-up = %v, want %v (identity)", got, e)
			}
		})
	})

	t.Run("compressor failure", func(t *testing.T) {
		tests := map[string]struct {
			continuation bool
			takeover     bool
			failure      string
		}{
			"opening frame write":      {failure: "write"},
			"opening frame flush":      {takeover: true, failure: "flush"},
			"opening frame short sync": {failure: "short"},
			"continuation frame write": {continuation: true, failure: "write"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				compressor := installStreamCompressor(t, tt.continuation && tt.failure != "short")
				writes := 0
				wire := &scriptConn{}
				probe := &writeProbe{Conn: wire, write: func(p []byte) (int, error) {
					writes++
					return wire.Write(p)
				}}
				spy := newCloseCountConn(probe)
				var opts []ConnOption
				if tt.takeover {
					opts = []ConnOption{WithCompressionParams(CompressionParams{ServerContextTakeover: true})}
				} else {
					opts = []ConnOption{WithCompression(true)}
				}
				c := NewServerConn(spy, opts...)
				defer c.teardown()

				wantWrites := 0
				if tt.continuation {
					if err := c.WriteFrame(OpcodeText, false, []byte("opening"), true); err != nil {
						t.Fatal(err)
					}
					wantWrites = 1
				}

				switch tt.failure {
				case "write":
					compressor.writeErr = boom
				case "flush":
					compressor.flushErr = boom
				}

				op := OpcodeText
				if tt.continuation {
					op = OpcodeContinuation
				}
				e := c.WriteFrame(op, true, []byte("fragment"), true)
				if tt.failure == "short" {
					requireWriteFailure(t, e, nil)
					if !strings.Contains(e.Error(), "shorter than the sync-flush marker") {
						t.Fatalf("short marker error = %v", e)
					}
				} else {
					requireWriteFailure(t, e, boom)
				}
				if c.frameWrite.active || c.frameWrite.lease.w != nil {
					t.Fatalf("compressor state retained: %+v", c.frameWrite)
				}
				if writes != wantWrites {
					t.Fatalf("transport writes = %d, want %d", writes, wantWrites)
				}
				if got := c.WriteFrame(OpcodeText, true, nil, false); got != e {
					t.Fatalf("follow-up = %v, want %v (identity)", got, e)
				}
				c.teardown()
				if got := spy.closes.Load(); got != 1 {
					t.Fatalf("transport closes = %d, want 1", got)
				}
			})
		}
	})

	t.Run("close runs off lock", func(t *testing.T) {
		closeEntered := make(chan struct{})
		releaseClose := make(chan struct{})
		release := sync.OnceFunc(func() { close(releaseClose) })
		defer release()

		var closeOnce sync.Once
		probe := &writeProbe{
			Conn:  &scriptConn{},
			write: func([]byte) (int, error) { return 0, boom },
			close: func() error {
				closeOnce.Do(func() { close(closeEntered) })
				<-releaseClose
				return nil
			},
		}
		spy := newCloseCountConn(probe)
		c := NewServerConn(spy)
		defer c.teardown()

		e := within(t, "failing WriteFrame", time.Second, asyncResult(func() error {
			return c.WriteFrame(OpcodeText, true, []byte("x"), false)
		}))
		requireWriteFailure(t, e, boom)

		select {
		case <-closeEntered:
		case <-time.After(time.Second):
			t.Fatal("background transport close did not start within 1s")
		}

		got := within(t, "follow-up WriteFrame while Close blocked", time.Second, asyncResult(func() error {
			return c.WriteFrame(OpcodeText, true, nil, false)
		}))
		if got != e {
			t.Fatalf("follow-up = %v, want %v (identity)", got, e)
		}

		release()
		c.teardown()
		if closes := spy.closes.Load(); closes != 1 {
			t.Fatalf("transport closes = %d, want 1", closes)
		}
	})

	t.Run("usage error not retained", func(t *testing.T) {
		tests := map[string]struct {
			compressed bool
			badOp      Opcode
			badFin     bool
			badComp    bool
		}{
			"new data frame while awaiting continuation": {badOp: OpcodeText, badFin: true},
			"continuation compression mismatch":          {compressed: true, badOp: OpcodeContinuation, badFin: true, badComp: false},
			"fragmented control during open message":     {compressed: true, badOp: OpcodePing, badFin: false, badComp: false},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				wire := &scriptConn{}
				spy := newCloseCountConn(wire)
				c := NewServerConn(spy, WithCompression(tt.compressed))
				defer c.teardown()

				if err := c.WriteFrame(OpcodeText, false, []byte("hel"), tt.compressed); err != nil {
					t.Fatal(err)
				}
				err := c.WriteFrame(tt.badOp, tt.badFin, []byte("bad"), tt.badComp)
				if _, ok := errors.AsType[*FrameUsageError](err); !ok || errors.Is(err, net.ErrClosed) {
					t.Fatalf("usage error = %T %v, want FrameUsageError without net.ErrClosed", err, err)
				}
				if _, ok := errors.AsType[*writeError](err); ok || spy.closes.Load() != 0 {
					t.Fatalf("usage error retained = %t, closes = %d", ok, spy.closes.Load())
				}
				if err := c.WriteFrame(OpcodeContinuation, true, []byte("lo"), tt.compressed); err != nil {
					t.Fatalf("continuation after usage error = %v", err)
				}

				reader := NewClientConn(&scriptConn{in: wire.out.Bytes()}, WithCompression(tt.compressed))
				defer reader.teardown()
				var out []byte
				for range 2 {
					f, err := reader.ReadFrame()
					if err != nil {
						t.Fatal(err)
					}
					if tt.compressed {
						p, complete, err := reader.DecodeFrame(f)
						if err != nil {
							t.Fatal(err)
						}
						out = append(out, p...)
						if complete {
							break
						}
					} else {
						out = append(out, f.Payload...)
					}
				}
				if !bytes.Equal(out, []byte("hello")) {
					t.Fatalf("decoded = %q, want %q", out, "hello")
				}
			})
		}

		t.Run("unsupported outgoing window", func(t *testing.T) {
			wire := &scriptConn{}
			spy := newCloseCountConn(wire)
			c := NewServerConn(spy, WithCompressionParams(CompressionParams{ServerMaxWindowBits: 9}))
			defer c.teardown()

			err := c.WriteFrame(OpcodeBinary, true, []byte("x"), true)
			if !errors.Is(err, ErrUnsupportedWindowBits) || errors.Is(err, net.ErrClosed) {
				t.Fatalf("window error = %v, want ErrUnsupportedWindowBits without net.ErrClosed", err)
			}
			if spy.closes.Load() != 0 {
				t.Fatalf("closes = %d, want 0", spy.closes.Load())
			}
			if err := c.WriteFrame(OpcodeBinary, true, []byte("ok"), false); err != nil {
				t.Fatalf("uncompressed frame after window error = %v", err)
			}
		})
	})

	t.Run("local close and precedence", func(t *testing.T) {
		t.Run("interrupted by local close", func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			spy := newCloseCountConn(a)
			c := NewServerConn(spy)
			defer c.teardown()

			ch := asyncResult(func() error {
				return c.WriteFrame(OpcodeBinary, true, []byte("blocked"), false)
			})
			awaitEntered(t, "frame write", spy.writeEntered, ch)
			c.closeNow()

			got := awaitResult(t, "interrupted WriteFrame", ch)
			if _, ok := errors.AsType[*writeError](got); ok || !errors.Is(got, net.ErrClosed) {
				t.Fatalf("interrupted WriteFrame = %T %v, want closedError without *writeError", got, got)
			}
			if c.werr != nil {
				t.Fatalf("werr = %v, want nil after local close", c.werr)
			}
			if later := c.WriteFrame(OpcodeBinary, true, nil, false); later != errWriteClosed {
				t.Fatalf("later data WriteFrame = %v, want errWriteClosed", later)
			}
		})

		t.Run("message-mode precedence", func(t *testing.T) {
			mc := NewServerConn(&failWriteConn{Conn: &scriptConn{}, err: boom})
			defer mc.teardown()
			e := mc.WriteMessage(OpcodeText, nil)
			requireWriteFailure(t, e, boom)
			if err := mc.WriteFrame(OpcodeText, true, nil, false); !errors.Is(err, ErrConnMode) {
				t.Fatalf("WriteFrame on message-mode Conn = %v, want ErrConnMode", err)
			}
			if got := mc.WriteMessage(OpcodeText, nil); got != e {
				t.Fatalf("retained message error = %v, want %v", got, e)
			}
		})

		t.Run("torn down beats control usage", func(t *testing.T) {
			c := NewServerConn(&scriptConn{})
			if err := c.selectMode(connModeFrame); err != nil {
				t.Fatal(err)
			}
			c.teardown()
			if err := c.WriteFrame(OpcodePing, false, nil, false); err != errWriteClosed {
				t.Fatalf("torn-down invalid control = %v, want errWriteClosed", err)
			}
		})

		t.Run("after sent Close", func(t *testing.T) {
			c := NewServerConn(&scriptConn{})
			defer c.teardown()
			if err := c.WriteFrame(OpcodeClose, true, nil, false); err != nil {
				t.Fatal(err)
			}
			err := c.WriteFrame(OpcodeClose, true, []byte{1}, false)
			if _, ok := errors.AsType[*FrameUsageError](err); !ok {
				t.Fatalf("invalid Close after sent Close = %v, want FrameUsageError", err)
			}
			if err := c.WriteFrame(OpcodeClose, true, nil, false); err != nil {
				t.Fatalf("valid Close after sent Close = %v, want nil", err)
			}
			if err := c.WriteFrame(OpcodeText, true, nil, false); err != errWriteClosed {
				t.Fatalf("data after sent Close = %v, want errWriteClosed", err)
			}
		})
	})
}
