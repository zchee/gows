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
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"time"
)

func TestCloseStreamReader(t *testing.T) {
	writeErr := errors.New("write rejected")
	deadlineErr := errors.New("deadline rejected")
	failWrite := func([]byte) (int, error) { return 0, writeErr }
	tests := map[string]struct {
		write         func([]byte) (int, error)
		deadline      func(time.Time) error
		before        func(*testing.T, *Conn)
		canceled      bool
		wantPeerClose bool
		want          error
	}{
		"retained write failure": {write: failWrite, before: func(t *testing.T, c *Conn) {
			requireWriteFailure(t, c.WriteMessage(OpcodeBinary, nil), writeErr)
		}},
		"after CloseNow": {before: func(t *testing.T, c *Conn) {
			if err := c.CloseNow(); err != nil {
				t.Fatal(err)
			}
		}},
		"canceled context":       {canceled: true, want: context.Canceled},
		"deadline setup failure": {deadline: func(time.Time) error { return deadlineErr }, want: deadlineErr},
		"close send failure":     {write: failWrite, want: writeErr},
		"second Close": {before: func(t *testing.T, c *Conn) {
			if err := c.Close(t.Context(), CloseNormalClosure, ""); err != nil {
				t.Fatalf("first Close: %v", err)
			}
		}},
		"graceful close": {wantPeerClose: true},
	}
	payload := []byte("abc")
	readers := map[string]struct {
		wire     []byte
		complete bool
	}{
		"completed":          {wire: clientFrame(true, OpcodeBinary, payload), complete: true},
		"partial compressed": {wire: buildCompressedFrame(t, true, OpcodeBinary, payload)},
		"partial fragmented": {wire: append(clientFrame(false, OpcodeBinary, payload[:2]), clientFrame(true, OpcodeContinuation, payload[2:])...)},
	}
	for name, tt := range tests {
		for state, reader := range readers {
			t.Run(name+"/"+state, func(t *testing.T) {
				wire := slices.Concat(reader.wire, closeFrame(CloseNormalClosure, "peer reply"))
				p := &writeProbe{Conn: &scriptConn{in: wire}, write: tt.write, deadline: tt.deadline}
				c := NewServerConn(p, WithCompression(true))
				_, r, err := c.NextReader()
				if err != nil {
					t.Fatal(err)
				}
				var b [1]byte
				if reader.complete {
					if got, err := io.ReadAll(r); err != nil || string(got) != string(payload) {
						t.Fatalf("ReadAll = %q, %v; want %q, nil", got, err, payload)
					}
					if n, err := r.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
						t.Fatalf("completed Read = %d, %v; want 0, EOF", n, err)
					}
				} else if n, err := r.Read(b[:]); n != 1 || err != nil || b[0] != payload[0] {
					t.Fatalf("partial Read = %q, %d, %v; want %q, 1, nil", b, n, err, payload[0])
				}
				if tt.before != nil {
					tt.before(t, c)
				}
				ctx := t.Context()
				if tt.canceled {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				if err := c.Close(ctx, CloseNormalClosure, ""); !errors.Is(err, tt.want) {
					t.Fatalf("Close = %v; want %v", err, tt.want)
				}
				requireSupersededReader(t, c, r)
				if tt.wantPeerClose {
					if ce, ok := errors.AsType[*CloseError](c.readErr); !ok || ce.Sent || ce.Code != CloseNormalClosure || ce.Reason != "peer reply" {
						t.Fatalf("recorded read error = %#v; want received CloseNormalClosure with reason %q", c.readErr, "peer reply")
					}
				}
			})
		}
	}
}

func requireSupersededReader(t *testing.T, c *Conn, r io.Reader) {
	t.Helper()
	// Check ownership first: the test must never read a returned pool buffer.
	if c.msgReader != nil {
		t.Fatal("Close left the stream reader active")
	}
	var b [1]byte
	if n, err := r.Read(b[:]); n != 0 || !errors.Is(err, errStreamReaderStale) {
		t.Fatalf("Read after Close = %d, %v; want 0, superseded reader", n, err)
	}
}

func TestCloseStreamReaderAfterReadError(t *testing.T) {
	c := NewServerConn(&scriptConn{in: clientFrame(false, OpcodeBinary, nil)})
	_, r, err := c.NextReader()
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	for range 2 {
		if n, err := r.Read(b[:]); n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("Read before Close = %d, %v; want 0, unexpected EOF", n, err)
		}
	}
	if err := c.Close(t.Context(), CloseNormalClosure, ""); err != nil {
		t.Fatal(err)
	}
	requireSupersededReader(t, c, r)
}

func TestCloseStreamReaderInvalidArguments(t *testing.T) {
	wire := clientFrame(false, OpcodeText, []byte("ab"))
	wire = append(wire, clientFrame(true, OpcodeContinuation, []byte("c"))...)
	wire = append(wire, clientFrame(true, OpcodeText, []byte("next"))...)
	wire = append(wire, closeFrame(CloseNormalClosure, "")...)
	c := NewServerConn(&scriptConn{in: wire})
	_, r, err := c.NextReader()
	if err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := r.Read(b[:]); n != 1 || err != nil || b[0] != 'a' {
		t.Fatalf("Read before Close = %q, %d, %v; want a, 1, nil", b, n, err)
	}
	if err := c.Close(t.Context(), CloseNoStatusReceived, ""); !errors.Is(err, ErrInvalidCloseCode) {
		t.Fatalf("Close = %v; want invalid close code", err)
	}
	if got, err := io.ReadAll(r); err != nil || string(got) != "bc" {
		t.Fatalf("remaining payload = %q, %v; want bc, nil", got, err)
	}
	if op, got, err := c.ReadMessage(); err != nil || op != OpcodeText || string(got) != "next" {
		t.Fatalf("next message = %v, %q, %v; want Text, next, nil", op, got, err)
	}
	if err := c.Close(t.Context(), CloseNormalClosure, ""); err != nil {
		t.Fatal(err)
	}
}
