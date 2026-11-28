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
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The hooks can hold a transport call while another goroutine enters Close.
// closeCountConn observes the first read and write before passing them to the hooks.
type writeProbe struct {
	net.Conn
	write    func([]byte) (int, error)
	deadline func(time.Time) error
	close    func() error
}

func (p *writeProbe) Write(b []byte) (int, error) {
	if p.write != nil {
		return p.write(b)
	}
	return p.Conn.Write(b)
}

func (p *writeProbe) SetDeadline(d time.Time) error {
	if p.deadline != nil {
		return p.deadline(d)
	}
	return p.Conn.SetDeadline(d)
}

func (p *writeProbe) Close() error {
	if p.close != nil {
		return p.close()
	}
	return p.Conn.Close()
}

func asyncResult(f func() error) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- f() }()
	return ch
}

func within[T any](t *testing.T, op string, limit time.Duration, result <-chan T) T {
	t.Helper()
	select {
	case v := <-result:
		return v
	case <-time.After(limit):
		t.Fatalf("%s still blocked after %v", op, limit)
		panic("unreachable")
	}
}

func requireWriteFailure(t *testing.T, err, cause error) {
	t.Helper()
	if _, ok := err.(*writeError); !ok || !errors.Is(err, net.ErrClosed) || (cause != nil && !errors.Is(err, cause)) {
		t.Fatalf("write failure = %T %v; want *writeError matching net.ErrClosed and %v", err, err, cause)
	}
}

func TestWriteErrorRetained(t *testing.T) {
	boom := errors.New("write interrupted")
	pm, err := NewPreparedMessage(OpcodeText, []byte("prepared"))
	if err != nil {
		t.Fatal(err)
	}
	message := func(size int) func(*Conn) error {
		return func(c *Conn) error { return c.WriteMessage(OpcodeBinary, make([]byte, size)) }
	}
	closeFrame := func(c *Conn) error { return c.WriteClose(CloseNormalClosure, "bye") }
	handshake := func(c *Conn) error { return c.Close(t.Context(), CloseNormalClosure, "bye") }
	first := map[string]struct {
		call                        func(*Conn) error
		client, compressed, pending bool
		failAt, partial             int
		failures                    []error
	}{
		"inline":               {call: message(16), failures: []error{boom, os.ErrDeadlineExceeded, nil}},
		"inline partial error": {call: message(16), partial: 2, failures: []error{boom}},
		"staged":               {call: message(16 << 10), failures: []error{boom, nil}},
		"staged prefix":        {call: message(maxBufferedWriteSize + 1)},
		"staged remainder":     {call: message(maxBufferedWriteSize + 1), failAt: 2},
		"client":               {call: message(16), client: true},
		"compressed":           {call: message(4096), compressed: true},
		"automatic flush":      {call: func(c *Conn) error { return c.WriteMessageBuffered(OpcodeBinary, make([]byte, maxBufferedWriteSize)) }, failures: []error{boom, nil}},
		"explicit flush":       {call: (*Conn).Flush, pending: true, failures: []error{boom, nil}},
		"flush before message": {call: message(1), pending: true},
		"flush before Close":   {call: closeFrame, pending: true},
		"prepared":             {call: func(c *Conn) error { return c.WritePreparedMessage(pm) }},
		"server WriteClose":    {call: closeFrame}, "client WriteClose": {call: closeFrame, client: true},
		"server Close": {call: handshake}, "client Close": {call: handshake, client: true},
	}
	for name, tt := range first {
		t.Run(name, func(t *testing.T) {
			failures := tt.failures
			if failures == nil {
				failures = []error{boom}
			}
			for _, cause := range failures {
				want := cause
				if want == nil {
					want = io.ErrShortWrite
				}
				t.Run(want.Error(), func(t *testing.T) {
					count := 0
					failAt := max(1, tt.failAt)
					p := &writeProbe{Conn: &scriptConn{}, write: func(b []byte) (int, error) {
						count++
						if count == failAt {
							return tt.partial, cause
						}
						return len(b), nil
					}}
					spy := newCloseCountConn(p)
					c := newConn(spy, tt.client, []ConnOption{WithCompression(tt.compressed)})
					if tt.pending {
						if err := c.WriteMessageBuffered(OpcodeText, []byte("first")); err != nil {
							t.Fatal(err)
						}
					}
					e := tt.call(c)
					requireWriteFailure(t, e, want)
					if got := c.WriteMessage(OpcodeText, nil); got != e {
						t.Fatalf("follow-up = %v; want same error %v", got, e)
					}
					if name == "server Close" || name == "client Close" {
						if got := handshake(c); got != nil {
							t.Fatalf("second Close = %v", got)
						}
					}
					if err := c.CloseNow(); err != nil {
						t.Fatal(err)
					}
					if got := spy.closes.Load(); count != failAt || got != 1 {
						t.Fatalf("writes, closes = %d, %d; want %d, 1", count, got, failAt)
					}
				})
			}
		})
	}
	t.Run("vectored TCP deadline", func(t *testing.T) {
		raw, peer := loopbackPair(t)
		defer peer.Close()
		c := NewServerConn(raw)
		defer c.CloseNow()
		if err := raw.(*net.TCPConn).SetWriteBuffer(4096); err != nil {
			t.Fatal(err)
		}
		if err := c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, 16<<10)
		var e error
		for e == nil {
			e = c.WriteMessage(OpcodeBinary, payload)
		}
		requireWriteFailure(t, e, os.ErrDeadlineExceeded)
		if got := c.WriteMessage(OpcodeBinary, payload); got != e {
			t.Fatalf("follow-up = %v, want %v", got, e)
		}
	})
	for _, client := range []bool{false, true} {
		role := "server"
		if client {
			role = "client"
		}
		t.Run(role+" follow-up", func(t *testing.T) {
			writes := 0
			p := &writeProbe{Conn: &scriptConn{}, write: func([]byte) (int, error) { writes++; return 0, boom }}
			spy := newCloseCountConn(p)
			c := newConn(spy, client, nil)
			e := c.WriteMessage(OpcodeText, nil)
			requireWriteFailure(t, e, boom)
			ended, cancel := context.WithCancel(t.Context())
			cancel()
			preparedErr := e
			if client {
				preparedErr = ErrPreparedMessageClientRole
			}
			tests := map[string]struct {
				call func() error
				want error
			}{
				"message":     {func() error { return c.WriteMessage(OpcodeText, nil) }, e},
				"buffered":    {func() error { return c.WriteMessageBuffered(OpcodeText, nil) }, e},
				"empty flush": {c.Flush, nil},
				// Public emitters flush and reset a pending batch before they can fail,
				// so only an in-package test can set up this closed-Flush state.
				"pending flush": {func() error {
					c.wmu.Lock()
					c.wbatch = c.appendFrameLocked(nil, OpcodeText, []byte("pending"))
					c.wmu.Unlock()
					return c.Flush()
				}, e},
				"prepared":     {func() error { return c.WritePreparedMessage(pm) }, preparedErr},
				"data writer":  {func() error { _, err := c.NextWriter(OpcodeText); return err }, e},
				"live context": {func() error { return c.WriteMessageContext(t.Context(), OpcodeText, nil) }, e},
			}
			for name, tt := range tests {
				t.Run(name, func(t *testing.T) {
					if got := tt.call(); got != tt.want {
						t.Fatalf("got %v, want %v (identity)", got, tt.want)
					}
					if len(c.wbatch) != 0 || writes != 1 {
						t.Fatalf("batch = %d bytes, transport writes = %d; want empty batch and no additional write", len(c.wbatch), writes)
					}
				})
			}
			if _, err := c.NextWriter(OpcodePing); err == nil || !strings.Contains(err.Error(), "not a data opcode") {
				t.Errorf("non-data NextWriter = %v", err)
			}
			if got := c.WriteMessageContext(ended, OpcodeText, nil); !errors.Is(got, context.Canceled) || !strings.HasPrefix(got.Error(), "gows: write: ") {
				t.Errorf("ended context = %v", got)
			}
			if err := c.CloseNow(); err != nil {
				t.Fatal(err)
			}
			if writes != 1 || spy.closes.Load() != 1 {
				t.Errorf("writes=%d closes=%d, want one each", writes, spy.closes.Load())
			}
		})
	}
}

type rejectCompression struct {
	DeflateWriter
	cause error
}

func (w rejectCompression) Write([]byte) (int, error) { return 0, w.cause }

func TestWriteErrorNotRetained(t *testing.T) {
	boom := errors.New("compression rejected")
	tests := map[string]struct {
		call             func(*Conn) error
		want             error
		client, compress bool
	}{
		"invalid close code":         {call: func(c *Conn) error { return c.WriteClose(0, "") }, want: ErrInvalidCloseCode},
		"invalid close reason":       {call: func(c *Conn) error { return c.WriteClose(CloseNormalClosure, "\xff") }, want: ErrInvalidCloseReason},
		"too-long close reason":      {call: func(c *Conn) error { return c.WriteClose(CloseNormalClosure, strings.Repeat("x", 124)) }, want: ErrCloseReasonTooLong},
		"non-data NextWriter opcode": {call: func(c *Conn) error { _, err := c.NextWriter(OpcodePing); return err }},
		"ErrWriterBusy": {call: func(c *Conn) error {
			w, err := c.NextWriter(OpcodeText)
			if err != nil {
				return err
			}
			refused := c.WriteMessage(OpcodeText, nil)
			if err := w.Close(); err != nil {
				return err
			}
			return refused
		}, want: ErrWriterBusy},
		"client WritePreparedMessage": {call: func(c *Conn) error { return c.WritePreparedMessage(nil) }, want: ErrPreparedMessageClientRole, client: true},
		"WriteMessageContext ended ctx": {call: func(c *Conn) error {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			return c.WriteMessageContext(ctx, OpcodeText, nil)
		}, want: context.Canceled},
		"compression error before any byte": {call: func(c *Conn) error {
			c.deflate.outgoing = rejectCompression{c.deflate.outgoing, boom}
			return c.WriteMessage(OpcodeBinary, make([]byte, defaultCompressMinSize))
		}, want: boom, compress: true},
		"frame-mode precedence": {call: func(*Conn) error {
			fc := NewServerConn(&failWriteConn{Conn: &scriptConn{}, err: boom})
			defer fc.teardown()
			e := fc.WriteFrame(OpcodeText, true, nil, false)
			requireWriteFailure(t, e, boom)
			err := fc.WriteMessage(OpcodeText, nil)
			if got := fc.WriteFrame(OpcodeText, true, nil, false); got != e {
				t.Fatalf("retained frame error = %v, want %v", got, e)
			}
			return err
		}, want: ErrConnMode},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			if err := a.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var opts []ConnOption
			if tt.compress {
				opts = []ConnOption{WithCompressionParams(CompressionParams{ServerContextTakeover: true})}
			}
			c := newConn(a, tt.client, opts)
			peer := newConn(b, !tt.client, nil)
			received := asyncResult(func() error {
				for {
					op, p, err := peer.ReadMessage()
					if err != nil {
						return err
					}
					if name == "ErrWriterBusy" && len(p) == 0 {
						continue
					}
					if op != OpcodeText || string(p) != "follow" {
						return errors.New("unexpected frame before follow-up")
					}
					return nil
				}
			})
			err := tt.call(c)
			if tt.want != nil {
				if !errors.Is(err, tt.want) {
					t.Fatalf("error = %v, want %v", err, tt.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "not a data opcode") {
				t.Fatalf("opcode error = %v", err)
			}
			if err := c.WriteMessage(OpcodeText, []byte("follow")); err != nil {
				t.Fatalf("follow-up = %v", err)
			}
			if err := awaitResult(t, "peer message", received); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRetainedErrorEndsReader(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	boom := errors.New("write failed")
	spy := newCloseCountConn(&failWriteConn{Conn: a, err: boom})
	c := NewServerConn(spy, WithBuffered(clientFrame(true, OpcodeText, []byte("buffered"))))
	if op, p, err := c.ReadMessage(); op != OpcodeText || string(p) != "buffered" || err != nil {
		t.Fatalf("buffered = %v %q %v", op, p, err)
	}
	result := asyncResult(func() error { _, _, err := c.ReadMessage(); return err })
	within(t, "blocked read", time.Second, spy.readEntered)
	requireWriteFailure(t, c.WriteMessage(OpcodeText, nil), boom)
	if err := within(t, "interrupted reader", time.Second, result); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestBufferedPingAfterClose(t *testing.T) {
	t.Run("CloseNow", func(t *testing.T) {
		wire := append(clientFrame(true, OpcodePing, nil), clientFrame(true, OpcodeText, []byte("buffered"))...)
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		c := NewServerConn(a, WithBuffered(wire))
		if err := c.CloseNow(); err != nil {
			t.Fatal(err)
		}
		if op, p, err := c.ReadMessage(); err != nil || op != OpcodeText || string(p) != "buffered" {
			t.Fatalf("after Ping = %v %q %v", op, p, err)
		}
		if _, _, err := c.ReadMessage(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("transport read = %v", err)
		}
	})
	t.Run("retained write failure", func(t *testing.T) {
		wire := append(clientFrame(true, OpcodePing, nil), clientFrame(true, OpcodeText, []byte("buffered"))...)
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		boom := errors.New("write failed")
		c := NewServerConn(&failWriteConn{a, boom}, WithBuffered(wire))
		requireWriteFailure(t, c.WriteMessage(OpcodeText, nil), boom)
		if op, p, err := c.ReadMessage(); err != nil || op != OpcodeText || string(p) != "buffered" {
			t.Fatalf("after Ping = %v %q %v", op, p, err)
		}
		if _, _, err := c.ReadMessage(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("transport read = %v", err)
		}
	})
}

func TestFlushDropsPendingBatchAfterCloseNow(t *testing.T) {
	wire := &scriptConn{}
	c := NewServerConn(wire)
	if err := c.WriteMessageBuffered(OpcodeText, []byte("pending")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseNow(); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); !errors.Is(err, net.ErrClosed) || len(c.wbatch) != 0 || wire.out.Len() != 0 {
		t.Fatalf("Flush = %v, batch = %d bytes, wire = %d bytes", err, len(c.wbatch), wire.out.Len())
	}
}

func TestFlushEmptyAfterRetainedError(t *testing.T) {
	tests := map[string]struct {
		echo bool
		want int
	}{"reader only": {want: 2}, "echo": {true, 1}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			frame := clientFrame(true, OpcodeText, []byte("reply"))
			wire := append(frame, frame...)
			boom := errors.New("write failed")
			c := NewServerConn(&failWriteConn{a, boom}, WithBuffered(wire))
			e := c.WriteMessage(OpcodeText, nil)
			requireWriteFailure(t, e, boom)
			if err := c.Flush(); err != nil {
				t.Fatalf("empty flush = %v", err)
			}
			calls := 0
			got := c.Serve(func(op Opcode, b []byte) error {
				calls++
				if op != OpcodeText || string(b) != "reply" {
					t.Fatalf("handler = %v %q", op, b)
				}
				if tt.echo {
					return c.WriteMessageBuffered(op, b)
				}
				return nil
			})
			if calls != tt.want || !errors.Is(got, net.ErrClosed) || (tt.echo && got != e) {
				t.Fatalf("Serve = %v, calls=%d; retained=%v, want calls=%d", got, calls, e, tt.want)
			}
		})
	}
}

func TestLocalCloseDuringBlockedWriteNotRetained(t *testing.T) {
	tests := map[string]struct {
		context bool
		later   error
	}{
		"CloseNow during blocked write":      {later: errClosedNow},
		"context ended during blocked write": {context: true, later: errWriteClosed},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			spy := newCloseCountConn(a)
			c := NewServerConn(spy)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("caller stopped write")
			ch := asyncResult(func() error {
				if tt.context {
					return c.WriteMessageContext(ctx, OpcodeText, nil)
				}
				return c.WriteMessage(OpcodeText, nil)
			})
			awaitEntered(t, "write", spy.writeEntered, ch)
			if tt.context {
				cancel(cause)
			} else if err := c.CloseNow(); err != nil {
				t.Fatal(err)
			}
			got := awaitResult(t, "interrupted write", ch)
			if _, ok := errors.AsType[*writeError](got); ok || (tt.context && (!errors.Is(got, context.Canceled) || !errors.Is(got, cause))) || (!tt.context && !errors.Is(got, net.ErrClosed)) {
				t.Fatalf("interrupted write = %T %v", got, got)
			}
			if err := c.WriteMessage(OpcodeText, nil); err != tt.later {
				t.Fatalf("later write = %v, want %v", err, tt.later)
			}
			if c.rbuf == nil {
				t.Fatal("writer released read buffer")
			}
			if err := c.Close(t.Context(), CloseNormalClosure, ""); err != nil || c.rbuf != nil {
				t.Fatalf("Close = %v, buffer released = %t", err, c.rbuf == nil)
			}
		})
	}
}

func TestPongWriteFailureRetained(t *testing.T) {
	boom := errors.New("Pong failed")
	c := NewServerConn(&failWriteConn{Conn: &scriptConn{in: clientFrame(true, OpcodePing, []byte("ping"))}, err: boom})
	_, _, err := c.ReadMessage()
	requireWriteFailure(t, err, boom)
	if got := c.WriteMessage(OpcodeText, nil); got != err {
		t.Fatalf("later write = %v; want read failure %v", got, err)
	}
}

// tlsCloseProbe arms on the raw write error, before tls can start close_notify.
type tlsCloseProbe struct {
	*closeCountConn
	armed   chan struct{}
	closing chan time.Time
	release chan struct{}
}

func (p *tlsCloseProbe) Write(b []byte) (int, error) {
	select {
	case <-p.armed:
		<-p.release
	default:
	}
	n, err := p.closeCountConn.Write(b)
	if err != nil {
		select {
		case <-p.armed:
		default:
			close(p.armed)
		}
	}
	return n, err
}

func (p *tlsCloseProbe) SetWriteDeadline(d time.Time) error {
	select {
	case <-p.armed:
		select {
		case p.closing <- d:
		default:
		}
		<-p.release
	default:
	}
	return p.Conn.SetWriteDeadline(d)
}

func TestRetainedWriteTLS(t *testing.T) {
	const bound = 1200 * time.Millisecond
	peer, raw := loopbackPair(t)
	defer peer.Close()
	defer raw.Close()
	if err := raw.(*net.TCPConn).SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	spy := &tlsCloseProbe{newCloseCountConn(raw), make(chan struct{}), make(chan time.Time, 1), make(chan struct{})}
	release := sync.OnceFunc(func() { close(spy.release) })
	defer release()
	server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	client := tls.Client(spy, &tls.Config{InsecureSkipVerify: true}) // Test-only self-signed loopback.
	handshake := asyncResult(func() error { return server.HandshakeContext(t.Context()) })
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := awaitResult(t, "TLS handshake", handshake); err != nil {
		t.Fatal(err)
	}
	readerSpy := newCloseCountConn(client)
	c := NewClientConn(readerSpy)
	read := asyncResult(func() error { _, _, err := c.ReadMessage(); return err })
	within(t, "TLS reader", bound, readerSpy.readEntered)
	if err := c.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	first := asyncResult(func() error {
		payload := make([]byte, 16<<10)
		for {
			if err := c.WriteMessage(OpcodeBinary, payload); err != nil {
				return err
			}
		}
	})
	e := within(t, "failed TLS write", bound, first)
	requireWriteFailure(t, e, nil)
	if d := within(t, "TLS close_notify deadline", bound, spy.closing); time.Until(d) < 3*time.Second || time.Until(d) > 5*time.Second {
		t.Fatalf("TLS close_notify deadline = %v, want about five seconds ahead", d)
	}
	if got := within(t, "second TLS write", bound, asyncResult(func() error { return c.WriteMessage(OpcodeText, nil) })); got != e {
		t.Fatalf("later write = %v, want %v", got, e)
	}
	started := make(chan struct{})
	closed := asyncResult(func() error { close(started); return c.CloseNow() })
	<-started
	select {
	case err := <-closed:
		t.Fatalf("CloseNow returned %v with close_notify held", err)
	default:
	}
	// Let close_notify make progress after releasing the spy.
	drain := asyncResult(func() error { _, err := io.Copy(io.Discard, server); return err })
	release()
	if err := within(t, "CloseNow after TLS release", bound, closed); err != nil {
		t.Fatal(err)
	}
	if got := spy.closes.Load(); got != 1 {
		t.Fatalf("raw transport closes = %d", got)
	}
	if err := within(t, "TLS reader after close", bound, read); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("reader = %v", err)
	}
	_ = within(t, "peer drain", bound, drain)
}

func TestCloseNowWaitsForTransportClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		c := NewServerConn(&writeProbe{Conn: &scriptConn{}, close: func() error {
			close(entered)
			<-release
			return nil
		}})
		closed := asyncResult(c.CloseNow)
		<-entered
		synctest.Wait()
		select {
		case err := <-closed:
			close(release)
			t.Fatalf("CloseNow returned %v while transport Close was blocked", err)
		default:
		}
		close(release)
		if err := <-closed; err != nil {
			t.Fatalf("CloseNow after transport Close = %v, want nil", err)
		}
	})
}

// advertisedDeadline lets the I/O deadline expire before cancellation is delivered.
type advertisedDeadline struct {
	context.Context
	at time.Time
}

func (c advertisedDeadline) Deadline() (time.Time, bool) { return c.at, true }

func TestCloseConcurrentBlockedWrite(t *testing.T) {
	const bound = 1200 * time.Millisecond
	newPipe := func(t *testing.T, timeout time.Duration) (*Conn, *writeProbe, *closeCountConn, net.Conn) {
		t.Helper()
		a, b := net.Pipe()
		t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
		p := &writeProbe{Conn: a}
		spy := newCloseCountConn(p)
		return NewServerConn(spy, WithCloseTimeout(timeout)), p, spy, b
	}
	write := func(t *testing.T, c *Conn, spy *closeCountConn) <-chan error {
		t.Helper()
		ch := asyncResult(func() error { return c.WriteMessage(OpcodeText, []byte("hello")) })
		within(t, "writer entered", bound, spy.writeEntered)
		return ch
	}
	startClose := func(c *Conn, ctx context.Context, code CloseCode) <-chan error {
		return asyncResult(func() error { return c.Close(ctx, code, "ok") })
	}
	final := func(t *testing.T, c *Conn, spy *closeCountConn) {
		t.Helper()
		if err := within(t, "second Close", bound, startClose(c, t.Context(), CloseNormalClosure)); err != nil || spy.closes.Load() != 1 {
			t.Fatalf("second Close = %v; closes = %d", err, spy.closes.Load())
		}
	}
	later := func(t *testing.T, c *Conn, want error) {
		t.Helper()
		if err := c.WriteMessage(OpcodeText, nil); err != want {
			t.Fatalf("later write = %v; want %v (identity)", err, want)
		}
	}
	tests := map[string]struct {
		timeout                                  time.Duration
		cancelBefore, cancelDuring, failDeadline bool
	}{
		"close timeout":         {timeout: 200 * time.Millisecond},
		"context ends":          {timeout: 30 * time.Second, cancelDuring: true},
		"context already ended": {timeout: 30 * time.Second, cancelBefore: true},
		"set deadline fails":    {timeout: 30 * time.Second, failDeadline: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, p, spy, _ := newPipe(t, tt.timeout)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("application canceled")
			armErr := errors.New("deadline rejected")
			armed := make(chan struct{})
			p.deadline = func(d time.Time) error {
				if tt.failDeadline {
					return armErr
				}
				err := p.Conn.SetDeadline(d)
				close(armed)
				return err
			}
			w := write(t, c, spy)
			if tt.cancelBefore {
				cancel(cause)
			}
			closing := startClose(c, ctx, CloseNormalClosure)
			if tt.cancelDuring {
				within(t, "guard armed", bound, armed)
				cancel(cause)
			}
			cerr := within(t, "Close", bound, closing)
			werr := within(t, "interrupted writer", bound, w)
			switch {
			case tt.cancelBefore || tt.cancelDuring:
				if !errors.Is(cerr, context.Canceled) || !errors.Is(cerr, cause) {
					t.Fatalf("Close = %v; want cancellation and cause", cerr)
				}
			case tt.failDeadline:
				if !errors.Is(cerr, armErr) {
					t.Fatalf("Close = %v; want %v", cerr, armErr)
				}
			default:
				if _, ok := errors.AsType[*writeError](cerr); ok || !errors.Is(cerr, ErrCloseTimeout) {
					t.Fatalf("Close = %v; want timeout without writer's error", cerr)
				}
			}
			if tt.cancelBefore || tt.failDeadline {
				if _, ok := errors.AsType[*writeError](werr); ok || !errors.Is(werr, net.ErrClosed) {
					t.Fatalf("writer = %v; want local close without retention", werr)
				}
				later(t, c, errWriteClosed)
			} else {
				var want error
				if !tt.cancelDuring {
					want = os.ErrDeadlineExceeded
				}
				requireWriteFailure(t, werr, want)
				later(t, c, werr)
			}
			final(t, c, spy)
		})
	}
	t.Run("invalid close arguments", func(t *testing.T) {
		c, _, spy, peer := newPipe(t, 5*time.Second)
		w := write(t, c, spy)
		ctx := t.Context()
		if err := within(t, "invalid Close", bound, startClose(c, ctx, 0)); !errors.Is(err, ErrInvalidCloseCode) || spy.closes.Load() != 0 {
			t.Fatalf("invalid Close = %v; closes = %d", err, spy.closes.Load())
		}
		select {
		case err := <-w:
			t.Fatalf("writer completed before peer read: %v", err)
		default:
		}
		client := NewClientConn(peer)
		if op, b, err := client.ReadMessage(); err != nil || op != OpcodeText || string(b) != "hello" {
			t.Fatalf("peer message = %v %q %v", op, b, err)
		}
		if err := within(t, "peer read", bound, w); err != nil {
			t.Fatal(err)
		}
		ack := asyncResult(func() error { _, _, err := client.ReadMessage(); return err })
		final(t, c, spy)
		if ce, ok := errors.AsType[*CloseError](within(t, "peer Close", bound, ack)); !ok || ce.Code != CloseNormalClosure {
			t.Fatalf("peer Close = %v", ce)
		}
	})
	budgets := map[string]struct{ ctx bool }{"close timeout budget": {}, "context deadline budget": {true}}
	t.Run("writer failed on earlier deadline", func(t *testing.T) {
		for name, budget := range budgets {
			t.Run(name, func(t *testing.T) {
				c, p, spy, _ := newPipe(t, 5*time.Second)
				expired := make(chan struct{})
				armed := make(chan struct{})
				release := sync.OnceFunc(func() { close(armed) })
				defer release()
				p.write = func(b []byte) (int, error) { n, err := p.Conn.Write(b); close(expired); <-armed; return n, err }
				p.deadline = func(d time.Time) error { err := p.Conn.SetDeadline(d); release(); return err }
				if err := c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				w := write(t, c, spy)
				within(t, "writer's own deadline", bound, expired)
				ctx := t.Context()
				if budget.ctx {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
				}
				cerr := within(t, "Close", bound, startClose(c, ctx, CloseNormalClosure))
				if !errors.Is(cerr, net.ErrClosed) || errors.Is(cerr, ErrCloseTimeout) || errors.Is(cerr, context.DeadlineExceeded) {
					t.Fatalf("drain = %v; want closed transport without budget expiry", cerr)
				}
				e := within(t, "writer", bound, w)
				requireWriteFailure(t, e, os.ErrDeadlineExceeded)
				later(t, c, e)
				final(t, c, spy)
			})
		}
	})
	t.Run("after retained write failure", func(t *testing.T) {
		tests := map[string]struct{ read bool }{"reader not torn down": {}, "reader torn down": {true}}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				c, p, spy, _ := newPipe(t, 5*time.Second)
				cause := errors.New("writer failed")
				p.write = func([]byte) (int, error) { return 0, cause }
				e := within(t, "writer", bound, write(t, c, spy))
				requireWriteFailure(t, e, cause)
				if tt.read {
					if _, _, err := c.ReadMessage(); !errors.Is(err, net.ErrClosed) {
						t.Fatalf("read = %v", err)
					}
				}
				if c.tornDown.Load() != tt.read || (c.rbuf == nil) != tt.read {
					t.Fatalf("unexpected reader state before Close")
				}
				if err := within(t, "close after failure", bound, startClose(c, t.Context(), CloseNormalClosure)); err != nil || c.rbuf != nil || !c.tornDown.Load() {
					t.Fatalf("Close = %v, buffer released = %t", err, c.rbuf == nil)
				}
				later(t, c, e)
				if err := c.WriteClose(CloseNormalClosure, "bye"); err != e {
					t.Fatalf("WriteClose = %v (%p); want retained error %v (%p)", err, err, e, e)
				}
				final(t, c, spy)
			})
		}
	})
	t.Run("early drain error with slow teardown", func(t *testing.T) {
		tests := map[string]struct{ eof bool }{"peer eof": {true}, "protocol violation": {}}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				for name, budget := range budgets {
					t.Run(name, func(t *testing.T) {
						c, p, spy, peer := newPipe(t, 150*time.Millisecond)
						p.close = func() error { time.Sleep(250 * time.Millisecond); return p.Conn.Close() }
						ctx := t.Context()
						if budget.ctx {
							parent, cancel := context.WithTimeout(ctx, 5*time.Second)
							defer cancel()
							ctx = advertisedDeadline{parent, time.Now().Add(150 * time.Millisecond)}
						}
						closing := startClose(c, ctx, CloseNormalClosure)
						f := readWireFrame(t, peer)
						if f.h.Opcode != OpcodeClose {
							t.Fatalf("sent %v, want Close", f.h.Opcode)
						}
						if tt.eof {
							_ = peer.Close()
						} else {
							if _, err := peer.Write([]byte{0x81, 1, 'x'}); err != nil {
								t.Fatal(err)
							}
						}
						err := within(t, "slow teardown", bound, closing)
						if errors.Is(err, ErrCloseTimeout) || errors.Is(err, context.DeadlineExceeded) {
							t.Fatalf("false budget expiry: %v", err)
						}
						if tt.eof {
							if !errors.Is(err, io.EOF) {
								t.Fatalf("drain = %v, want EOF", err)
							}
						} else if ce, ok := errors.AsType[*CloseError](err); !ok || !ce.Sent || ce.Code != CloseProtocolError {
							t.Fatalf("protocol drain = %v, want sent CloseProtocolError", err)
						}
						final(t, c, spy)
					})
				}
			})
		}
	})
	t.Run("set deadline fails after writer failure", func(t *testing.T) {
		c, p, spy, _ := newPipe(t, 5*time.Second)
		entered := make(chan struct{})
		release := sync.OnceFunc(func() { close(entered) })
		defer release()
		closed := make(chan struct{})
		cause := errors.New("writer failed during deadline setup")
		p.write = func([]byte) (int, error) { <-entered; return 0, cause }
		p.close = func() error { err := p.Conn.Close(); close(closed); return err }
		p.deadline = func(d time.Time) error { release(); <-closed; return p.Conn.SetDeadline(d) }
		w := write(t, c, spy)
		cerr := within(t, "failed deadline setup", bound, startClose(c, t.Context(), CloseNormalClosure))
		if !errors.Is(cerr, io.ErrClosedPipe) || !strings.HasPrefix(cerr.Error(), "gows: set close deadline: ") || errors.Is(cerr, cause) || errors.Is(cerr, ErrCloseTimeout) {
			t.Fatalf("Close = %v; want SetDeadline error", cerr)
		}
		e := within(t, "writer", bound, w)
		requireWriteFailure(t, e, cause)
		later(t, c, e)
		if err := c.WriteClose(CloseNormalClosure, "bye"); err != e {
			t.Fatalf("WriteClose = %v (%p); want retained error %v (%p)", err, err, e, e)
		}
		final(t, c, spy)
	})
}

func TestCloseReplyFailureRetained(t *testing.T) {
	boom := errors.New("Close reply failed")
	frame := clientFrame(true, OpcodeClose, AppendCloseBody(nil, CloseGoingAway, []byte("bye")))
	c := NewServerConn(&failWriteConn{Conn: &scriptConn{in: frame}, err: boom})
	_, _, err := c.ReadMessage()
	if ce, ok := errors.AsType[*CloseError](err); !ok || ce.Sent || ce.Code != CloseGoingAway || ce.Reason != "bye" {
		t.Fatalf("received Close = %v", err)
	}
	requireWriteFailure(t, c.WriteMessage(OpcodeText, nil), boom)
}
