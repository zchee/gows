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
	"fmt"
	rand "math/rand/v2"
	"net"
	"runtime"
	"testing"
	"time"
)

// loopbackPair returns the two ends of a real loopback TCP connection. Both
// are closed when the test ends; closing an end twice is harmless.
func loopbackPair(tb testing.TB) (accepted, dialed net.Conn) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	dialed, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		_ = dialed.Close()
		tb.Fatalf("accept: %v", r.err)
	}
	tb.Cleanup(func() {
		_ = r.c.Close()
		_ = dialed.Close()
	})
	return r.c, dialed
}

// stallConn is an in-memory transport for ordering tests that must not
// create happens-before edges through the operating system: in race builds
// the syscall package orders every Read after every earlier Write
// process-wide, which hides races between goroutines that talk to a real
// socket. Reads block until fail is closed and then fail; writes are
// discarded.
type stallConn struct {
	fail chan struct{}
}

var errStallConnFailed = errors.New("stallConn: read failed on request")

func (s *stallConn) Read([]byte) (int, error) {
	<-s.fail
	return 0, errStallConnFailed
}

func (s *stallConn) Write(p []byte) (int, error) { return len(p), nil }

func (s *stallConn) Close() error { return nil }

func (s *stallConn) LocalAddr() net.Addr { return fakeAddr{} }

func (s *stallConn) RemoteAddr() net.Addr { return fakeAddr{} }

func (s *stallConn) SetDeadline(time.Time) error { return nil }

func (s *stallConn) SetReadDeadline(time.Time) error { return nil }

func (s *stallConn) SetWriteDeadline(time.Time) error { return nil }

// TestNextWriterCompressionAfterReaderTeardown opens a context-takeover
// compressed NextWriter stream, lets the reader on another goroutine fail and
// tear the connection down, and only then writes enough to the stream to
// engage its compressor. Nothing synchronizes the writer with the reader: it
// waits by sleeping, the way a writer that learned of the failure some other
// way would carry on, and the timestamps afterwards confirm the order. The
// stream must reach the Conn's deflate state only under the write lock, or
// the race detector reports the teardown's write against the stream's read.
func TestNextWriterCompressionAfterReaderTeardown(t *testing.T) {
	t.Parallel()

	params := CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}
	chunk := make([]byte, 2*defaultWriteBufferSize)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(chunk)

	for attempt := 1; ; attempt++ {
		tc := &stallConn{fail: make(chan struct{})}
		c := NewServerConn(tc, WithCompressionParams(params))
		w, err := c.NextWriter(OpcodeBinary)
		if err != nil {
			t.Fatalf("NextWriter: %v", err)
		}

		type writeResult struct {
			at  time.Time
			err error
		}
		writerDone := make(chan writeResult, 1)
		go func() {
			time.Sleep(50 * time.Millisecond)
			at := time.Now()
			_, werr := w.Write(chunk)
			writerDone <- writeResult{at, errors.Join(werr, w.Close())}
		}()

		type readResult struct {
			at  time.Time
			err error
		}
		readerDone := make(chan readResult, 1)
		go func() {
			_, _, err := c.ReadMessage()
			readerDone <- readResult{time.Now(), err}
		}()
		close(tc.fail)

		rr := <-readerDone
		if !errors.Is(rr.err, errStallConnFailed) {
			t.Fatalf("ReadMessage = %v, want the transport failure", rr.err)
		}
		wr := <-writerDone
		if !wr.at.After(rr.at) {
			if attempt == 5 {
				t.Fatalf("stream write started before the reader's teardown finished in %d attempts", attempt)
			}
			continue
		}
		if !errors.Is(wr.err, net.ErrClosed) {
			t.Fatalf("stream after teardown = %v, want errors.Is net.ErrClosed", wr.err)
		}
		return
	}
}

// stagedConn hides the concrete *net.TCPConn type, so the Conn writes through
// its staged (non-writev) path.
type stagedConn struct{ net.Conn }

// concurrentPayload builds writer id's message seq: one id byte, a big-endian
// sequence number, then a body whose every byte depends on id, seq, and
// position, so a frame mixed with another writer's bytes fails verification.
// The size cycles through the coalesced, writev, compressed, and staged-split
// write paths.
func concurrentPayload(id byte, seq int) []byte {
	sizes := [...]int{5, 125, 600, 3000, 20000, 300 << 10}
	n := sizes[seq%len(sizes)]
	p := make([]byte, n)
	p[0] = id
	p[1], p[2], p[3], p[4] = byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq)
	for i := 5; i < n; i++ {
		p[i] = byte(int(id)*31 + seq*7 + i/3)
	}
	return p
}

// retryBusy repeats write while a NextWriter stream on another goroutine
// holds the data-message slot, which is the documented ErrWriterBusy case.
func retryBusy(write func() error) error {
	for {
		err := write()
		if !errors.Is(err, ErrWriterBusy) {
			return err
		}
		runtime.Gosched()
	}
}

// TestConcurrentWriters runs several goroutines that send on one Conn
// through every data-write entry point at once -- WriteMessage,
// WriteMessageBuffered with Flush, a NextWriter stream, and (server role)
// WritePreparedMessage -- beside a reader that answers the peer's Pings.
// The peer verifies that every message arrives whole and that each writer's
// messages arrive in the order that writer sent them.
func TestConcurrentWriters(t *testing.T) {
	t.Parallel()

	takeover := CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}
	compressions := map[string][]ConnOption{
		"uncompressed":     nil,
		"pooled deflate":   {WithCompression(true)},
		"context takeover": {WithCompressionParams(takeover)},
	}
	transports := map[string]func(net.Conn) net.Conn{
		"writev": func(c net.Conn) net.Conn { return c },
		"staged": func(c net.Conn) net.Conn { return stagedConn{c} },
	}
	for _, client := range []bool{false, true} {
		role := "server"
		if client {
			role = "client"
		}
		for cname, copts := range compressions {
			for tname, wrap := range transports {
				t.Run(role+"/"+cname+"/"+tname, func(t *testing.T) {
					t.Parallel()
					testConcurrentWriters(t, client, copts, wrap)
				})
			}
		}
	}
}

func testConcurrentWriters(t *testing.T, client bool, copts []ConnOption, wrap func(net.Conn) net.Conn) {
	const perWriter = 12
	rawA, rawB := loopbackPair(t)
	// A corrupted stream would leave either side waiting for bytes that never
	// come; the deadline turns that into a test failure instead of a hang.
	deadline := time.Now().Add(20 * time.Second)
	for _, raw := range []net.Conn{rawA, rawB} {
		if err := raw.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	}
	opts := append([]ConnOption{WithReadLimit(1 << 20)}, copts...)
	var a, b *Conn
	if client {
		a, b = NewClientConn(wrap(rawA), opts...), NewServerConn(wrap(rawB), opts...)
	} else {
		a, b = NewServerConn(wrap(rawA), opts...), NewClientConn(wrap(rawB), opts...)
	}

	// The peer reads and verifies until a's Close arrives.
	type peerResult struct {
		got [4]int
		err error
	}
	peerDone := make(chan peerResult, 1)
	go func() {
		var res peerResult
		for {
			_, p, err := b.ReadMessage()
			if err != nil {
				res.err = err
				peerDone <- res
				return
			}
			if len(p) < 5 || p[0] >= byte(len(res.got)) {
				res.err = fmt.Errorf("malformed message of %d bytes", len(p))
				peerDone <- res
				return
			}
			id := p[0]
			seq := int(p[1])<<24 | int(p[2])<<16 | int(p[3])<<8 | int(p[4])
			if seq != res.got[id] {
				res.err = fmt.Errorf("writer %d: got seq %d, want %d", id, seq, res.got[id])
				peerDone <- res
				return
			}
			if want := concurrentPayload(id, seq); !bytes.Equal(p, want) {
				res.err = fmt.Errorf("writer %d seq %d: payload of %d bytes differs from the %d bytes sent", id, seq, len(p), len(want))
				peerDone <- res
				return
			}
			res.got[id]++
		}
	}()

	// The peer also sends Pings and data, so a's reader issues Pong replies
	// that interleave with a's writers.
	peerSendDone := make(chan struct{})
	go func() {
		defer close(peerSendDone)
		for i := range 200 {
			if err := b.WriteMessage(OpcodePing, []byte("ping")); err != nil {
				return
			}
			if err := b.WriteMessage(OpcodeBinary, []byte{byte(i)}); err != nil {
				return
			}
		}
	}()

	readerDone := make(chan error, 1)
	go func() {
		for {
			if _, _, err := a.ReadMessage(); err != nil {
				readerDone <- err
				return
			}
		}
	}()

	writers := []func(seq int) error{
		func(seq int) error {
			return retryBusy(func() error { return a.WriteMessage(OpcodeBinary, concurrentPayload(0, seq)) })
		},
		func(seq int) error {
			if err := retryBusy(func() error { return a.WriteMessageBuffered(OpcodeBinary, concurrentPayload(1, seq)) }); err != nil {
				return err
			}
			if seq%3 == 2 || seq == perWriter-1 {
				return a.Flush()
			}
			return nil
		},
		func(seq int) error {
			p := concurrentPayload(2, seq)
			w, err := a.NextWriter(OpcodeBinary)
			if err != nil {
				return err
			}
			if _, err := w.Write(p[:len(p)/2]); err != nil {
				_ = w.Close()
				return err
			}
			if _, err := w.Write(p[len(p)/2:]); err != nil {
				_ = w.Close()
				return err
			}
			return w.Close()
		},
		func(seq int) error {
			p := concurrentPayload(3, seq)
			if client {
				return retryBusy(func() error { return a.WriteMessage(OpcodeBinary, p) })
			}
			pm, err := NewPreparedMessage(OpcodeBinary, p)
			if err != nil {
				return err
			}
			return retryBusy(func() error { return a.WritePreparedMessage(pm) })
		},
	}
	errs := make(chan error, len(writers))
	for id, write := range writers {
		go func() {
			for seq := range perWriter {
				if err := write(seq); err != nil {
					errs <- fmt.Errorf("writer %d seq %d: %w", id, seq, err)
					return
				}
			}
			errs <- nil
		}()
	}
	for range writers {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}

	if err := a.WriteClose(CloseNormalClosure, "done"); err != nil {
		t.Fatalf("WriteClose: %v", err)
	}
	res := <-peerDone
	var ce *CloseError
	if !errors.As(res.err, &ce) || ce.Code != CloseNormalClosure {
		t.Errorf("peer ReadMessage ended with %v, want *CloseError code %d", res.err, CloseNormalClosure)
	}
	for id, n := range res.got {
		if n != perWriter {
			t.Errorf("writer %d: peer received %d messages, want %d", id, n, perWriter)
		}
	}
	<-peerSendDone
	if err := <-readerDone; !errors.As(err, &ce) {
		t.Errorf("reader ended with %v, want the peer's *CloseError reply", err)
	}
}
