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
	rand "math/rand/v2"
	"net"
	"testing"
	"time"
)

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
