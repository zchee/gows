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
	"testing"
	"time"
)

// --- UTF-8 fail-fast across delayed chops (Autobahn 6.4.3 / 6.4.4) ----------

// choppyConn delivers a fixed wire script one chop per Read, simulating a peer
// that writes a single frame's payload across several delayed TCP segments. It
// records how many bytes had been served the moment the connection first wrote
// a frame (the reader's Close reply), so a test can prove a 1007 close fired
// mid-frame rather than only after the whole frame assembled.
type choppyConn struct {
	chops        [][]byte
	ci, off      int
	served       int
	firstWriteAt int // c.served when Write was first called; -1 until then
	out          bytes.Buffer
}

func newChoppyConn(chops [][]byte) *choppyConn {
	return &choppyConn{chops: chops, firstWriteAt: -1}
}

func (c *choppyConn) Read(p []byte) (int, error) {
	if c.ci >= len(c.chops) {
		return 0, io.EOF
	}
	chop := c.chops[c.ci]
	n := copy(p, chop[c.off:])
	c.off += n
	c.served += n
	if c.off >= len(chop) {
		c.ci++
		c.off = 0
	}
	return n, nil
}

func (c *choppyConn) Write(p []byte) (int, error) {
	if c.firstWriteAt < 0 {
		c.firstWriteAt = c.served
	}
	return c.out.Write(p)
}

func (c *choppyConn) Close() error                       { return nil }
func (c *choppyConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *choppyConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *choppyConn) SetDeadline(_ time.Time) error      { return nil }
func (c *choppyConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *choppyConn) SetWriteDeadline(_ time.Time) error { return nil }

// choppedInvalidTextFrame builds a single masked Text frame of total bytes
// whose payload is ASCII except for one invalid UTF-8 octet at badAt (chosen
// beyond the read buffer so it lands in the direct read path, not the buffered
// drain), then chops the wire bytes into chopSize-byte segments. The invalid
// octet sits well before the final chop, so a fail-fast reader must reply 1007
// before the whole frame is served.
func choppedInvalidTextFrame(total, badAt, chopSize int) (frame []byte, chops [][]byte) {
	payload := bytes.Repeat([]byte("a"), total)
	payload[badAt] = 0xff // 0xff is never valid UTF-8 in any state
	frame = clientFrame(true, OpcodeText, payload)
	for off := 0; off < len(frame); off += chopSize {
		chops = append(chops, frame[off:min(off+chopSize, len(frame))])
	}
	return frame, chops
}

// TestReadMessageUTF8FailFastMidFrame reproduces Autobahn 6.4.3/6.4.4: a large
// Text frame arrives in delayed chops with an invalid UTF-8 octet in an
// early-middle chop, beyond the read buffer so it exercises the direct read
// path. ReadMessage must fail the connection with 1007 as soon as that chop is
// validated -- before the whole frame has been read off the wire.
func TestReadMessageUTF8FailFastMidFrame(t *testing.T) {
	t.Parallel()

	// badAt (5000) is well past the 4096-byte read buffer, so the invalid
	// octet is validated in the beyond-rbuf direct path rather than the drain.
	frame, chops := choppedInvalidTextFrame(10000, 5000, 512)
	cc := newChoppyConn(chops)
	c := NewServerConn(cc)

	_, _, err := c.ReadMessage()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != CloseInvalidFramePayloadData {
		t.Fatalf("error = %v, want *CloseError 1007", err)
	}
	if cc.firstWriteAt < 0 {
		t.Fatal("no Close frame was written")
	}
	// Fail-fast proof: the 1007 reply was written before the whole frame was
	// served. A reader that validated only after assembling the full frame
	// would have consumed all len(frame) bytes first.
	if cc.firstWriteAt >= len(frame) {
		t.Errorf("Close written after %d/%d bytes served: UTF-8 validation was not fail-fast", cc.firstWriteAt, len(frame))
	}
}
