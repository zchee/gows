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

	"github.com/zchee/gows/internal/mask"
)

type frameReadState struct {
	active     bool
	compressed bool
	text       bool
	total      int64
}

// ReadFrame reads exactly one frame and permanently selects frame mode. Message
// APIs on the same Conn then return ErrConnMode. All Ping, Pong and Close frames
// are returned without automatic replies, draining, or transport closure. A
// valid Close returns a Frame and nil; ParseClose validates and interprets its
// body. EOF following a peer Close returns ErrPeerClosed; data after Close is a
// ProtocolError. Other transport errors are preserved and terminal.
//
// Payload is unmasked but remains wire-compressed when Compressed is true.
// Its storage belongs to the Conn and is valid until the next ReadFrame or
// Abort. Copy it before retaining it or writing concurrently with another read.
// WithBuffered bytes are consumed before the transport and are never reread.
// The read limit bounds total wire bytes across a data message; compressed
// plaintext must additionally be validated and bounded by the frame decoder.
//
// One reader may run concurrently with one frame writer. Abort safely interrupts
// either operation; SetReadDeadline can also interrupt a blocked read. Any read
// error is sticky. Protocol violations never write an unsolicited Close frame.
func (c *Conn) ReadFrame() (Frame, error) {
	if err := c.selectMode(connModeFrame); err != nil {
		return Frame{}, err
	}
	c.frameReadMu.Lock()
	defer c.frameReadMu.Unlock()
	if c.readErr != nil {
		return Frame{}, c.readErr
	}
	if c.tornDown.Load() {
		return Frame{}, net.ErrClosed
	}
	h, err := c.readRelayHeader()
	if err != nil {
		return Frame{}, err
	}
	s := &c.frameRead
	if !h.Opcode.IsControl() {
		if c.closeRcvd.Load() {
			return Frame{}, c.relayProtocolError(CloseProtocolError, "data frame after Close")
		}
		if h.Opcode.IsData() {
			if s.active {
				return Frame{}, c.relayProtocolError(CloseProtocolError, "new data frame while awaiting continuation")
			}
			*s = frameReadState{active: true, compressed: h.Rsv == RSV1, text: h.Opcode == OpcodeText}
			c.utf8v.Reset()
		} else if !s.active {
			return Frame{}, c.relayProtocolError(CloseProtocolError, "continuation frame with no message in progress")
		}
		if h.Length > c.readLimit-s.total {
			return Frame{}, c.relayProtocolError(CloseMessageTooBig, "message exceeds read limit")
		}
		s.total += h.Length
	}
	c.msgBuf = c.msgBuf[:0]
	remaining, key := h.Length, h.MaskKey
	for remaining > 0 {
		if c.r0 == c.r1 {
			if err := c.fillOnce(); err != nil {
				if errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
				return Frame{}, c.relayTransportError(err)
			}
		}
		n := int(min(remaining, int64(c.r1-c.r0)))
		chunk := c.rbuf[c.r0 : c.r0+n]
		if h.Masked {
			key = mask.Mask(chunk, key)
		}
		if !h.Opcode.IsControl() && s.text && !s.compressed && !c.skipUTF8 && !c.utf8v.Feed(chunk) {
			return Frame{}, c.relayProtocolError(CloseInvalidFramePayloadData, "invalid UTF-8 in text message")
		}
		// Grow only for bytes that have arrived, never for an untrusted length.
		c.msgBuf = append(c.msgBuf, chunk...)
		c.r0 += n
		remaining -= int64(n)
	}
	f := Frame{Header: h, Payload: c.msgBuf, Compressed: !h.Opcode.IsControl() && s.compressed}
	if h.Opcode == OpcodeClose {
		if _, err := ParseClose(f.Payload); err != nil {
			c.readErr = err
			return Frame{}, err
		}
		c.closeRcvd.Store(true)
	}
	if !h.Opcode.IsControl() && h.Fin {
		if s.text && !s.compressed && !c.skipUTF8 && !c.utf8v.Done() {
			return Frame{}, c.relayProtocolError(CloseInvalidFramePayloadData, "incomplete UTF-8 sequence at message end")
		}
		s.active = false
	}
	return f, nil
}

func (c *Conn) readRelayHeader() (Header, error) {
	for {
		if c.r1-c.r0 >= 2 {
			h, n, reason := decodeFrameHeaderFast(c.hdrTable, c.hdrMaskBit, c.rbuf[c.r0:c.r1])
			switch reason {
			case rejectNone:
				c.r0 += n
				return h, nil
			case rejectShort:
			default:
				return Header{}, c.relayProtocolError(CloseProtocolError, reason.closeMessage(c.client))
			}
		}
		if err := c.fillOnce(); err != nil {
			if errors.Is(err, io.EOF) {
				if c.r1-c.r0 != 0 {
					err = io.ErrUnexpectedEOF
				} else if c.closeRcvd.Load() {
					err = ErrPeerClosed
				} else if c.frameRead.active {
					err = io.ErrUnexpectedEOF
				}
			}
			return Header{}, c.relayTransportError(err)
		}
	}
}

func (c *Conn) relayProtocolError(code CloseCode, reason string) error {
	err := &ProtocolError{Code: code, Reason: reason}
	c.readErr = err
	return err
}

func (c *Conn) relayTransportError(err error) error {
	c.readErr = err
	c.teardown()
	return err
}

// Abort abruptly closes a frame-mode transport without writing a control frame
// or draining inbound data. It safely interrupts blocked frame reads and writes,
// waits for their buffer use to finish, and releases connection buffers exactly
// once. Repeated calls return nil. Calling Abort on a message-mode Conn returns
// ErrConnMode; use the message-mode closing handshake on that connection.
func (c *Conn) Abort() error {
	if err := c.selectMode(connModeFrame); err != nil {
		return err
	}
	c.frameStopOnce.Do(func() { _ = c.conn.Close() })
	c.frameReadMu.Lock()
	defer c.frameReadMu.Unlock()
	c.teardown()
	return nil
}
