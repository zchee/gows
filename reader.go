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
	"net"

	"github.com/zchee/gows/internal/mask"
	"github.com/zchee/gows/internal/utf8x"
)

// ReadMessage reads the next complete data message from the connection,
// returning its opcode ([OpcodeText] or [OpcodeBinary]) and payload.
//
// The returned slice is owned by the Conn and is only valid until the next
// call to ReadMessage, or until [Conn.Close] returns, whichever comes first
// (fasthttp-style buffer reuse); a caller that needs to retain it must copy
// it. Close's internal teardown returns the read and reassembly buffers to
// the shared pool, so a payload slice from a prior ReadMessage call may be
// silently overwritten by an unrelated connection's data the instant Close
// returns -- not just reused by this Conn. For a message that arrives as a
// single frame no larger than the read buffer the slice aliases the internal
// read buffer with no copy; larger or fragmented messages are reassembled
// into a growable buffer. Either way the steady-state cost is zero
// allocations.
//
// ReadMessage transparently handles interleaved control frames: it answers a
// Ping with a Pong, ignores Pongs, and on a Close frame completes the closing
// handshake and returns a [*CloseError] (which also matches
// errors.Is(err, [net.ErrClosed])). A protocol violation fails the connection
// with the appropriate Close code (1002 protocol error, 1007 invalid payload
// data, 1009 message too big) and returns the resulting error. Once any error
// is returned it is sticky: every subsequent call returns the same error.
//
// At most one goroutine may call ReadMessage at a time.
func (c *Conn) ReadMessage() (Opcode, []byte, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	return c.readMessage()
}

// readMessage implements ReadMessage without the sticky-error short circuit,
// so [Conn.Close] can reuse it to drain the connection.
func (c *Conn) readMessage() (Opcode, []byte, error) {
	// Defense in depth: never index the freed read buffer after teardown. The
	// Close idempotency guard already prevents the known re-entry path; this
	// makes readMessage itself safe to call in any torn-down state.
	if c.tornDown.Load() {
		if c.readErr != nil {
			return 0, nil, c.readErr
		}
		return 0, nil, net.ErrClosed
	}

	c.msgBuf = c.msgBuf[:0]
	c.utf8v.Reset()

	inMessage := false
	var msgOp Opcode

	for {
		h, err := c.readHeader()
		if err != nil {
			return 0, nil, err
		}

		// RSV1 ("Per-Message Compressed", RFC 7692 §6.1) is only legal when
		// permessage-deflate is negotiated, on a data frame (never a
		// control frame), and on the first frame of a message (never a
		// continuation frame, even mid-compressed-message). Any other
		// combination -- RSV1 without negotiation, RSV1 on a continuation
		// or control frame, or RSV2/RSV3 at all -- is a protocol error;
		// frame.go itself has no notion of negotiated extensions and
		// leaves this validation to the connection layer.
		rsv1OK := c.compression && h.Rsv == RSV1 && !h.Opcode.IsControl() && h.Opcode != OpcodeContinuation
		if h.Rsv != 0 && !rsv1OK {
			return c.failData(CloseProtocolError, "invalid RSV bit for the negotiated extension set")
		}

		// Role masking rules (RFC 6455 §5.1): a server's peer (a client) must
		// mask; a client's peer (a server) must not.
		if c.client && h.Masked {
			return c.failData(CloseProtocolError, "masked frame received by client")
		}
		if !c.client && !h.Masked {
			return c.failData(CloseProtocolError, "unmasked frame received by server")
		}

		if h.Opcode.IsControl() {
			if err := c.handleControl(h); err != nil {
				return 0, nil, err
			}
			continue
		}

		switch h.Opcode {
		case OpcodeText, OpcodeBinary:
			if inMessage {
				return c.failData(CloseProtocolError, "new data frame while awaiting continuation")
			}
			c.msgIsText = h.Opcode == OpcodeText
			c.msgCompressed = h.Rsv == RSV1

			// Zero-copy fast path: a message delivered as a single frame that
			// fits the read buffer is returned as a subslice of that buffer.
			// Not available for a compressed message: decompression cannot
			// be in-place, so it always goes through the reassembly buffer
			// below, decompressed once at message end.
			if !c.msgCompressed && h.Fin && h.Length <= int64(cap(c.rbuf)) {
				p, err := c.readContiguousPayload(h)
				if err != nil {
					return 0, nil, err
				}
				if c.msgIsText && !c.skipUTF8 && !utf8x.Valid(p) {
					return c.failData(CloseInvalidFramePayloadData, "invalid UTF-8 in text message")
				}
				return h.Opcode, p, nil
			}
			inMessage = true
			msgOp = h.Opcode

		case OpcodeContinuation:
			if !inMessage {
				return c.failData(CloseProtocolError, "continuation frame with no message in progress")
			}
		}

		if err := c.readFramePayload(h); err != nil {
			return 0, nil, err
		}

		if h.Fin {
			if c.msgCompressed {
				decoded, err := c.decompressMessage(c.msgBuf)
				if err != nil {
					if errors.Is(err, errDecompressedTooLarge) {
						return c.failData(CloseMessageTooBig, "decompressed message exceeds read limit")
					}
					return c.failData(CloseProtocolError, "invalid compressed message payload")
				}
				// UTF-8 validation for a compressed text message runs once,
				// here, against the decompressed bytes -- the wire bytes fed
				// to readFramePayload were compressed data, not UTF-8, and
				// were never fed to c.utf8v (see readFramePayload).
				if c.msgIsText && !c.skipUTF8 && !utf8x.Valid(decoded) {
					return c.failData(CloseInvalidFramePayloadData, "invalid UTF-8 in text message")
				}
				return msgOp, decoded, nil
			}
			if c.msgIsText && !c.skipUTF8 && !c.utf8v.Done() {
				return c.failData(CloseInvalidFramePayloadData, "incomplete UTF-8 sequence at message end")
			}
			return msgOp, c.msgBuf, nil
		}
	}
}

// readHeader decodes the next frame header, reading more bytes as needed. A
// malformed header fails the connection with a 1002 protocol error.
func (c *Conn) readHeader() (Header, error) {
	for {
		if c.r1-c.r0 >= 2 {
			h, n, err := DecodeHeader(c.rbuf[c.r0:c.r1])
			if err == nil {
				c.r0 += n
				return h, nil
			}
			if err != ErrShortHeader {
				return Header{}, c.failClose(CloseProtocolError, "malformed frame header: "+err.Error())
			}
		}
		if err := c.fillOnce(); err != nil {
			return Header{}, c.ioError(err)
		}
	}
}

// readContiguousPayload consumes an n-byte payload that is guaranteed to fit
// the read buffer, unmasks it in place, and returns it as a subslice of the
// read buffer (no copy). Used by ReadMessage's single-frame fast path.
func (c *Conn) readContiguousPayload(h Header) ([]byte, error) {
	n := int(h.Length)
	if int64(n) > c.readLimit {
		return nil, c.failClose(CloseMessageTooBig, "message exceeds read limit")
	}
	if err := c.ensure(n); err != nil {
		return nil, c.ioError(err)
	}
	p := c.rbuf[c.r0 : c.r0+n]
	c.r0 += n
	if h.Masked {
		mask.Mask(p, h.MaskKey)
	}
	return p, nil
}

// readFramePayload consumes h.Length payload bytes from the stream, unmasking
// with a resumable key across buffer refills, appending them to the reassembly
// buffer, and validating UTF-8 incrementally for text messages. It enforces
// the read limit across the whole message.
func (c *Conn) readFramePayload(h Header) error {
	if int64(len(c.msgBuf))+h.Length > c.readLimit {
		return c.failClose(CloseMessageTooBig, "message exceeds read limit")
	}

	remaining := h.Length
	key := h.MaskKey
	for remaining > 0 {
		if c.r0 == c.r1 {
			if err := c.fillOnce(); err != nil {
				return c.ioError(err)
			}
			continue
		}
		take := int(min(int64(c.r1-c.r0), remaining))
		chunk := c.rbuf[c.r0 : c.r0+take]
		if h.Masked {
			key = mask.Mask(chunk, key)
		}
		// A compressed message's wire bytes are compressed data, not UTF-8;
		// validation for that case runs once, after decompression (see the
		// Fin handling in readMessage), so incremental feeding is skipped
		// entirely here while c.msgCompressed.
		if c.msgIsText && !c.skipUTF8 && !c.msgCompressed {
			if !c.utf8v.Feed(chunk) {
				return c.failClose(CloseInvalidFramePayloadData, "invalid UTF-8 in text message")
			}
		}
		c.msgBuf = append(c.msgBuf, chunk...)
		c.r0 += take
		remaining -= int64(take)
	}
	return nil
}

// handleControl reads and dispatches a control frame (Ping, Pong, or Close).
// Its payload is at most 125 bytes (enforced by [DecodeHeader]).
func (c *Conn) handleControl(h Header) error {
	n := int(h.Length)
	if err := c.ensure(n); err != nil {
		return c.ioError(err)
	}
	payload := c.rbuf[c.r0 : c.r0+n]
	if h.Masked {
		mask.Mask(payload, h.MaskKey)
	}
	c.r0 += n

	switch h.Opcode {
	case OpcodePing:
		return c.writeControl(OpcodePong, payload)
	case OpcodePong:
		return nil
	case OpcodeClose:
		return c.handleClose(payload)
	default:
		// Reserved control opcodes are already rejected by DecodeHeader.
		return nil
	}
}

// handleClose processes an inbound Close frame: it validates the close body,
// replies with a Close frame per RFC 6455 §7.4, tears down the connection, and
// returns the terminal [*CloseError].
func (c *Conn) handleClose(payload []byte) error {
	c.closeRcvd.Store(true)

	code, reason, err := ParseCloseBody(payload)
	if err != nil {
		return c.failClose(CloseProtocolError, "malformed close frame body")
	}

	if code != CloseNoStatusReceived {
		if !ValidCloseCode(code) {
			return c.failClose(CloseProtocolError, "invalid close code")
		}
		if !c.skipUTF8 && !utf8x.Valid(reason) {
			return c.failClose(CloseInvalidFramePayloadData, "invalid UTF-8 in close reason")
		}
		_ = c.sendClose(code, nil)
	} else {
		// The peer sent no status code; reply with an empty Close body
		// (echoing the reserved 1005 on the wire would itself be illegal).
		_ = c.sendClose(0, nil)
	}

	retErr := &CloseError{Code: code, Reason: string(reason), Sent: false}
	c.readErr = retErr
	c.teardown()
	return retErr
}

// ensure guarantees the read buffer window holds at least n bytes, reading
// from the connection as needed. n must not exceed cap(c.rbuf).
func (c *Conn) ensure(n int) error {
	for c.r1-c.r0 < n {
		if err := c.fillOnce(); err != nil {
			return err
		}
	}
	return nil
}

// fillOnce reads once from the connection into the read buffer, compacting the
// unconsumed bytes to the front first when the buffer tail is exhausted.
func (c *Conn) fillOnce() error {
	if c.r1 == len(c.rbuf) {
		// ensure/readFramePayload only reach here with a window shorter than
		// the buffer (they never request more than cap(rbuf) contiguous
		// bytes, and consume as they go), so r0 > 0 and compaction frees room.
		n := copy(c.rbuf, c.rbuf[c.r0:c.r1])
		c.r0, c.r1 = 0, n
	}
	n, err := c.conn.Read(c.rbuf[c.r1:])
	c.r1 += n
	if n == 0 && err != nil {
		return err
	}
	return nil
}

// failClose fails the connection: it sends a Close frame with the given code
// and reason (best effort), records the terminal error, tears the connection
// down, and returns that error.
func (c *Conn) failClose(code CloseCode, reason string) error {
	_ = c.sendClose(code, []byte(reason))
	err := &CloseError{Code: code, Reason: reason, Sent: true}
	c.readErr = err
	c.teardown()
	return err
}

// failData adapts failClose to ReadMessage's three-value signature.
func (c *Conn) failData(code CloseCode, reason string) (Opcode, []byte, error) {
	return 0, nil, c.failClose(code, reason)
}

// ioError records an underlying transport error (EOF, deadline, reset) as the
// terminal read error and tears the connection down. It preserves any
// protocol-level error already recorded.
func (c *Conn) ioError(err error) error {
	if c.readErr != nil {
		return c.readErr
	}
	c.readErr = err
	c.teardown()
	return err
}
