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
	"slices"

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

	// If a prior NextReader stream is still open, this new read supersedes it:
	// discard whatever of that message remains on the wire and invalidate the
	// stale reader (the 1-reader contract). On the ReadMessage-only hot path
	// msgReader is always nil, so this is a single predictable nil check.
	if c.msgReader != nil {
		if err := c.discardStreamRemainder(); err != nil {
			return 0, nil, err
		}
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

		if err := c.checkFrameHeader(h); err != nil {
			return 0, nil, err
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
// buffer, and validating UTF-8 for text messages. It enforces the read limit
// across the whole message.
//
// Bytes already sitting in the read buffer are drained with a plain append --
// that data is already resident in memory, so there is nothing to gain by
// routing it anywhere else. Once the read buffer is exhausted and more of
// this frame's payload remains on the wire (the common case once h.Length
// exceeds the read buffer's capacity, e.g. any message bigger than the
// default 4096-byte buffer), looping fillOnce (read into rbuf, up to
// cap(rbuf) bytes at a time) plus an append per refill would double-buffer
// every remaining byte through rbuf before it lands in msgBuf. Instead,
// readFramePayload grows msgBuf once to its final size for this frame and
// reads the remainder directly into it, halving the memory traffic for the
// part of a large frame that doesn't fit in the read buffer.
func (c *Conn) readFramePayload(h Header) error {
	if int64(len(c.msgBuf))+h.Length > c.readLimit {
		return c.failClose(CloseMessageTooBig, "message exceeds read limit")
	}

	remaining := h.Length
	key := h.MaskKey
	for remaining > 0 && c.r0 < c.r1 {
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
	if remaining == 0 {
		return nil
	}

	start := len(c.msgBuf)
	c.msgBuf = slices.Grow(c.msgBuf, int(remaining))
	c.msgBuf = c.msgBuf[:start+int(remaining)]
	dst := c.msgBuf[start:]

	// Fused read-and-validate loop over the direct (beyond-rbuf) remainder.
	// Each iteration issues ONE Read over the *entire* remaining destination --
	// not a cap(rbuf)-sized slice of it -- so the transport is free to hand
	// back as much as it already has in one Read rather than being limited to a
	// 4096-byte gulp, and then immediately unmasks and UTF-8-validates exactly
	// the bytes that arrived, before waiting for any more. Validating per
	// arrival (rather than reading the whole remainder first and validating
	// afterward) is what lets an invalid UTF-8 octet delivered in an early TCP
	// chop of a large frame fail the connection with 1007 the instant it
	// arrives, instead of only after the final chop assembles the whole frame
	// (RFC 6455 §8.1; Autobahn 6.4.3/6.4.4 require this "fail as soon as
	// possible" behavior even mid-frame).
	//
	// Processing still runs over cap(rbuf)-sized sub-chunks regardless of how
	// much a single Read returned, because a single very large (tens of KB+)
	// mask.Mask/utf8v.Feed call measurably loses cache residency in the SIMD
	// mask kernel (see the 64KB row of .omc/research/phase5-results.md's kernel
	// table, and bench/results/phase5-linux-amd64.md's "64KB drops off ...
	// consistent with leaving cache residency"). A Read that already returns
	// everything at once (e.g. a single-writer peer's writev'd frame, or the
	// benchmark's loopConn) is processed identically to the old
	// read-all-then-feed order, so hot-path throughput is unchanged; only the
	// order of I/O and validation relative to a *chopped* arrival differs.
	//
	// I/O-error contract (mirrors fillOnce): a Read returning zero new bytes
	// alongside a non-nil error propagates that error verbatim (a plain io.EOF,
	// not io.ReadFull's io.ErrUnexpectedEOF upgrade), so a truncated stream
	// surfaces identically here and on the buffered path.
	//
	// Known limitation, confirmed by strace on the AC5 benchmark harness: how
	// many actual read(2) calls this needs is governed by *arrival pacing* on
	// the wire, not by the size requested here. If a peer writes a frame's
	// header and payload as two separate write(2) calls, a fast reader can
	// re-enter Read before the second write's bytes have arrived, splitting the
	// payload across more reads than a slower reader would "accidentally" batch
	// by being late to ask -- gows measured 5.02 reads/msg for a 16KB frame
	// against gws's 2.00 there, entirely attributable to this pacing effect,
	// not to any artificial chunk cap on gows's side (there is none). A
	// single-writer sender (e.g. this package's own writev'd WriteMessage
	// output) does not trigger the pattern. MSG_WAITALL via a raw syscall
	// (RawConn) was evaluated as a way to force full-remainder reads regardless
	// of arrival pacing and rejected: on the non-blocking sockets Go's
	// netpoller requires, MSG_WAITALL does not block in-kernel across multiple
	// future arrivals -- it is an atomic single-attempt gate that returns
	// EAGAIN immediately (discarding whatever partial bytes did arrive) if the
	// full requested length is not already buffered, so it does not reduce the
	// read count here and can add wasted round-trips instead.
	chunkSize := cap(c.rbuf)
	for len(dst) > 0 {
		n, err := c.conn.Read(dst)
		for arrived := dst[:n]; len(arrived) > 0; {
			m := min(len(arrived), chunkSize)
			sub := arrived[:m]
			if h.Masked {
				key = mask.Mask(sub, key)
			}
			if c.msgIsText && !c.skipUTF8 && !c.msgCompressed {
				if !c.utf8v.Feed(sub) {
					return c.failClose(CloseInvalidFramePayloadData, "invalid UTF-8 in text message")
				}
			}
			arrived = arrived[m:]
		}
		dst = dst[n:]
		if n == 0 && err != nil {
			return c.ioError(err)
		}
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

// checkFrameHeader validates a just-decoded frame header against the
// negotiated extension set (RSV bits) and the connection's role masking
// rules (RFC 6455 §5.1), failing the connection and returning the resulting
// terminal error on a violation. It is shared by [Conn.readMessage] and the
// [Conn.NextReader] streaming path so the two agree byte-for-byte on which
// frames are legal.
func (c *Conn) checkFrameHeader(h Header) error {
	// RSV1 ("Per-Message Compressed", RFC 7692 §6.1) is only legal when
	// permessage-deflate is negotiated, on a data frame (never a control
	// frame), and on the first frame of a message (never a continuation
	// frame, even mid-compressed-message). Any other combination -- RSV1
	// without negotiation, RSV1 on a continuation or control frame, or
	// RSV2/RSV3 at all -- is a protocol error; frame.go itself has no notion
	// of negotiated extensions and leaves this validation here.
	rsv1OK := c.compression && h.Rsv == RSV1 && !h.Opcode.IsControl() && h.Opcode != OpcodeContinuation
	if h.Rsv != 0 && !rsv1OK {
		return c.failClose(CloseProtocolError, "invalid RSV bit for the negotiated extension set")
	}
	// Role masking rules: a server's peer (a client) must mask; a client's
	// peer (a server) must not.
	if c.client && h.Masked {
		return c.failClose(CloseProtocolError, "masked frame received by client")
	}
	if !c.client && !h.Masked {
		return c.failClose(CloseProtocolError, "unmasked frame received by server")
	}
	return nil
}

// errStreamReaderStale is the sticky error a [Conn.NextReader] reader's Read
// returns once it has been superseded -- by a later NextReader, a
// [Conn.ReadMessage], or a [Conn.Close]. Because the invalidation swaps the
// Conn's active reader, it can never be undone, so the error is permanently
// sticky for that reader.
var errStreamReaderStale = errors.New("gows: stream reader superseded by a later read")

// messageReader streams one inbound data message's payload through the
// [io.Reader] returned by [Conn.NextReader], fragment by fragment, without
// reassembling it in memory. It reuses the Conn's connection read buffer and
// resumable-mask/UTF-8 state, so a large streamed message costs no
// per-message reassembly allocation on the read side.
//
// A messageReader is not safe for concurrent use, and only one may be active
// per Conn at a time (the same single-reader contract as ReadMessage).
type messageReader struct {
	c   *Conn
	op  Opcode // the message opcode (Text or Binary)
	err error  // sticky terminal error for this reader

	// --- streaming (uncompressed) state ---
	frameRem int64  // unconsumed payload bytes of the current frame
	key      uint32 // resumable mask key for the current frame
	total    int64  // total declared message bytes admitted so far (read limit)
	masked   bool   // current frame is masked
	fin      bool   // current frame is the message's final fragment
	complete bool   // the final fragment has been fully consumed (Read => io.EOF)

	// --- compressed fallback state ---
	// A compressed inbound message (RSV1) cannot be streamed in place, so
	// NextReader reassembles and inflates it eagerly (correctness kept, the
	// streaming benefit lost) and Read serves the decoded bytes from here.
	compressed  bool
	inflated    []byte
	inflatedPos int
}

// NextReader returns the opcode and an [io.Reader] streaming the next inbound
// data message's payload, blocking until that message begins. Unlike
// [Conn.ReadMessage], which returns a fully reassembled payload, the reader
// yields the payload incrementally as its fragments arrive, so an arbitrarily
// large message can be consumed with only the connection read buffer resident
// -- no per-message reassembly buffer is allocated.
//
// The reader handles interleaved control frames transparently, exactly like
// ReadMessage: a Ping is answered with a Pong, a Pong is ignored, and a Close
// completes the closing handshake (the pending Read then returns the
// [*CloseError]). For a Text message every chunk is validated as UTF-8 as it
// streams and the trailing-sequence completeness is checked at the final
// fragment; invalid or truncated UTF-8 fails the connection with 1007 and the
// Read that encounters it returns the error. The reader returns [io.EOF]
// exactly once the final fragment has been fully consumed.
//
// The configured read limit ([WithReadLimit]) still bounds the message's
// total declared size and a message exceeding it fails with 1009. Here the
// limit is purely a protocol-abuse guard, not a memory guard: because the
// payload is streamed rather than buffered, a caller that legitimately needs
// to stream messages larger than the default limit should raise it with
// WithReadLimit.
//
// Lifetime and mixing: the returned reader is valid only until the next
// NextReader, ReadMessage, or Close call on the same Conn; afterward its Read
// returns a sticky "superseded" error. NextReader and ReadMessage may be
// interleaved from one message to the next but never used concurrently (the
// single-reader contract), and -- per [Conn]'s own concurrency doc -- a Read
// on the returned reader must not run concurrently with [Conn.Close] either;
// it drives the same read side and shares the same buffers ReadMessage does.
// Starting a new read -- via either method -- while a previously returned
// reader has not been drained to io.EOF discards the unread remainder of
// that message (it is consumed off the wire and thrown away), matching
// gorilla/websocket's drain-on-next-read behavior.
//
// A compressed message (permessage-deflate, RSV1) cannot be streamed in
// place; NextReader falls back to reassembling and inflating it in full, then
// serves the inflated bytes through the returned reader. Correctness and the
// read-limit guard are preserved; only the streaming memory benefit is lost
// for compressed inbound messages.
//
// At most one goroutine may call NextReader at a time.
func (c *Conn) NextReader() (Opcode, io.Reader, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	if c.tornDown.Load() {
		return 0, nil, net.ErrClosed
	}

	// Supersede any still-open prior stream: drain its remainder and
	// invalidate it before starting a new message (the 1-reader contract).
	if c.msgReader != nil {
		if err := c.discardStreamRemainder(); err != nil {
			return 0, nil, err
		}
	}

	c.utf8v.Reset()

	op, h, err := c.readDataFrameHeader()
	if err != nil {
		return 0, nil, err
	}

	if h.Rsv == RSV1 {
		decoded, err := c.reassembleCompressed(h, op)
		if err != nil {
			return 0, nil, err
		}
		r := &messageReader{c: c, op: op, compressed: true, inflated: decoded}
		c.msgReader = r
		return op, r, nil
	}

	if h.Length > c.readLimit {
		return 0, nil, c.failClose(CloseMessageTooBig, "message exceeds read limit")
	}
	r := &messageReader{
		c:        c,
		op:       op,
		frameRem: h.Length,
		key:      h.MaskKey,
		masked:   h.Masked,
		fin:      h.Fin,
		total:    h.Length,
	}
	c.msgReader = r
	return op, r, nil
}

// readDataFrameHeader reads frame headers, auto-handling control frames, until
// the header that opens a data message (Text or Binary) is found. A
// Continuation frame with no message in progress is a protocol error.
func (c *Conn) readDataFrameHeader() (Opcode, Header, error) {
	for {
		h, err := c.readHeader()
		if err != nil {
			return 0, Header{}, err
		}
		if err := c.checkFrameHeader(h); err != nil {
			return 0, Header{}, err
		}
		if h.Opcode.IsControl() {
			if err := c.handleControl(h); err != nil {
				return 0, Header{}, err
			}
			continue
		}
		switch h.Opcode {
		case OpcodeText, OpcodeBinary:
			return h.Opcode, h, nil
		case OpcodeContinuation:
			return 0, Header{}, c.failClose(CloseProtocolError, "continuation frame with no message in progress")
		}
	}
}

// discardStreamRemainder invalidates the Conn's active NextReader stream and,
// if it was left unfinished, drains the rest of its message off the wire so
// the connection is positioned at the next message boundary. A protocol or IO
// error surfaced while draining is returned (and is terminal for the Conn).
func (c *Conn) discardStreamRemainder() error {
	r := c.msgReader
	c.msgReader = nil // invalidate the stale reader (identity check in Read)
	if r.compressed || r.complete || r.err != nil {
		return nil
	}
	return r.drain()
}

// drain consumes and discards the unread remainder of a streamed message,
// auto-handling interleaved control frames, until the final fragment has been
// fully consumed. It does not run UTF-8 completeness validation: the message
// is being thrown away, and the next message resets the validator regardless.
func (r *messageReader) drain() error {
	c := r.c
	for {
		if r.frameRem == 0 {
			if r.fin {
				return nil
			}
			if err := r.nextFrame(); err != nil {
				return err
			}
			continue
		}
		if err := c.skipPayload(r.frameRem); err != nil {
			return err
		}
		r.frameRem = 0
	}
}

// Read implements [io.Reader] for a NextReader stream. It returns the message
// payload in the order it arrives, io.EOF once the final fragment is fully
// consumed, or a terminal error (which becomes sticky for this reader) on a
// protocol violation, transport failure, or once the reader has been
// superseded by a later read.
func (r *messageReader) Read(p []byte) (int, error) {
	c := r.c
	if c.msgReader != r {
		return 0, errStreamReaderStale
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.complete {
		return 0, io.EOF
	}

	if r.compressed {
		if r.inflatedPos >= len(r.inflated) {
			r.complete = true
			return 0, io.EOF
		}
		n := copy(p, r.inflated[r.inflatedPos:])
		r.inflatedPos += n
		return n, nil
	}

	if len(p) == 0 {
		return 0, nil
	}

	for {
		if r.frameRem == 0 {
			if r.fin {
				if r.op == OpcodeText && !c.skipUTF8 && !c.utf8v.Done() {
					r.err = c.failClose(CloseInvalidFramePayloadData, "incomplete UTF-8 sequence at message end")
					return 0, r.err
				}
				r.complete = true
				return 0, io.EOF
			}
			if err := r.nextFrame(); err != nil {
				r.err = err
				return 0, err
			}
			continue
		}
		n, err := r.readFrameChunk(p)
		if err != nil {
			r.err = err
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
		// A transport that returned zero bytes without an error: retry rather
		// than surface a spurious (0, nil) to the caller.
	}
}

// nextFrame advances the stream to the next payload-bearing continuation
// frame of the current message, auto-handling any interleaved control frames.
// A new data frame while a message is in progress, or a message whose total
// declared size exceeds the read limit, fails the connection.
func (r *messageReader) nextFrame() error {
	c := r.c
	for {
		h, err := c.readHeader()
		if err != nil {
			return err
		}
		if err := c.checkFrameHeader(h); err != nil {
			return err
		}
		if h.Opcode.IsControl() {
			if err := c.handleControl(h); err != nil {
				return err
			}
			continue
		}
		if h.Opcode != OpcodeContinuation {
			return c.failClose(CloseProtocolError, "new data frame while awaiting continuation")
		}
		if r.total+h.Length > c.readLimit {
			return c.failClose(CloseMessageTooBig, "message exceeds read limit")
		}
		r.total += h.Length
		r.frameRem = h.Length
		r.key = h.MaskKey
		r.masked = h.Masked
		r.fin = h.Fin
		return nil
	}
}

// readFrameChunk copies up to len(p) bytes of the current frame's payload into
// p, unmasking with the resumable key and validating UTF-8 for a text
// message. Bytes already buffered in the read buffer are served from there;
// when the read buffer is empty it either reads a large request straight into
// p (no double-buffering) or refills the read buffer for a small request (so
// tiny Read calls still batch one large transport read). It returns the
// number of bytes written to p and never reads past the current frame.
func (r *messageReader) readFrameChunk(p []byte) (int, error) {
	c := r.c
	want := int(min(int64(len(p)), r.frameRem))

	if c.r0 == c.r1 {
		c.r0, c.r1 = 0, 0
		if want >= cap(c.rbuf) {
			// Large read into an empty buffer: read straight into p.
			n, err := c.conn.Read(p[:want])
			if n == 0 && err != nil {
				return 0, c.ioError(err)
			}
			if err := r.applyChunk(p[:n]); err != nil {
				return 0, err
			}
			return n, nil
		}
		if err := c.fillOnce(); err != nil {
			return 0, c.ioError(err)
		}
	}

	take := min(c.r1-c.r0, want)
	chunk := c.rbuf[c.r0 : c.r0+take]
	if err := r.applyChunk(chunk); err != nil {
		return 0, err
	}
	copy(p, chunk)
	c.r0 += take
	return take, nil
}

// applyChunk unmasks chunk in place with the resumable key, feeds it to the
// UTF-8 validator for a text message (failing the connection with 1007 on
// invalid bytes), and debits its length from the current frame's remainder.
func (r *messageReader) applyChunk(chunk []byte) error {
	c := r.c
	if r.masked {
		r.key = mask.Mask(chunk, r.key)
	}
	if r.op == OpcodeText && !c.skipUTF8 {
		if !c.utf8v.Feed(chunk) {
			return c.failClose(CloseInvalidFramePayloadData, "invalid UTF-8 in text message")
		}
	}
	r.frameRem -= int64(len(chunk))
	return nil
}

// skipPayload consumes and discards n payload bytes from the stream, refilling
// the read buffer as needed. It neither unmasks nor validates, since the bytes
// are being thrown away (see [messageReader.drain]).
func (c *Conn) skipPayload(n int64) error {
	for n > 0 {
		if c.r0 == c.r1 {
			c.r0, c.r1 = 0, 0
			if err := c.fillOnce(); err != nil {
				return c.ioError(err)
			}
		}
		take := min(int64(c.r1-c.r0), n)
		c.r0 += int(take)
		n -= take
	}
	return nil
}

// reassembleCompressed reassembles a compressed message whose opening frame
// header has already been decoded, accumulating the compressed wire bytes of
// every fragment into c.msgBuf (enforcing the read limit), inflates them (bounded
// by the read limit), and validates UTF-8 for a text message. It mirrors
// [Conn.readMessage]'s compressed-message handling exactly, and is used only
// by NextReader's compressed-inbound fallback -- never the hot path.
func (c *Conn) reassembleCompressed(first Header, op Opcode) ([]byte, error) {
	c.msgBuf = c.msgBuf[:0]
	c.msgIsText = op == OpcodeText
	c.msgCompressed = true

	h := first
	for {
		if err := c.readFramePayload(h); err != nil {
			return nil, err
		}
		if h.Fin {
			break
		}
		// Read the next frame; it must be a continuation (control frames are
		// auto-handled inline, exactly as in readMessage).
		for {
			next, err := c.readHeader()
			if err != nil {
				return nil, err
			}
			if err := c.checkFrameHeader(next); err != nil {
				return nil, err
			}
			if next.Opcode.IsControl() {
				if err := c.handleControl(next); err != nil {
					return nil, err
				}
				continue
			}
			if next.Opcode != OpcodeContinuation {
				return nil, c.failClose(CloseProtocolError, "new data frame while awaiting continuation")
			}
			h = next
			break
		}
	}

	decoded, err := c.decompressMessage(c.msgBuf)
	if err != nil {
		if errors.Is(err, errDecompressedTooLarge) {
			return nil, c.failClose(CloseMessageTooBig, "decompressed message exceeds read limit")
		}
		return nil, c.failClose(CloseProtocolError, "invalid compressed message payload")
	}
	if c.msgIsText && !c.skipUTF8 && !utf8x.Valid(decoded) {
		return nil, c.failClose(CloseInvalidFramePayloadData, "invalid UTF-8 in text message")
	}
	return decoded, nil
}
