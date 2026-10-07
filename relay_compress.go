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

	"github.com/zchee/gows/internal/pool"
	"github.com/zchee/gows/internal/utf8x"
)

type frameDecodeState struct {
	active, compressed, text bool
	total                    int64
	buf                      []byte
	err                      error
}

// DecodeFrame decodes data frames returned by ReadFrame in their original order.
// Call it for every data frame, including uncompressed ones, before the next
// message. Do not pass interleaved controls; doing so returns FrameUsageError.
// Non-final compressed fragments return (nil, false, nil); the final fragment
// returns the whole plaintext and complete=true. Uncompressed frames return
// their payload directly and complete equals FIN. DEFLATE plaintext has no
// correspondence to the original compressed fragment sizes.
//
// Compressed output belongs to the Conn until the next DecodeFrame or Abort;
// uncompressed output retains the ReadFrame payload's lifetime. Copy either to
// retain it. Wire and plaintext message sizes are bounded by WithReadLimit;
// exceeding either returns ProtocolError code 1009 and releases decode buffers.
// Invalid DEFLATE or text returns ProtocolError code 1007. Decode failures are
// sticky and do not send controls. Compression dictionaries are inbound-only,
// honor this Conn's peer-direction parameters and survive only when context
// takeover was negotiated. One reader/decoder may run alongside a frame writer;
// Abort safely releases its buffers. This method permanently selects frame mode.
func (c *Conn) DecodeFrame(f Frame) ([]byte, bool, error) {
	if err := c.selectMode(connModeFrame); err != nil {
		return nil, false, err
	}
	c.frameReadMu.Lock()
	defer c.frameReadMu.Unlock()
	s := &c.frameDecode
	if s.err != nil {
		return nil, false, s.err
	}
	if c.tornDown.Load() {
		return nil, false, net.ErrClosed
	}
	h := f.Header
	if !h.Opcode.IsData() && h.Opcode != OpcodeContinuation {
		return nil, false, &FrameUsageError{Reason: "decoder requires a data frame"}
	}
	if h.Length != int64(len(f.Payload)) {
		return nil, false, &FrameUsageError{Reason: "payload length disagrees with header"}
	}
	if h.Opcode.IsData() {
		if s.active {
			return nil, false, &FrameUsageError{Reason: "new message during a decode continuation chain"}
		}
		if f.Compressed && !c.compression || (h.Rsv == RSV1) != f.Compressed || h.Rsv != 0 && h.Rsv != RSV1 {
			return nil, false, &FrameUsageError{Reason: "inconsistent opening compression flags"}
		}
		s.active, s.compressed, s.text, s.total = true, f.Compressed, h.Opcode == OpcodeText, 0
		s.buf = s.buf[:0]
	} else if !s.active || f.Compressed != s.compressed || h.Rsv != 0 {
		return nil, false, &FrameUsageError{Reason: "inconsistent continuation state"}
	}
	if int64(len(f.Payload)) > c.readLimit-s.total {
		return nil, false, c.failFrameDecode(CloseMessageTooBig, "message exceeds read limit")
	}
	s.total += int64(len(f.Payload))
	if !s.compressed {
		s.active = !h.Fin
		return f.Payload, h.Fin, nil
	}
	s.buf = append(s.buf, f.Payload...)
	if !h.Fin {
		return nil, false, nil
	}
	out, err := c.decompressMessage(s.buf)
	s.active = false
	s.buf = s.buf[:0]
	if err != nil {
		code := CloseInvalidFramePayloadData
		if errors.Is(err, errDecompressedTooLarge) {
			code = CloseMessageTooBig
		}
		return nil, false, c.failFrameDecode(code, err.Error())
	}
	if s.text && !c.skipUTF8 && !utf8x.Valid(out) {
		return nil, false, c.failFrameDecode(CloseInvalidFramePayloadData, "invalid UTF-8 in decoded text message")
	}
	return out, true, nil
}

func (c *Conn) failFrameDecode(code CloseCode, reason string) error {
	err := &ProtocolError{Code: code, Reason: reason}
	c.frameDecode.err = err
	c.readErr = err
	pool.Put(c.frameDecode.buf)
	c.frameDecode.buf = nil
	pool.Put(c.inflateBuf)
	c.inflateBuf = nil
	return err
}
