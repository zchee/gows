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

import "fmt"

type frameWriteState struct {
	active, compressed bool
	lease              compressorLease
	err                error
}

// WriteFrame writes exactly one frame, borrowing payload only until return and
// never mutating it. op and fin explicitly select fragment boundaries, including
// empty fragments. The connection role determines masking, with a fresh key per
// client frame. Frame writes are serialized and may run alongside one reader.
// SetWriteDeadline or Abort interrupts blocked writes; write failures are sticky.
//
// compress selects compression only on the opening Text or Binary frame and
// must match that selection on every continuation. Compression must have been
// negotiated and uses this Conn's outgoing window and context-takeover policy,
// never another peer's dictionary. Compressed fragments are flushed individually;
// only the final fragment strips the RFC 7692 trailer. RSV1 is set only on the
// opening fragment. Controls can interleave, must be final and uncompressed,
// and are validated before emission. A Close stops later data writes, but still
// permits the application's control completion. Usage errors do not write or
// poison the writer. The first call permanently selects frame mode.
func (c *Conn) WriteFrame(op Opcode, fin bool, payload []byte, compress bool) error {
	if err := c.selectMode(connModeFrame); err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	s := &c.frameWrite
	if s.err != nil {
		return s.err
	}
	if c.tornDown.Load() {
		return errWriteClosed
	}
	if op.IsControl() {
		if op != OpcodePing && op != OpcodePong && op != OpcodeClose {
			return &FrameUsageError{Reason: "unsupported control opcode"}
		}
		if !fin || len(payload) > 125 || compress {
			return &FrameUsageError{Reason: "controls must be final, at most 125 bytes and uncompressed"}
		}
		if op == OpcodeClose {
			if _, err := ParseClose(payload); err != nil {
				return &FrameUsageError{Reason: err.Error()}
			}
			if c.closeSent {
				return nil
			}
		}
	} else {
		if c.closeSent || c.closeRcvd.Load() {
			return errWriteClosed
		}
		if op.IsData() {
			if s.active {
				return &FrameUsageError{Reason: "new data frame while awaiting continuation"}
			}
			if compress && !c.compression {
				return &FrameUsageError{Reason: "compression was not negotiated"}
			}
			if compress {
				if c.deflate != nil && c.deflate.outgoingDisabled {
					return fmt.Errorf("%w: outgoing compression is disabled", ErrUnsupportedWindowBits)
				}
				lease, reset, ok := c.acquireCompressor()
				if !ok {
					return fmt.Errorf("%w: backend exceeds outgoing window ceiling", ErrUnsupportedWindowBits)
				}
				s.lease = lease
				lease.sw.b = lease.sw.b[:0]
				if reset {
					lease.w.Reset(lease.sw)
				}
			}
			s.active, s.compressed = true, compress
		} else if op != OpcodeContinuation {
			return &FrameUsageError{Reason: "unsupported data opcode"}
		} else if !s.active {
			return &FrameUsageError{Reason: "continuation without an open message"}
		} else if compress != s.compressed {
			return &FrameUsageError{Reason: "continuation compression disagrees with opening frame"}
		}
	}
	var rsv byte
	if !op.IsControl() && s.compressed {
		if op.IsData() {
			rsv = RSV1
		}
		s.lease.sw.b = s.lease.sw.b[:0]
		out, err := writeAndFlush(s.lease.w, s.lease.sw, payload)
		if err != nil {
			return c.failFrameWrite(err)
		}
		if !fin {
			out = s.lease.sw.b
		} // Sync-flush markers inside a message must remain.
		payload = out
	}
	if err := c.emitFrameLocked(op, fin, rsv, payload); err != nil {
		return c.failFrameWrite(err)
	}
	if op == OpcodeClose {
		c.closeSent = true
		c.releaseFrameCompressor()
	} else if !op.IsControl() && fin {
		c.releaseFrameCompressor()
	}
	return nil
}

func (c *Conn) releaseFrameCompressor() {
	s := &c.frameWrite
	if s.lease.w != nil {
		s.lease.release()
		s.lease = compressorLease{}
	}
	s.active = false
}

func (c *Conn) failFrameWrite(err error) error {
	c.frameWrite.err = err
	c.releaseFrameCompressor()
	// No later writes may repair a partially emitted frame or compressor context.
	c.frameStopOnce.Do(func() { _ = c.conn.Close() })
	return err
}
