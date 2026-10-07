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
	"fmt"

	"github.com/zchee/gows/internal/utf8x"
)

// Frame describes one received WebSocket frame, preserving its wire metadata.
// Payload is unmasked but is not decompressed. Its storage belongs to the Conn
// and remains valid until the next frame read or abrupt connection teardown;
// copy the payload to retain it longer.
type Frame struct {
	// Header is the original wire header, including masking and payload length.
	Header Header
	// Payload is the unmasked application data, possibly still compressed.
	Payload []byte
	// Compressed reports whether this data frame belongs to a compressed
	// message, including continuation frames whose RSV1 bit is clear. Control
	// frames are never compressed.
	Compressed bool
}

// ErrConnMode indicates an attempt to mix message and frame APIs on one Conn.
// The first message or frame operation permanently selects that mode, even
// when the operation itself fails.
var ErrConnMode = errors.New("gows: message and frame APIs cannot be mixed")

// ErrPeerClosed indicates transport EOF after a well-formed peer Close frame.
// The Close frame itself is a successful frame read, not an error.
var ErrPeerClosed = errors.New("gows: peer closed after a Close frame")

// ProtocolError reports an invalid frame or message without sending a Close
// frame automatically. The application owns the closing handshake.
type ProtocolError struct {
	// Code is the RFC 6455 close status appropriate for the violation.
	Code CloseCode
	// Reason describes the violated rule.
	Reason string
}

// Error implements the error interface.
func (e *ProtocolError) Error() string {
	return fmt.Sprintf("gows: protocol error (%d): %s", e.Code, e.Reason)
}

// FrameUsageError reports incorrect use of a frame encoder or decoder, such
// as starting another message before finishing its continuation chain.
type FrameUsageError struct {
	// Reason describes the invalid operation. No frame is written on this error.
	Reason string
}

// Error implements the error interface.
func (e *FrameUsageError) Error() string { return "gows: frame API: " + e.Reason }

// ParseClose validates a Close frame's application data and returns its code
// and reason. An absent code is represented by CloseNoStatusReceived. The
// returned reason is an owned string; malformed bodies return a ProtocolError.
func ParseClose(payload []byte) (CloseError, error) {
	code, reason, err := ParseCloseBody(payload)
	if err != nil {
		return CloseError{}, &ProtocolError{Code: CloseProtocolError, Reason: "malformed close frame body"}
	}
	if code != CloseNoStatusReceived && !ValidCloseCode(code) || len(payload) != 0 && code == CloseNoStatusReceived {
		return CloseError{}, &ProtocolError{Code: CloseProtocolError, Reason: "invalid close code"}
	}
	if !utf8x.Valid(reason) {
		return CloseError{}, &ProtocolError{Code: CloseInvalidFramePayloadData, Reason: "invalid UTF-8 in close reason"}
	}
	return CloseError{Code: code, Reason: string(reason)}, nil
}

const (
	connModeMessage uint32 = 1
	connModeFrame   uint32 = 2
)

func (c *Conn) selectMode(mode uint32) error {
	current := c.mode.Load()
	if current == mode || current == 0 && c.mode.CompareAndSwap(0, mode) {
		return nil
	}
	if c.mode.Load() == mode {
		return nil
	}
	return ErrConnMode
}
