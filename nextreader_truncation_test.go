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
	"testing"
)

type closeCountingScriptConn struct {
	scriptConn
	closeCount int
}

func (c *closeCountingScriptConn) Close() error {
	c.closeCount++
	return nil
}

func TestNextReaderPromotesIncompleteMessageEOF(t *testing.T) {
	t.Parallel()

	full := clientFrame(true, OpcodeBinary, []byte("payload"))
	tests := []struct {
		name string
		wire []byte
		want string
	}{
		{
			name: "truncated payload",
			wire: full[:len(full)-2],
			want: "paylo",
		},
		{
			name: "missing continuation",
			wire: clientFrame(false, OpcodeBinary, []byte("fragment")),
			want: "fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport := &closeCountingScriptConn{scriptConn: scriptConn{in: tt.wire}}
			c := NewServerConn(transport)
			_, r, err := c.NextReader()
			if err != nil {
				t.Fatalf("NextReader: %v", err)
			}

			got, firstErr := io.ReadAll(r)
			if string(got) != tt.want {
				t.Fatalf("payload = %q, want %q", got, tt.want)
			}
			if !errors.Is(firstErr, io.ErrUnexpectedEOF) {
				t.Fatalf("drain error = %v, want io.ErrUnexpectedEOF", firstErr)
			}
			if transport.closeCount != 1 {
				t.Fatalf("transport close count = %d, want 1", transport.closeCount)
			}

			if _, stickyErr := r.Read(make([]byte, 1)); stickyErr != firstErr {
				t.Fatalf("reader sticky error = %v, want same error %v", stickyErr, firstErr)
			}
			if _, _, stickyErr := c.ReadMessage(); stickyErr != firstErr {
				t.Fatalf("Conn sticky error = %v, want same error %v", stickyErr, firstErr)
			}
			if transport.closeCount != 1 {
				t.Fatalf("transport close count after sticky reads = %d, want 1", transport.closeCount)
			}
		})
	}
}

func TestNextReaderPromotesPartialInitialHeaderEOF(t *testing.T) {
	t.Parallel()

	full := clientFrame(true, OpcodeBinary, nil)
	transport := &closeCountingScriptConn{scriptConn: scriptConn{in: full[:5]}}
	c := NewServerConn(transport)

	_, r, firstErr := c.NextReader()
	if r != nil {
		t.Fatalf("reader = %v, want nil", r)
	}
	if !errors.Is(firstErr, io.ErrUnexpectedEOF) {
		t.Fatalf("NextReader error = %v, want io.ErrUnexpectedEOF", firstErr)
	}
	if transport.closeCount != 1 {
		t.Fatalf("transport close count = %d, want 1", transport.closeCount)
	}

	if _, _, stickyErr := c.NextReader(); stickyErr != firstErr {
		t.Fatalf("NextReader sticky error = %v, want same error %v", stickyErr, firstErr)
	}
	if _, _, stickyErr := c.ReadMessage(); stickyErr != firstErr {
		t.Fatalf("ReadMessage sticky error = %v, want same error %v", stickyErr, firstErr)
	}
	if transport.closeCount != 1 {
		t.Fatalf("transport close count after sticky reads = %d, want 1", transport.closeCount)
	}
}

func TestNextReaderCleanBoundaryEOFUnchanged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wire []byte
	}{
		{name: "empty transport"},
		{name: "after handled control frame", wire: clientFrame(true, OpcodePong, nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport := &closeCountingScriptConn{scriptConn: scriptConn{in: tt.wire}}
			c := NewServerConn(transport)
			_, r, firstErr := c.NextReader()
			if r != nil {
				t.Fatalf("reader = %v, want nil", r)
			}
			if !errors.Is(firstErr, io.EOF) || errors.Is(firstErr, io.ErrUnexpectedEOF) {
				t.Fatalf("NextReader error = %v, want bare io.EOF", firstErr)
			}
			if transport.closeCount != 1 {
				t.Fatalf("transport close count = %d, want 1", transport.closeCount)
			}
			if _, _, stickyErr := c.NextReader(); stickyErr != firstErr {
				t.Fatalf("sticky error = %v, want same error %v", stickyErr, firstErr)
			}
			if transport.closeCount != 1 {
				t.Fatalf("transport close count after sticky read = %d, want 1", transport.closeCount)
			}
		})
	}
}

func TestNextReaderCompleteFinalFrameEOFUnchanged(t *testing.T) {
	t.Parallel()

	transport := &closeCountingScriptConn{scriptConn: scriptConn{in: clientFrame(true, OpcodeBinary, []byte("payload"))}}
	c := NewServerConn(transport)
	_, r, err := c.NextReader()
	if err != nil {
		t.Fatalf("NextReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "payload" {
		t.Fatalf("ReadAll = (%q, %v), want (payload, nil)", got, err)
	}
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("complete stream error = %v, want io.EOF", err)
	}
	if transport.closeCount != 0 {
		t.Fatalf("transport close count = %d, want 0", transport.closeCount)
	}
}

func TestReadMessageTruncatedPayloadEOFUnchanged(t *testing.T) {
	t.Parallel()

	full := clientFrame(true, OpcodeBinary, []byte("payload"))
	_, _, err := NewServerConn(&scriptConn{in: full[:len(full)-2]}).ReadMessage()
	if !errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadMessage truncated error = %v, want bare io.EOF", err)
	}
}

func TestReadMessageInvalidUTF8BeforeTruncationFailsFast(t *testing.T) {
	t.Parallel()

	// Masked FIN/Text, declared length 12, with only one payload byte. The
	// available byte unmasks to 0xb0, which is already invalid UTF-8, so the
	// protocol error must win over the later transport EOF.
	wire := []byte{0x81, 0x8c, 0x80, 0x30, 0x30, 0x30, 0x30}
	transport := &closeCountingScriptConn{scriptConn: scriptConn{in: wire}}
	c := NewServerConn(transport)

	_, _, firstErr := c.ReadMessage()
	var ce *CloseError
	if !errors.As(firstErr, &ce) || ce.Code != CloseInvalidFramePayloadData {
		t.Fatalf("ReadMessage error = %v, want CloseError{Code: %d}", firstErr, CloseInvalidFramePayloadData)
	}
	if transport.closeCount != 1 {
		t.Fatalf("transport close count = %d, want 1", transport.closeCount)
	}
	code, _, ok := firstClose(t, parseFrames(t, transport.out.Bytes()))
	if !ok || code != CloseInvalidFramePayloadData {
		t.Fatalf("wire close = (%d, %v), want (%d, true)", code, ok, CloseInvalidFramePayloadData)
	}

	if _, _, stickyErr := c.ReadMessage(); stickyErr != firstErr {
		t.Fatalf("ReadMessage sticky error = %v, want same error %v", stickyErr, firstErr)
	}
	if transport.closeCount != 1 {
		t.Fatalf("transport close count after sticky read = %d, want 1", transport.closeCount)
	}
}
