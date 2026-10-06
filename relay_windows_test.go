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
	"testing"
)

func TestFrameCompressionDirectionWindows(t *testing.T) {
	tests := map[string]struct {
		client bool
		params CompressionParams
		bits   int
	}{
		"server incoming client window": {params: CompressionParams{ClientMaxWindowBits: 9, ServerMaxWindowBits: 15, ClientContextTakeover: true}, bits: 9},
		"client incoming server window": {client: true, params: CompressionParams{ServerMaxWindowBits: 10, ClientMaxWindowBits: 15, ServerContextTakeover: true}, bits: 10},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := newConn(&scriptConn{}, tt.client, []ConnOption{WithCompressionParams(tt.params)})
			defer c.Abort()
			// Each independent 64-byte DEFLATE stream is valid for every RFC window.
			// Resetting outbound compression is legal even with takeover negotiated.
			payload := bytes.Repeat([]byte("x"), 64)
			compressed, err := compressPayload(nil, payload)
			if err != nil {
				t.Fatal(err)
			}
			for range 32 {
				f := Frame{Header: Header{Opcode: OpcodeBinary, Fin: true, Rsv: RSV1, Length: int64(len(compressed))}, Payload: compressed, Compressed: true}
				out, complete, err := c.DecodeFrame(f)
				if err != nil || !complete || !bytes.Equal(out, payload) {
					t.Fatalf("decode = %x,%v,%v", out, complete, err)
				}
			}
			if c.outgoingWindowCeil != 15 || c.deflate.incomingWindowBits != tt.bits || cap(c.deflate.incomingDict) != 1<<tt.bits || len(c.deflate.incomingDict) != 1<<tt.bits {
				t.Fatalf("direction windows: %+v", c.deflate)
			}
		})
	}
}

func TestFrameCompressionUnsupportedOutgoingWindow(t *testing.T) {
	c := NewServerConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerMaxWindowBits: 9}))
	defer c.Abort()
	if err := c.WriteFrame(OpcodeBinary, true, nil, true); !errors.Is(err, ErrUnsupportedWindowBits) {
		t.Fatalf("unsupported outgoing window = %v", err)
	}
	if err := c.WriteFrame(OpcodeBinary, true, nil, false); err != nil {
		t.Fatalf("uncompressed fallback = %v", err)
	}
}
