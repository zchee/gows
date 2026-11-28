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
	"testing"
)

func TestWithHandshake(t *testing.T) {
	payload := bytes.Repeat([]byte("buffered"), defaultReadBufferSize)
	tests := map[string]struct {
		compressed bool
		params     CompressionParams
	}{
		"declined":          {params: CompressionParams{ClientContextTakeover: true}},
		"no takeover":       {compressed: true},
		"outgoing takeover": {compressed: true, params: CompressionParams{ClientContextTakeover: true}},
		"incoming takeover": {compressed: true, params: CompressionParams{ServerContextTakeover: true, ServerMaxWindowBits: 12}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			hs := Handshake{Compressed: tt.compressed, CompressionParams: tt.params, Buffered: serverFrame(true, OpcodeBinary, payload)}
			if !tt.compressed {
				cfg := connConfig{compressionParams: tt.params}
				WithHandshake(hs)(&cfg)
				if cfg.compressionParams != (CompressionParams{}) {
					t.Fatalf("unnegotiated compression parameters retained: %+v", cfg.compressionParams)
				}
			}
			opts := []ConnOption{WithReadBufferSize(128), WithBuffered([]byte("discard")), WithCompressionParams(CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true})}
			low := NewClientConn(&scriptConn{}, append(opts, WithHandshake(hs))...)
			high := newConnFromHandshake(&scriptConn{}, true, &hs, opts)
			clear(hs.Buffered) // Both constructors must have copied the read-ahead bytes.
			for _, c := range []*Conn{low, high} {
				defer c.CloseNow()
				if c.compression != tt.compressed {
					t.Fatalf("compression = %t, want %t", c.compression, tt.compressed)
				}
				if !tt.compressed || !tt.params.ClientContextTakeover && !tt.params.ServerContextTakeover {
					if c.deflate != nil {
						t.Fatal("unexpected takeover state")
					}
				} else if c.deflate == nil || c.deflate.outgoingTakeover != tt.params.ClientContextTakeover || (c.deflate.incomingDict != nil) != tt.params.ServerContextTakeover || c.deflate.incomingWindowBits != effectiveWindowBits(tt.params.ServerMaxWindowBits) {
					t.Fatalf("takeover state = %+v, want %+v", c.deflate, tt.params)
				}
				op, got, err := c.ReadMessage()
				if err != nil || op != OpcodeBinary || !bytes.Equal(got, payload) {
					t.Fatalf("buffered message: opcode %v, length %d, error %v; want binary, %d bytes", op, len(got), err, len(payload))
				}
			}
		})
	}
}
