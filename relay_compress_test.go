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
	"strings"
	"testing"
)

func TestDecodeFrameLifecycle(t *testing.T) {
	tests := map[string]struct {
		params CompressionParams
		client bool
	}{
		"reset": {}, "takeover": {params: CompressionParams{ServerContextTakeover: true, ClientContextTakeover: true}},
		"client takeover": {client: true, params: CompressionParams{ClientContextTakeover: true}},
		"server takeover": {params: CompressionParams{ServerContextTakeover: true}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			nc := &scriptConn{}
			src := newConn(nc, tt.client, []ConnOption{WithCompressionParams(tt.params)})
			defer src.Abort()
			messages := []string{strings.Repeat("dictionary ", 200), "plain", strings.Repeat("dictionary ", 200), "", strings.Repeat("dictionary ", 200)}
			for i, p := range messages {
				cut := len(p) / 2
				compressed := i != 1
				if err := src.WriteFrame(OpcodeText, false, []byte(p[:cut]), compressed); err != nil {
					t.Fatal(err)
				}
				if err := src.WriteFrame(OpcodePing, true, []byte("ping"), false); err != nil {
					t.Fatal(err)
				}
				if err := src.WriteFrame(OpcodeContinuation, true, []byte(p[cut:]), compressed); err != nil {
					t.Fatal(err)
				}
			}
			dst := newConn(&scriptConn{}, !tt.client, []ConnOption{WithCompressionParams(tt.params), WithBuffered(nc.out.Bytes())})
			defer dst.Abort()
			for i, want := range messages {
				var got []byte
				for {
					f, err := dst.ReadFrame()
					if err != nil {
						t.Fatal(err)
					}
					if f.Header.Opcode.IsControl() {
						continue
					}
					p, complete, err := dst.DecodeFrame(f)
					if err != nil {
						t.Fatal(err)
					}
					if i != 1 && !f.Header.Fin && (p != nil || complete) {
						t.Fatal("compressed non-FIN emitted plaintext")
					}
					got = append(got, p...)
					if complete {
						break
					}
				}
				if string(got) != want {
					t.Fatalf("message %d = %q, want %q", i, got, want)
				}
			}
		})
	}
}

func TestDecodeFrameErrors(t *testing.T) {
	compressed, err := compressPayload(nil, []byte(strings.Repeat("bomb", 1000)))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		payload []byte
		limit   int64
		op      Opcode
		code    CloseCode
	}{
		"plaintext limit": {payload: compressed, limit: 16, op: OpcodeBinary, code: CloseMessageTooBig},
		"invalid deflate": {payload: []byte{0xff}, op: OpcodeBinary, code: CloseInvalidFramePayloadData},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := NewClientConn(&scriptConn{}, WithCompression(true), WithReadLimit(tt.limit))
			defer c.Abort()
			f := Frame{Header: Header{Opcode: tt.op, Fin: true, Rsv: RSV1, Length: int64(len(tt.payload))}, Payload: tt.payload, Compressed: true}
			_, _, err := c.DecodeFrame(f)
			pe, ok := errors.AsType[*ProtocolError](err)
			if !ok || pe.Code != tt.code {
				t.Fatalf("error = %v, want code %d", err, tt.code)
			}
			if c.inflateBuf != nil || c.frameDecode.buf != nil {
				t.Fatal("failed decode retained buffers")
			}
			if _, _, again := c.DecodeFrame(f); again != err {
				t.Fatalf("non-sticky decoder error: %v", again)
			}
		})
	}
	c := NewClientConn(&scriptConn{}, WithCompression(true))
	defer c.Abort()
	f := Frame{Header: Header{Opcode: OpcodePing, Fin: true}}
	if _, _, err := c.DecodeFrame(f); err == nil {
		t.Fatal("decoder accepted a control")
	}
	f = Frame{Header: Header{Opcode: OpcodeText, Rsv: RSV1}, Compressed: true}
	if _, _, err := c.DecodeFrame(f); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.DecodeFrame(f); err == nil {
		t.Fatal("decoder accepted a new opening inside fragments")
	}
	f.Payload, err = compressPayload(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Header = Header{Opcode: OpcodeContinuation, Fin: true, Length: int64(len(f.Payload))}
	if _, _, err := c.DecodeFrame(f); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeFrameInvalidText(t *testing.T) {
	p, err := compressPayload(nil, []byte{255})
	if err != nil {
		t.Fatal(err)
	}
	c := NewClientConn(&scriptConn{}, WithCompression(true))
	defer c.Abort()
	f := Frame{Header: Header{Opcode: OpcodeText, Rsv: RSV1, Fin: true, Length: int64(len(p))}, Payload: p, Compressed: true}
	if _, _, err := c.DecodeFrame(f); err == nil {
		t.Fatal("decoder accepted compressed invalid UTF-8")
	}
}

func TestDecodeFrameRelayRecompression(t *testing.T) {
	p := []byte(strings.Repeat("message ", 200))
	wire := &scriptConn{}
	inbound := NewServerConn(wire, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
	defer inbound.Abort()
	for range 3 {
		if err := inbound.WriteFrame(OpcodeBinary, true, p, true); err != nil {
			t.Fatal(err)
		}
	}
	reader := NewClientConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}), WithBuffered(wire.out.Bytes()))
	defer reader.Abort()
	out := &scriptConn{}
	writer := NewClientConn(out, WithCompression(true))
	defer writer.Abort()
	for range 3 {
		f, err := reader.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		decoded, complete, err := reader.DecodeFrame(f)
		if err != nil || !complete {
			t.Fatalf("decode: %v, %v", complete, err)
		}
		edited := append(bytes.Clone(decoded), []byte("edited")...)
		if err := writer.WriteFrame(OpcodeBinary, true, edited, true); err != nil {
			t.Fatal(err)
		}
	}
	target := NewServerConn(&scriptConn{}, WithCompression(true), WithBuffered(out.out.Bytes()))
	defer target.Abort()
	for range 3 {
		f, err := target.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		decoded, complete, err := target.DecodeFrame(f)
		if err != nil || !complete || string(decoded) != string(p)+"edited" {
			t.Fatalf("edited message = %q, %v, %v", decoded, complete, err)
		}
	}
}
