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
	"io"
	"net"
	"testing"
)

func TestReadFrameControlsAndFragments(t *testing.T) {
	tests := map[string]struct {
		op    Opcode
		parts [][]byte
	}{
		"text":   {OpcodeText, [][]byte{[]byte("hel"), nil, []byte("lo")}},
		"binary": {OpcodeBinary, [][]byte{{0, 255}, nil, {1}}},
		"empty":  {OpcodeBinary, [][]byte{nil}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var wire []byte
			var want []Frame
			add := func(op Opcode, fin bool, p []byte) {
				wire = append(wire, frameBytes(fin, op, 0, true, 0x12345678, p)...)
				want = append(want, Frame{Header: Header{Fin: fin, Opcode: op, Masked: true, MaskKey: 0x12345678, Length: int64(len(p))}, Payload: p})
			}
			add(OpcodePing, true, []byte("ping"))
			add(OpcodePong, true, []byte("pong"))
			for i, p := range tt.parts {
				op := OpcodeContinuation
				if i == 0 {
					op = tt.op
				}
				add(op, i == len(tt.parts)-1, p)
				if i == 0 && len(tt.parts) > 1 {
					add(OpcodePing, true, nil)
				}
			}
			add(OpcodeClose, true, nil)
			nc := &scriptConn{in: wire, chunk: 1}
			c := NewServerConn(nc)
			defer c.Abort()
			for i, expected := range want {
				f, err := c.ReadFrame()
				if err != nil || f.Header != expected.Header || f.Compressed || !bytes.Equal(f.Payload, expected.Payload) {
					t.Fatalf("frame %d = %+v, %v; want %+v", i, f, err, expected)
				}
			}
			if nc.out.Len() != 0 {
				t.Fatalf("unsolicited control writes: %x", nc.out.Bytes())
			}
			if _, err := c.ReadFrame(); !errors.Is(err, ErrPeerClosed) {
				t.Fatalf("EOF after Close = %v", err)
			}
		})
	}
}

func TestReadFrameProtocolErrors(t *testing.T) {
	tests := map[string]struct {
		wire        []byte
		client      bool
		compression bool
		code        CloseCode
	}{
		"unmasked to server":           {wire: frameBytes(true, OpcodeBinary, 0, false, 0, nil), code: CloseProtocolError},
		"masked to client":             {wire: clientFrame(true, OpcodeBinary, nil), client: true, code: CloseProtocolError},
		"unexpected continuation":      {wire: frameBytes(true, OpcodeContinuation, 0, true, 1, nil), code: CloseProtocolError},
		"new message during fragments": {wire: append(frameBytes(false, OpcodeBinary, 0, true, 1, nil), clientFrame(true, OpcodeText, nil)...), code: CloseProtocolError},
		"fragmented ping":              {wire: frameBytes(false, OpcodePing, 0, true, 1, nil), code: CloseProtocolError},
		"oversized ping":               {wire: clientFrame(true, OpcodePing, make([]byte, 126)), code: CloseProtocolError},
		"reserved opcode":              {wire: frameBytes(true, Opcode(3), 0, true, 1, nil), code: CloseProtocolError},
		"unnegotiated RSV1":            {wire: frameBytes(true, OpcodeBinary, RSV1, true, 1, nil), code: CloseProtocolError},
		"RSV1 control":                 {wire: frameBytes(true, OpcodePing, RSV1, true, 1, nil), compression: true, code: CloseProtocolError},
		"RSV1 continuation":            {wire: append(frameBytes(false, OpcodeBinary, RSV1, true, 1, nil), frameBytes(true, OpcodeContinuation, RSV1, true, 1, nil)...), compression: true, code: CloseProtocolError},
		"short close":                  {wire: clientFrame(true, OpcodeClose, []byte{1}), code: CloseProtocolError},
		"bad close code":               {wire: clientFrame(true, OpcodeClose, []byte{3, 237}), code: CloseProtocolError},
		"bad close reason":             {wire: clientFrame(true, OpcodeClose, []byte{3, 232, 255}), code: CloseInvalidFramePayloadData},
		"data after close":             {wire: append(clientFrame(true, OpcodeClose, nil), clientFrame(true, OpcodeBinary, nil)...), code: CloseProtocolError},
		"invalid text":                 {wire: clientFrame(true, OpcodeText, []byte{255}), code: CloseInvalidFramePayloadData},
		"truncated text":               {wire: clientFrame(true, OpcodeText, []byte{0xe2}), code: CloseInvalidFramePayloadData},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			nc := &scriptConn{in: tt.wire}
			c := newConn(nc, tt.client, []ConnOption{WithCompression(tt.compression)})
			defer c.Abort()
			var err error
			for range 3 {
				if _, err = c.ReadFrame(); err != nil {
					break
				}
			}
			pe, ok := errors.AsType[*ProtocolError](err)
			if !ok || pe.Code != tt.code {
				t.Fatalf("error = %v, want ProtocolError code %d", err, tt.code)
			}
			if nc.out.Len() != 0 {
				t.Fatalf("protocol failure wrote: %x", nc.out.Bytes())
			}
			if _, again := c.ReadFrame(); again != err {
				t.Fatalf("sticky error = %v, want %v", again, err)
			}
		})
	}
}

func TestReadFrameBufferedPrefixes(t *testing.T) {
	wire := append(clientFrame(true, OpcodeBinary, []byte("payload")), clientFrame(true, OpcodePong, []byte("next"))...)
	for prefix := range len(wire) + 1 {
		t.Run(string(rune('A'+prefix)), func(t *testing.T) {
			buffered := bytes.Clone(wire[:prefix])
			c := NewServerConn(&scriptConn{in: wire[prefix:], chunk: 1}, WithBuffered(buffered), WithReadBufferSize(16))
			clear(buffered)
			defer c.Abort()
			for _, want := range []string{"payload", "next"} {
				f, err := c.ReadFrame()
				if err != nil || string(f.Payload) != want {
					t.Fatalf("prefix %d = %q, %v, want %q", prefix, f.Payload, err, want)
				}
			}
			if _, err := c.ReadFrame(); !errors.Is(err, io.EOF) {
				t.Fatalf("EOF = %v", err)
			}
		})
	}
}

func TestReadFrameLimitsAndTruncation(t *testing.T) {
	tests := map[string]struct {
		wire  []byte
		limit int64
		want  error
		code  CloseCode
	}{
		"huge declared length":     {wire: AppendHeader(nil, Header{Fin: true, Opcode: OpcodeBinary, Masked: true, Length: 1 << 62}), limit: 8, code: CloseMessageTooBig},
		"message total":            {wire: append(clientFrame(false, OpcodeBinary, []byte("12345")), clientFrame(true, OpcodeContinuation, []byte("6789"))...), limit: 8, code: CloseMessageTooBig},
		"partial header":           {wire: []byte{0x82}, want: io.ErrUnexpectedEOF},
		"partial masked payload":   {wire: clientFrame(true, OpcodeBinary, []byte("data"))[:8], want: io.ErrUnexpectedEOF},
		"missing continuation":     {wire: clientFrame(false, OpcodeBinary, nil), want: io.ErrUnexpectedEOF},
		"close abandons fragments": {wire: append(clientFrame(false, OpcodeBinary, nil), clientFrame(true, OpcodeClose, nil)...), want: ErrPeerClosed},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := NewServerConn(&scriptConn{in: tt.wire}, WithReadLimit(tt.limit))
			defer c.Abort()
			var err error
			for range 4 {
				if _, err = c.ReadFrame(); err != nil {
					break
				}
			}
			if tt.code != 0 {
				pe, ok := errors.AsType[*ProtocolError](err)
				if !ok || pe.Code != tt.code {
					t.Fatalf("error = %v, want code %d", err, tt.code)
				}
			} else if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if cap(c.msgBuf) > 4096 {
				t.Fatalf("declared length allocated %d bytes", cap(c.msgBuf))
			}
		})
	}
}

func TestAbortBlockedFrameRead(t *testing.T) {
	nc, peer := net.Pipe()
	defer peer.Close()
	c := NewClientConn(nc)
	done := make(chan error, 1)
	go func() { _, err := c.ReadFrame(); done <- err }()
	// A complete header proves the read has entered frame mode and is blocked
	// waiting for its payload before Abort interrupts the transport.
	if _, err := peer.Write([]byte{0x82, 1}); err != nil {
		t.Fatal(err)
	}
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("blocked read succeeded after Abort")
	}
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
	if c.rbuf != nil || c.msgBuf != nil {
		t.Fatal("read buffers retained after Abort")
	}
	if _, err := c.ReadFrame(); err == nil {
		t.Fatal("read succeeded after Abort")
	}
}
