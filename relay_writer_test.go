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

func TestWriteFrameFragments(t *testing.T) {
	tests := map[string]struct{ client, compressed bool }{
		"server": {}, "client": {client: true}, "compressed server": {compressed: true}, "compressed client": {client: true, compressed: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			nc := &scriptConn{}
			c := newConn(nc, tt.client, []ConnOption{WithCompression(tt.compressed)})
			defer c.Abort()
			frames := []Frame{
				{Header: Header{Opcode: OpcodeText}, Payload: []byte("hello")},
				{Header: Header{Opcode: OpcodePing, Fin: true}, Payload: []byte("control")},
				{Header: Header{Opcode: OpcodeContinuation}, Payload: nil},
				{Header: Header{Opcode: OpcodeContinuation, Fin: true}, Payload: []byte(" world")},
				{Header: Header{Opcode: OpcodeClose, Fin: true}, Payload: nil},
			}
			for _, f := range frames {
				before := bytes.Clone(f.Payload)
				if err := c.WriteFrame(f.Header.Opcode, f.Header.Fin, f.Payload, tt.compressed && !f.Header.Opcode.IsControl()); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, f.Payload) {
					t.Fatal("write mutated caller payload")
				}
			}
			reader := newConn(&scriptConn{in: nc.out.Bytes()}, !tt.client, []ConnOption{WithCompression(tt.compressed)})
			defer reader.Abort()
			var compressed []byte
			for i, want := range frames {
				f, err := reader.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if f.Header.Opcode != want.Header.Opcode || f.Header.Fin != want.Header.Fin || f.Header.Masked != tt.client {
					t.Fatalf("frame %d: %+v, want %+v", i, f, want)
				}
				if tt.compressed && !want.Header.Opcode.IsControl() {
					if !f.Compressed || (f.Header.Rsv == RSV1) != (i == 0) {
						t.Fatalf("compression flags: %+v", f)
					}
					compressed = append(compressed, f.Payload...)
				} else if !bytes.Equal(f.Payload, want.Payload) {
					t.Fatalf("frame %d payload %x, want %x", i, f.Payload, want.Payload)
				}
			}
			if tt.compressed {
				out, err := reader.decompressMessage(compressed)
				if err != nil || string(out) != "hello world" {
					t.Fatalf("decode = %q, %v", out, err)
				}
			}
		})
	}
}

func TestWriteFrameUsage(t *testing.T) {
	tests := map[string]struct {
		op            Opcode
		fin, compress bool
		payload       []byte
	}{
		"unexpected continuation":  {op: OpcodeContinuation, fin: true},
		"reserved opcode":          {op: Opcode(3), fin: true},
		"fragmented control":       {op: OpcodePing},
		"compressed control":       {op: OpcodePong, fin: true, compress: true},
		"large control":            {op: OpcodePing, fin: true, payload: make([]byte, 126)},
		"bad close":                {op: OpcodeClose, fin: true, payload: []byte{1}},
		"unnegotiated compression": {op: OpcodeBinary, fin: true, compress: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			nc := &scriptConn{}
			c := NewServerConn(nc)
			defer c.Abort()
			err := c.WriteFrame(tt.op, tt.fin, tt.payload, tt.compress)
			if _, ok := errors.AsType[*FrameUsageError](err); !ok {
				t.Fatalf("error = %v, want FrameUsageError", err)
			}
			if nc.out.Len() != 0 {
				t.Fatal("invalid write emitted bytes")
			}
			if err := c.WriteFrame(OpcodeBinary, true, nil, false); err != nil {
				t.Fatalf("usage error poisoned writer: %v", err)
			}
		})
	}
	nc := &scriptConn{}
	c := NewServerConn(nc, WithCompression(true))
	defer c.Abort()
	if err := c.WriteFrame(OpcodeBinary, false, nil, true); err != nil {
		t.Fatal(err)
	}
	for _, op := range []Opcode{OpcodeText, OpcodeContinuation} {
		n := nc.out.Len()
		err := c.WriteFrame(op, true, nil, false)
		if _, ok := errors.AsType[*FrameUsageError](err); !ok || nc.out.Len() != n {
			t.Fatalf("interleaving: %v", err)
		}
	}
	if err := c.WriteFrame(OpcodeContinuation, true, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteFrame(OpcodeClose, true, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteFrame(OpcodeBinary, true, nil, false); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("data after Close: %v", err)
	}
	if err := c.WriteFrame(OpcodePong, true, nil, false); err != nil {
		t.Fatalf("control completion: %v", err)
	}
}

type shortFrameConn struct{ scriptConn }

func (c *shortFrameConn) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestWriteFrameShortWrite(t *testing.T) {
	c := NewServerConn(&shortFrameConn{})
	defer c.Abort()
	if err := c.WriteFrame(OpcodeBinary, true, []byte("x"), false); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if err := c.WriteFrame(OpcodeBinary, true, nil, false); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("sticky write: %v", err)
	}
}

func TestAbortBlockedFrameWrite(t *testing.T) {
	nc, peer := net.Pipe()
	defer peer.Close()
	c := NewClientConn(nc)
	done := make(chan error, 1)
	go func() { done <- c.WriteFrame(OpcodeBinary, true, []byte("blocked"), false) }()
	// Reading the header byte establishes an in-flight write with unread bytes.
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("blocked write succeeded")
	}
	if c.wpay != nil || c.wstage != nil {
		t.Fatal("writer buffers retained after Abort")
	}
}
