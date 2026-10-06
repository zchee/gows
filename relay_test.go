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
	"sync"
	"testing"
)

func TestParseClose(t *testing.T) {
	tests := map[string]struct {
		body []byte
		want CloseError
		code CloseCode
	}{
		"empty":          {want: CloseError{Code: CloseNoStatusReceived}},
		"normal":         {body: []byte{3, 232, 'b', 'y', 'e'}, want: CloseError{Code: CloseNormalClosure, Reason: "bye"}},
		"private":        {body: []byte{15, 160}, want: CloseError{Code: 4000}},
		"short":          {body: []byte{3}, code: CloseProtocolError},
		"reserved":       {body: []byte{3, 237}, code: CloseProtocolError},
		"invalid reason": {body: []byte{3, 232, 255}, code: CloseInvalidFramePayloadData},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseClose(tt.body)
			if tt.code != 0 {
				var pe *ProtocolError
				if !errors.As(err, &pe) || pe.Code != tt.code {
					t.Fatalf("ParseClose(%x) error = %v, want ProtocolError code %d", tt.body, err, tt.code)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ParseClose(%x) = %+v, %v; want %+v, nil", tt.body, got, err, tt.want)
			}
		})
	}
}

func TestConnModeExclusion(t *testing.T) {
	tests := map[string]struct{ call func(*Conn) error }{
		"ReadMessage":          {func(c *Conn) error { _, _, err := c.ReadMessage(); return err }},
		"NextReader":           {func(c *Conn) error { _, _, err := c.NextReader(); return err }},
		"NextWriter":           {func(c *Conn) error { _, err := c.NextWriter(OpcodeBinary); return err }},
		"WriteMessage":         {func(c *Conn) error { return c.WriteMessage(OpcodeBinary, nil) }},
		"WriteMessageBuffered": {func(c *Conn) error { return c.WriteMessageBuffered(OpcodeBinary, nil) }},
		"WritePreparedMessage": {func(c *Conn) error { return c.WritePreparedMessage(nil) }},
		"Flush":                {func(c *Conn) error { return c.Flush() }},
		"Serve":                {func(c *Conn) error { return c.Serve(nil) }},
		"Close":                {func(c *Conn) error { return c.Close(CloseNormalClosure, "") }},
		"WriteClose":           {func(c *Conn) error { return c.WriteClose(CloseNormalClosure, "") }},
		"CloseContext":         {func(c *Conn) error { return c.CloseContext(t.Context(), CloseNormalClosure, "") }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := NewServerConn(&scriptConn{})
			defer c.teardown()
			if err := c.selectMode(connModeFrame); err != nil {
				t.Fatal(err)
			}
			if err := tt.call(c); !errors.Is(err, ErrConnMode) {
				t.Fatalf("%s = %v, want ErrConnMode", name, err)
			}
		})
	}
}

func TestConnModeSelection(t *testing.T) {
	c := NewServerConn(&scriptConn{})
	defer c.teardown()
	if err := c.WriteMessage(OpcodeBinary, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.selectMode(connModeFrame); !errors.Is(err, ErrConnMode) {
		t.Fatalf("frame after message = %v", err)
	}
	for range 100 {
		var c Conn
		var wg sync.WaitGroup
		result := make(chan error, 2)
		for _, mode := range []uint32{connModeMessage, connModeFrame} {
			wg.Go(func() { result <- c.selectMode(mode) })
		}
		wg.Wait()
		a, b := <-result, <-result
		if (a == nil) == (b == nil) || a != nil && !errors.Is(a, ErrConnMode) || b != nil && !errors.Is(b, ErrConnMode) {
			t.Fatalf("concurrent selection = %v, %v; want exactly one mode owner", a, b)
		}
	}
}
