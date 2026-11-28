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
	"net"
	"testing"
)

func TestWriteCloseOrder(t *testing.T) {
	tests := map[string]struct {
		state      string
		code       CloseCode
		reason     string
		validation error
	}{
		"torn down invalid code":  {state: "torn down", validation: ErrInvalidCloseCode},
		"torn down valid":         {state: "torn down", code: CloseNormalClosure},
		"after CloseNow valid":    {state: "abrupt", code: CloseNormalClosure},
		"after sent Close valid":  {state: "sent", code: CloseNormalClosure},
		"retained invalid reason": {state: "failed", code: CloseNormalClosure, reason: "\xff", validation: ErrInvalidCloseReason},
		"retained valid":          {state: "failed", code: CloseNormalClosure},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cause := errors.New("transport write failed")
			writes := 0
			c := NewServerConn(&writeProbe{Conn: &scriptConn{}, write: func(b []byte) (int, error) {
				writes++
				if tt.state == "failed" {
					return 0, cause
				}
				return len(b), nil
			}})
			defer c.teardown()
			var want error
			switch tt.state {
			case "torn down":
				if _, _, err := c.ReadMessage(); !errors.Is(err, io.EOF) || !c.tornDown.Load() {
					t.Fatalf("ReadMessage = %v, torn down = %t", err, c.tornDown.Load())
				}
			case "abrupt":
				if err := c.CloseNow(); err != nil {
					t.Fatal(err)
				}
				want = errClosedNow
			case "sent":
				if err := c.WriteClose(CloseGoingAway, "bye"); err != nil {
					t.Fatal(err)
				}
			case "failed":
				want = c.WriteMessage(OpcodeText, nil)
				requireWriteFailure(t, want, cause)
			}
			before := writes
			got := c.WriteClose(tt.code, tt.reason)
			if tt.validation != nil {
				if !errors.Is(got, tt.validation) {
					t.Errorf("WriteClose = %v, want %v", got, tt.validation)
				}
			} else if got != want {
				t.Errorf("WriteClose = %v, want identical error %v", got, want)
			}
			if writes != before {
				t.Errorf("WriteClose attempted %d additional transport writes", writes-before)
			}
		})
	}
}

func TestRetainedErrorRaceCloseNow(t *testing.T) {
	tests := map[string]struct{ waitForFailure bool }{
		"peer close races CloseNow": {},
		"peer close wins":           {waitForFailure: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			a, peer := net.Pipe()
			defer a.Close()
			defer peer.Close()
			spy := newCloseCountConn(a)
			c := NewServerConn(spy)
			writing := asyncResult(func() error { return c.WriteMessage(OpcodeText, nil) })
			awaitEntered(t, "write", spy.writeEntered, writing)

			peerClosed := asyncResult(peer.Close)
			var first error
			if tt.waitForFailure {
				first = awaitResult(t, "failed write", writing)
				requireWriteFailure(t, first, io.ErrClosedPipe)
			}
			if err := c.CloseNow(); err != nil {
				t.Fatal(err)
			}
			if err := awaitResult(t, "peer Close", peerClosed); err != nil {
				t.Fatal(err)
			}
			if !tt.waitForFailure {
				first = awaitResult(t, "failed write", writing)
			}
			want := errClosedNow
			if _, ok := first.(*writeError); ok {
				requireWriteFailure(t, first, io.ErrClosedPipe)
				want = first
			} else {
				wantClosed(t, "interrupted write", first)
			}
			if got := c.WriteMessage(OpcodeBinary, nil); got != want {
				t.Fatalf("WriteMessage = %v, want identical error %v", got, want)
			}
			_, _, readErr := c.ReadMessage()
			wantClosed(t, "ReadMessage", readErr)
			if c.rbuf != nil {
				t.Fatal("reader kept its buffer after teardown")
			}
			if got := c.WriteMessage(OpcodeBinary, nil); got != want {
				t.Fatalf("WriteMessage after reader teardown = %v, want identical error %v", got, want)
			}
			if got := c.WriteClose(CloseNormalClosure, ""); got != want {
				t.Fatalf("WriteClose after reader teardown = %v, want identical error %v", got, want)
			}
		})
	}
}

func TestCloseAfterCloseNowReleasesBuffers(t *testing.T) {
	a, peer := net.Pipe()
	defer a.Close()
	defer peer.Close()
	spy := newCloseCountConn(a)
	c := NewServerConn(spy)
	if err := c.CloseNow(); err != nil || c.rbuf == nil {
		t.Fatalf("CloseNow = %v, buffer retained = %t", err, c.rbuf != nil)
	}
	if err := c.Close(CloseNormalClosure, "bye"); err != nil || c.rbuf != nil {
		t.Fatalf("Close = %v, buffer released = %t", err, c.rbuf == nil)
	}
	select {
	case <-spy.writeEntered:
		t.Fatal("closing the connection attempted a transport write")
	default:
	}
}
