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
	"time"
)

func TestCloseDefaultBudget(t *testing.T) {
	tests := map[string]struct{ readClose bool }{
		"silent peer":               {readClose: true},
		"blocked Close-frame write": {},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server, peer := net.Pipe()
			defer server.Close()
			defer peer.Close()
			c := NewServerConn(server, WithCloseTimeout(200*time.Millisecond))
			watchdog := time.Now().Add(1200 * time.Millisecond)
			if err := peer.SetReadDeadline(watchdog); err != nil {
				t.Fatal(err)
			}
			closed := make(chan error, 1)
			go func() { closed <- c.Close(CloseNormalClosure, "") }()
			if tt.readClose {
				// Unmasked Close frame carrying only status 1000.
				var frame [4]byte
				if _, err := io.ReadFull(peer, frame[:]); err != nil || frame != [4]byte{0x88, 2, 0x03, 0xe8} {
					t.Fatalf("peer read %x, %v; want Close(1000)", frame, err)
				}
			}
			select {
			case err := <-closed:
				if !errors.Is(err, ErrCloseTimeout) {
					t.Fatalf("Close = %v, want ErrCloseTimeout", err)
				}
				if !tt.readClose {
					retained, ok := errors.AsType[*writeError](err)
					if !ok || !errors.Is(err, retained) {
						t.Fatalf("Close = %v, want retained write error", err)
					}
					if got := c.WriteMessage(OpcodeText, nil); got != retained {
						t.Fatalf("WriteMessage = %v, want same retained write error %p", got, retained)
					}
				}
			case <-time.After(time.Until(watchdog)):
				t.Fatal("Close did not return within 1.2s")
			}
			if err := c.Close(CloseNormalClosure, ""); err != nil {
				t.Fatalf("second Close = %v, want nil", err)
			}
		})
	}
}
