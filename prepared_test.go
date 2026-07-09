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
	"net"
	"strings"
	"testing"
)

func TestNewPreparedMessage(t *testing.T) {
	tests := map[string]struct {
		payload           []byte
		wantHasCompressed bool
	}{
		"below threshold: no compressed frame": {
			payload:           bytes.Repeat([]byte{'a'}, 511),
			wantHasCompressed: false,
		},
		"at threshold: has compressed frame": {
			payload:           bytes.Repeat([]byte{'a'}, 512),
			wantHasCompressed: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			pm, err := NewPreparedMessage(OpcodeBinary, tt.payload)
			if err != nil {
				t.Fatalf("NewPreparedMessage: %v", err)
			}
			if pm.hasCompressed != tt.wantHasCompressed {
				t.Fatalf("hasCompressed = %v, want %v", pm.hasCompressed, tt.wantHasCompressed)
			}

			// The uncompressed frame must always decode back to the exact
			// original payload, unmasked, Fin set, RSV1 clear.
			h, n, err := DecodeHeader(pm.plain)
			if err != nil {
				t.Fatalf("DecodeHeader(plain): %v", err)
			}
			if !h.Fin || h.Rsv != 0 || h.Masked || !bytes.Equal(pm.plain[n:], tt.payload) {
				t.Fatalf("plain frame = %+v payload=%q, want Fin unmasked Rsv=0 payload=%q", h, pm.plain[n:], tt.payload)
			}

			if !tt.wantHasCompressed {
				return
			}
			ch, cn, err := DecodeHeader(pm.compressed)
			if err != nil {
				t.Fatalf("DecodeHeader(compressed): %v", err)
			}
			if !ch.Fin || ch.Rsv != RSV1 || ch.Masked {
				t.Fatalf("compressed frame header = %+v, want Fin RSV1 unmasked", ch)
			}
			c := NewServerConn(&scriptConn{})
			decoded, err := c.decompressMessage(pm.compressed[cn:])
			if err != nil {
				t.Fatalf("decompressMessage: %v", err)
			}
			if !bytes.Equal(decoded, tt.payload) {
				t.Fatalf("decompressed payload mismatch: got %d bytes, want %d bytes", len(decoded), len(tt.payload))
			}
		})
	}
}

func TestWritePreparedMessage(t *testing.T) {
	payload := []byte(strings.Repeat("broadcast payload ", 40)) // above the compression threshold
	pm, err := NewPreparedMessage(OpcodeText, payload)
	if err != nil {
		t.Fatalf("NewPreparedMessage: %v", err)
	}
	if !pm.hasCompressed {
		t.Fatalf("hasCompressed = false, want true for a %d-byte payload", len(payload))
	}

	tests := map[string]struct {
		compression bool
		wantRSV1    bool
	}{
		"target negotiated compression: sends the compressed frame": {
			compression: true,
			wantRSV1:    true,
		},
		"target did not negotiate compression: sends the plain frame": {
			compression: false,
			wantRSV1:    false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sc := &scriptConn{}
			c := NewServerConn(sc, WithCompression(tt.compression))
			if err := c.WritePreparedMessage(pm); err != nil {
				t.Fatalf("WritePreparedMessage: %v", err)
			}
			h, n, err := DecodeHeader(sc.out.Bytes())
			if err != nil {
				t.Fatalf("DecodeHeader: %v", err)
			}
			if got := h.Rsv == RSV1; got != tt.wantRSV1 {
				t.Fatalf("RSV1 set = %v, want %v", got, tt.wantRSV1)
			}

			var got []byte
			if tt.wantRSV1 {
				got, err = c.decompressMessage(sc.out.Bytes()[n:])
				if err != nil {
					t.Fatalf("decompressMessage: %v", err)
				}
			} else {
				got = sc.out.Bytes()[n:]
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d bytes", len(got), len(payload))
			}
		})
	}
}

func TestWritePreparedMessageClientRoleRejected(t *testing.T) {
	pm, err := NewPreparedMessage(OpcodeText, []byte("hi"))
	if err != nil {
		t.Fatalf("NewPreparedMessage: %v", err)
	}
	c := NewClientConn(&scriptConn{})
	if err := c.WritePreparedMessage(pm); !errors.Is(err, errPreparedMessageClientRole) {
		t.Fatalf("WritePreparedMessage on client role: err = %v, want errPreparedMessageClientRole", err)
	}
}

// TestPreparedMessageBroadcastFreshWindow confirms a PreparedMessage's
// compressed frame -- built once -- decodes correctly for a peer with no
// prior compression state on the connection, i.e. it was compressed
// against a fresh window as compress-design.md §6 requires for a message
// reused across many connections.
func TestPreparedMessageBroadcastFreshWindow(t *testing.T) {
	payload := []byte(strings.Repeat("shared broadcast message ", 60))
	pm, err := NewPreparedMessage(OpcodeBinary, payload)
	if err != nil {
		t.Fatalf("NewPreparedMessage: %v", err)
	}

	// Simulate broadcasting to two independent client connections, each
	// with its own Conn state and negotiated compression.
	for i := range 2 {
		srvConn, cliConn := net.Pipe()
		srv := NewServerConn(srvConn, WithCompression(true))
		cli := NewClientConn(cliConn, WithCompression(true))

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = srv.WritePreparedMessage(pm)
		}()

		op, got, err := cli.ReadMessage()
		if err != nil {
			t.Fatalf("connection %d: ReadMessage: %v", i, err)
		}
		if op != OpcodeBinary || !bytes.Equal(got, payload) {
			t.Fatalf("connection %d: payload mismatch: got %d bytes, want %d bytes", i, len(got), len(payload))
		}
		<-done
		// Close the raw pipe halves directly rather than running the full
		// WS closing handshake (Conn.Close): neither side is looping
		// ReadMessage any more at this point, so Conn.Close's outbound
		// Close-frame write would block forever on net.Pipe waiting for a
		// reader that will never come, for both ends symmetrically.
		_ = srvConn.Close()
		_ = cliConn.Close()
	}
}

// TestWritePreparedMessageOutgoingTakeoverSendsPlain confirms that on a
// Conn whose outgoing direction has context takeover, WritePreparedMessage
// sends the plain frame (RSV1 clear) so the peer's sliding dict stays in
// sync with this Conn's persistent compressor. A subsequent compressMessage
// message then decodes correctly at a peer maintaining a dict.
func TestWritePreparedMessageOutgoingTakeoverSendsPlain(t *testing.T) {
	withDeflateBackend(t, DefaultDeflateBackend(), 6, deflateWindowBits)

	payload := []byte(strings.Repeat("prepared-takeover-payload-", 40))
	pm, err := NewPreparedMessage(OpcodeBinary, payload)
	if err != nil {
		t.Fatalf("NewPreparedMessage: %v", err)
	}
	if !pm.hasCompressed {
		t.Fatalf("hasCompressed = false, want true")
	}

	sc := &scriptConn{}
	c := NewServerConn(sc, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
	if err := c.WritePreparedMessage(pm); err != nil {
		t.Fatalf("WritePreparedMessage: %v", err)
	}
	h, n, err := DecodeHeader(sc.out.Bytes())
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.Rsv&RSV1 != 0 {
		t.Fatalf("RSV1 set, want plain frame under outgoing takeover")
	}
	if !bytes.Equal(sc.out.Bytes()[n:], payload) {
		t.Fatalf("plain payload mismatch")
	}

	// Follow with a compressMessage-backed WriteMessage; a peer with a
	// sliding dict (client role, ServerContextTakeover) must still decode.
	sc.out.Reset()
	follow := []byte("Hello")
	// Force compress regardless of size via compressMessage + emit.
	compressed, _, err := c.compressMessage(nil, follow)
	if err != nil {
		t.Fatalf("compressMessage: %v", err)
	}
	peer := NewClientConn(&scriptConn{}, WithCompressionParams(CompressionParams{ServerContextTakeover: true}))
	// The prepared plain frame did not advance either side's deflate
	// context; the first compressed message is still against a fresh window.
	got, err := peer.decompressMessage(compressed)
	if err != nil || string(got) != string(follow) {
		t.Fatalf("peer decompress after prepared plain = %q, %v, want %q", got, err, follow)
	}
}

// TestWritePreparedMessageWriterBusy confirms WritePreparedMessage refuses
// to run while a NextWriter stream is open (RFC 6455 §5.4).
func TestWritePreparedMessageWriterBusy(t *testing.T) {
	pm, err := NewPreparedMessage(OpcodeText, []byte("hi"))
	if err != nil {
		t.Fatalf("NewPreparedMessage: %v", err)
	}
	c := NewServerConn(&scriptConn{}, WithCompression(true))
	w, err := c.NextWriter(OpcodeText)
	if err != nil {
		t.Fatalf("NextWriter: %v", err)
	}
	defer w.Close()
	if err := c.WritePreparedMessage(pm); !errors.Is(err, ErrWriterBusy) {
		t.Fatalf("WritePreparedMessage with open NextWriter: err = %v, want ErrWriterBusy", err)
	}
}

// TestWritePreparedMessagePrepWindowBitsAboveCeiling confirms a prepared
// frame compressed at windowBits 15 is sent plain on a Conn whose
// outgoing ceiling is 9.
func TestWritePreparedMessagePrepWindowBitsAboveCeiling(t *testing.T) {
	// Build prepared under default stdlib (windowBits 15).
	payload := []byte(strings.Repeat("ceil-check-payload-", 40))
	pm, err := NewPreparedMessage(OpcodeBinary, payload)
	if err != nil {
		t.Fatalf("NewPreparedMessage: %v", err)
	}
	if pm.prepWindowBits != deflateWindowBits {
		t.Fatalf("prepWindowBits = %d, want %d", pm.prepWindowBits, deflateWindowBits)
	}

	withDeflateBackend(t, fakeWindowedBackend, defaultDeflateLevel, 9)
	sc := &scriptConn{}
	c := NewServerConn(sc, WithCompressionParams(CompressionParams{ServerMaxWindowBits: 9}))
	if c.outgoingWindowCeil != 9 {
		t.Fatalf("outgoingWindowCeil = %d, want 9", c.outgoingWindowCeil)
	}
	if err := c.WritePreparedMessage(pm); err != nil {
		t.Fatalf("WritePreparedMessage: %v", err)
	}
	h, n, err := DecodeHeader(sc.out.Bytes())
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.Rsv&RSV1 != 0 {
		t.Fatalf("RSV1 set, want plain (prepWindowBits 15 > ceiling 9)")
	}
	if !bytes.Equal(sc.out.Bytes()[n:], payload) {
		t.Fatalf("plain payload mismatch")
	}
}
