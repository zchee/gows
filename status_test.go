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

package gows_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/zchee/gows"
	"github.com/zchee/gows/internal/httpx"
)

// dialWithRawResponse runs one Dial whose fake server answers with the
// given raw response bytes, returning Dial's error.
func dialWithRawResponse(t *testing.T, d *gows.Dialer, response string) error {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		readRawHeaderBlock(t, serverConn)
		serverConn.Write([]byte(response))
	}()
	d.NetDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return clientConn, nil
	}
	_, _, err := d.Dial(t.Context(), "ws://example.invalid/")
	if err == nil {
		t.Fatal("Dial = nil error, want failure")
	}
	return err
}

func TestDialUnexpectedStatus(t *testing.T) {
	tests := map[string]struct {
		response   string
		wantStatus int
		wantReason string
	}{
		"error: 403 with reason": {
			response:   "HTTP/1.1 403 Forbidden\r\n\r\n",
			wantStatus: 403,
			wantReason: "Forbidden",
		},
		"error: 500 empty reason": {
			response:   "HTTP/1.1 500 \r\n\r\n",
			wantStatus: 500,
			wantReason: "",
		},
		"error: redirect status without opt-in stays a status error": {
			response:   "HTTP/1.1 302 Found\r\nLocation: ws://elsewhere.invalid/\r\n\r\n",
			wantStatus: 302,
			wantReason: "Found",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := dialWithRawResponse(t, &gows.Dialer{}, tt.response)
			if !errors.Is(err, gows.ErrUnexpectedStatus) {
				t.Fatalf("Dial = %v, want errors.Is ErrUnexpectedStatus", err)
			}
			var use *gows.UnexpectedStatusError
			if !errors.As(err, &use) {
				t.Fatalf("Dial = %v, want a *UnexpectedStatusError in the chain", err)
			}
			if use.StatusCode != tt.wantStatus || use.Reason != tt.wantReason {
				t.Fatalf("UnexpectedStatusError = (%d, %q), want (%d, %q)", use.StatusCode, use.Reason, tt.wantStatus, tt.wantReason)
			}
		})
	}
}

// TestDialMalformedStatus pins that a status-code field that is not
// exactly three ASCII digits is a malformed status line, never a typed
// unexpected-status result.
func TestDialMalformedStatus(t *testing.T) {
	for name, response := range map[string]string{
		"error: alphabetic code": "HTTP/1.1 ABC Nope\r\n\r\n",
		"error: four-digit code": "HTTP/1.1 4033 Nope\r\n\r\n",
		"error: two-digit code":  "HTTP/1.1 42 Nope\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := dialWithRawResponse(t, &gows.Dialer{}, response)
			if errors.Is(err, gows.ErrUnexpectedStatus) {
				t.Fatalf("Dial = %v, want a malformed-status error, not ErrUnexpectedStatus", err)
			}
			if !errors.Is(err, httpx.ErrMalformedStatusLine) {
				t.Fatalf("Dial = %v, want errors.Is httpx.ErrMalformedStatusLine", err)
			}
		})
	}
}

// TestDialStatusReasonRedaction reflects a recognizable bearer secret
// back in the peer's reason phrase and asserts it never surfaces in
// Error() output anywhere in the chain -- only in the explicitly
// documented Reason field.
func TestDialStatusReasonRedaction(t *testing.T) {
	const secret = "SECRET-BEARER-TOKEN-XYZ"
	d := &gows.Dialer{HTTPHeader: http.Header{"Authorization": {"Bearer " + secret}}}
	err := dialWithRawResponse(t, d, "HTTP/1.1 401 denied "+secret+"\r\n\r\n")

	if !errors.Is(err, gows.ErrUnexpectedStatus) {
		t.Fatalf("Dial = %v, want errors.Is ErrUnexpectedStatus", err)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), secret) {
			t.Fatalf("error chain leaks the reflected secret: %q", e)
		}
	}
	var use *gows.UnexpectedStatusError
	if !errors.As(err, &use) {
		t.Fatalf("Dial = %v, want a *UnexpectedStatusError", err)
	}
	if use.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", use.StatusCode)
	}
	// The field carries the verbatim reason for callers that opt in to
	// inspecting it; only Error() text must stay clean.
	if !strings.Contains(use.Reason, secret) {
		t.Errorf("Reason field = %q, want the verbatim peer reason", use.Reason)
	}
}
