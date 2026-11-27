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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zchee/gows"
)

// bearerTransport adds an Authorization header the way an API client's
// authenticating RoundTripper does, so the session tests dial through a
// transport gows did not create.
type bearerTransport struct {
	next  http.RoundTripper
	token string
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

// readSignalConn reports the first Read on the transport, which is how a
// test knows a reader has entered its blocking call.
type readSignalConn struct {
	net.Conn
	once    sync.Once
	reading chan struct{}
}

func (c *readSignalConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}

const sessionRefusal = `{"error":{"message":"Invalid API Key","type":"authentication_error"}}`

// newSessionServer serves an echo endpoint that refuses any token but "good"
// with a JSON error document, as an API server does.
func newSessionServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(sessionRefusal))
			return
		}
		conn, hs, err := gows.UpgradeHTTP(w, r)
		if err != nil {
			t.Errorf("UpgradeHTTP: %v", err)
			return
		}
		c := gows.NewServerConn(conn, gows.WithBuffered(hs.Buffered), gows.WithCompression(hs.Compressed))
		for {
			op, p, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(op, p); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dialSession dials srv through its HTTP client wrapped in a bearerTransport.
// The returned channel is closed when the Conn first reads from the transport.
func dialSession(t *testing.T, srv *httptest.Server, token string) (*gows.Conn, <-chan struct{}, error) {
	t.Helper()
	hc := *srv.Client()
	hc.Transport = bearerTransport{next: hc.Transport, token: token}
	d := gows.Dialer{HTTPClient: &hc, MaxErrorBodyBytes: 4096}
	conn, hs, err := d.Dial(t.Context(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		return nil, nil, err
	}
	sc := &readSignalConn{Conn: conn, reading: make(chan struct{})}
	c := gows.NewClientConn(sc, gows.WithBuffered(hs.Buffered), gows.WithCompression(hs.Compressed))
	t.Cleanup(func() { _ = c.CloseNow() })
	return c, sc.reading, nil
}

// TestClientSession drives a connection the way an API client's session type
// does: it dials through the client's own HTTP stack, turns a refused
// handshake into an API error, sends from several goroutines beside one
// reader, and closes from a goroutine that is not the reader.
func TestClientSession(t *testing.T) {
	t.Run("error: refused handshake reports the API error document", func(t *testing.T) {
		_, _, err := dialSession(t, newSessionServer(t), "bad")
		refused, ok := errors.AsType[*gows.UnexpectedStatusError](err)
		if !ok {
			t.Fatalf("Dial error = %v, want an *UnexpectedStatusError", err)
		}
		if refused.StatusCode != http.StatusUnauthorized {
			t.Errorf("StatusCode = %d, want %d", refused.StatusCode, http.StatusUnauthorized)
		}
		if got := refused.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}
		if string(refused.Body) != sessionRefusal {
			t.Errorf("Body = %q, want %q", refused.Body, sessionRefusal)
		}
		if strings.Contains(err.Error(), "Invalid API Key") {
			t.Errorf("error text repeats the server's message: %q", err)
		}
	})

	t.Run("success: several senders beside a reader, closed by another goroutine", func(t *testing.T) {
		c, _, err := dialSession(t, newSessionServer(t), "good")
		if err != nil {
			t.Fatal(err)
		}
		const senders, perSender = 4, 50
		type result struct {
			got []string
			err error
		}
		done := make(chan result, 1)
		received := make(chan struct{})
		go func() {
			var got []string
			for {
				_, p, err := c.ReadMessageContext(t.Context())
				if err != nil {
					done <- result{got, err}
					return
				}
				got = append(got, string(p))
				if len(got) == senders*perSender {
					close(received)
				}
			}
		}()

		var wg sync.WaitGroup
		for s := range senders {
			wg.Go(func() {
				for i := range perSender {
					if err := c.WriteMessageContext(t.Context(), gows.OpcodeText, fmt.Appendf(nil, "%d:%d", s, i)); err != nil {
						t.Errorf("sender %d message %d: %v", s, i, err)
						return
					}
				}
			})
		}
		wg.Wait()
		select {
		case <-received:
		case <-time.After(10 * time.Second):
			t.Fatal("the reader did not receive every echo")
		}

		// The reader still owns the read side, so only the write half of
		// the closing handshake runs here; the reader reports the reply.
		if err := c.WriteClose(gows.CloseNormalClosure, ""); err != nil {
			t.Fatalf("WriteClose: %v", err)
		}
		r := <-done
		closed, ok := errors.AsType[*gows.CloseError](r.err)
		if !ok || closed.Code != gows.CloseNormalClosure {
			t.Errorf("reader ended with %v, want a CloseError with code %d", r.err, gows.CloseNormalClosure)
		}
		if err := c.Close(gows.CloseNormalClosure, ""); err != nil {
			t.Errorf("Close after the reader finished = %v, want nil", err)
		}

		next := make([]int, senders)
		for _, m := range r.got {
			var s, i int
			if _, err := fmt.Sscanf(m, "%d:%d", &s, &i); err != nil || s < 0 || s >= senders {
				t.Fatalf("unexpected echo %q", m)
			}
			if i != next[s] {
				t.Fatalf("sender %d: got message %d, want %d", s, i, next[s])
			}
			next[s]++
		}
		for s, n := range next {
			if n != perSender {
				t.Errorf("sender %d: %d echoes, want %d", s, n, perSender)
			}
		}
	})

	t.Run("success: abrupt close releases a blocked reader", func(t *testing.T) {
		c, reading, err := dialSession(t, newSessionServer(t), "good")
		if err != nil {
			t.Fatal(err)
		}
		readErr := make(chan error, 1)
		go func() {
			_, _, err := c.ReadMessage()
			readErr <- err
		}()
		<-reading
		if err := c.CloseNow(); err != nil {
			t.Fatalf("CloseNow: %v", err)
		}
		if err := <-readErr; !errors.Is(err, net.ErrClosed) {
			t.Errorf("reader ended with %v, want an error matching net.ErrClosed", err)
		}
		if err := c.WriteMessage(gows.OpcodeText, []byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Errorf("WriteMessage after CloseNow = %v, want an error matching net.ErrClosed", err)
		}
		if err := c.Close(gows.CloseNormalClosure, ""); err != nil {
			t.Errorf("Close after CloseNow = %v, want nil", err)
		}
	})

	t.Run("error: a read whose context ends closes the connection", func(t *testing.T) {
		c, reading, err := dialSession(t, newSessionServer(t), "good")
		if err != nil {
			t.Fatal(err)
		}
		cause := errors.New("session abandoned")
		ctx, cancel := context.WithCancelCause(t.Context())
		readErr := make(chan error, 1)
		go func() {
			_, _, err := c.ReadMessageContext(ctx)
			readErr <- err
		}()
		<-reading
		cancel(cause)
		if err := <-readErr; !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
			t.Errorf("reader ended with %v, want an error matching context.Canceled and the cause", err)
		}
		if err := c.WriteMessage(gows.OpcodeText, []byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Errorf("WriteMessage after the context ended = %v, want an error matching net.ErrClosed", err)
		}
	})
}
