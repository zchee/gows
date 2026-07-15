package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/antlabs/quickws"
)

type strictQuickWSProbe struct {
	messages chan []byte
	closed   chan error
}

func (p *strictQuickWSProbe) OnOpen(*quickws.Conn) {}

func (p *strictQuickWSProbe) OnMessage(_ *quickws.Conn, _ quickws.Opcode, payload []byte) {
	p.messages <- append([]byte(nil), payload...)
}

func (p *strictQuickWSProbe) OnClose(_ *quickws.Conn, err error) { p.closed <- err }

func TestStrictQuickWSRejectsInvalidTextBeforeCallback(t *testing.T) {
	probe := &strictQuickWSProbe{messages: make(chan []byte, 1), closed: make(chan error, 1)}
	readErr := make(chan error, 1)
	upgrader := newStrictQuickWSUpgrade(probe)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r)
		if err != nil {
			readErr <- err
			return
		}
		readErr <- conn.ReadLoop()
	}))
	t.Cleanup(server.Close)

	client, err := quickws.Dial("ws" + strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatalf("dial quickws strict server: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.WriteMessage(quickws.Text, []byte{0xff, 0xfe}); err != nil {
		t.Fatalf("unvalidated client write: %v", err)
	}

	select {
	case payload := <-probe.messages:
		t.Fatalf("invalid UTF-8 reached OnMessage: %x", payload)
	case err := <-probe.closed:
		if !errors.Is(err, quickws.ErrTextNotUTF8) {
			t.Fatalf("OnClose error = %v, want %v", err, quickws.ErrTextNotUTF8)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for invalid UTF-8 rejection")
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, quickws.ErrTextNotUTF8) {
			t.Fatalf("ReadLoop error = %v, want %v", err, quickws.ErrTextNotUTF8)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for strict ReadLoop to return")
	}
}

func TestQuickWSEchoReportsWriteFailureAndClosesConnection(t *testing.T) {
	serverConnCh := make(chan *quickws.Conn, 1)
	upgradeErrCh := make(chan error, 1)
	releaseHandler := make(chan struct{})

	upgrader := quickws.NewUpgrade()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r)
		if err != nil {
			upgradeErrCh <- err
			return
		}
		serverConnCh <- conn
		<-releaseHandler
	}))
	t.Cleanup(func() {
		close(releaseHandler)
		server.Close()
	})

	client, err := quickws.Dial("ws" + strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatalf("dial quickws test server: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var serverConn *quickws.Conn
	select {
	case serverConn = <-serverConnCh:
	case err := <-upgradeErrCh:
		t.Fatalf("upgrade quickws test connection: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upgraded quickws connection")
	}

	// Close only the transport so quickws.Conn still considers itself open.
	// Its next WriteMessage therefore executes the real frame-write path and
	// deterministically returns the closed-network error that the callback
	// must not discard.
	if err := serverConn.NetConn().Close(); err != nil {
		t.Fatalf("close server transport: %v", err)
	}

	failures := newQuickWSFailures()
	echo := quickwsEcho{reportFailure: failures.report}
	echo.OnMessage(serverConn, quickws.Binary, []byte("echo payload"))

	select {
	case failure := <-failures.ch:
		if !strings.Contains(failure.Error(), "quickws echo write") {
			t.Fatalf("reported failure %q does not identify the echo write", failure)
		}
		if !strings.Contains(failure.Error(), "payload_bytes=12") {
			t.Fatalf("reported failure %q does not include payload accounting", failure)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for quickws callback failure")
	}

	if err := serverConn.WriteMessage(quickws.Binary, []byte("after failure")); !errors.Is(err, quickws.ErrClosed) {
		t.Fatalf("WriteMessage after callback failure = %v, want %v", err, quickws.ErrClosed)
	}
}

func TestQuickWSFailuresPublishesOnlyFirstFailure(t *testing.T) {
	failures := newQuickWSFailures()
	first := errors.New("first")
	second := errors.New("second")

	failures.report(first)
	failures.report(second)

	if got := <-failures.ch; !errors.Is(got, first) {
		t.Fatalf("reported failure = %v, want first failure", got)
	}
	select {
	case got := <-failures.ch:
		t.Fatalf("unexpected second reported failure: %v", got)
	default:
	}
}
