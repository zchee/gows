package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/antlabs/quickws"
)

// quickwsEcho implements quickws.Callback, echoing every received message
// back with the same opcode. quickws.Callback cannot return an error, so the
// first failed echo write is reported to runQuickWS explicitly instead of
// being silently discarded.
type quickwsEcho struct {
	reportFailure func(error)
}

func (quickwsEcho) OnOpen(*quickws.Conn) {}

func (e quickwsEcho) OnMessage(c *quickws.Conn, op quickws.Opcode, data []byte) {
	if err := c.WriteMessage(op, data); err != nil {
		failure := fmt.Errorf("quickws echo write opcode=%v payload_bytes=%d: %w", op, len(data), err)
		if closeErr := c.Close(); closeErr != nil {
			failure = errors.Join(failure, fmt.Errorf("quickws close after echo write failure: %w", closeErr))
		}
		e.reportFailure(failure)
	}
}

func (quickwsEcho) OnClose(*quickws.Conn, error) {}

// quickwsFailures publishes only the first callback failure. The channel is
// buffered so a callback never blocks waiting for runQuickWS to schedule.
type quickwsFailures struct {
	once sync.Once
	ch   chan error
}

func newQuickWSFailures() *quickwsFailures {
	return &quickwsFailures{ch: make(chan error, 1)}
}

func newStrictQuickWSUpgrade(callback quickws.Callback) *quickws.UpgradeServer {
	return quickws.NewUpgrade(
		quickws.WithServerCallback(callback),
		quickws.WithServerEnableUTF8Check(),
		quickws.WithServerReadTimeout(0),
	)
}

func (f *quickwsFailures) report(err error) {
	if err == nil {
		panic("echoserver: quickws reported a nil callback failure")
	}
	f.once.Do(func() { f.ch <- err })
}

// runQuickWS serves a binary echo using antlabs/quickws's recommended
// callback API over net/http Hijack.
func runQuickWS(ctx context.Context, addr string, cfg serverConfig) error {
	failures := newQuickWSFailures()
	up := newStrictQuickWSUpgrade(quickwsEcho{reportFailure: failures.report})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r)
		if err != nil {
			return
		}
		// ReadLoop returns the terminal peer-close/read error. Echo write
		// failures are reported through quickwsFailures above, while normal
		// client disconnects must not stop the shared benchmark server.
		_ = conn.ReadLoop()
	})

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- serveHTTP(serveCtx, addr, mux, cfg)
	}()

	select {
	case err := <-serveErrCh:
		return err
	case err := <-failures.ch:
		// Terminate the HTTP runner as soon as an echo callback can no longer
		// account for a requested reply. main then terminates the process, so the
		// benchmark load generator observes either an I/O error or a failed
		// post-run debug read; both are existing hard gates.
		cancel()
		return errors.Join(err, <-serveErrCh)
	}
}
