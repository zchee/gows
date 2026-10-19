package main

import (
	"context"
	"errors"
	"net"
	"net/http"
)

// serveHTTP runs a net/http server on addr with handler until ctx is
// canceled, at which point it shuts down and returns nil. It is shared by
// every library whose idiomatic upgrade path is net/http-based (gorilla,
// coder, quickws). The listener is obtained through newListener, so the
// -notsent-lowat and -trace-file accept hooks apply to these backends at the
// same shared point they apply to the raw-accept backends (gows, gobwas).
func serveHTTP(ctx context.Context, addr string, handler http.Handler, cfg serverConfig) error {
	ln, err := newListener(addr, cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: handler}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		_ = srv.Close()
		<-errCh
		return nil
	}
}

// serveRaw accepts TCP connections on addr and runs handle on its own
// goroutine for each one until ctx is canceled, at which point the listener is
// closed and serveRaw returns nil. It is shared by the libraries whose
// idiomatic upgrade path takes a raw net.Conn (gows, gobwas); handle owns the
// connection and must close it. The listener comes from newListener, so the
// accept hooks apply here as they do in serveHTTP.
func serveRaw(ctx context.Context, addr string, cfg serverConfig, handle func(net.Conn)) error {
	ln, err := newListener(addr, cfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(conn)
	}
}
