package main

import (
	"context"
	"errors"
	"net/http"
)

// serveHTTP runs a net/http server on addr with handler until ctx is
// canceled, at which point it shuts down and returns nil. It is shared by
// every library whose idiomatic upgrade path is net/http-based (gorilla,
// coder, fasthttp/websocket's net/http variant is not used since fasthttp
// has its own listener, quickws, gws, nbio).
func serveHTTP(ctx context.Context, addr string, handler http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: handler}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

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
