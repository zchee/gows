package main

import (
	"context"
	"errors"
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
