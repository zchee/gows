package main

import (
	"context"

	"github.com/fasthttp/websocket"
	"github.com/valyala/fasthttp"
)

// runFastHTTP serves a binary echo using fasthttp/websocket's
// FastHTTPUpgrader over a valyala/fasthttp server, the library's intended
// integration (it is a gorilla/websocket fork targeting fasthttp; see
// bench/README.md for the gofiber/contrib equivalence note). cfg is ignored:
// fasthttp.Server.ListenAndServe owns its listener, so the shared newListener
// accept hooks (-notsent-lowat, -trace-file) do not reach it; the H3/H5
// experiments only exercise gows and quickws.
func runFastHTTP(ctx context.Context, addr string, _ serverConfig) error {
	upgrader := websocket.FastHTTPUpgrader{
		ReadBufferSize:    bufferSize,
		WriteBufferSize:   bufferSize,
		EnableCompression: false,
		CheckOrigin:       func(*fasthttp.RequestCtx) bool { return true },
	}

	handler := func(fctx *fasthttp.RequestCtx) {
		_ = upgrader.Upgrade(fctx, func(conn *websocket.Conn) {
			defer conn.Close()
			for {
				mt, p, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(mt, p); err != nil {
					return
				}
			}
		})
	}

	srv := &fasthttp.Server{Handler: handler}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(addr) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		_ = srv.Shutdown()
		<-errCh
		return nil
	}
}
