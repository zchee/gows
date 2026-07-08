package main

import (
	"context"
	"net/http"

	"github.com/coder/websocket"
)

// runCoder serves a binary echo using coder/websocket's Accept + Read/Write
// API. coder/websocket does not expose configurable read/write buffer sizes
// (unlike gorilla/gobwas) — its buffers are managed internally, documented
// as a caveat in bench/README.md.
func runCoder(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer conn.CloseNow()

		for {
			mt, p, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			if err := conn.Write(r.Context(), mt, p); err != nil {
				return
			}
		}
	})

	return serveHTTP(ctx, addr, mux)
}
