package main

import (
	"context"
	"net/http"

	"github.com/antlabs/quickws"
)

// quickwsEcho implements quickws.Callback, echoing every received message
// back with the same opcode.
type quickwsEcho struct{}

func (quickwsEcho) OnOpen(*quickws.Conn) {}

func (quickwsEcho) OnMessage(c *quickws.Conn, op quickws.Opcode, data []byte) {
	_ = c.WriteMessage(op, data)
}

func (quickwsEcho) OnClose(*quickws.Conn, error) {}

// runQuickWS serves a binary echo using antlabs/quickws's recommended
// callback API over net/http Hijack.
func runQuickWS(ctx context.Context, addr string) error {
	up := quickws.NewUpgrade(
		quickws.WithServerCallback(quickwsEcho{}),
		quickws.WithServerReadTimeout(0),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r)
		if err != nil {
			return
		}
		conn.ReadLoop()
	})

	return serveHTTP(ctx, addr, mux)
}
