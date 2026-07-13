package main

import (
	"context"
	"net/http"

	"github.com/lesismal/nbio/nbhttp"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

// runNBIO serves a binary echo using lesismal/nbio's epoll/kqueue reactor
// engine (nbhttp), the library's recommended high-throughput mode. cfg is
// ignored: nbhttp.Engine binds its own sockets, so the shared newListener
// accept hooks (-notsent-lowat, -trace-file) do not reach it; the H3/H5
// experiments only exercise gows and quickws.
func runNBIO(ctx context.Context, addr string, _ serverConfig) error {
	upgrader := websocket.NewUpgrader()
	upgrader.EnableCompression(false)
	upgrader.OnMessage(func(c *websocket.Conn, mt websocket.MessageType, data []byte) {
		_ = c.WriteMessage(mt, data)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if _, err := upgrader.Upgrade(w, r, nil); err != nil {
			return
		}
	})

	engine := nbhttp.NewEngine(nbhttp.Config{
		Network:        "tcp",
		Addrs:          []string{addr},
		Handler:        mux,
		ReadBufferSize: bufferSize,
	})

	if err := engine.Start(); err != nil {
		return err
	}
	<-ctx.Done()
	engine.Stop()
	return nil
}
