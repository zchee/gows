package main

import (
	"context"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// runGorilla serves a binary echo using gorilla/websocket's recommended
// net/http Hijack-based Upgrader, with WriteBufferPool enabled so each
// library uses its recommended high-performance API.
func runGorilla(ctx context.Context, addr string, cfg serverConfig) error {
	upgrader := websocket.Upgrader{
		ReadBufferSize:    bufferSize,
		WriteBufferSize:   bufferSize,
		WriteBufferPool:   &gorillaBufferPool{},
		CheckOrigin:       func(*http.Request) bool { return true },
		EnableCompression: false,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
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

	return serveHTTP(ctx, addr, mux, cfg)
}

// gorillaBufferPool implements websocket.BufferPool with sync.Pool, the
// pattern gorilla's own docs recommend for high-connection-count servers.
type gorillaBufferPool struct{ p sync.Pool }

func (bp *gorillaBufferPool) Get() any {
	if b := bp.p.Get(); b != nil {
		return b
	}
	return make([]byte, 0, bufferSize)
}

func (bp *gorillaBufferPool) Put(v any) { bp.p.Put(v) }
