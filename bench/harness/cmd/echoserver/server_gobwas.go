package main

import (
	"context"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// runGobwas serves a binary echo using gobwas/ws's zero-copy raw net.Conn
// upgrade path (no net/http), the library's fastest and idiomatic mode.
func runGobwas(ctx context.Context, addr string, cfg serverConfig) error {
	upgrader := ws.Upgrader{
		ReadBufferSize:  bufferSize,
		WriteBufferSize: bufferSize,
	}
	return serveRaw(ctx, addr, cfg, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if _, err := upgrader.Upgrade(conn); err != nil {
			return
		}
		for {
			msg, op, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			if err := wsutil.WriteServerMessage(conn, op, msg); err != nil {
				return
			}
		}
	})
}
