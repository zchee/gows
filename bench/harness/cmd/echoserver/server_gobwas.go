package main

import (
	"context"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// runGobwas serves a binary echo using gobwas/ws's zero-copy raw net.Conn
// upgrade path (no net/http), the library's fastest and idiomatic mode per
// plan §4.1/§4.2.
func runGobwas(ctx context.Context, addr string, cfg serverConfig) error {
	ln, err := newListener(addr, cfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	upgrader := ws.Upgrader{
		ReadBufferSize:  bufferSize,
		WriteBufferSize: bufferSize,
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(conn net.Conn) {
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
		}(conn)
	}
}
