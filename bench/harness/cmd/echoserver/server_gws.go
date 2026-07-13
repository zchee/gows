package main

import (
	"context"

	"github.com/lxzan/gws"
)

// gwsEcho implements gws.Event, echoing every received message back with
// the same opcode. gws recommends embedding BuiltinEventHandler so only the
// hooks actually used need overriding.
type gwsEcho struct {
	gws.BuiltinEventHandler
}

func (gwsEcho) OnMessage(socket *gws.Conn, message *gws.Message) {
	defer message.Close()
	_ = socket.WriteMessage(message.Opcode, message.Bytes())
}

// runGWS serves a binary echo using lxzan/gws's recommended Event/callback
// API with compression and UTF-8 checking left at their documented defaults
// (both off), matching the other libraries' fairness configuration. cfg is
// ignored: gws.Server.Run owns its listener internally, so the shared
// newListener accept hooks (-notsent-lowat, -trace-file) do not reach it; the
// H3/H5 experiments only exercise gows and quickws.
func runGWS(ctx context.Context, addr string, _ serverConfig) error {
	server := gws.NewServer(gwsEcho{}, &gws.ServerOption{
		ReadBufferSize:     bufferSize,
		ParallelEnabled:    false,
		CheckUtf8Enabled:   false,
		ReadMaxPayloadSize: 16 * 1024 * 1024,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- server.Run(addr) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}
