// Copyright 2026 The gows Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package autobahnapp implements the application loop shared by the canonical
// Autobahn example and feature-specific backend commands.
package autobahnapp

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/gows"
)

const (
	readLimit = 64 << 20
	// Some Autobahn cases exchange 1000 compressed 128 KiB messages. Keep the
	// per-case deadline bounded, but leave enough room for those cases on the
	// slower cross-backend and race-enabled runs.
	caseTimeout = time.Minute
)

// Config defines one Autobahn application profile.
type Config struct {
	AgentName string
	Upgrader  gows.Upgrader
	Dialer    gows.Dialer
}

// Run parses args and runs the requested server or client mode. It returns a
// process exit code; server mode does not return during normal operation.
func Run(args []string, cfg Config, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("autobahn", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := fs.String("mode", "", `"server" or "client"`)
	addr := fs.String("addr", ":9001", "server mode: address to listen on")
	server := fs.String("server", "ws://127.0.0.1:9001", "client mode: fuzzingserver base URL")
	echo := fs.String("echo", "message", `echo loop: "message" (ReadMessage/WriteMessage) or "stream" (NextReader/NextWriter)`)
	takeover := fs.Bool("takeover", false, "offer/accept permessage-deflate context takeover and honor the negotiated params per connection")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	caseDelay, err := parseCaseDelay(os.Getenv("AUTOBAHN_CASE_DELAY"))
	if err != nil {
		fmt.Fprintf(stderr, "autobahn: invalid AUTOBAHN_CASE_DELAY: %v\n", err)
		return 2
	}

	if cfg.AgentName == "" {
		fmt.Fprintln(stderr, "autobahn: empty agent name")
		return 2
	}
	if *takeover {
		cfg.Upgrader.AllowContextTakeover = true
		cfg.Dialer.AllowContextTakeover = true
	}

	streamEcho := false
	switch *echo {
	case "message":
	case "stream":
		streamEcho = true
	default:
		fmt.Fprintf(stderr, "unknown -echo mode %q (want message or stream)\n", *echo)
		return 2
	}

	logger := log.New(stderr, "", log.LstdFlags)
	app := application{config: cfg, logger: logger, streamEcho: streamEcho, caseDelay: caseDelay, sleep: time.Sleep}
	switch *mode {
	case "server":
		return app.runServer(*addr)
	case "client":
		if err := app.runClient(*server); err != nil {
			logger.Printf("client: %v", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(stderr, `usage: autobahn -mode server|client [-addr :9001] [-server ws://127.0.0.1:9001]`)
		return 2
	}
}

type application struct {
	config     Config
	logger     *log.Logger
	streamEcho bool
	caseDelay  time.Duration
	sleep      func(time.Duration)
}

func (a *application) runServer(addr string) int {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		a.logger.Printf("listen %s: %v", addr, err)
		return 1
	}
	defer ln.Close()
	a.logger.Printf("autobahn echo server listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			a.logger.Printf("accept: %v", err)
			continue
		}
		a.beforeServerUpgrade()
		go a.serveConn(conn)
	}
}

func (a *application) serveConn(conn net.Conn) {
	hs, err := a.config.Upgrader.Upgrade(conn)
	if err != nil {
		a.logger.Printf("upgrade %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	c := gows.NewServerConn(conn, connOptions(hs)...)
	defer c.Close(gows.CloseNormalClosure, "")
	a.echoLoop(c)
}

func (a *application) echoLoop(c *gows.Conn) {
	for {
		if a.streamEcho {
			op, r, err := c.NextReader()
			if err != nil {
				return
			}
			w, err := c.NextWriter(op)
			if err != nil {
				return
			}
			_, copyErr := io.Copy(w, r)
			if err := w.Close(); err != nil || copyErr != nil {
				return
			}
			continue
		}
		op, payload, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(op, payload); err != nil {
			return
		}
	}
}

func (a *application) runClient(base string) error {
	count, err := a.getCaseCount(base)
	if err != nil {
		return fmt.Errorf("get case count: %w", err)
	}
	a.logger.Printf("running %d cases against %s", count, base)
	for n := 1; n <= count; n++ {
		if err := a.runCase(base, n); err != nil {
			a.logger.Printf("case %d/%d: %v", n, count, err)
		}
		if n%25 == 0 || n == count {
			a.logger.Printf("progress: %d/%d cases run", n, count)
		}
		a.afterClientCase(n, count)
	}
	if err := a.updateReports(base); err != nil {
		return fmt.Errorf("update reports: %w", err)
	}
	a.logger.Printf("done: %d cases, reports updated", count)
	return nil
}

func parseCaseDelay(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %s is negative", value)
	}
	return d, nil
}

func (a *application) beforeServerUpgrade() {
	if a.caseDelay > 0 {
		a.sleep(a.caseDelay)
	}
}

func (a *application) afterClientCase(n, count int) {
	if a.caseDelay > 0 && n < count {
		a.sleep(a.caseDelay)
	}
}

func (a *application) dialCase(url string) (*gows.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()
	conn, hs, err := a.config.Dialer.Dial(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", url, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(caseTimeout))
	return gows.NewClientConn(conn, connOptions(hs)...), nil
}

func connOptions(hs gows.Handshake) []gows.ConnOption {
	opts := []gows.ConnOption{gows.WithBuffered(hs.Buffered), gows.WithReadLimit(readLimit)}
	if hs.Compressed {
		opts = append(opts, gows.WithCompressionParams(hs.CompressionParams))
	}
	return opts
}

func (a *application) getCaseCount(base string) (int, error) {
	c, err := a.dialCase(base + "/getCaseCount")
	if err != nil {
		return 0, err
	}
	defer c.Close(gows.CloseNormalClosure, "")
	op, payload, err := c.ReadMessage()
	if err != nil {
		return 0, fmt.Errorf("read case count: %w", err)
	}
	if op != gows.OpcodeText {
		return 0, fmt.Errorf("expected a text message, got opcode %d", op)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(payload)))
	if err != nil {
		return 0, fmt.Errorf("parse case count %q: %w", payload, err)
	}
	return n, nil
}

func (a *application) runCase(base string, n int) error {
	url := fmt.Sprintf("%s/runCase?case=%d&agent=%s", base, n, a.config.AgentName)
	c, err := a.dialCase(url)
	if err != nil {
		return err
	}
	defer c.Close(gows.CloseNormalClosure, "")
	a.echoLoop(c)
	return nil
}

func (a *application) updateReports(base string) error {
	url := fmt.Sprintf("%s/updateReports?agent=%s", base, a.config.AgentName)
	c, err := a.dialCase(url)
	if err != nil {
		return err
	}
	defer c.Close(gows.CloseNormalClosure, "")
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			return nil
		}
	}
}
