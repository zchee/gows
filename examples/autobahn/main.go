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

// Command autobahn is the gows side of the Autobahn|Testsuite conformance
// gate (see ../../autobahn/run.sh): a dual-mode binary that either serves
// as the WebSocket server the fuzzingclient tests, or drives the client
// side of the protocol against a running fuzzingserver. It depends on
// nothing but the standard library and the root gows package.
//
// Usage:
//
//	autobahn -mode server -addr :9001
//	autobahn -mode client -server ws://127.0.0.1:9001
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zchee/gows"
)

// agentName identifies this implementation to the Autobahn|Testsuite
// reports (the "agent" query parameter and report column).
const agentName = "gows"

// readLimit bounds the largest reassembled message either side accepts.
// Autobahn sections 1-10 exercise payloads well under this; it exists so
// a misbehaving peer cannot force unbounded memory growth.
const readLimit = 64 << 20 // 64 MiB

// caseTimeout bounds how long a single client-driven case (or the
// getCaseCount/updateReports requests) may take before this driver gives
// up on it, so one stuck case cannot hang the whole 301-case run. It is
// generous relative to anything sections 1-10 actually exercises.
const caseTimeout = 30 * time.Second

func main() {
	mode := flag.String("mode", "", `"server" or "client"`)
	addr := flag.String("addr", ":9001", "server mode: address to listen on")
	server := flag.String("server", "ws://127.0.0.1:9001", "client mode: fuzzingserver base URL")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*addr)
	case "client":
		if err := runClient(*server); err != nil {
			log.Fatalf("client: %v", err)
		}
	default:
		fmt.Fprintln(os.Stderr, `usage: autobahn -mode server|client [-addr :9001] [-server ws://127.0.0.1:9001]`)
		os.Exit(2)
	}
}

// runServer listens on addr and serves every connection as a WebSocket
// echo endpoint: every text or binary message is echoed back verbatim
// with the same opcode, until the connection closes. It never returns
// under normal operation.
func runServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("autobahn echo server listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go serveConn(conn)
	}
}

// upgrader is shared by every accepted connection: EnableCompression opts
// the server into negotiating permessage-deflate (RFC 7692) with clients
// that offer it (Autobahn sections 12/13), while leaving UTF-8 validation
// at its default (on).
var upgrader = gows.Upgrader{EnableCompression: true}

// serveConn performs the zero-copy raw-TCP handshake on conn and echoes
// every message until the peer closes the connection or a protocol
// violation ends it.
func serveConn(conn net.Conn) {
	hs, err := upgrader.Upgrade(conn)
	if err != nil {
		log.Printf("upgrade %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	c := gows.NewServerConn(
		conn,
		gows.WithBuffered(hs.Buffered),
		gows.WithReadLimit(readLimit),
		gows.WithCompression(hs.Compressed),
	)
	// Close is idempotent (safe to call even if ReadMessage/WriteMessage
	// already tore the Conn down internally), so this alone is enough to
	// guarantee the pooled buffers and underlying connection are always
	// released exactly once.
	defer c.Close(gows.CloseNormalClosure, "")

	for {
		op, payload, err := c.ReadMessage()
		if err != nil {
			return
		}
		if err := c.WriteMessage(op, payload); err != nil {
			return
		}
	}
}

// runClient drives the full Autobahn client-conformance protocol against
// base (a fuzzingserver, e.g. "ws://127.0.0.1:9001"): fetch the case
// count, run every case by echoing its messages back, then ask the
// server to write its report.
func runClient(base string) error {
	count, err := getCaseCount(base)
	if err != nil {
		return fmt.Errorf("get case count: %w", err)
	}
	log.Printf("running %d cases against %s", count, base)

	for n := 1; n <= count; n++ {
		if err := runCase(base, n); err != nil {
			// A single case's connection misbehaving (e.g. a dial
			// failure) must not abort the remaining cases: the judge
			// decides pass/fail per case from the report, not from this
			// driver's exit status.
			log.Printf("case %d/%d: %v", n, count, err)
		}
		if n%25 == 0 || n == count {
			log.Printf("progress: %d/%d cases run", n, count)
		}
	}

	if err := updateReports(base); err != nil {
		return fmt.Errorf("update reports: %w", err)
	}
	log.Printf("done: %d cases, reports updated", count)
	return nil
}

// dialer is shared by every client-mode connection: EnableCompression opts
// this driver into offering permessage-deflate (RFC 7692) in the handshake
// request, so Autobahn sections 12/13 actually exercise negotiated
// compression instead of falling back to uncompressed frames.
var dialer = gows.Dialer{EnableCompression: true}

// dialCase performs the client-side handshake for url and wires
// Handshake.Buffered and the shared read limit into the resulting Conn.
func dialCase(url string) (*gows.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), caseTimeout)
	defer cancel()

	conn, hs, err := dialer.Dial(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", url, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(caseTimeout))

	return gows.NewClientConn(
		conn,
		gows.WithBuffered(hs.Buffered),
		gows.WithReadLimit(readLimit),
		gows.WithCompression(hs.Compressed),
	), nil
}

// getCaseCount asks base for the number of cases in the suite: a single
// request/response exchange over its own short-lived connection.
func getCaseCount(base string) (int, error) {
	c, err := dialCase(base + "/getCaseCount")
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

// runCase drives case number n to completion: it echoes every message it
// receives, with the same opcode, until the server ends the connection
// (which it always eventually does, whether the case passed, failed, or
// this driver itself detected and reported a protocol violation — the
// pass/fail verdict is the judge's, not this function's).
func runCase(base string, n int) error {
	url := fmt.Sprintf("%s/runCase?case=%d&agent=%s", base, n, agentName)
	c, err := dialCase(url)
	if err != nil {
		return err
	}
	defer c.Close(gows.CloseNormalClosure, "")

	for {
		op, payload, err := c.ReadMessage()
		if err != nil {
			return nil
		}
		if err := c.WriteMessage(op, payload); err != nil {
			return nil
		}
	}
}

// updateReports asks base to write out its accumulated report for
// agentName, waiting for it to close the connection when done.
func updateReports(base string) error {
	url := fmt.Sprintf("%s/updateReports?agent=%s", base, agentName)
	c, err := dialCase(url)
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
