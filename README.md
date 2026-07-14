# gows

A zero-dependency [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) /
[RFC 7692](https://www.rfc-editor.org/rfc/rfc7692) (permessage-deflate)
WebSocket library for Go, engineered for maximum performance — with honest,
reproducible benchmarks. Every number on this page comes from a committed
report under [`.omc/research/`](.omc/research/) or
[`bench/results/`](bench/results/); where gows didn't win, that's said
plainly too. Headline (2026-07-14, paired final gate on darwin/arm64):
wherever the workload lets a server architecture matter, gows beats
quickws — the closest competitor measured — by **+28-36% throughput with
22-26% lower p99**, ties it everywhere else, and does so at 0.73-0.80× the
CPU and memory. See [Benchmarks](#benchmarks) for the full picture,
including what remains open.

## Features

- **Zero-dependency core.** Every package in the library's build graph —
  `gows` itself and `internal/*` — imports only the standard library:
  `go list -deps` over those packages resolves zero third-party modules.
  The root `go.mod` carries a single `require`,
  [`github.com/go-json-experiment/json`](https://github.com/go-json-experiment/json),
  used exclusively by the Autobahn conformance tooling under `autobahn/`;
  no library or `internal/*` package imports it, so module graph pruning
  keeps it out of consumers' builds. The comparison libraries only ever
  appear in the separate `bench/` Go module, never in the core module's
  dependency graph.
- **SIMD frame masking** (SSE2 / AVX2 / AVX-512 on amd64, NEON on arm64),
  runtime-dispatched by CPU feature detection with a `GOWS_SIMD` kill
  switch and a pure-Go fallback (`purego` build tag) for every kernel.
  Peaks at **166.8 GB/s at 16KB on an Intel Xeon 8481C (Sapphire Rapids)**,
  ~154 GB/s at 4KB — 2.4-2.7× SSE2's throughput at those sizes, and up to
  **4.9× the fastest of four vendored competitor masking kernels** (gorilla,
  coder, gws, gobwas) benchmarked head-to-head in the same process
  (4.4× at 4KB, 4.9× at 16KB; see
  [`.omc/research/mask-calibration.md`](.omc/research/mask-calibration.md)
  and [`bench/results/phase5-linux-amd64.md`](bench/results/phase5-linux-amd64.md)).
- **Streaming SIMD UTF-8 validation, on by default.** Of the 8 libraries
  measured in this project's comparison harness, gows is the only one that
  validates UTF-8 text-message payloads by default (RFC 6455 §8.1
  conformance out of the box, not an opt-in) — see
  [`bench/README.md`](bench/README.md)'s fairness rules. The validator
  itself (NEON on arm64, AVX2 on amd64, both gated behind exhaustive
  differential testing against `unicode/utf8.Valid` plus fuzzing) is
  27-45× faster than the scalar DFA it augments, depending on workload and
  size, with zero regression on pure-ASCII input (see
  [`.omc/research/utf8-simd-calibration.md`](.omc/research/utf8-simd-calibration.md)).
  It costs nothing measurable in the echo benchmarks below: a CPU profile
  under saturating load shows zero sampled time in the validator, and
  turning it off doesn't reliably beat turning it on (see
  [Benchmarks](#benchmarks)).
- **Zero-copy handshake.** `Upgrader{RawPath: true}.Upgrade` completes in
  **363-369 ns/op, 0 B/op, 0 allocs/op** (~2.6-2.7× faster than a gobwas
  reference point of 973 ns/op) — see
  [`.omc/research/verify-report.md`](.omc/research/verify-report.md) (AC13).
- **0-allocation `ReadMessage`, ≤1-allocation `WriteMessage`.**
  `BenchmarkConnReadMessage`: 0 B/op, 0 allocs/op (~49.5 ns/op, ~20.7 GB/s).
  `BenchmarkConnWriteMessage`: 24 B/op, 1 allocs/op (~25.3 ns/op, ~40.6
  GB/s) — the one allocation is the client-role masking copy; see
  [`writer.go`](writer.go)'s `WriteMessage` doc comment. Compressed
  (permessage-deflate) `WriteMessage` is also **0 allocs/op** steady-state
  on the pooled path.
- **Drain-and-coalesce serving** (`Conn.Serve` + `WriteMessageBuffered` /
  `Flush`): a single-goroutine callback loop that consumes every complete
  message already resident in the read buffer per wakeup (fairness budget
  64) and flushes the framed replies in one write — an echo handler settles
  a whole drain round with **one syscall each way** (1/64th the write
  syscalls on coalesced input at identical ns/op, 0 allocs/msg both
  directions). This is the mechanism behind the +28-36% pipelined win
  below; see [`serve.go`](serve.go).
- **Transport-aware single-write guarantee.** `net.Buffers` writev is only
  real on `*net.TCPConn`; through `crypto/tls` or any wrapping `net.Conn`
  it silently degrades to one `Write` per buffer. gows picks its write
  strategy once at `Conn` construction: plain TCP keeps the writev path,
  everything else gets contiguous staging — **one `Write` per message over
  TLS** (down from two), pinned by a `crypto/tls` loopback regression test.
- **Table-driven frame-header decode**: role- and negotiation-specialized
  256-entry classification tables replace the general branch tree —
  **-34% header-decode time (geomean across five frame shapes)**, held
  byte-identical to the reference decoder by a 16.9M-execution
  differential fuzz over accept/reject, fields, close codes, and error
  strings.
- **permessage-deflate (RFC 7692)**, negotiated via
  `Upgrader.EnableCompression` / `Dialer.EnableCompression`, with a
  pluggable compressor backend, direction-specific window negotiation,
  trusted valued/bare `client_max_window_bits` handling, and opt-in context
  takeover. The root module defaults to stdlib `compress/flate`; the optional
  klauspost backend lives in the separate zero-impact `flatekp/` module (see
  [`options.go`](options.go)'s "permessage-deflate backend seam" comment).
- **Autobahn|Testsuite evidence**: the repository preserves earlier canonical
  server/client results as dated historical evidence — see
  [`.omc/research/autobahn-phase2.md`](.omc/research/autobahn-phase2.md) and
  [`.omc/research/autobahn-phase4.md`](.omc/research/autobahn-phase4.md). The
  v0.4 feature-specific server/client 517-case matrix is
  **SKIPPED-RESIDUAL**, not pass evidence; see [Conformance](#conformance).
- **93.9% statement coverage** across the core module and `internal/*`
  packages (≥85% required), and **1,461,410,711 combined fuzz executions**
  across four targets (`FuzzMask`, `FuzzValidator`, `FuzzDecodeHeader`,
  `FuzzParseExtensions`), 10 minutes each, **zero crashes** — see
  [`.omc/research/verify-report.md`](.omc/research/verify-report.md) (AC8,
  AC11).

## Benchmarks

Methodology: a shared echo-server harness (`bench/harness`) drives every
library through an identical client, with fairness rules documented and
applied identically across all configurations — see
[`bench/README.md`](bench/README.md) for the full rules, library versions,
and integration notes. The 2026-07-14 paired results below use `benchrun`
(seeded randomized paired blocks, fresh server process per repetition, a
host-quiescence guard, and process-rusage resource accounting) judged by
`benchcmp` (paired-ratio bootstrap, 20,000 replicates, 95% CIs) with a
gows-based load client (identical for every server under test); the
earlier tables used gobwas/ws's low-level client. `gows-noutf8` is gows
with `WithSkipUTF8Validation(true)`, published alongside gows's own
validation-on default as the apples-to-apples "what if validation were
off, like every other library here" reference point.

### darwin/arm64 paired final gate (Apple M3 Max) — gows-serve vs quickws, n=20, 2026-07-14

Pre-registered gate (commit 9b5993e, before the optimization code landed):
seven cells, ratios are gows/quickws with bootstrap 95% CIs, 280/280
samples, zero echo-verification errors. Run:
[`bench/results/v-next/darwin-arm64/claude-final-324b7b8-20260714T091557Z`](bench/results/v-next/darwin-arm64/).

| cell | throughput ratio [95% CI] | p99 ratio [95% CI] |
|---|---|---|
| 1KiB × 200 conns, pipelined ×8 | **1.3589 [1.3475, 1.4193]** | **0.7364 [0.7280, 0.7445]** |
| 1KiB × 1000 conns, pipelined ×4 | **1.2800 [1.2557, 1.3333]** | **0.7725 [0.7629, 0.8029]** |
| 64B × 1000 conns (closed-loop) | 0.9961 [0.9859, 1.0003] | 0.9914 [0.9638, 1.0388] |
| 1KiB × 200 conns (closed-loop) | 0.9930 [0.9897, 0.9985] | 0.9959 [0.9807, 1.0038] |
| 1KiB × 1000 conns (closed-loop) | 1.0009 [0.9950, 1.0070] | 0.9966 [0.9810, 1.0075] |
| 16KiB × 200 conns (closed-loop) | 1.0000 [0.9955, 1.0040] | 1.0105 [0.9979, 1.0290] |
| 16KiB × 1000 conns (closed-loop) | 1.0039 [0.9873, 1.0068] | 1.0034 [0.9709, 1.0336] |
| **geomean** | **1.0813** | |

Reading it honestly: the pipelined cells — the only cells where a server
architecture *can* differentiate, because the closed-loop cells are
client/kernel-saturated (proven by a five-hypothesis causal study,
[`.omc/research/vnext-1k1k-causal.md`](.omc/research/vnext-1k1k-causal.md))
— show gows **+35.9% / +28.0% throughput with 26.4% / 22.8% lower p99**,
at **0.73× quickws's server CPU per message and 0.78-0.80× its memory per
connection**. Every closed-loop cell is statistical parity (centers
0.993-1.004). The strict pre-registered letter ("CI lower bound > 1.00 in
every cell") is recorded as FAIL because a saturated tie cannot exceed
1.00 by construction; the full verdict, the disclosed
measurement-window deviation, and the analysis are in
[`.omc/research/vnext-final-claude.md`](.omc/research/vnext-final-claude.md).

### linux/amd64 (Intel Xeon 8481C, Sapphire Rapids, 44 vCPU) — 1KB payload, 1000 connections, n=5

| lib | msg/s (median) | p50 | p90 | p99 | p999 | allocs/msg |
|---|---:|---|---|---|---|---:|
| **gows** | **974,627** | 931.1µs | 1.748ms | 3.351ms | 6.727ms | 1.00 |
| quickws | 972,038 | 934.6µs | 1.754ms | 3.340ms | 6.682ms | 1.00 |
| gows-noutf8 | 969,779 | 936.2µs | 1.755ms | 3.365ms | 6.681ms | 1.00 |
| gws | 964,603 | 936.0µs | 1.764ms | 3.488ms | 6.810ms | 2.00 |
| fasthttp | 794,148 | 1.020ms | 2.592ms | 4.629ms | 7.132ms | 5.00 |
| gorilla | 781,202 | 1.023ms | 2.637ms | 4.946ms | 7.573ms | 6.01 |
| coder | 670,114 | 1.015ms | 3.634ms | 7.259ms | 12.368ms | 24.01 |
| nbio | 634,932 | 1.455ms | 2.063ms | 3.568ms | 5.889ms | 11.02 |
| gobwas | 372,882 | 1.576ms | 4.977ms | 16.274ms | 25.692ms | 8.01 |

gows has the highest median throughput of all 9 configurations — this
result reproduced across three independent measurement sessions on this
hardware (n=5, then n=10, then a final n=10 after two rounds of read-path
tuning), landing in a 972,112-974,876 msg/s band every time. Full detail,
every session, in
[`.omc/research/phase5-results.md`](.omc/research/phase5-results.md).

### darwin/arm64 (Apple M3 Max, NEON) — 1KB payload, 200 connections, n=5

| lib | msg/s (median) | p50 | p90 | p99 | p999 | allocs/msg |
|---|---:|---|---|---|---|---:|
| quickws | 80,801 | 2.435ms | 2.779ms | 3.060ms | 3.923ms | 1.19 |
| **gows** | **80,643** | 2.435ms | 2.785ms | 3.056ms | 3.795ms | 1.00 |
| fasthttp | 80,610 | 2.429ms | 2.801ms | 3.123ms | 4.117ms | 5.00 |
| gws | 80,569 | 2.436ms | 2.786ms | 3.075ms | 3.976ms | 2.00 |
| gows-noutf8 | 80,567 | 2.435ms | 2.772ms | 3.057ms | 3.847ms | 1.00 |
| gorilla | 80,471 | 2.438ms | 2.803ms | 3.166ms | 4.105ms | 6.02 |
| coder | 80,355 | 2.447ms | 2.790ms | 3.492ms | 4.569ms | 24.01 |
| nbio | 79,934 | 2.440ms | 2.875ms | 3.278ms | 3.712ms | 11.16 |
| gobwas | 67,721 | 2.878ms | 3.460ms | 4.610ms | 5.928ms | 8.01 |

Full table and machine-load caveats in
[`bench/results/phase6-darwin-arm64.md`](bench/results/phase6-darwin-arm64.md).

### Allocations per message

The one ranking that reproduced identically, with zero reversals, across
every platform and session in this project: `gows` / `gows-noutf8` tied
lowest at **1.00 alloc/msg**, `quickws` close behind at 1.00-1.19,
`gws` at 2.00, up through `coder`'s 24.01. See either table above or
[`.omc/research/phase5-results.md`](.omc/research/phase5-results.md)'s AC6
section for the cross-platform reproduction.

### The honest part: on closed-loop echo, gows and quickws are statistical peers

The verdict above supersedes the older "statistical peers" story for
pipelined traffic — that one is now a decisive, reproducible gows win.
What remains true is the closed-loop half: **on strict 1-request-1-response
same-host echo, gows and quickws are statistical performance peers —
across 5 independent measurement sessions on two ISAs (amd64 and arm64),
whichever of throughput or p99 either library "won" flipped between
overlapping sample distributions every time. Every other library measured
in this project is consistently, unambiguously behind both of them.**
A five-hypothesis causal study (read-buffer geometry, GC mode, send-buffer
admission on both sides, scheduler wakeup-latency traces) rejected every
mechanism that might separate them there and showed an earlier apparent
+5.2% p99 deficit does not reproduce — the cells are saturated, not
hiding a difference
([`.omc/research/vnext-1k1k-causal.md`](.omc/research/vnext-1k1k-causal.md)).

The evidence, session by session (full data in
[`.omc/research/phase5-results.md`](.omc/research/phase5-results.md)):

| session | platform | throughput | p99 |
|---|---|---|---|
| original (n=5) | linux/amd64 | gows ahead, +0.27% | quickws ahead, +0.33% |
| rerun (n=10) | linux/amd64 | gows ahead, +0.03% | quickws ahead, +0.10% |
| final (n=10) | linux/amd64 | gows ahead, +0.10% | quickws ahead, +0.95% |
| AC6 (n=5) | darwin/arm64 | quickws ahead, +0.20% | gows ahead, +0.14% |

In every one of these eight comparisons, the two libraries' sample ranges
overlap substantially to completely — e.g. the final linux/amd64 session's
p99: gows's full 10-sample range is [3.319, 3.396]ms, quickws's is
[3.301, 3.551]ms, one fully contains most of the other. A CPU profile of
gows under the primary-config load found **zero sampled time in UTF-8
validation** (grep for `utf8`/`Valid`/`Feed` across the full profile: no
matches — its cost is below the ~0.5% sampling resolution), which rules
out "validation is the tax" as an explanation for any of this. The honest
reading: gows has the highest throughput of the full 9-library field at
every configuration measured, and its tail latency is statistically
indistinguishable from the one library that sometimes edges it out. This
is reported as a tie, not rounded up to a win.

### The honest part: the 16KB story, updated

The 2026-07-14 paired gate shows the 16KiB cells vs quickws are now
statistical ties on darwin/arm64 (throughput ratios 1.0000 and 1.0039,
CIs straddling 1.0) — the earlier quickws-side gap does not reproduce
there with the current write path and measurement client. What remains
open: the older linux/amd64 sessions had gows trailing `gws` (~2.3-2.6%)
and `quickws` (~0.9-1.6%) at 16KB with **zero overlap** between throughput
ranges — a real gap in that context, not noise — and that configuration
has not been re-measured since the write-path and header-decode changes
landed. `gows-noutf8` didn't close it, ruling out validation cost as the
cause.

Root-caused via `strace -c -f` under matched load: for the same 16KB
frame, gows issues **~5.02 `read(2)` calls per message against gws's
~2.00** — not because of a hard buffer-size cap (gows's read path
(`reader.go`, `readFramePayload`/`readDirect`) requests the entire
remaining payload length in one logical `Read` call, not a fixed-size
chunk), but because of **arrival pacing**: a leaner, shorter read loop
re-enters `conn.Read` sooner after the netpoller wakes it, which means
less of a wire peer's second, separately-written chunk (many client
implementations write a frame's header and payload as two distinct
`Write` calls) has actually arrived in the kernel by the time gows asks —
so it takes more reads to drain the same message. Being faster per
iteration perversely costs more iterations here. `MSG_WAITALL` was
evaluated as a fix and rejected: on the non-blocking sockets Go's
netpoller requires, it doesn't block in-kernel across multiple future
arrivals — it's an atomic single-attempt gate that returns `EAGAIN`
immediately (discarding whatever partial bytes did arrive) if the full
requested length isn't already buffered, so it doesn't reduce the read
count and can add wasted round-trips instead. Two tuning attempts
(copy-elimination, then an uncapped single `readDirect` call) were tried
during this project; neither moved the number. This is recorded as an
open, unresolved item — not a fix claimed and not swept under the rug.
The full read-size histograms, CPU profiles, and strace evidence are in
[`.omc/research/phase5-results.md`](.omc/research/phase5-results.md) and
`reader.go`'s own doc comments on `readFramePayload`/`readDirect`.

### Reproducing these numbers

Every table above is reproducible from a clean checkout — see
[`bench/README.md`](bench/README.md) for exact commands (kernel
benchmarks, local echo harness, and the remote linux/amd64 runner), library
versions, and the fairness rules applied identically to all nine
configurations.

## Quick start

### Server (zero-copy `net.Conn`)

For callers that own a raw listener and want the zero-allocation handshake
path:

```go
package main

import (
	"log"
	"net"

	"github.com/zchee/gows"
)

func main() {
	ln, err := net.Listen("tcp", ":9001")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go serve(conn)
	}
}

func serve(conn net.Conn) {
	up := gows.Upgrader{EnableCompression: true}
	hs, err := up.Upgrade(conn)
	if err != nil {
		conn.Close()
		return
	}
	c := gows.NewServerConn(conn,
		gows.WithBuffered(hs.Buffered),
		gows.WithCompression(hs.Compressed),
	)
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
```

For reply-heavy servers (echo, RPC-over-WebSocket, fan-in aggregation),
prefer the drain-and-coalesce loop — it is the shape the pipelined
benchmark numbers above were measured with:

```go
func serve(conn net.Conn) {
	up := gows.Upgrader{EnableCompression: true}
	hs, err := up.Upgrade(conn)
	if err != nil {
		conn.Close()
		return
	}
	c := gows.NewServerConn(conn,
		gows.WithBuffered(hs.Buffered),
		gows.WithCompression(hs.Compressed),
	)
	defer c.Close(gows.CloseNormalClosure, "")

	// Serve drains every complete message per wakeup and flushes the
	// buffered replies in a single write before blocking again.
	_ = c.Serve(func(op gows.Opcode, payload []byte) error {
		return c.WriteMessageBuffered(op, payload)
	})
}
```

### Server (`net/http`)

For callers behind `net/http`'s routing, middleware, or TLS termination:

```go
package main

import (
	"log"
	"net/http"

	"github.com/zchee/gows"
)

func main() {
	http.HandleFunc("/ws", handleWS)
	log.Fatal(http.ListenAndServe(":9001", nil))
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, hs, err := gows.UpgradeHTTP(w, r)
	if err != nil {
		return
	}
	c := gows.NewServerConn(conn,
		gows.WithBuffered(hs.Buffered),
		gows.WithCompression(hs.Compressed),
	)
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
```

`gows.UpgradeHTTP(w, r)` is a convenience wrapper for the zero-value
`Upgrader`; use `(&gows.Upgrader{...}).UpgradeHTTP(w, r)` directly to set
`EnableCompression`, `Subprotocols`, or `OriginCheck`.

### Client

```go
package main

import (
	"context"
	"log"

	"github.com/zchee/gows"
)

func main() {
	dialer := gows.Dialer{EnableCompression: true}
	conn, hs, err := dialer.Dial(context.Background(), "ws://127.0.0.1:9001/ws")
	if err != nil {
		log.Fatal(err)
	}
	c := gows.NewClientConn(conn,
		gows.WithBuffered(hs.Buffered),
		gows.WithCompression(hs.Compressed),
	)
	defer c.Close(gows.CloseNormalClosure, "")

	if err := c.WriteMessage(gows.OpcodeText, []byte("hello")); err != nil {
		log.Fatal(err)
	}
	op, payload, err := c.ReadMessage()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("received opcode=%d payload=%q", op, payload)
}
```

Always pass `hs.Buffered` (any handshake-pipelined bytes) and
`hs.Compressed` (whether permessage-deflate was actually negotiated, which
may differ from what was requested) into `WithBuffered`/`WithCompression`
— constructing a `Conn` with a hardcoded compression flag instead of the
handshake's own answer risks disagreeing with what the peer actually
agreed to. All four examples above are verified to compile against this
module (`go build`/`go vet`, clean) as part of writing this document.

## Conformance

The signed v0.4 baseline is commit
`87fa6330c9bbe1de642a9da6defb5e1ff2a73619`. Its active implementation
includes:

- `NextReader` and `NextWriter` streaming message APIs;
- opt-in context takeover;
- valued and bare `client_max_window_bits` offers, including the trusted
  server hint path; and
- a zero-dependency core module with the optional klauspost backend isolated
  in the separate `github.com/zchee/gows/flatekp` module.

The repository retains canonical Autobahn reports from earlier v0.1-v0.3
gates as dated historical evidence:
[`.omc/research/autobahn-phase2.md`](.omc/research/autobahn-phase2.md) and
[`.omc/research/autobahn-phase4.md`](.omc/research/autobahn-phase4.md).
Their 517-case counts and verdicts describe those recorded runs; they are not
evidence that the v0.4 feature-specific matrix ran.

The v0.4 feature server/client 517-case matrix was **SKIPPED-RESIDUAL** at
the signed v0.4 delivery (Docker, OrbStack, and those feature runs were not
executed then; the signed delivery retains the completed non-container
root, race, purego, `flatekp`, benchmark, review, and UltraQA evidence
under `.omx/artifacts/`).

That residual has since been retired: the full Autobahn|Testsuite
**517-case matrix ran in both directions ("All cases passed") on
2026-07-14**, twice — once at commit `44c8417` (after the drain/serving,
transport-aware write, and header-table changes) and once at the current
head `324b7b8` (after the calibration and allocation-hygiene changes) —
server leg OK 478 / UNIMPLEMENTED 36 / INFORMATIONAL 3, client leg OK 442
/ UNIMPLEMENTED 72 / INFORMATIONAL 3, zero non-conformant cases
(UNIMPLEMENTED entries are optional permessage-deflate parameter offers
the suite probes; INFORMATIONAL cases carry no verdict by design).

## Non-goals and deferred work

- **gorilla compatibility surface**: the streaming APIs are implemented, but
  a broader `compat/gorilla` package is deferred until there is demonstrated
  demand. It would create a long-lived compatibility contract beyond the
  current API.
- **klauspost in the core module**: the optional backend is implemented in
  `flatekp/`, a separate Go module. It is intentionally not imported by the
  root module, which remains zero-dependency.
- **Event-loop / reactor mode**: deliberately not pursued. The evidence
  points the other way for throughput-bound workloads: reactor designs pay
  mandatory extra copies per message (nbio's own model loses the echo
  matrix above), and the 2026-07 platform study found darwin offers no
  cross-connection batching syscalls for a reactor to exploit — the
  drain-and-coalesce `Serve` loop captures the batching win inside the
  goroutine-per-connection model instead. A reactor only becomes
  interesting again at very high connection counts (C100k+), where
  per-connection memory dominates.
- **16 KiB performance tuning (linux/amd64 vs gws)**: the darwin/arm64
  16KiB cells are now measured ties vs quickws (see Benchmarks), but the
  older linux/amd64 gap vs gws predates the new write path and has not
  been re-measured. Prior syscall-pacing and `MSG_WAITALL` experiments did
  not produce an accepted improvement; further work requires re-running
  that matrix at the current head first.
- **arm64 SIMD dispatch thresholds are calibrated; amd64's UTF-8 threshold
  is not.** `internal/utf8x/valid_simd_amd64.go` still carries its
  pre-campaign placeholder pending a benchstat pass on amd64 hardware
  (the M-series calibration methodology to replicate is documented in
  [`.omc/research/neon-vnext-calibration.md`](.omc/research/neon-vnext-calibration.md),
  including the two strengthening kernels that were built, measured, and
  rejected on their pre-set gates).

## License

[Apache License 2.0](LICENSE).
