# bench

Cross-library WebSocket benchmark harness for the `gows` project. This is a
**separate Go module** (`github.com/zchee/gows/bench`) so the seven
comparison libraries never appear in the core `gows` module's dependency
graph (core stays zero-dependency; see plan ADR §3, AC9). `gows` itself now
joins this harness via `require github.com/zchee/gows v0.0.0` +
`replace github.com/zchee/gows => ../` — the local path replace means the
harness always measures the working tree, never a tagged release.

This directory implements plan `.omc/plans/2026-07-08-gows-fastest-websocket-plan.md`
§6 Phase 0 items 2–3 and the corresponding parts of §8 (methodology) and
AC4/AC5/AC6.

## Libraries compared

| Flag        | Module                              | Version | Server integration used |
|-------------|--------------------------------------|---------|--------------------------|
| `gorilla`   | github.com/gorilla/websocket         | v1.5.3  | net/http Hijack, `Upgrader.WriteBufferPool` enabled |
| `coder`     | github.com/coder/websocket           | v1.8.15 | net/http Hijack, `Accept`/`Read`/`Write` |
| `gobwas`    | github.com/gobwas/ws (+ wsutil)      | v1.4.0  | zero-copy raw `net.Conn` upgrade (no net/http) |
| `gws`       | github.com/lxzan/gws                 | v1.9.1  | `Event` callback API, `Server.Run` |
| `quickws`   | github.com/antlabs/quickws            | v0.2.2  | callback API over net/http Hijack |
| `fasthttp`  | github.com/fasthttp/websocket (+valyala/fasthttp v1.72.0) | v1.5.12 | `FastHTTPUpgrader` over `fasthttp.Server` |
| `nbio`      | github.com/lesismal/nbio              | v1.6.11 | `nbhttp` epoll/kqueue reactor engine |
| `gows`      | github.com/zchee/gows (this repo, via `replace => ../`) | working tree | zero-copy raw `net.Conn` upgrade (`gows.Upgrade` + `NewServerConn`), UTF-8 validation **on** (gows's default) |
| `gows-noutf8` | same as `gows` | working tree | identical, plus `WithSkipUTF8Validation(true)` — the harness's paired validation-OFF reference config |

**gofiber/contrib/websocket skipped.** The plan asked for "gofiber/contrib
v3 websocket" as an eighth entry. As of this writing gofiber/contrib's
`websocket` package (latest v1.3.4) has no v2/v3-suffixed module path and its
`go.mod` still requires `github.com/gofiber/fiber/v2`, not fiber v3 — there
is no released fiber-v3-compatible websocket contrib module to pull in.
Functionally it is confirmed to be a thin handler-registration wrapper around
`fasthttp/websocket` (same `Upgrader`/`Conn`, same mask code, same UTF-8
behavior — see plan §4.1), so it would not add a distinct performance data
point; it would only add fiber v2's dependency tree (testify, brotli, uuid,
etc.) for zero additional signal. Per the task's own instruction, it is
skipped and documented here instead of vendored.

## Fairness rules (plan §8)

Applied identically across every server implementation, verified by reading
each `harness/cmd/echoserver/server_*.go` file:

- **Read/write buffer size: 4096 bytes** wherever the library exposes the
  knob (`bufferSize` const in `harness/cmd/echoserver/main.go`).
  - `coder/websocket` exposes no read/write buffer size configuration at all
    (its `AcceptOptions` has no such field) — this is a real capability gap
    documented here, not an oversight.
  - `antlabs/quickws` sizes its internal bufio buffer relative to the
    observed payload size (`WithServerBufioMultipleTimesPayloadSize`) rather
    than as an absolute byte count, so no absolute 4096 setting exists to
    apply; left at the library default.
  - `gows` exposes `WithReadBufferSize` (set to 4096 here) but no separate
    write-buffer-size knob: writes go out via a direct scatter-gather
    `net.Buffers` write of the header plus the caller's payload, with no
    intermediate write buffer to size.
- **Compression: off** everywhere (`EnableCompression: false` / zero-value
  `PermessageDeflate` / `CompressionDisabled`, per library).
- **TCP_NODELAY**: left at each library/runtime's default, which is on for
  Go's `net` package (plan §4.2) and for fasthttp/nbio's socket setup.
- **No logging in the hot path.** `nbio`'s engine prints a handful of INFO
  lines at start/stop only (not per-message).
- **Each library's own recommended API is used**, including advantageous
  options the library's own docs recommend (e.g. gorilla/fasthttp's
  `WriteBufferPool`), per plan §8's explicit fairness allowance.
- **UTF-8 validation**: `gws` (`CheckUtf8Enabled`) and `quickws`
  (`WithServerEnableUTF8Check`) default to *off* in this harness, matching
  gorilla/coder/fasthttp/gobwas's default (non-)validation. `gows` is the
  one library in this harness where validation defaults *on*
  (`WithSkipUTF8Validation` is opt-out, not opt-in) — the plan's explicit
  differentiator (RFC 6455 §8.1 conformance by default) at the cost of
  doing work no other library here does by default. Both configs are
  published: `gows` (validation on, the AC5/AC6 gate per plan §13) and
  `gows-noutf8` (`WithSkipUTF8Validation(true)`, the reference "OFF" number
  published alongside it, matching every other library's default) — see
  plan §8's ON/OFF policy.

## Harness components

- `harness/support`: shared, non-hot-path utilities.
  - `payload.go`: `DeterministicPayload(n)` — xorshift64*-filled, fixed seed,
    reproducible across runs and processes.
  - `latency.go`: `Recorder` — reservoir sampling (Algorithm R) latency
    recorder bounded at 20,000 samples/connection so long high-rate runs
    don't grow memory unbounded; `ComputePercentiles` returns p50/p90/p99/p999.
  - `memstats.go`: `StartDebugServer` exposes `GET /debug/memstats` (JSON
    `runtime.MemStats` subset) on a separate debug listener, polled by
    `loadgen` only before/after the measurement window — never on the
    message hot path.
- `harness/cmd/echoserver`: `-lib {gorilla|coder|gobwas|gws|quickws|fasthttp|nbio|gows|gows-noutf8} -addr :9001 -debug-addr :9101`.
  Plain binary echo: read one message, write the same opcode + payload back.
- `harness/cmd/loadgen`: `-addr host:port -debug-addr host:port -conns N -payload BYTES -inflight K -duration DUR -warmup DUR -rate N`.
  Drives load using **gobwas/ws's low-level client API** (`ws.Dial` +
  `wsutil.WriteClientMessage`/`wsutil.ReadServerData`) against every server
  under test, so the client side of every comparison is identical. `-rate 0`
  (default) saturates: each connection is a closed request/response loop
  (send, wait for echo, send again) with no artificial throttling; `-rate N`
  spreads a target aggregate messages/sec across all connections via a
  per-connection ticker. `-inflight K` (default 1) keeps K messages
  outstanding per connection: K=1 is the closed loop above; K>1 pipelines by
  splitting each connection's synchronous gobwas read and write onto two
  goroutines (a writer that keeps the window primed and a reader that drains
  and verifies echoes), so the writer never wedges on a full socket buffer
  while echoes go unread — a single interleaved goroutine could deadlock there
  once K*payload exceeds the buffers. Latency is timed from the instant a
  message is handed to the send path; under saturation that equals the
  intended send time, so there is no coordinated-omission correction to make.
  Every echo is verified byte-for-byte against the deterministic payload and a
  mismatch aborts the run. K*payload is capped at 1 MiB, and `-rate` with
  K>1 is rejected (open-loop pacing and pipelining measure different things).
- `internal/thirdparty/{gorilla,coder,gws,gobwas}`: minimal vendored copies
  of each library's unexported (or, for gobwas, exported-but-otherwise-
  identical) masking kernel, used only by `kernels_test.go`. Vendored rather
  than `go:linkname`'d for build stability across upstream internal
  refactors; each file's doc comment names its exact source file, version,
  and license (gorilla BSD-2-Clause, coder ISC, gws Apache-2.0, gobwas MIT).
  These files are intentionally left byte-faithful to upstream — including
  patterns `modernize`/lint would otherwise flag — because the whole point
  is to benchmark exactly what each library ships today.
- `kernels_test.go`: `BenchmarkMask{Gorilla,Coder,GWS,Gobwas}` at sizes
  `{64B,256B,1KB,4KB,16KB,64KB}` using `b.Loop()` + `b.SetBytes`.

## How to run

### Kernel benchmarks (any machine)

```sh
cd bench
go test -run=NONE -bench=BenchmarkMask -benchmem -count=10 . | tee results/kernels-baseline-<goos>-<goarch>.txt
# Compare two runs (e.g. before/after a gows kernel lands) with benchstat:
go run golang.org/x/perf/cmd/benchstat@latest old.txt new.txt
```

Do not run kernel benchmarks in parallel with anything else on the machine
(user Absolute Rule — benchmarks competing for CPU invalidate results). A
single `go test -bench` invocation is already serial across subtests.

### Echo harness (local)

```sh
cd bench
go build -o /tmp/echoserver ./harness/cmd/echoserver
go build -o /tmp/loadgen ./harness/cmd/loadgen

/tmp/echoserver -lib gorilla -addr 127.0.0.1:9001 -debug-addr 127.0.0.1:9101 &
/tmp/loadgen -addr 127.0.0.1:9001 -debug-addr 127.0.0.1:9101 \
  -conns 200 -payload 1024 -duration 15s -warmup 3s -rate 0
kill %1
```

Repeat per `-lib` value. `loadgen` polls `/debug/memstats` once right before
the measurement window starts (after warmup) and once right after it ends,
and reports the delta — this is the "server allocs" figure in the results
table, not a per-request instrumentation hook.

### Remote (linux/amd64, e.g. 8481C)

```sh
./run-remote.sh debian-trixie-xslq.asia-northeast1-c.gaudiy-platform
```

It tars the repo to the remote host (excluding `bench/results`, which is
recreated empty remotely so nothing tries to write into a missing
directory), runs the kernel benchmarks and the full 7-library echo harness
there with the remote's Go toolchain (absolute path — bare `go` does not
resolve over non-interactive ssh), pins `echoserver`/`loadgen` to disjoint
`taskset` CPU sets (plan §8), raises the remote shell's `ulimit -n` to
65535 for the 1000-conn runs (fd limits don't persist across separate ssh
invocations, so this is set once at the top of the combined per-library
remote command rather than per-binary), and pulls `results/` back via
tar-over-ssh (not `scp`: its SFTP-protocol mode doesn't reliably glob a
remote path built from a literal `"$HOME"` token — this was hit and fixed
during the first real run against the 8481C).

Already executed once against the 8481C — see
`results/kernels-baseline-linux-amd64.txt` and
`results/echo-baseline-linux-amd64.md` for the resulting baseline, and
`.omc/research/baseline-arm64.md` for the cross-platform summary.

## Known caveats

- `coder/websocket`'s `Server` shutdown on this harness relies on process
  termination for `gws` and `nbio`-style engines that don't expose a
  context-cancelable `Run`; `echoserver` handles `SIGINT`/`SIGTERM` for the
  net/http- and fasthttp-based servers (gorilla, coder, gobwas, quickws,
  fasthttp) but `gws.Server.Run` and `nbio`'s `Engine.Stop` are invoked from
  a signal-driven goroutine that returns once the process is asked to exit;
  in practice each `-lib` run is a fresh process killed after measurement,
  so this has no effect on the numbers.
- `loadgen`'s allocation counters are proxies: "allocs/msg" divides the
  server's `runtime.MemStats.Mallocs` delta by the client's *sent* message
  count for the window, since echo semantics make sent == received.
- Local darwin/arm64 runs use whatever `ulimit -n` the shell already has;
  this machine's default (524288) comfortably covers `-conns 200` with room
  to scale to the plan's 1k/10k linux targets without change.

## Paired verdict runner (`benchrun` / `benchcmp`)

`benchrun` and `benchcmp` turn a candidate-vs-comparator comparison into a
machine-checkable verdict: `benchrun` executes a policy's scenario matrix
under strict host hygiene and records raw samples; `benchcmp` pairs those
samples, computes deterministic median-bootstrap confidence intervals, applies
the policy's gate thresholds, and writes `verdict.json`. `loadgen -json`
emits one JSON result line (the fixed-schema `LoadgenResult`: message count,
window durations, throughput, p50/p90/p99/p999 ns, error count, and the
client's own `getrusage(RUSAGE_SELF)` CPU seconds and peak RSS), which
`benchrun` consumes; the human summary is unchanged when `-json` is absent.

### Policy schema (`harness/policy`)

A policy is JSON with Go duration strings for the windows. The canonical
darwin/arm64 policy is `harness/policy/darwin-arm64.json` (five primary cells:
`binary-64b-1k`, `binary-1k-200`, `binary-1k-1k`, `binary-16k-200`,
`binary-16k-1k`; all warmup `5s`, duration `30s`, 20 repetitions) plus two
non-primary experimental cells that exercise the pipelined client
(`binary-1k-200-inflight8` at inflight 8, `binary-1k-1k-inflight4` at
inflight 4). Each scenario carries an `inflight` window (>= 1) that `benchrun`
passes to `loadgen`; the schema rejects `inflight < 1` and any
`inflight*payload_bytes` above the 1 MiB pipeline cap. Primary cells gate the
verdict; non-primary cells are evaluated and reported in `verdict.json` for
context but never flip the pass/fail decision or the throughput geomean.

```json
{
  "candidate": "gows",
  "comparator": "quickws",
  "seed": 12648430,
  "bootstrap": {"replicates": 20000, "confidence": 0.95},
  "thresholds": {
    "throughput_lower_bound": 1.0,
    "throughput_geomean": 1.05,
    "p99_upper_bound": 1.01,
    "p999_center_upper_bound": 1.05
  },
  "guard": {"max_load1": 6.0, "forbidden_process_patterns": ["echoserver", "loadgen"]},
  "scenarios": [
    {"name": "binary-1k-200", "primary": true, "payload_bytes": 1024,
     "connections": 200, "inflight": 1, "warmup": "5s", "duration": "30s",
     "repetitions": 20}
  ]
}
```

### Running

```sh
cd bench
go build -o /tmp/benchrun ./harness/cmd/benchrun
go build -o /tmp/benchcmp ./harness/cmd/benchcmp

# Full run (writes results/v-next/darwin-arm64/claude-run-<UTCstamp>-<gitshort>).
/tmp/benchrun -policy harness/policy/darwin-arm64.json
# End-to-end sanity pass (warmup 1s / measure 3s / 2 reps per cell).
/tmp/benchrun -policy harness/policy/darwin-arm64.json -smoke -out /tmp/smoke

/tmp/benchcmp -run /tmp/smoke   # exit 0 pass, 1 gate failure, 2 usage/data error
```

`benchrun` builds its own `echoserver`/`loadgen` binaries into the run
directory with `-mod=mod` (so the working-tree `gows` is linked, not the
vendored snapshot), copies the policy in, and records provenance
(`meta.json`), before/after environment snapshots (`env-start.json` /
`env-end.json`: load averages, power via `pmset -g batt`, thermal/throttle
state via `pmset -g therm`, logical CPU count, memory bytes), one line per
(scenario, library, repetition) in `samples.jsonl`, and a `done.json`
completion marker. Execution is paired and
seeded: for each repetition the candidate/comparator order is shuffled with a
`math/rand/v2` PCG seeded from `policy.seed`, each library gets a fresh
`echoserver` child process, and the two ports alternate off a base (19301) to
dodge TIME_WAIT. Any child or JSON-parse failure is written to `errors.log`
and aborts the run (non-zero exit) — never a silent skip.

### Host-guard behavior

Before spawning anything, `benchrun` enforces three preconditions and aborts
(non-zero exit, clear message) on any of them:

- **Load average**: `sysctl -n vm.loadavg` `load1` must not exceed
  `guard.max_load1`.
- **Foreign processes**: `pgrep -fl` must not match any
  `guard.forbidden_process_patterns` (benchrun's own pid is excluded; the
  check runs before its children exist).
- **Exclusive lock**: `/tmp/gows-benchrun.lock` is created `O_CREATE|O_EXCL`
  with benchrun's pid. A live holder aborts; a stale lock (dead pid) is
  removed and retried once. The lock is released on exit, including on
  `SIGINT`/`SIGTERM`.

### Measurement rule: no `net.Conn` wrapper on gating paths

All resource accounting (CPU seconds, peak RSS) comes **only** from process
rusage — never from wrapping `net.Conn` to count bytes or messages on a path
that feeds a gate. The server figures come from `benchrun` reading the
echoserver child's `os.ProcessState.SysUsage().(*syscall.Rusage)` after
SIGTERM; the client figures come from `loadgen`'s own
`getrusage(RUSAGE_SELF)`, emitted in its `-json` line. Per-message and
per-connection figures in `samples.jsonl` (`server_cpu_seconds_per_message`,
`server_rss_bytes_per_connection`, `client_cpu_seconds_per_message`) are
derived from that rusage plus the loadgen-reported message count. On darwin
`Rusage.Maxrss` is already bytes.

### Verdict and gates (`harness/paired`, `benchcmp`)

For each primary scenario `benchcmp` pairs candidate repetition *i* with
comparator repetition *i* (equal counts required) and forms candidate/
comparator ratios. `Bootstrap` resamples the ratio set with replacement, takes
the **median** as the statistic, and reports the `(1-confidence)/2` percentile
interval — fully deterministic for a given seed. Gates (all must hold to pass):

- every primary scenario throughput CI lower bound `> throughput_lower_bound`;
- geomean of the primary throughput centers `>= throughput_geomean`;
- every primary p99 CI upper bound `<= p99_upper_bound`;
- every primary p999 center `<= p999_center_upper_bound`.

`verdict.json` records `pass`, the throughput `geomean`, per-scenario centers/
intervals/gate outcomes, the resource ratio centers, the thresholds, and the
`policy_sha256`. A `-smoke` run (short windows, 2 reps) is sanity evidence
only — never a gating measurement.
