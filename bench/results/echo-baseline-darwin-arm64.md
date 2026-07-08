# Echo harness baseline — darwin/arm64 (Apple M3 Max, 16 logical CPUs)

Command per library (raw logs in `results/echo-raw/<lib>.{server,loadgen}.log`):

```sh
/tmp/echoserver -lib <lib> -addr 127.0.0.1:19001 -debug-addr 127.0.0.1:19101 &
/tmp/loadgen -addr 127.0.0.1:19001 -debug-addr 127.0.0.1:19101 \
  -conns 200 -payload 1024 -duration 15s -warmup 3s -rate 0
```

`-conns 200` (not the plan's linux 1000-conn target): local `ulimit -n` is
524288, so the connection count itself isn't fd-limited here; 200 was chosen
to keep the single-machine client+server+OS scheduling contention reasonable
for a darwin/arm64 sanity baseline. The plan's AC6 (darwin/arm64: "beat every
library on throughput") is a relative ranking check, which 200 conns already
exercises meaningfully; the 8481C linux/amd64 run (AC5, `run-remote.sh`) is
where the plan's absolute 1000-conn target applies.

**Caveat**: this machine had other concurrent OMC team-agent processes
running during this measurement window (a sibling teammate's `internal/mask`
work, editor/IDE processes). Load average was 11–20 on a 16-core machine.
Absolute numbers below should be read as a rough one-run baseline, not a
benchstat-gated result — re-run before using these to gate any AC.

| lib | msg/s | MB/s | p50 | p90 | p99 | p999 | server mallocs/msg | total_alloc delta |
|---|---|---|---|---|---|---|---|---|
| gorilla | 80,819 | 157.85 | 2.439ms | 2.718ms | 3.773ms | 7.667ms | 6.02 | 2,710,841,456 B |
| coder | 82,026 | 160.21 | 2.388ms | 2.688ms | 3.676ms | 7.865ms | 24.01 | 3,613,429,000 B |
| gobwas | 67,883 | 132.58 | 2.870ms | 3.388ms | 4.798ms | 11.533ms | 8.01 | 2,477,372,800 B |
| gws | 80,710 | 157.64 | 2.445ms | 2.680ms | 3.384ms | 9.943ms | 2.00 | 49,488,976 B |
| quickws | 81,955 | 160.07 | 2.413ms | 2.648ms | 3.248ms | 7.293ms | 1.17 | 34,600,664 B |
| fasthttp | 81,539 | 159.26 | 2.419ms | 2.696ms | 3.418ms | 7.209ms | 5.00 | 2,671,978,264 B |
| nbio | 78,751 | 153.81 | 2.496ms | 2.841ms | 3.230ms | 6.252ms | 11.15 | 1,702,917,920 B |

## Observations

- **Allocations**: `gws` (2.00/msg) and `quickws` (1.17/msg) allocate far
  less than the rest, consistent with plan §4.1's note that gws targets
  0 allocs/op reads and 1 alloc/op writes — the harness's echo path (message
  read + immediate same-size write) landing at ~1-2 matches that closely.
  `coder` (24.01/msg) is the highest; its `Read`/`Write` API returns/accepts
  plain `[]byte` but internally does more bookkeeping per call than the
  lower-level libraries in this configuration.
- **gobwas's throughput here is the lowest of the seven**, which looks
  surprising given the library's zero-copy/zero-alloc-upgrade reputation
  (plan §4.1/§4.2). The harness's gobwas server uses the exact pattern shown
  in gobwas's own package doc overview: `ln.Accept()` → `ws.Upgrade(conn)` →
  `wsutil.ReadClientData(conn)` / `wsutil.WriteServerMessage(conn, ...)` in a
  loop, with **no explicit `bufio.Reader` wrapping the data-phase reads**.
  gobwas deliberately leaves that choice to the caller (it is the "low-level,
  you decide" library per its own docs); the simplest idiomatic form used
  here does one syscall for the frame header and another for the payload per
  message, where gorilla/gws/quickws wrap the hijacked connection in a
  buffered reader internally. This is a real, faithfully-measured
  characteristic of the *plain* recommended API, not a harness bug — but it
  means gobwas's per-message-syscall-count is doing more raw work than its
  zero-copy-upgrade reputation might suggest, in this particular (small,
  1024B, unbuffered-read) configuration. Worth re-measuring with an
  explicit bufio-wrapped variant in Phase 5's comparative tuning pass if
  gobwas is to be represented at its best.
- All seven produced broadly similar p50 latency (~2.4–2.9ms) at 200
  saturating connections; the differentiators are firmly allocation count
  and (for gobwas here) raw throughput, not median latency.
