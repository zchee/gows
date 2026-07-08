# Echo harness baseline — linux/amd64 (Sapphire Rapids 8481C, 44 vCPU)

Remote host: `debian-trixie-xslq.asia-northeast1-c.gaudiy-platform`, via
`run-remote.sh`. Command per library:

```sh
ulimit -n 65535
taskset -c 0-19  /tmp/echoserver -lib <lib> -addr 127.0.0.1:9001 -debug-addr 127.0.0.1:9101 &
taskset -c 22-41 /tmp/loadgen -addr 127.0.0.1:9001 -debug-addr 127.0.0.1:9101 \
  -conns 1000 -payload 1024 -duration 15s -warmup 3s -rate 0
```

**Verified quiet before capture**: `uptime` and `pgrep -af 'go |echoserver|
loadgen'` were checked on the remote immediately before this run — 1-minute
load average 0.11–0.17 on 44 vCPUs, no other go/build/benchmark processes
running (a sibling teammate's remote calibration work had just finished; its
tail was visible as elevated 5/15-minute load averages, which is why this
run waited for the 1-minute average to settle before starting). Server and
client are additionally pinned to disjoint CPU sets (plan §8) so `loadgen`
never steals cycles from the process being measured.

This is the **canonical AC5 reference baseline** ahead of Phase 5 (when
`gows` itself joins the harness). A first capture was taken a few minutes
earlier, before this explicit quiet-check — cross-checking the two: every
library's throughput differs by ≤1.3% between the two runs, and allocs/msg
is identical to the reported precision in every case. That agreement means
the earlier capture was not meaningfully contaminated either, but this run
is the one to cite since it was explicitly verified quiet first.

| lib | msg/s | MB/s | p50 | p90 | p99 | p999 | server mallocs/msg | total_alloc delta |
|---|---|---|---|---|---|---|---|---|
| quickws | 977,409 | 1909.00 | 0.928ms | 1.737ms | 3.374ms | 7.069ms | 1.00 | 352,835,400 B |
| gws | 968,723 | 1892.04 | 0.932ms | 1.760ms | 3.466ms | 6.919ms | 2.00 | 590,490,784 B |
| fasthttp | 801,604 | 1565.63 | 1.006ms | 2.561ms | 4.730ms | 7.319ms | 5.00 | 26,265,163,376 B |
| gorilla | 783,720 | 1530.70 | 1.022ms | 2.605ms | 5.054ms | 7.438ms | 6.01 | 26,038,514,120 B |
| coder | 678,104 | 1324.42 | 1.010ms | 3.565ms | 6.995ms | 11.891ms | 24.01 | 29,873,433,176 B |
| nbio | 647,410 | 1264.47 | 1.425ms | 2.046ms | 3.551ms | 5.981ms | 11.02 | 12,022,774,736 B |
| gobwas | 379,919 | 742.03 | 1.226ms | 4.965ms | 17.722ms | 29.233ms | 8.01 | 13,868,875,320 B |

(Sorted by throughput, descending.)

## Observations

- At 1000 saturating connections on a verified-idle, dedicated 44-vCPU VM,
  quickws/gws (~970-980k msg/s) lead gorilla/fasthttp (~780-800k) by ~22%,
  which lead coder/nbio (~650-680k) by 20-27%. gobwas trails the field
  sharply (380k) — see the darwin/arm64 writeup and `bench/README.md` for
  why: this harness's gobwas server uses the library's plainest documented
  pattern with no explicit `bufio.Reader` wrapping the data-phase read,
  costing one extra syscall per message relative to every other library's
  internally buffered hijacked connection. gobwas's p99/p999 (17.7ms/29.2ms)
  are also the tail-latency outlier by a wide margin, consistent with that
  per-message syscall cost compounding under 1000-connection concurrency.
- Allocation ranking is stable across both platforms and both remote runs:
  quickws (1.00/msg) and gws (2.00/msg) allocate least; coder (24.01/msg)
  allocates most. This is now confirmed by three independent captures
  (darwin/arm64 local, linux/amd64 first remote pass, linux/amd64
  verified-quiet remote pass) — the strongest signal in this baseline.
