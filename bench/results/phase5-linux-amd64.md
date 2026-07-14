# Phase 5 comparative benchmark — linux/amd64 (Sapphire Rapids 8481C, 44 vCPU)

Remote host: `debian-trixie-xslq.asia-northeast1-c.gaudiy-platform`. Verified
idle before the run: `uptime` load average 0.00/0.00/0.00, `pgrep` showed no
other go/build/benchmark processes. Server pinned to `taskset -c 0-19`,
`loadgen` to `taskset -c 22-41` (plan §8, disjoint CPU sets). `ulimit -n
65535` set once per remote session. Nothing else ran on the remote or
locally for the duration of this capture.

This is the **AC5 comparative dataset**: 9 configurations (`gorilla`,
`coder`, `gobwas`, `gws`, `quickws`, `fasthttp`, `nbio`, `gows`,
`gows-noutf8`) rotated one at a time, never concurrently, fresh server
process per run per library. Raw per-run `loadgen` output is under
`results/phase5-raw/<config>/<lib>/rep<N>.log`; `results/phase5-raw/_progress.log`
confirms all 99 runs (45 primary + 27 + 27 secondary) completed with **zero
failures**. This file is the raw numeric record backing the AC5 verdict
and analysis.

Each table's "msg/s spread" column is the min-max range across n reps, so a
row's real position relative to a close neighbor can be read directly
instead of trusting the median alone.

## Primary config (AC5 gate): 1KB payload, 1000 conns, 15s + 3s warmup, n=5

| lib | n | msg/s (median) | msg/s spread | MB/s | p50 | p90 | p99 | p999 | allocs/msg | total_alloc delta |
|---|---|---|---|---|---|---|---|---|---|---|
| gows | 5 | 974,627 | 969,621-978,748 | 1903.57 | 931.1µs | 1.748ms | 3.351ms | 6.727ms | 1.00 | 351,108,776 B |
| quickws | 5 | 972,038 | 968,890-979,505 | 1898.51 | 934.6µs | 1.754ms | 3.340ms | 6.682ms | 1.00 | 351,280,120 B |
| gows-noutf8 | 5 | 969,779 | 964,582-971,686 | 1894.10 | 936.2µs | 1.755ms | 3.365ms | 6.681ms | 1.00 | 349,424,392 B |
| gws | 5 | 964,603 | 959,690-971,444 | 1883.99 | 936.0µs | 1.764ms | 3.488ms | 6.810ms | 2.00 | 588,754,776 B |
| fasthttp | 5 | 794,148 | 788,481-795,132 | 1551.07 | 1.020ms | 2.592ms | 4.629ms | 7.132ms | 5.00 | 26,021,562,168 B |
| gorilla | 5 | 781,202 | 771,502-783,935 | 1525.79 | 1.023ms | 2.637ms | 4.946ms | 7.573ms | 6.01 | 25,956,087,256 B |
| coder | 5 | 670,114 | 668,459-670,675 | 1308.82 | 1.015ms | 3.634ms | 7.259ms | 12.368ms | 24.01 | 29,521,775,208 B |
| nbio | 5 | 634,932 | 630,168-641,494 | 1240.10 | 1.455ms | 2.063ms | 3.568ms | 5.889ms | 11.02 | 11,793,017,856 B |
| gobwas | 5 | 372,882 | 371,751-374,101 | 728.29 | 1.576ms | 4.977ms | 16.274ms | 25.692ms | 8.01 | 13,611,569,320 B |

(Sorted by median throughput, descending.)

**gows (validation ON) has the highest median throughput of all 9
configurations** — ahead of quickws by 0.27%, gws by 1.04%, and every
non-SIMD-masked library by 22%+. Its median p99 (3.351ms) is marginally
*higher* than quickws's (3.340ms, a 0.33% / ~11µs gap) — see
`phase5-results.md` for why this is very likely measurement noise rather
than a real effect (the two libraries' 5-sample p99 distributions overlap
substantially: gows spans 3.335-3.392ms, quickws spans 3.309-3.378ms) and
for the CPU profile evidence.

## Secondary: 16KB payload, 1000 conns, n=3 (reference, not AC5-gating)

| lib | n | msg/s (median) | msg/s spread | MB/s | p50 | p90 | p99 | p999 | allocs/msg | total_alloc delta |
|---|---|---|---|---|---|---|---|---|---|---|
| gws | 3 | 353,760 | 353,650-355,112 | 11055.01 | 1.280ms | 4.894ms | 34.853ms | 46.112ms | 2.00 | 247,218,072 B |
| quickws | 3 | 348,089 | 347,040-351,798 | 10877.79 | 1.256ms | 4.866ms | 35.532ms | 46.854ms | 1.08 | 136,791,664 B |
| gows | 3 | 345,027 | 344,551-345,113 | 10782.08 | 1.299ms | 5.006ms | 35.567ms | 47.101ms | 1.00 | 124,262,264 B |
| gows-noutf8 | 3 | 343,450 | 342,118-345,388 | 10732.82 | 1.337ms | 5.135ms | 35.273ms | 47.043ms | 1.00 | 123,692,304 B |
| gorilla | 3 | 191,286 | 191,073-192,511 | 5977.70 | 852.4µs | 7.375ms | 70.300ms | 113.301ms | 17.07 | 108,924,241,328 B |
| fasthttp | 3 | 181,065 | 180,345-182,812 | 5658.28 | 845.0µs | 9.590ms | 70.420ms | 113.899ms | 16.01 | 102,812,799,704 B |
| coder | 3 | 167,761 | 167,151-168,478 | 5242.52 | 1.126ms | 11.140ms | 73.273ms | 119.510ms | 61.03 | 99,647,368,896 B |
| nbio | 3 | 137,001 | 131,059-137,566 | 4281.27 | 7.128ms | 8.467ms | 11.091ms | 12.679ms | 14.58 | 96,073,023,216 B |
| gobwas | 3 | 91,924 | 91,757-92,029 | 2872.62 | 6.442ms | 27.859ms | 53.749ms | 76.937ms | 17.03 | 52,458,151,600 B |

At 16KB, `gows`'s throughput edge over `gorilla`/`fasthttp`/`coder`/`nbio`/`gobwas`
widens further (80%+), but it trails `gws` (-2.5%) and `quickws` (-0.9%)
here — a bigger, more consistent gap than at the primary config, consistent
with UTF-8 validation cost scaling with payload size (see
`phase5-results.md`). `gows-noutf8` still doesn't close the gap to `gws`,
so the gap isn't purely validation cost.

## Secondary: 1KB payload, 100 conns, n=3 (reference, not AC5-gating)

| lib | n | msg/s (median) | msg/s spread | MB/s | p50 | p90 | p99 | p999 | allocs/msg | total_alloc delta |
|---|---|---|---|---|---|---|---|---|---|---|
| gows | 3 | 592,021 | 585,401-595,799 | 1156.29 | 121.1µs | 316.7µs | 751.8µs | 1.795ms | 1.00 | 213,222,088 B |
| gows-noutf8 | 3 | 590,916 | 588,820-595,043 | 1154.13 | 121.2µs | 317.4µs | 755.2µs | 1.808ms | 1.00 | 212,819,040 B |
| gws | 3 | 586,111 | 583,926-588,184 | 1144.75 | 122.3µs | 320.4µs | 779.3µs | 1.811ms | 2.00 | 355,313,136 B |
| quickws | 3 | 584,771 | 581,734-590,539 | 1142.13 | 123.2µs | 320.8µs | 741.1µs | 1.812ms | 1.02 | 216,644,000 B |
| nbio | 3 | 529,380 | 527,969-530,266 | 1033.95 | 152.6µs | 326.5µs | 770.9µs | 1.738ms | 11.02 | 9,887,094,056 B |
| gorilla | 3 | 454,313 | 451,736-456,880 | 887.33 | 126.4µs | 476.1µs | 1.378ms | 1.959ms | 6.03 | 15,213,207,424 B |
| fasthttp | 3 | 450,576 | 447,646-453,049 | 880.03 | 125.9µs | 465.8µs | 1.365ms | 1.989ms | 5.00 | 14,763,665,208 B |
| coder | 3 | 415,308 | 414,364-415,862 | 811.15 | 116.1µs | 521.9µs | 2.353ms | 2.928ms | 24.00 | 18,291,640,304 B |
| gobwas | 3 | 353,041 | 352,493-354,007 | 689.53 | 118.3µs | 999.4µs | 1.606ms | 2.465ms | 8.00 | 12,881,471,992 B |

At 100 connections (below saturation of the 44-vCPU box), `gows` has both
the highest median throughput **and** the lowest median p99 of the SIMD-masked
top tier except `quickws`, which edges it out on p99 by 10.7µs (1.4%) despite
`gows` leading throughput by 1.2%. Same pattern as the primary config: `gows`
wins on throughput, is essentially tied with `quickws` on tail latency.

## Kernel benchmarks: masking, `-count=10`

`go test -run=NONE -bench=BenchmarkMask -benchmem -count=10 .`, raw:
`results/kernels-phase5-linux-amd64.txt` (306 lines). `BenchmarkMaskGows`
calls gows's real `internal/mask.Mask` dispatch (AVX2/AVX-512 on this CPU),
not a fixed kernel — the same code path `Conn.ReadMessage`/`WriteMessage`
use in production. Zero allocations across every kernel at every size.

| size | Gorilla | Coder | GWS | Gobwas | **Gows** | Gows vs next-best |
|---|---:|---:|---:|---:|---:|---:|
| 64B | 17.45ns | 4.767ns | 5.968ns | 8.614ns | 5.951ns | 0.80x (coder wins here) |
| 256B | 32.04ns | 15.39ns | 9.277ns | 21.10ns | 6.740ns | **1.38x** |
| 1KB | 96.12ns | 51.67ns | 31.67ns | 74.68ns | 11.57ns | **2.74x** |
| 4KB | 359.6ns | 196.8ns | 120.5ns | 298.8ns | 27.28ns | **4.42x** |
| 16KB | 1.387µs | 775.4ns | 484.2ns | 1.157µs | 98.55ns | **4.91x** |
| 64KB | 5.502µs | 3.101µs | 2.137µs | 4.593µs | 1.352µs | **1.58x** |

`gows`'s SIMD kernel wins decisively from 256B up (1.4x-4.9x over the
next-best of the four vendored kernels), confirming the arm64/NEON
calibration (documented in internal/mask's godocs) reproduces on
amd64/AVX2+AVX-512. The one exception is 64B, where `coder`'s plain scalar
loop is ~20% faster than `gows`'s dispatch — consistent with the
already-documented pattern (see the UTF-8 SIMD calibration doc) that a
vectorized kernel's fixed dispatch/setup cost isn't always worth it at the
very smallest sizes. 16KB is the per-kernel peak for `gows` (98.55ns, ± 7% —
the one benchmark in this run with meaningful variance); 64KB drops off
(1.352µs, up from what a straight-line extrapolation from 16KB would
predict), consistent with leaving cache residency, mirroring the same
plateau pattern already documented for the UTF-8 validator kernels.

## Rerun after read-path tuning: head-to-head, n=10

Validates an uncommitted `reader.go` read-path optimization (direct read
into `msgBuf`, chunked at `cap(rbuf)`) at the plan's benchstat n=10
standard. Only the closest competitors were rerun (interleaved
round-robin order, one rep of each lib per round, to decorrelate machine
drift); the other 5 libraries' n=5 numbers above stand. All 70 reps (40 +
30) passed with zero failures. Raw logs:
`results/phase5-raw/rerun/{primary,16KB-1000conns}/<lib>/rep<N>.log`;
this is the rerun after read-path tuning (n=10), and the overlap analysis
below is its verdict.

### Primary (1KB, 1000 conns), n=10

| lib | n | msg/s (median) | msg/s spread | p99 (median) | p99 spread |
|---|---|---:|---|---:|---|
| gows | 10 | 974,876 | 968,979-978,187 | 3.349ms | 3.325-3.385ms |
| gows-noutf8 | 10 | 971,830 | 959,513-972,918 | 3.364ms | — |
| quickws | 10 | 971,344 | 955,982-976,678 | 3.345ms | 3.307-3.485ms |
| gws | 10 | 966,857 | 957,453-971,269 | 3.476ms | — |

### 16KB, 1000 conns, n=10

| lib | n | msg/s (median) | msg/s spread |
|---|---|---:|---|
| gws | 10 | 352,132 | 350,906-354,452 |
| quickws | 10 | 349,610 | 346,410-351,007 |
| gows | 10 | 344,174 | 343,016-346,191 |

Compared to the n=3 pass above, every value moved by less than 0.5% —
**the tuning did not measurably change either config.** The 16KB gap
(gows trailing gws/quickws) is unchanged and, at n=10, shows zero overlap
between any pair of libraries' throughput ranges — a real, reproducible
gap, not noise. The primary config's p99 gap to quickws shrank from 0.33%
(n=5) to 0.10% (n=10) with fully overlapping sample distributions —
consistent with a statistical tie rather than a real effect either way.

## Final (loop 3, frozen tree): the numbers the README cites

Third and final measurement pass, on the shipping tree (frozen: single
uncapped `readDirect` + `MSG_WAITALL`-evaluation comment, counting test
removed — verified present/absent respectively immediately before this
run). This is the final (loop 3, frozen tree) session; the overlap
discussion and the strace re-sample methodology caveat accompany the
tables below. Raw logs:
`results/phase5-raw/final/{16KB-1000conns,primary}/<lib>/rep<N>.log` (50
reps, 0 failures) plus `results/phase5-raw/final/strace/`.

### 16KB, 1000 conns, n=10

| lib | msg/s (median) | spread | vs prior sessions |
|---|---:|---|---|
| gws | 353,332 | 351,446-354,563 | 352,132 (rerun) / 353,760 (original) |
| quickws | 349,030 | 346,417-350,103 | 349,610 / 348,089 |
| gows | 344,254 | 343,063-346,140 | 344,174 / 345,027 |

Gap to gws: -2.57%. Gap to quickws: -1.37%. Zero overlap between gows and
either competitor, third consecutive session confirming this. **Not moved
by the loop-3 tuning.**

### Primary (1KB, 1000 conns), n=10 — control

| lib | msg/s (median) | spread | p99 (median) | p99 spread |
|---|---:|---|---:|---|
| gows | 972,112 | 964,532-978,304 | 3.353ms | 3.319-3.396ms |
| quickws | 971,151 | 958,480-982,337 | 3.321ms | 3.301-3.551ms |

Throughput: 0.10% gap, fully overlapping ranges — a tie, as expected (1KB
never touches the tuned path). p99: quickws ahead by 0.95% this session
(vs 0.10% in the rerun, 0.33% originally) — directionally consistent
across all three sessions but the magnitude is not stable, and quickws's
own distribution has two high outliers (3.449ms, 3.551ms) pulling its
spread wide while its median stays low. Read as noisy, not a settled gap.

### strace re-sample (30s, gows only, outside timed runs)

1,824,751 `read` / 911,331 `writev` = **2.00 reads/msg**, down from the
earlier 10s sample's 5.02 — same code both times, no tree change between
samples. Flagged as a likely ptrace-overhead artifact (this sample
attached to far more threads and depressed throughput much further: 108.6k
msg/s and 375ms p99, vs the earlier sample's 125.4k/45.9ms) rather than a
real property of the code, because the unperturbed n=10 throughput above
shows **no corresponding improvement** — if gows were really achieving
2.00 reads/msg under real load it should track much closer to gws's
throughput, and it doesn't. The throughput numbers are the trustworthy
signal here, not the strace count.
