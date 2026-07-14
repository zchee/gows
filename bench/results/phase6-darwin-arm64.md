# AC6 comparative benchmark — darwin/arm64 (Apple M3 Max, 16 logical CPUs)

Local machine, no `taskset` (not meaningful on darwin without a
CPU-affinity API the harness uses; team-lead confirmed this run gets no
pinning, matching the earlier darwin baseline's methodology). Command per
library:

```sh
/tmp/echoserver-darwin -lib <lib> -addr 127.0.0.1:19001 -debug-addr 127.0.0.1:19101 &
/tmp/loadgen-darwin -addr 127.0.0.1:19001 -debug-addr 127.0.0.1:19101 \
  -conns 200 -payload 1024 -duration 15s -warmup 3s -rate 0
```

`-conns 200` matches the original darwin baseline's documented choice
(`local ulimit -n` is 524288, not fd-limited; 200 keeps single-machine
client+server+OS scheduling contention reasonable — the plan's absolute
1000-conn target is the linux/amd64 AC5 run's job, not AC6's). All 9
configs (`gorilla`, `coder`, `gobwas`, `gws`, `quickws`, `fasthttp`,
`nbio`, `gows`, `gows-noutf8`) rotated one at a time, **never
concurrently**, fresh server process per run per library, **interleaved
round-robin order per round** (one rep of each config per round, 5 rounds
— not 5 reps of one config back to back) to decorrelate desktop-load
drift from library identity. All 45 reps completed with zero failures
(`results/phase5-raw/darwin-final/_progress.log`).

**Machine load**: `uptime` immediately before the run showed load averages
5.23/6.08/6.10 on a 16-logical-CPU machine — normal desktop baseline
(Chrome, IDE/editor helpers, a couple of other Claude Code sessions), not
a fully idle machine, but substantially quieter than the original darwin
baseline's documented 11-20 load average during a sibling teammate's
concurrent work. No other benchmark of any kind ran during this window.
**This is a laptop, not a dedicated benchmark box: spreads are
correspondingly wider than the linux/amd64 8481C runs, and medians (not
single-run point estimates) are the only numbers that should be cited.**

## Results (n=5, sorted by median throughput, descending)

| lib | msg/s (median) | msg/s spread | MB/s | p50 | p90 | p99 | p999 | allocs/msg | total_alloc delta |
|---|---:|---|---:|---|---|---|---|---:|---|
| quickws | 80,801 | 80,135-80,825 | 157.81 | 2.435ms | 2.779ms | 3.060ms | 3.923ms | 1.19 | 34,623,536 B |
| gows | 80,643 | 80,141-80,741 | 157.51 | 2.435ms | 2.785ms | 3.056ms | 3.795ms | 1.00 | 29,059,352 B |
| fasthttp | 80,610 | 79,594-80,983 | 157.44 | 2.429ms | 2.801ms | 3.123ms | 4.117ms | 5.00 | 2,641,459,176 B |
| gws | 80,569 | 80,110-80,718 | 157.36 | 2.436ms | 2.786ms | 3.075ms | 3.976ms | 2.00 | 49,198,136 B |
| gows-noutf8 | 80,567 | 80,139-81,057 | 157.36 | 2.435ms | 2.772ms | 3.057ms | 3.847ms | 1.00 | 29,040,352 B |
| gorilla | 80,471 | 79,183-80,819 | 157.17 | 2.438ms | 2.803ms | 3.166ms | 4.105ms | 6.02 | 2,694,740,632 B |
| coder | 80,355 | 79,522-80,404 | 156.94 | 2.447ms | 2.790ms | 3.492ms | 4.569ms | 24.01 | 3,539,759,936 B |
| nbio | 79,934 | 79,171-80,073 | 156.12 | 2.440ms | 2.875ms | 3.278ms | 3.712ms | 11.16 | 1,746,879,688 B |
| gobwas | 67,721 | 66,283-67,874 | 132.27 | 2.878ms | 3.460ms | 4.610ms | 5.928ms | 8.01 | 2,471,379,040 B |

## AC6 verdict: gows (validation ON) throughput ≥ all 8 others?

**No — narrowly, against one library (quickws), by 0.20%, with fully
overlapping sample distributions.** gows beats fasthttp, gws,
gows-noutf8, gorilla, coder, nbio (by 0.04%-0.89%) and gobwas by a wide
margin (19.1%), passing 7 of 8. Against quickws specifically:

- **Throughput**: gows [80,141, 80,389, 80,643, 80,735, 80,741] msg/s
  (median 80,643) vs quickws [80,135, 80,600, 80,801, 80,817, 80,825]
  msg/s (median 80,801) — quickws ahead by 0.20%. The two ranges overlap
  almost completely (gows's minimum, 80,141, sits below quickws's minimum,
  80,135, by only 6 msg/s; gows's second-lowest sample, 80,389, is the
  only one of either set clearly separated from the rest).
- **p99**: gows [3.040, 3.051, 3.056, 3.058, 3.112] ms (median 3.056ms) vs
  quickws [3.040, 3.054, 3.060, 3.097, 3.097] ms (median 3.060ms) — **gows
  is actually ahead here**, by 0.14%, also fully overlapping.

**This is the same pattern documented for the linux/amd64 AC5 run**:
gows and quickws are close enough, at every metric measured across both
platforms, that whichever one is "ahead" in a given n=5/n=10 sample
depends on which metric and which run — not a stable, reproducible
architectural gap in either direction. Read literally: AC6's throughput
comparison is not met at the strict letter (one library, one metric,
0.20%, indistinguishable from noise at n=5); every other comparison in
this table — 7 of 8 libraries on throughput, and quickws itself on p99 —
passes.

## Allocations

Same ranking as every prior platform/session: `gows`/`gows-noutf8` at
1.00/msg (tied lowest with `quickws`'s 1.19), `gws` at 2.00, `coder`
highest at 24.01. Consistent with the darwin baseline, the linux/amd64
AC5 runs, and plan §4.1's characterization of each library's allocation
profile — this ranking has now held across three platforms/host
combinations without a single reversal.

Kernel benches were not re-run for this task: the NEON masking-kernel
numbers are already recorded in
`bench/results/kernels-baseline-darwin-arm64.txt`, and this task's read
path is unrelated to the masking kernel.

Raw logs: `results/phase5-raw/darwin-final/<lib>/rep<N>.log` (45 reps, 0
failures per `_progress.log`).
