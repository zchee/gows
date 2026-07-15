# bench

`bench` is the separate benchmark module for `gows`. Comparison libraries and
the HDR histogram dependency remain outside the root module's production
dependency graph. The local replacement
`github.com/zchee/gows => ../` makes every benchmark binary bind to the exact
repository source recorded in its manifest.

This document describes the Phase 0 benchmark-truth harness. It does not make a
current `gows`-versus-`quickws` superiority claim. A current result is valid
only when the tracked receipt under `evidence/phase0/current` resolves every
immutable artifact and the fixed evaluator exits zero.

## Evidence classes

Policy schema version 3 makes purpose and interpretation part of the run
identity. Samples use schema version 2, and load-generator results embedded in
them use schema version 5. Unknown fields, versionless policies, and older
schemas are rejected rather than upgraded implicitly.

<!-- markdownlint-disable MD013 -->

| Run kind | Evidence class | Host mode | Interpretation |
| --- | --- | --- | --- |
| `diagnostic` | `diagnostic` | `same_host` | Smoke, debugging, and screening only; never promotable |
| `aa` | `self_validation` | `same_host` | Same-binary A/A validation of the host and harness |
| `baseline` | `baseline` | `same_host` | Current implementation measurement; record-only in Phase 0 |
| `baseline` | `claim` | `separate_host` | A future public-claim class; not produced by the Phase 0 baseline |

<!-- markdownlint-enable MD013 -->

`stock` and custom `GOEXPERIMENT` series have different artifact roots and
identities. The Phase 0 A/A and current baseline are stock-Go evidence.
Validation-off configurations are diagnostic only; strict evidence uses
`strict_on`.

## Compared libraries and benchmark-only dependencies

The version column below is the current `bench/go.mod` module graph. Verify it
instead of copying this table into a report:

```sh
GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$(go env GOROOT)/bin/go" -C bench list -m -f \
  '{{if not .Main}}{{.Path}} {{.Version}}{{end}}' all
```

<!-- markdownlint-disable MD013 -->

<!-- BEGIN GENERATED: module-metadata -->
| Harness role | Module | Version | Integration |
| --- | --- | ---: | --- |
| `latency histogram` | `github.com/HdrHistogram/hdrhistogram-go` | `v1.3.0` | mergeable HDR observations (MIT) |
| `gorilla` | `github.com/gorilla/websocket` | `v1.5.3` | `net/http` upgrader |
| `coder` | `github.com/coder/websocket` | `v1.8.15` | `Accept` / `Read` / `Write` |
| `gobwas` | `github.com/gobwas/ws` | `v1.4.0` | raw `net.Conn` upgrade |
| `gws` | `github.com/lxzan/gws` | `v1.10.0` | callback server API |
| `quickws` | `github.com/antlabs/quickws` | `v0.2.2` | callback API over `net/http` hijack |
| `fasthttp` | `github.com/fasthttp/websocket` | `v1.5.12` | `fasthttp` upgrader (`fasthttp v1.72.0`) |
| `nbio` | `github.com/lesismal/nbio` | `v1.6.12` | `nbhttp` reactor engine |
| `gows` / `gows-serve` | `github.com/zchee/gows` | `working tree` | raw upgrade / drain-and-coalesce server |
<!-- END GENERATED: module-metadata -->

<!-- markdownlint-enable MD013 -->

The HDRHistogram module listed in the generated table is benchmark-only. It is
MIT-licensed and is used by `harness/support` because
mergeable histograms preserve every recorded message across connections and
make bounds, bucket counts, drops, and overflow auditable. Confirm the graph
edge with:

```sh
GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$(go env GOROOT)/bin/go" -C bench mod why \
  github.com/HdrHistogram/hdrhistogram-go
```

## Comparator and client contract

The policy identifies the adapter class, validation profile, and client; they
cannot be substituted after a run.

<!-- markdownlint-disable MD013 -->

| Series | Purpose | Required behavior |
| --- | --- | --- |
| `best_api` | Compare each server through its intended high-performance API | Same wire semantics and hard error accounting |
| `semantic_parity` | Hold callback/reply behavior as close as practical | Separate policy and adapter hashes |
| `gows` client | Canonical baseline client | Same client binary for both servers in a pair |
| `gobwas` client | Independent-client check | Separate baseline role and receipt |
| `raw` client | Minimal independent RFC 6455 check | Separate baseline role and receipt |

<!-- markdownlint-enable MD013 -->

The Phase 0 strict adapter explicitly enables quickws UTF-8 checking with
`WithServerEnableUTF8Check`. A quickws callback write failure is reported to
the server runner, closes the connection, and terminates the server; it is not
silently discarded. Protocol errors, I/O errors, payload mismatches, rejected
messages, dropped messages, queue overflow, and histogram loss are hard
measurement failures for every client and server.

Validation-off `gows-noutf8` data may be useful diagnostically, but it is not a
strict Phase 0 baseline or headline series.

## Harness components

### `benchrun`

`harness/cmd/benchrun` executes a strict policy and creates a new immutable run
directory. It:

- rejects dirty final runs, unknown or changed source identity, mixed
  toolchains, unrecorded binaries, and policy/adapter hash drift;
- builds with a controlled toolchain environment (`GOENV=off`,
  `GOTOOLCHAIN=local`, `GOFLAGS=-mod=mod`, `GOFIPS140=latest`,
  `GOWORK=off`, stock or policy-declared `GOEXPERIMENT`, `CGO_ENABLED=0`)
  and records binary SHA-256 plus
  `go version -m`;
- records Git remote/branch/HEAD/tree/status, `go env -json`,
  `go list -m -json all`, module-file hashes, OS/kernel, CPU/system profile,
  limits, runtime settings, host boot identity, uptime, load, power, and
  thermal state in `manifest.json` and provenance files;
- generates deterministic balanced AB/BA blocks and records `session_id`,
  `block_id`, order, binary hash, policy hash, and adapter hash in every
  schema-v2 sample;
- continuously guards the host and immutable binaries during a measurement;
  source drift, reboot, thermal/power/load drift, or competing work aborts the
  run. Final Phase 0 policies cap aggregate foreign `ps %CPU` at 75% of one
  logical CPU: normal multi-core macOS housekeeping remains admissible, while
  a sustained competing build or benchmark still invalidates the run; and
- writes `INVALIDATED.json` after any post-directory failure. An invalidated
  run can never be sealed or evaluated.

Run directories are never overwritten or implicitly resumed. Diagnostic,
self-validation, baseline, stock, and custom series are separated below
`.omx/bench`.

### `loadgen` and observation accounting

`harness/cmd/loadgen` supports `gows`, `gobwas`, and independent `raw` clients;
binary or Text messages; and `closed_loop`, `pipelined`, and `open_loop`
arrival contracts.

Open loop schedules against intended arrival time rather than a lossy ticker.
Every policy preregisters `max_scheduler_lateness`, no greater than one arrival
interval. A late scheduler rejects missed slots and any over-limit current slot
instead of replaying them as a catch-up burst. Queue rejection remains a
separate counter. A queued exchange whose worker does not start before the
measurement boundary is a post-window drop and a hard failure. An exchange
that did start before the boundary may complete successfully during the
bounded drain; the drain duration is recorded, and its valid response remains
an achieved latency observation. A drain timeout or I/O error is a hard
failure.

The result records the exact scheduled offered count, requested/offered/
achieved/rejected rates, scheduler-late messages, maximum and allowed scheduler
lateness, queue overflow, post-window messages, drops, drain duration, and
scheduled-start response-time correction independently. Overload is never
relabeled as success.

Latency uses mergeable HDR histograms, not a per-connection reservoir. The raw
and coordinated-omission-corrected histograms contain their geometry, bucket
counts, and `seen`/`recorded`/`dropped`/`overflow` counters. Merging preserves
message weighting rather than weighting each connection equally. The p50,
p90, p99, and p999 summaries must reconstruct exactly from the corrected
histogram.

Server and client allocation snapshots carry raw before/after deltas and an
independent control-window observation overhead. Allocations/message and
bytes/message use the raw, observer-inclusive delta as a conservative upper
bound; the stochastic control observation is never subtracted per sample or
clamped into a false zero. Process CPU and peak RSS come from OS-specific
`rusage` collectors; MaxRSS is normalized to bytes and unavailable data is
represented as unavailable, never as a fabricated zero. Microbenchmark
`0 alloc/op` and macro allocation rate are distinct contracts.

### Immutable artifacts and tracked receipts

Successful runs are sealed into the content-addressed store at
`.omx/artifacts`. Every reference has the form
`omx-cas://sha256/<digest>` and carries its SHA-256, size, and media type.
Run receipts bind the exact source tree, module files, Go tool, policy,
adapters, client, binaries, samples, histograms, logs, and provenance files.
Assembly and verification directories use equally strict directory receipts.

Raw artifacts are intentionally not copied into Git. The compact tracked
`evidence/phase0/current/receipt.json` is the only root the evaluator follows;
it never scans legacy `bench/results`, old `.omx`/`.omc` trees, or unrelated
CAS objects. A missing store, missing blob, digest mismatch, symlink,
`INVALIDATED.json`, non-ancestor source, dirty current tree, unknown JSON
field, or identity mismatch fails closed. Historical/versionless evidence is
not silently promoted.

The generated Phase 0 verdict contains no timestamp. The same tracked receipt,
raw bytes, policy, and seed must regenerate byte-identical `verdict.json`.

### Assembly provenance

`harness/cmd/asmprobe` supports only the Phase 0 production targets:
`amd64` and `arm64`. For each target its bundle records the controlled stock
toolchain, target baseline (`GOAMD64=v1` or `GOARM64=v8.0`), `go list -json`
selection, linked production graph, selected source hashes, package-object
hashes, binary hash, symbol table, per-symbol `go tool objdump`, CPU features,
runtime-selected mask/UTF-8 profiles, and runtime self-checks. Reference-oracle
packages must be absent from the production probe graph.

The required linked profiles are SSE2/AVX2/AVX-512 masking plus AVX2 UTF-8 on
amd64, and NEON masking/UTF-8 on arm64. The probe does not force unsupported
ISA execution. Phase 0 does not add or qualify pure-Go/no-assembly production
fallbacks or any other architecture.

## Phase 0 policies

<!-- markdownlint-disable MD013 -->

<!-- BEGIN GENERATED: phase0-policy-metadata -->
| Evidence role | Policy | Client | Adapter | Window |
| --- | --- | --- | --- | --- |
| A/A sessions 1-3 | `harness/policy/phase0/darwin-arm64-aa.json` | `gows` | same binary, `aa` | 5s warmup, 30s measure, n=20/session |
| Best API baseline | `harness/policy/darwin-arm64.json` | `gows` | `best_api` | 5s/30s, n=20/cell |
| Semantic parity | `harness/policy/phase0/darwin-arm64-semantic-parity.json` | `gows` | `semantic_parity` | 5s/30s, n=20 |
| Independent client | `harness/policy/phase0/darwin-arm64-independent-gobwas.json` | `gobwas` | `best_api` | 5s/30s, n=20 |
| Independent raw client | `harness/policy/phase0/darwin-arm64-independent-raw.json` | `raw` | `best_api` | 5s/30s, n=20 |
<!-- END GENERATED: phase0-policy-metadata -->

<!-- markdownlint-enable MD013 -->

The full best-API policy contains saturated closed-loop cells and
server-sensitive pipelined cells. The other policies keep their semantic or
client question isolated. No baseline ratio is required to beat quickws in
Phase 0: every complete metric and unfavorable cell is recorded, while the
baseline verdict field `superiority_gate` remains `false`.

The A/A policy deliberately includes one saturated closed-loop cell and one
server-sensitive pipelined cell. Its null relabel therefore exercises both
branches of the preregistered full-claim predicate instead of validating only
one workload class.

## A/A self-validation gate

Optimization A/B data is not interpretable until three independent A/A
sessions pass all of these gates:

- exactly the same binary and adapter hashes under different A/A labels;
- at least 20 paired repetitions per session with balanced AB/BA blocks;
- session/block-preserving hierarchical 95% confidence intervals;
- throughput and p99 ratio intervals wholly within `[0.98, 1.02]`;
- p999 ratio intervals wholly within `[0.95, 1.05]`;
- each interval width no greater than its equivalence-band width;
- AB/BA order-effect interval wholly within `[0.99, 1.01]`;
- at least 1,000 deterministic session/block-preserving null relabels/sign
  flips with empirical full-verdict false-positive rate at most 5%; and
- zero errors, mismatches, drops, rejected messages, queue overflows,
  scheduler-late messages, post-window messages, or histogram loss.

The verdict also emits session-aware 95% intervals for the primary geomean,
p999, CPU/message, RSS/connection, allocations/message, and allocated
bytes/message.

## Running Phase 0

Resolve and verify the stock controller before disabling the user's Go
environment. Do not derive the controller from `GOENV=off`: on a development
machine that can expose a different custom GOROOT than the selected stock SDK.

```sh
repo="$(git rev-parse --show-toplevel)"
stock_go="$(go env GOROOT)/bin/go"
test "$("$stock_go" env GOVERSION)" = go1.26.5
case "$("$stock_go" version)" in *' X:'*) exit 1 ;; esac
test -z "$(git -C "$repo" status --porcelain=v1 --untracked-files=all)"
source_short="$(git -C "$repo" rev-parse --short HEAD)"
```

Every evidence-producing command below uses the same controlled environment:

```text
GOENV=off
GOTOOLCHAIN=local
GOEXPERIMENT=
GOFLAGS=-mod=mod
GOFIPS140=latest
GOWORK=off
CGO_ENABLED=0
```

First create the typed verification result. The runner executes the complete
root, benchmark-module, and `flatekp` gates sequentially, then seals the
verification logs and the two assembly bundles into the repository-local CAS.

```sh
verification="$repo/.omx/phase0-verification-$(date -u +%Y%m%dT%H%M%SZ)"
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/phase0verify \
  -repo "$repo" -out "$verification"
verification_result="$verification/result.json"
```

Run the three A/A sessions sequentially. The default output root includes the
exact series identity and source HEAD; `phase0receipt` accepts either the run
directory or its `receipt.json`.

```sh
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/benchrun \
  -policy harness/policy/phase0/darwin-arm64-aa.json \
  -session-id p0-aa-01
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/benchrun \
  -policy harness/policy/phase0/darwin-arm64-aa.json \
  -session-id p0-aa-02
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/benchrun \
  -policy harness/policy/phase0/darwin-arm64-aa.json \
  -session-id p0-aa-03

aa_root="$repo/.omx/bench/stock/self_validation/same_host/aa/phase0-darwin-arm64-aa"
aa1="$aa_root/p0-aa-01-$source_short"
aa2="$aa_root/p0-aa-02-$source_short"
aa3="$aa_root/p0-aa-03-$source_short"
aa_verdict="$repo/.omx/phase0-aa-$source_short/verdict.json"
mkdir -p "$(dirname "$aa_verdict")"
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/phase0receipt \
  aa-preflight -repo "$repo" -verification-result "$verification_result" \
  -session-1 "$aa1" -session-2 "$aa2" -session-3 "$aa3" \
  -out "$aa_verdict"
```

Only after the A/A preflight passes, run all four current-baseline roles. Phase
0 records every result and does not require any ratio to beat quickws.

```sh
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/benchrun \
  -policy harness/policy/darwin-arm64.json \
  -session-id p0-baseline-best-api
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/benchrun \
  -policy harness/policy/phase0/darwin-arm64-semantic-parity.json \
  -session-id p0-baseline-semantic-parity
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/benchrun \
  -policy harness/policy/phase0/darwin-arm64-independent-gobwas.json \
  -session-id p0-baseline-gobwas
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/benchrun \
  -policy harness/policy/phase0/darwin-arm64-independent-raw.json \
  -session-id p0-baseline-raw

baseline_root="$repo/.omx/bench/stock/baseline/same_host/baseline"
best="$baseline_root/darwin-arm64/p0-baseline-best-api-$source_short"
semantic="$baseline_root/phase0-darwin-arm64-semantic-parity/p0-baseline-semantic-parity-$source_short"
gobwas="$baseline_root/phase0-darwin-arm64-independent-gobwas/p0-baseline-gobwas-$source_short"
raw="$baseline_root/phase0-darwin-arm64-independent-raw/p0-baseline-raw-$source_short"
tracked="$repo/bench/evidence/phase0/current"
mkdir -p "$tracked"
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" run ./harness/cmd/phase0receipt build \
  -repo "$repo" -verification-result "$verification_result" \
  -session-1 "$aa1" -session-2 "$aa2" -session-3 "$aa3" \
  -baseline-best-api-gows-client "$best" \
  -baseline-semantic-parity-gows-client "$semantic" \
  -baseline-independent-gobwas-client "$gobwas" \
  -baseline-independent-raw-client "$raw" \
  -out "$tracked/receipt.json"
```

Commit `receipt.json` without changing the implementation source, generate the
deterministic verdict, then commit only `verdict.json`. The final read-only
command must remain exactly the frozen evaluator below.

```sh
GOEXPERIMENT= GOFLAGS=-mod=mod go -C bench run \
  ./harness/cmd/benchcmp -run evidence/phase0/current \
  -write-verdict evidence/phase0/current/verdict.json

GOEXPERIMENT= GOFLAGS=-mod=mod go -C bench run \
  ./harness/cmd/benchcmp -run evidence/phase0/current
```

Short smoke windows are accepted only by an explicitly diagnostic policy and
are never eligible for A/A or baseline receipts.

The path-stable, read-only final evaluator command is:

```sh
GOEXPERIMENT= GOFLAGS=-mod=mod go -C bench run \
  ./harness/cmd/benchcmp -run evidence/phase0/current
```

It exits zero only after the tracked verdict is reproduced byte-for-byte and
all A/A, baseline, assembly, provenance, verification, and scope gates pass.
Until the tracked receipt and immutable artifact store exist, a nonzero result
is the intended fail-closed behavior.

## Verification

The Phase 0 verification receipt binds fresh output from root, benchmark, and
`flatekp` tests/vet/race/build checks, supported amd64/arm64 assembly probes,
static checks, and the production-scope audit. The final evaluator validates
those command identities and their immutable log hashes; a short smoke run is
not verification evidence.

For local development, run the benchmark module checks with the same stock
environment:

```sh
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" test ./... -count=1
env GOENV=off GOTOOLCHAIN=local GOEXPERIMENT= GOFLAGS=-mod=mod \
  GOFIPS140=latest GOWORK=off CGO_ENABLED=0 \
  "$stock_go" -C "$repo/bench" vet ./...
```
