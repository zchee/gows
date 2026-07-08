#!/usr/bin/env bash
# run-remote.sh — sync bench/ (plus the parent repo, needed once gows joins
# the harness in Phase 5) to a remote host, run the same baseline commands
# there with the remote's own Go toolchain, and copy results/ back.
#
# Intended target per plan: ssh debian-trixie-xslq.asia-northeast1-c.gaudiy-platform
# (linux/amd64, Sapphire Rapids 8481C). Confirmed provisioned: Go 1.26.5 at
# ~/sdk/go1.26.5/bin/go, docker working non-root. Bare `go` does NOT resolve
# over non-interactive ssh (no login shell, no PATH sourcing) — every go
# invocation below uses the absolute ${REMOTE_GO} path for that reason.
set -euo pipefail

REMOTE="${1:?usage: run-remote.sh <remote-host> [remote-go-bin]}"
REMOTE_GO="${2:-\$HOME/sdk/go1.26.5/bin/go}"
REMOTE_DIR="\$HOME/gows"

# Disjoint CPU sets for the echo harness (plan §8: isolate harness load from
# server load so the client driver never steals cycles from the process
# being measured). taskset is available at /usr/bin/taskset on the remote.
SERVER_CPUSET="0-19"
LOADGEN_CPUSET="22-41"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> checking for a Go toolchain on ${REMOTE}"
if ! ssh "${REMOTE}" "test -x ${REMOTE_GO}"; then
	echo "error: ${REMOTE_GO} not found on ${REMOTE}." >&2
	echo "       install Go there first (plan §6 Phase 0 item 1), then re-run." >&2
	exit 1
fi

echo "==> tar-syncing ${repo_root} to ${REMOTE}:${REMOTE_DIR}"
# bench/results is excluded from the tar (this machine's local results
# shouldn't be overwritten by an empty/stale remote copy), so it must be
# recreated remotely before anything tries to write or append into it.
ssh "${REMOTE}" "mkdir -p ${REMOTE_DIR}/bench/results"
tar -C "${repo_root}" \
	--exclude .git \
	--exclude bench/results \
	-czf - . |
	ssh "${REMOTE}" "tar -C ${REMOTE_DIR} -xzf -"

echo "==> running kernel benchmarks on ${REMOTE}"
ssh "${REMOTE}" "cd ${REMOTE_DIR}/bench && ${REMOTE_GO} test -run=NONE -bench=BenchmarkMask -benchmem -count=10 . > results/kernels-baseline-linux-amd64.txt"

echo "==> building echoserver/loadgen on ${REMOTE}"
ssh "${REMOTE}" "cd ${REMOTE_DIR}/bench && ${REMOTE_GO} build -o /tmp/echoserver ./harness/cmd/echoserver && ${REMOTE_GO} build -o /tmp/loadgen ./harness/cmd/loadgen"

echo "==> running echo harness for each library on ${REMOTE}"
for lib in gorilla coder gobwas gws quickws fasthttp nbio; do
	echo "--- ${lib} ---"
	# ulimit is a shell-session setting, not a process one: it does not
	# persist across separate ssh invocations, so it must be set once at
	# the top of this combined remote script (before anything is forked,
	# background or foreground) rather than prefixed onto each command —
	# both the backgrounded echoserver and the foreground loadgen below
	# inherit it via fork/exec from this same shell.
	ssh "${REMOTE}" "
		echo '### ${lib}' >> ${REMOTE_DIR}/bench/results/echo-baseline-linux-amd64.md
		ulimit -n 65535
		taskset -c ${SERVER_CPUSET} /tmp/echoserver -lib ${lib} -addr 127.0.0.1:9001 -debug-addr 127.0.0.1:9101 &
		server_pid=\$!
		sleep 1
		taskset -c ${LOADGEN_CPUSET} /tmp/loadgen -addr 127.0.0.1:9001 -debug-addr 127.0.0.1:9101 \
			-conns 1000 -payload 1024 -duration 15s -warmup 3s -rate 0 \
			>> ${REMOTE_DIR}/bench/results/echo-baseline-linux-amd64.md
		kill \$server_pid 2>/dev/null || true
		wait \$server_pid 2>/dev/null || true
	"
done

echo "==> copying results/ back"
# scp's SFTP-protocol mode does not reliably glob/expand a remote path built
# from a literal "$HOME" token (observed: "remote readdir(...): No such file
# or directory"), so pull results/ the same way it was pushed: tar over ssh.
ssh "${REMOTE}" "cd ${REMOTE_DIR}/bench/results && tar -czf - ." |
	tar -C "${repo_root}/bench/results" -xzf -

echo "==> done. See bench/results/*linux-amd64*"
