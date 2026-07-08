#!/usr/bin/env bash
#
# run.sh - Autobahn|Testsuite conformance harness for gows.
#
# Runs crossbario/autobahn-testsuite in docker against either our server
# (fuzzingclient mode) or our client (fuzzingserver mode), then judges the
# resulting report and exits non-zero on any non-conformant case.
#
# Usage:
#   run.sh server <ws-url>
#   run.sh client
#
# See usage() below for details.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
REPORTS_DIR="${SCRIPT_DIR}/reports"
IMAGE="${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite:latest}"
CLIENT_PORT=9001
CLIENT_TIMEOUT="${AUTOBAHN_CLIENT_TIMEOUT:-120}"

usage() {
    cat <<'USAGE'
Usage:
  run.sh server <ws-url>
      Test OUR SERVER: run the Autobahn fuzzingclient against <ws-url>
      (e.g. ws://127.0.0.1:9001), the address of a gows server the caller
      has already started. Writes a report to autobahn/reports/server and
      exits non-zero if any case's behavior is not one of
      OK/INFORMATIONAL/NON-STRICT/UNIMPLEMENTED.

  run.sh client
      Test OUR CLIENT: run the Autobahn fuzzingserver, reachable from the
      host at ws://127.0.0.1:9001, and wait up to AUTOBAHN_CLIENT_TIMEOUT
      seconds (default 120) for a gows client to connect and exercise every
      case. Writes a report to autobahn/reports/clients and judges it the
      same way as "server" mode.

Environment:
  AUTOBAHN_IMAGE            docker image to use (default crossbario/autobahn-testsuite:latest)
  AUTOBAHN_CLIENT_TIMEOUT   seconds to wait for the client run to finish (default 120)
USAGE
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "run.sh: '$1' is required but was not found in PATH" >&2
        exit 1
    }
}

# judge parses the index.json report under report_dir and fails the build
# if any case did not behave acceptably.
judge() {
    local report_dir="$1"
    if [[ ! -f "${report_dir}/index.json" ]]; then
        echo "run.sh: no report produced at ${report_dir}/index.json" >&2
        return 1
    fi
    need_cmd go
    (cd "$SCRIPT_DIR" && go run ./judge "$report_dir")
}

cmd_server() {
    if [[ $# -lt 1 ]]; then
        echo "run.sh: 'server' mode requires a <ws-url> argument" >&2
        usage >&2
        exit 1
    fi
    local ws_url="$1"

    local scheme host port
    if [[ "$ws_url" =~ ^(wss?)://([^/:]+)(:([0-9]+))?(/.*)?$ ]]; then
        scheme="${BASH_REMATCH[1]}"
        host="${BASH_REMATCH[2]}"
        port="${BASH_REMATCH[4]}"
    else
        echo "run.sh: invalid ws URL: ${ws_url} (expected ws://host[:port] or wss://host[:port])" >&2
        exit 1
    fi

    # The testsuite container needs to reach a server bound on the host's
    # network. On Linux we share the host netns (--network=host) so the
    # given host is already reachable as-is. Docker Desktop/OrbStack on
    # macOS run containers in a VM, so loopback addresses must be rewritten
    # to the "host.docker.internal" gateway instead.
    local resolved_host="$host"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        case "$host" in
        127.0.0.1 | localhost | ::1)
            resolved_host="host.docker.internal"
            ;;
        esac
    fi
    local resolved_url="${scheme}://${resolved_host}"
    [[ -n "$port" ]] && resolved_url="${resolved_url}:${port}"

    local report_dir="${REPORTS_DIR}/server"
    mkdir -p "$report_dir"

    # Deliberately not `local`: the EXIT trap below fires after set -e has
    # already unwound out of this function's scope, and a `local` variable
    # referenced there would read back as unbound under `set -u`.
    tmp_config="$(mktemp -d)"
    trap 'rm -rf "${tmp_config:-}"' EXIT
    sed "s#ws://HOST:9001#${resolved_url}#g" "${CONFIG_DIR}/fuzzingclient.json" >"${tmp_config}/fuzzingclient.json"

    echo "run.sh: testing server ${ws_url} (container will dial ${resolved_url})"

    local network_args=()
    if [[ "$(uname -s)" == "Linux" ]]; then
        network_args=(--network=host)
    fi

    docker run --rm \
        "${network_args[@]}" \
        -v "${tmp_config}/fuzzingclient.json:/config/fuzzingclient.json:ro" \
        -v "${REPORTS_DIR}:/reports" \
        "$IMAGE" \
        wstest --mode fuzzingclient --spec /config/fuzzingclient.json

    judge "$report_dir"
}

cmd_client() {
    local report_dir="${REPORTS_DIR}/clients"
    mkdir -p "$report_dir"

    local network_args=()
    local publish_args=()
    if [[ "$(uname -s)" == "Linux" ]]; then
        network_args=(--network=host)
    else
        publish_args=(-p "127.0.0.1:${CLIENT_PORT}:${CLIENT_PORT}")
    fi

    echo "run.sh: listening on ws://127.0.0.1:${CLIENT_PORT} for up to ${CLIENT_TIMEOUT}s - point a gows client at it"

    # wstest's fuzzingserver mode never exits on its own (it stays up to
    # accept further agents), so bound the run with `timeout` and treat its
    # 124 exit status (deadline hit) as expected rather than a hard failure.
    local status=0
    timeout "${CLIENT_TIMEOUT}" docker run --rm \
        "${network_args[@]}" "${publish_args[@]}" \
        -v "${CONFIG_DIR}/fuzzingserver.json:/config/fuzzingserver.json:ro" \
        -v "${REPORTS_DIR}:/reports" \
        "$IMAGE" \
        wstest --mode fuzzingserver --spec /config/fuzzingserver.json --webport 0 || status=$?

    if [[ $status -ne 0 && $status -ne 124 ]]; then
        echo "run.sh: docker run failed with status ${status}" >&2
        exit "$status"
    fi

    judge "$report_dir"
}

main() {
    need_cmd docker
    need_cmd sed

    local mode="${1:-}"
    case "$mode" in
    server)
        shift
        cmd_server "$@"
        ;;
    client)
        shift
        cmd_client "$@"
        ;;
    -h | --help | help)
        usage
        ;;
    "")
        usage >&2
        exit 1
        ;;
    *)
        echo "run.sh: unknown mode '${mode}'" >&2
        usage >&2
        exit 1
        ;;
    esac
}

main "$@"
