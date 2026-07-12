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
DEFAULT_REPORTS_DIR="${SCRIPT_DIR}/reports"
REPORTS_DIR="${AUTOBAHN_REPORTS_DIR:-${DEFAULT_REPORTS_DIR}}"
IMAGE="${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074}"
PROFILE="${AUTOBAHN_PROFILE:-canonical}"
AGENT="${AUTOBAHN_AGENT:-gows}"
APPLICATION_COMMAND="${AUTOBAHN_APPLICATION_COMMAND:-}"
CLIENT_PORT=9001
CLIENT_TIMEOUT="${AUTOBAHN_CLIENT_TIMEOUT:-120}"
SERVER_TIMEOUT="${AUTOBAHN_SERVER_TIMEOUT:-600}"
RUN_ID="${AUTOBAHN_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
STRICT_EVIDENCE="${AUTOBAHN_STRICT_EVIDENCE:-0}"
SKIP_PROVENANCE="${AUTOBAHN_SKIP_PROVENANCE:-0}"
NETWORK_MODE="${AUTOBAHN_NETWORK_MODE:-auto}"
EFFECTIVE_NETWORK_MODE="$NETWORK_MODE"
CASE_DELAY="${AUTOBAHN_CASE_DELAY:-0s}"
EFFECTIVE_CASE_DELAY="$CASE_DELAY"
COMPLETION_FILE="${AUTOBAHN_COMPLETION_FILE:-}"
COMPLETION_MECHANISM=default-timeout
COMPLETION_STOP_REASON=""
COMPLETION_STOP_STATUS=0

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
  AUTOBAHN_IMAGE            pinned docker image reference (defaults to the baseline digest)
  AUTOBAHN_CLIENT_TIMEOUT   seconds to wait for the client run to finish (default 120)
  AUTOBAHN_SERVER_TIMEOUT   seconds to bound fuzzingclient (default 600)
  AUTOBAHN_REPORTS_DIR      unique report root (default autobahn/reports)
  AUTOBAHN_PROFILE          canonical or feature (default canonical)
  AUTOBAHN_AGENT            expected report agent (default gows)
  AUTOBAHN_APPLICATION_COMMAND exact external gows command (required for feature)
  AUTOBAHN_RUN_ID           provenance/container identifier
  AUTOBAHN_NETWORK_MODE     auto, host, or bridge (default auto)
  AUTOBAHN_CASE_DELAY       nonnegative Go duration between cases/connections
  AUTOBAHN_COMPLETION_FILE  optional strict run-owned client completion sentinel
USAGE
}

validate_report_target() {
    local direction="$1" subtree="$2"
    if [[ "$STRICT_EVIDENCE" == 1 ]]; then
        [[ "$REPORTS_DIR" == /* ]] || { echo "run.sh: strict report root must be absolute" >&2; exit 1; }
        [[ "$(basename "$REPORTS_DIR")" == *"$RUN_ID"* ]] || { echo "run.sh: strict report root must contain run ID" >&2; exit 1; }
        [[ ! -e "$REPORTS_DIR" ]] || { echo "run.sh: strict report root already exists" >&2; exit 1; }
    elif [[ -e "${REPORTS_DIR}/${subtree}/index.json" ]]; then
        echo "run.sh: refusing pre-existing ${direction} index.json" >&2
        exit 1
    fi
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

validate_profile() {
    local direction="$1" expected_feature_agent="gows-v04-feature-$1"
    case "$PROFILE" in
    canonical)
        [[ "$AGENT" == "gows" ]] || {
            echo "run.sh: canonical profile requires agent gows" >&2
            exit 1
        }
        ;;
    feature)
        [[ "$REPORTS_DIR" != "$DEFAULT_REPORTS_DIR" ]] || {
            echo "run.sh: feature profile requires a unique AUTOBAHN_REPORTS_DIR" >&2
            exit 1
        }
        [[ "$AGENT" == "$expected_feature_agent" ]] || {
            echo "run.sh: feature $direction profile requires agent $expected_feature_agent" >&2
            exit 1
        }
        [[ -n "$APPLICATION_COMMAND" ]] || {
            echo "run.sh: feature profile requires AUTOBAHN_APPLICATION_COMMAND" >&2
            exit 1
        }
        [[ -n "${AUTOBAHN_GENERATOR_EVIDENCE:-}" && "${AUTOBAHN_GENERATOR_EVIDENCE}" != "autobahntestsuite/case/case12_x_x.py" ]] || { echo "run.sh: feature profile requires non-placeholder AUTOBAHN_GENERATOR_EVIDENCE" >&2; exit 1; }
        ;;
    *)
        echo "run.sh: unknown AUTOBAHN_PROFILE '$PROFILE'" >&2
        exit 1
        ;;
    esac
    if [[ "$STRICT_EVIDENCE" == 1 ]]; then
        [[ "${AUTOBAHN_GENERATOR_EVIDENCE:-}" =~ ^(/.*)@sha256:([0-9a-f]{64})$ ]] || { echo "run.sh: strict generator evidence must be <absolute-path>@sha256:<64 lowercase hex>" >&2; exit 1; }
        local generator_path="${BASH_REMATCH[1]}" generator_sha="${BASH_REMATCH[2]}"
        [[ -f "$generator_path" && "$(realpath "$generator_path")" == "$generator_path" && "$(shasum -a 256 "$generator_path" | awk '{print $1}')" == "$generator_sha" ]] || { echo "run.sh: strict generator evidence file/hash mismatch" >&2; exit 1; }
    fi
    [[ "$CLIENT_TIMEOUT" =~ ^[1-9][0-9]*$ && "$SERVER_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { echo "run.sh: timeout values must be positive base-10 integers" >&2; exit 1; }
    case "$NETWORK_MODE" in auto) [[ "$(uname -s)" == Linux ]] && EFFECTIVE_NETWORK_MODE=host || EFFECTIVE_NETWORK_MODE=bridge;; host|bridge) EFFECTIVE_NETWORK_MODE="$NETWORK_MODE";; *) echo "run.sh: AUTOBAHN_NETWORK_MODE must be auto, host, or bridge" >&2; exit 1;; esac
    EFFECTIVE_CASE_DELAY="$(cd "${SCRIPT_DIR}/.." && go run ./autobahn/provenance -normalize-duration "$CASE_DELAY")" || { echo "run.sh: AUTOBAHN_CASE_DELAY must be a nonnegative duration" >&2; exit 1; }
    if [[ ! "$IMAGE" =~ ^[^@]+@sha256:[0-9a-fA-F]{64}$ ]]; then
        echo "run.sh: AUTOBAHN_IMAGE must be pinned by digest" >&2
        exit 1
    fi
}

cleanup_container() {
    local cidfile="$1" id=""
    [[ -f "$cidfile" ]] && IFS= read -r id <"$cidfile" || true
    [[ "$id" =~ ^[0-9a-fA-F]{12,64}$ ]] || return 0
    docker rm -f "$id" >/dev/null 2>&1 || true
}

write_provenance() {
    local direction="$1" report_dir="$2" started="$3" command="$4" container_id="$5"
    local image_id runner_timeout
    image_id="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
    runner_timeout="$SERVER_TIMEOUT"; [[ "$direction" == client ]] && runner_timeout="$CLIENT_TIMEOUT"
    need_cmd go
    (cd "${SCRIPT_DIR}/.." && go run ./autobahn/provenance \
        -run-id "$RUN_ID" -profile "$PROFILE" -direction "$direction" \
        -agent "$AGENT" -index "${report_dir}/index.json" \
        -output "${report_dir}/provenance.json" -command "$command" \
        -status 0 -image "$IMAGE" -image-id "$image_id" -started "$started" \
        -application-command "$APPLICATION_COMMAND" \
        -report-root "$REPORTS_DIR" -container-id "$container_id" -runner-timeout "$runner_timeout" \
        -network-mode "$EFFECTIVE_NETWORK_MODE" \
        -case-delay "$EFFECTIVE_CASE_DELAY" \
        -completion-file "$COMPLETION_FILE" -completion-mechanism "$COMPLETION_MECHANISM" -completion-stop-reason "$COMPLETION_STOP_REASON" -completion-stop-status "$COMPLETION_STOP_STATUS" \
        -generator "${AUTOBAHN_GENERATOR_EVIDENCE:-autobahntestsuite/case/case12_x_x.py}")
}

record_failure() {
    local direction="$1" status="$2" stage="$3" started="$4" command="$5" container_id="${6:-}"
    mkdir -p "$REPORTS_DIR"
    {
        printf 'run_id=%s\n' "$RUN_ID"
        printf 'profile=%s\n' "$PROFILE"
        printf 'direction=%s\n' "$direction"
        printf 'agent=%s\n' "$AGENT"
        printf 'started_utc=%s\n' "$started"
        printf 'ended_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'exit_status=%s\n' "$status"
        printf 'failure_stage=%s\n' "$stage"
        printf 'command=%s\n' "$command"
        printf 'container_id=%s\n' "$container_id"
        printf 'cwd=%s\n' "$PWD"
        printf 'branch=%s\n' "$(git branch --show-current)"
        printf 'head=%s\n' "$(git rev-parse HEAD)"
        printf 'workspace_sha256=%s\n' "$(cd "${SCRIPT_DIR}/.." && go run ./autobahn/provenance -print-workspace)"
        printf 'image=%s\nreport_root=%s\nrunner_timeout=%s\n' "$IMAGE" "$REPORTS_DIR" "$([[ "$direction" == client ]] && echo "$CLIENT_TIMEOUT" || echo "$SERVER_TIMEOUT")"
        printf 'network_mode=%s\n' "$EFFECTIVE_NETWORK_MODE"
        printf 'case_delay=%s\n' "$EFFECTIVE_CASE_DELAY"
        printf 'completion_file=%s\ncompletion_mechanism=%s\ncompletion_stop_reason=%s\ncompletion_stop_status=%s\n' "$COMPLETION_FILE" "$COMPLETION_MECHANISM" "$COMPLETION_STOP_REASON" "$COMPLETION_STOP_STATUS"
    } >"${REPORTS_DIR}/${RUN_ID}-${direction}-failure.txt"
}

cmd_server() {
    [[ -z "$COMPLETION_FILE" ]] || { echo "run.sh: AUTOBAHN_COMPLETION_FILE is client-mode only" >&2; exit 1; }
    if [[ $# -lt 1 ]]; then
        echo "run.sh: 'server' mode requires a <ws-url> argument" >&2
        usage >&2
        exit 1
    fi
    validate_report_target server server
    local ws_url="$1" started command
    started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf -v command 'AUTOBAHN_RUN_ID=%q AUTOBAHN_PROFILE=%q AUTOBAHN_AGENT=%q AUTOBAHN_REPORTS_DIR=%q AUTOBAHN_IMAGE=%q AUTOBAHN_SERVER_TIMEOUT=%q AUTOBAHN_NETWORK_MODE=%q AUTOBAHN_CASE_DELAY=%q AUTOBAHN_GENERATOR_EVIDENCE=%q AUTOBAHN_APPLICATION_COMMAND=%q %q server %q' "$RUN_ID" "$PROFILE" "$AGENT" "$REPORTS_DIR" "$IMAGE" "$SERVER_TIMEOUT" "$EFFECTIVE_NETWORK_MODE" "$EFFECTIVE_CASE_DELAY" "${AUTOBAHN_GENERATOR_EVIDENCE:-}" "$APPLICATION_COMMAND" "${BASH_SOURCE[0]}" "$ws_url"

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
    if [[ "$EFFECTIVE_NETWORK_MODE" == bridge ]]; then
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
    sed -e "s#ws://HOST:9001#${resolved_url}#g" -e "s#\"agent\": \"gows\"#\"agent\": \"${AGENT}\"#g" "${CONFIG_DIR}/fuzzingclient.json" >"${tmp_config}/fuzzingclient.json"

    echo "run.sh: testing server ${ws_url} (container will dial ${resolved_url})"

    local network_args=()
    if [[ "$EFFECTIVE_NETWORK_MODE" == host ]]; then
        network_args=(--network=host)
    elif [[ "$(uname -s)" == Linux ]]; then
        network_args=(--add-host=host.docker.internal:host-gateway)
    fi

    local cidfile container_id="" status=0
    cidfile="$(mktemp)"; rm -f "$cidfile"
    trap 'cleanup_container "'"$cidfile"'"; rm -f "'"$cidfile"'"; rm -rf "${tmp_config:-}"' EXIT
    timeout "$SERVER_TIMEOUT" docker run --rm --cidfile "$cidfile" \
        ${network_args[@]+"${network_args[@]}"} \
        -v "${tmp_config}/fuzzingclient.json:/config/fuzzingclient.json:ro" \
        -v "${REPORTS_DIR}:/reports" \
        "$IMAGE" \
        wstest --mode fuzzingclient --spec /config/fuzzingclient.json || status=$?
    [[ -f "$cidfile" ]] && IFS= read -r container_id <"$cidfile" || true
    [[ -z "$container_id" ]] || printf '%s\n' "$container_id" >"${REPORTS_DIR}/${RUN_ID}-server-container-id.txt"
    printf '%s\n' "$EFFECTIVE_NETWORK_MODE" >"${REPORTS_DIR}/${RUN_ID}-server-network-mode.txt"
    cleanup_container "$cidfile"
    if [[ $status -ne 0 ]]; then
        record_failure server "$status" docker "$started" "$command" "$container_id"
        echo "run.sh: fuzzingclient failed or timed out with status ${status}" >&2
        exit "$status"
    fi

    status=0
    judge "$report_dir" || status=$?
    if [[ $status -ne 0 ]]; then
        record_failure server "$status" judge "$started" "$command" "$container_id"
        exit "$status"
    fi
    [[ "$SKIP_PROVENANCE" == 1 ]] || write_provenance server "$report_dir" "$started" "$command" "$container_id" || status=$?
    if [[ $status -ne 0 ]]; then
        record_failure server "$status" provenance "$started" "$command" "$container_id"
        exit "$status"
    fi
}

cmd_client() {
    validate_report_target client clients
    if [[ -n "$COMPLETION_FILE" ]]; then
        local completion_base
        completion_base="$(basename "$COMPLETION_FILE")"
        [[ "$STRICT_EVIDENCE" == 1 && "$COMPLETION_FILE" == /* && "$(dirname "$COMPLETION_FILE")" == "$REPORTS_DIR" && "$completion_base" != . && "$completion_base" != .. && ! -e "$COMPLETION_FILE" ]] || { echo "run.sh: completion file must be an absolute absent path inside the strict report root" >&2; exit 1; }
        COMPLETION_MECHANISM=sentinel
    fi
    local started command
    started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf -v command 'AUTOBAHN_RUN_ID=%q AUTOBAHN_PROFILE=%q AUTOBAHN_AGENT=%q AUTOBAHN_REPORTS_DIR=%q AUTOBAHN_IMAGE=%q AUTOBAHN_CLIENT_TIMEOUT=%q AUTOBAHN_NETWORK_MODE=%q AUTOBAHN_CASE_DELAY=%q AUTOBAHN_COMPLETION_FILE=%q AUTOBAHN_GENERATOR_EVIDENCE=%q AUTOBAHN_APPLICATION_COMMAND=%q %q client' "$RUN_ID" "$PROFILE" "$AGENT" "$REPORTS_DIR" "$IMAGE" "$CLIENT_TIMEOUT" "$EFFECTIVE_NETWORK_MODE" "$EFFECTIVE_CASE_DELAY" "$COMPLETION_FILE" "${AUTOBAHN_GENERATOR_EVIDENCE:-}" "$APPLICATION_COMMAND" "${BASH_SOURCE[0]}"
    local report_dir="${REPORTS_DIR}/clients"
    mkdir -p "$report_dir"

    local network_args=()
    local publish_args=()
    if [[ "$EFFECTIVE_NETWORK_MODE" == host ]]; then
        network_args=(--network=host)
    else
        publish_args=(-p "127.0.0.1:${CLIENT_PORT}:${CLIENT_PORT}")
    fi

    echo "run.sh: listening on ws://127.0.0.1:${CLIENT_PORT} for up to ${CLIENT_TIMEOUT}s - point a gows client at it"

    # wstest's fuzzingserver mode never exits on its own (it stays up to
    # accept further agents), so bound the run with `timeout` and treat its
    # 124 exit status (deadline hit) as expected rather than a hard failure.
    local status=0 cidfile container_id=""
    cidfile="$(mktemp)"; rm -f "$cidfile"
    trap 'cleanup_container "'"$cidfile"'"; rm -f "'"$cidfile"'"' EXIT
    if [[ -n "$COMPLETION_FILE" ]]; then
        timeout "${CLIENT_TIMEOUT}" docker run --rm --cidfile "$cidfile" \
            ${network_args[@]+"${network_args[@]}"} ${publish_args[@]+"${publish_args[@]}"} \
            -v "${CONFIG_DIR}/fuzzingserver.json:/config/fuzzingserver.json:ro" -v "${REPORTS_DIR}:/reports" "$IMAGE" \
            wstest --mode fuzzingserver --spec /config/fuzzingserver.json --webport 0 &
        docker_runner_pid=$!
        while true; do
            if [[ -f "$COMPLETION_FILE" ]]; then
                COMPLETION_STOP_REASON="sentinel"
                [[ -f "$cidfile" ]] && IFS= read -r container_id <"$cidfile" || true
                cleanup_container "$cidfile"
                if wait "$docker_runner_pid"; then COMPLETION_STOP_STATUS=0; else COMPLETION_STOP_STATUS=$?; fi
                break
            fi
            if ! kill -0 "$docker_runner_pid" >/dev/null 2>&1; then
                if wait "$docker_runner_pid"; then status=0; else status=$?; fi
                COMPLETION_STOP_STATUS=$status
                [[ $status -eq 124 ]] && COMPLETION_STOP_REASON="timeout" || COMPLETION_STOP_REASON="docker-exit"
                failure_status=$status; [[ $failure_status -ne 0 ]] || failure_status=1
                record_failure client "$failure_status" "$COMPLETION_STOP_REASON" "$started" "$command" "$container_id"
                echo "run.sh: client runner ended before completion sentinel (${COMPLETION_STOP_REASON}, status ${status})" >&2
                exit "$failure_status"
            fi
            sleep 0.1
        done
        [[ -f "$report_dir/index.json" ]] || { record_failure client 1 missing-report "$started" "$command" "$container_id"; echo "run.sh: completion sentinel observed without index.json" >&2; exit 1; }
    else
        timeout "${CLIENT_TIMEOUT}" docker run --rm --cidfile "$cidfile" \
            ${network_args[@]+"${network_args[@]}"} ${publish_args[@]+"${publish_args[@]}"} \
            -v "${CONFIG_DIR}/fuzzingserver.json:/config/fuzzingserver.json:ro" \
            -v "${REPORTS_DIR}:/reports" \
            "$IMAGE" \
            wstest --mode fuzzingserver --spec /config/fuzzingserver.json --webport 0 || status=$?
        COMPLETION_STOP_REASON="timeout"
        COMPLETION_STOP_STATUS=$status
    fi

    [[ -f "$cidfile" ]] && IFS= read -r container_id <"$cidfile" || true
    [[ -z "$container_id" ]] || printf '%s\n' "$container_id" >"${REPORTS_DIR}/${RUN_ID}-client-container-id.txt"
    printf '%s\n' "$EFFECTIVE_NETWORK_MODE" >"${REPORTS_DIR}/${RUN_ID}-client-network-mode.txt"
    printf '%s\n' "$COMPLETION_MECHANISM" >"${REPORTS_DIR}/${RUN_ID}-client-completion-mechanism.txt"
    printf '%s\n' "$COMPLETION_STOP_REASON" >"${REPORTS_DIR}/${RUN_ID}-client-completion-stop-reason.txt"
    printf '%s\n' "$COMPLETION_STOP_STATUS" >"${REPORTS_DIR}/${RUN_ID}-client-completion-stop-status.txt"
    cleanup_container "$cidfile"
    if [[ $status -ne 0 && $status -ne 124 ]]; then
        record_failure client "$status" docker "$started" "$command" "$container_id"
        echo "run.sh: docker run failed with status ${status}" >&2
        exit "$status"
    fi

    status=0
    judge "$report_dir" || status=$?
    if [[ $status -ne 0 ]]; then
        record_failure client "$status" judge "$started" "$command" "$container_id"
        exit "$status"
    fi
    [[ "$SKIP_PROVENANCE" == 1 ]] || write_provenance client "$report_dir" "$started" "$command" "$container_id" || status=$?
    if [[ $status -ne 0 ]]; then
        record_failure client "$status" provenance "$started" "$command" "$container_id"
        exit "$status"
    fi
}

main() {
    local mode="${1:-}"
    case "$mode" in
    server)
        validate_profile server
        need_cmd docker
        need_cmd sed
        need_cmd timeout
        shift
        cmd_server "$@"
        ;;
    client)
        validate_profile client
        need_cmd docker
        need_cmd timeout
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
