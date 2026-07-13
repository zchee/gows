#!/usr/bin/env bash
# Runs one feature-enabled Autobahn direction with an owned prebuilt gows app.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ROOT_DIR="${SCRIPT_DIR}/.."
DIRECTION="${1:-}"
[[ "$DIRECTION" == server || "$DIRECTION" == client ]] || { echo "usage: feature-run.sh server|client -- <prebuilt-app> [args...]" >&2; exit 2; }
shift
[[ "${1:-}" == -- ]] || { echo "feature-run.sh: -- before application command is required" >&2; exit 2; }
shift
[[ $# -gt 0 && -x "$1" ]] || { echo "feature-run.sh: application must be a prebuilt executable" >&2; exit 2; }
[[ "$(basename "$1")" != go ]] || { echo "feature-run.sh: go run is not allowed; pass a prebuilt binary" >&2; exit 2; }
case " $* " in *" -mode ${DIRECTION} "*|*" -mode=${DIRECTION} "*) ;; *) echo "feature-run.sh: application command must include -mode ${DIRECTION}" >&2; exit 2;; esac

RUN_ID="${AUTOBAHN_RUN_ID:?AUTOBAHN_RUN_ID is required}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "feature-run.sh: run ID has unsafe characters" >&2; exit 1; }
REPORTS_DIR="${AUTOBAHN_REPORTS_DIR:?AUTOBAHN_REPORTS_DIR is required}"
[[ "$REPORTS_DIR" == /* && "$(basename "$REPORTS_DIR")" == *"$RUN_ID"* && ! -e "$REPORTS_DIR" ]] || { echo "feature-run.sh: report root must be absolute, unique, absent, and contain run ID" >&2; exit 1; }
AGENT="gows-v04-feature-${DIRECTION}"
APP_TIMEOUT="${AUTOBAHN_APPLICATION_TIMEOUT:-480}"
READY_TIMEOUT="${AUTOBAHN_READY_TIMEOUT:-30}"
CLIENT_TIMEOUT="${AUTOBAHN_CLIENT_TIMEOUT:-480}"
SERVER_TIMEOUT="${AUTOBAHN_SERVER_TIMEOUT:-600}"
IMAGE="${AUTOBAHN_IMAGE:-crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074}"
NETWORK_MODE="${AUTOBAHN_NETWORK_MODE:-auto}"
CASE_DELAY="${AUTOBAHN_CASE_DELAY:-0s}"
case "$NETWORK_MODE" in auto|host|bridge);; *) echo "feature-run.sh: AUTOBAHN_NETWORK_MODE must be auto, host, or bridge" >&2; exit 1;; esac
APP_COMMAND="$(printf '%q ' "$@")"
APP_EXECUTABLE="$1"
EXPECTED_APP_SHA="${AUTOBAHN_EXPECTED_APPLICATION_SHA256:?AUTOBAHN_EXPECTED_APPLICATION_SHA256 is required}"
[[ "$EXPECTED_APP_SHA" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "feature-run.sh: expected application SHA-256 must be 64 hex" >&2; exit 1; }
APP_PID=""; RUNNER_PID=""
APP_OWNED=0
RUNNER_OWNED=0

for cmd in nc docker go timeout pgrep shasum realpath; do command -v "$cmd" >/dev/null 2>&1 || { echo "feature-run.sh: $cmd is required" >&2; exit 1; }; done
for value in "$APP_TIMEOUT" "$READY_TIMEOUT" "$CLIENT_TIMEOUT" "$SERVER_TIMEOUT"; do [[ "$value" =~ ^[1-9][0-9]*$ ]] || { echo "feature-run.sh: all timeout values must be positive base-10 integers" >&2; exit 1; }; done
OBSERVED_APP_SHA="$(shasum -a 256 "$APP_EXECUTABLE" | awk '{print $1}')"
[[ "$OBSERVED_APP_SHA" == "$EXPECTED_APP_SHA" ]] || { echo "feature-run.sh: application SHA-256 does not match reviewed binary" >&2; exit 1; }
GENERATOR_EVIDENCE="${AUTOBAHN_GENERATOR_EVIDENCE:?AUTOBAHN_GENERATOR_EVIDENCE is required}"
[[ "$GENERATOR_EVIDENCE" =~ ^(/.*)@sha256:([0-9a-f]{64})$ ]] || { echo "feature-run.sh: generator evidence must be <absolute-path>@sha256:<64 lowercase hex>" >&2; exit 1; }
GENERATOR_PATH="${BASH_REMATCH[1]}"; GENERATOR_SHA="${BASH_REMATCH[2]}"
[[ -f "$GENERATOR_PATH" && "$(realpath "$GENERATOR_PATH")" == "$GENERATOR_PATH" && "$(shasum -a 256 "$GENERATOR_PATH" | awk '{print $1}')" == "$GENERATOR_SHA" ]] || { echo "feature-run.sh: generator evidence file/hash mismatch" >&2; exit 1; }
EFFECTIVE_CASE_DELAY="$(cd "$ROOT_DIR" && go run ./autobahn/provenance -normalize-duration "$CASE_DELAY")" || { echo "feature-run.sh: AUTOBAHN_CASE_DELAY must be a nonnegative duration" >&2; exit 1; }
nc -z 127.0.0.1 9001 >/dev/null 2>&1 && { echo "feature-run.sh: port 9001 is already occupied" >&2; exit 1; }
RUN_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
FULL_INVOCATION="AUTOBAHN_RUN_ID=$(printf %q "$RUN_ID") AUTOBAHN_PROFILE=feature AUTOBAHN_AGENT=$(printf %q "$AGENT") AUTOBAHN_REPORTS_DIR=$(printf %q "$REPORTS_DIR") AUTOBAHN_IMAGE=$(printf %q "$IMAGE") AUTOBAHN_NETWORK_MODE=$(printf %q "$NETWORK_MODE") AUTOBAHN_CASE_DELAY=$(printf %q "$EFFECTIVE_CASE_DELAY") AUTOBAHN_GENERATOR_EVIDENCE=$(printf %q "$GENERATOR_EVIDENCE") AUTOBAHN_APPLICATION_TIMEOUT=$(printf %q "$APP_TIMEOUT") AUTOBAHN_READY_TIMEOUT=$(printf %q "$READY_TIMEOUT") AUTOBAHN_CLIENT_TIMEOUT=$(printf %q "$CLIENT_TIMEOUT") AUTOBAHN_SERVER_TIMEOUT=$(printf %q "$SERVER_TIMEOUT") AUTOBAHN_EXPECTED_APPLICATION_SHA256=$(printf %q "$EXPECTED_APP_SHA") $(printf %q "${BASH_SOURCE[0]}") $(printf %q "$DIRECTION") -- $APP_COMMAND"
COMPLETION_FILE=""; [[ "$DIRECTION" == client ]] && COMPLETION_FILE="${REPORTS_DIR}/${RUN_ID}-client-complete"
[[ -z "$COMPLETION_FILE" ]] || FULL_INVOCATION="AUTOBAHN_COMPLETION_FILE=$(printf %q "$COMPLETION_FILE") $FULL_INVOCATION"

cleanup() {
  local status=$?
  if [[ "$APP_OWNED" == 1 ]]; then
    kill_owned_app
    if wait "$APP_PID" >/dev/null 2>&1; then observed=0; else observed=$?; fi
    APP_OWNED=0
    if [[ $status -ne 0 && -n "$APP_STARTED" ]]; then
      mkdir -p "$REPORTS_DIR"
      receipt_status="$APP_STATUS"; [[ "$receipt_status" -ne 0 ]] || receipt_status="$observed"
      (cd "$ROOT_DIR" && go run ./autobahn/appreceipt -run-id "$RUN_ID" -direction "$DIRECTION" -agent "$AGENT" -command "$APP_COMMAND" -executable "$APP_EXECUTABLE" -expected-executable-sha256 "$EXPECTED_APP_SHA" -started "$APP_STARTED" -ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" -termination failure -pid "$APP_PID" -status "$receipt_status" -output "${REPORTS_DIR}/application-failure-receipt.json") || true
    fi
  fi
  if [[ "$RUNNER_OWNED" == 1 ]]; then
    [[ -z "${AUTOBAHN_RUNNER_OWNERSHIP_AUDIT_LOG:-}" ]] || printf '%s\n' "$RUNNER_PID" >>"$AUTOBAHN_RUNNER_OWNERSHIP_AUDIT_LOG"
    kill_owned_tree "$RUNNER_PID"
    wait "$RUNNER_PID" >/dev/null 2>&1 || true
    RUNNER_OWNED=0
  fi
  return "$status"
}

write_application_failure_receipt() {
  local receipt_status="$1"
  mkdir -p "$REPORTS_DIR"
  (cd "$ROOT_DIR" && go run ./autobahn/appreceipt -run-id "$RUN_ID" -direction "$DIRECTION" -agent "$AGENT" -command "$APP_COMMAND" -executable "$APP_EXECUTABLE" -expected-executable-sha256 "$EXPECTED_APP_SHA" -started "$APP_STARTED" -ended "$(date -u +%Y-%m-%dT%H:%M:%SZ)" -termination failure -pid "$APP_PID" -status "$receipt_status" -output "${REPORTS_DIR}/application-failure-receipt.json")
}

kill_owned_app() {
  [[ -z "${AUTOBAHN_OWNERSHIP_AUDIT_LOG:-}" ]] || printf '%s\n' "$APP_PID" >>"$AUTOBAHN_OWNERSHIP_AUDIT_LOG"
  kill_owned_tree "$APP_PID"
}

kill_owned_tree() {
  local pid="$1" child
  while read -r child; do [[ -z "$child" ]] || kill_owned_tree "$child"; done < <(pgrep -P "$pid" 2>/dev/null || true)
  kill "$pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_ready() {
  local pid="$1" deadline=$((SECONDS + READY_TIMEOUT))
  while (( SECONDS < deadline )); do
    kill -0 "$pid" >/dev/null 2>&1 || return 1
    nc -z 127.0.0.1 9001 >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

APP_STARTED=""; APP_ENDED=""; APP_STATUS=0; TERMINATION=natural
common_env=(AUTOBAHN_PROFILE=feature AUTOBAHN_AGENT="$AGENT" AUTOBAHN_REPORTS_DIR="$REPORTS_DIR" AUTOBAHN_RUN_ID="$RUN_ID" AUTOBAHN_IMAGE="$IMAGE" AUTOBAHN_NETWORK_MODE="$NETWORK_MODE" AUTOBAHN_CASE_DELAY="$EFFECTIVE_CASE_DELAY" AUTOBAHN_COMPLETION_FILE="$COMPLETION_FILE" AUTOBAHN_APPLICATION_COMMAND="$APP_COMMAND" AUTOBAHN_GENERATOR_EVIDENCE="$GENERATOR_EVIDENCE" AUTOBAHN_STRICT_EVIDENCE=1 AUTOBAHN_SKIP_PROVENANCE=1 AUTOBAHN_CLIENT_TIMEOUT="$CLIENT_TIMEOUT" AUTOBAHN_SERVER_TIMEOUT="$SERVER_TIMEOUT")
if [[ "$DIRECTION" == server ]]; then
  APP_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; "$@" & APP_PID=$!; APP_OWNED=1
  wait_ready "$APP_PID" || { echo "feature-run.sh: application did not become ready" >&2; exit 1; }
  env "${common_env[@]}" "${SCRIPT_DIR}/run.sh" server ws://127.0.0.1:9001
  kill_owned_app; wait "$APP_PID" >/dev/null 2>&1 || APP_STATUS=$?; APP_OWNED=0; TERMINATION=owned-cleanup
else
  env "${common_env[@]}" "${SCRIPT_DIR}/run.sh" client & RUNNER_PID=$!; RUNNER_OWNED=1
  wait_ready "$RUNNER_PID" || { echo "feature-run.sh: fuzzingserver did not become ready" >&2; exit 1; }
  APP_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; "$@" & APP_PID=$!; APP_OWNED=1
  deadline=$((SECONDS + APP_TIMEOUT))
  while kill -0 "$APP_PID" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then kill_owned_app; APP_STATUS=124; break; fi
    sleep 0.1
  done
  if wait "$APP_PID" >/dev/null 2>&1; then :; else observed=$?; [[ $APP_STATUS -eq 124 ]] || APP_STATUS=$observed; fi
  APP_OWNED=0
  [[ $APP_STATUS -eq 0 ]] || { write_application_failure_receipt "$APP_STATUS"; APP_PID=""; echo "feature-run.sh: application failed with status $APP_STATUS" >&2; exit "$APP_STATUS"; }
  touch "$COMPLETION_FILE"
  RUNNER_STATUS=0
  if wait "$RUNNER_PID"; then :; else RUNNER_STATUS=$?; fi
  RUNNER_OWNED=0; RUNNER_PID=""
  [[ $RUNNER_STATUS -eq 0 ]] || exit "$RUNNER_STATUS"
fi
APP_ENDED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$REPORTS_DIR"
RECEIPT="${REPORTS_DIR}/application-receipt.json"
(cd "$ROOT_DIR" && go run ./autobahn/appreceipt -run-id "$RUN_ID" -direction "$DIRECTION" -agent "$AGENT" -command "$APP_COMMAND" -executable "$APP_EXECUTABLE" -expected-executable-sha256 "$EXPECTED_APP_SHA" -started "$APP_STARTED" -ended "$APP_ENDED" -termination "$TERMINATION" -pid "$APP_PID" -status "$APP_STATUS" -output "$RECEIPT")
INDEX_SUBTREE=server; [[ "$DIRECTION" == client ]] && INDEX_SUBTREE=clients
IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
CONTAINER_ID="$(cat "${REPORTS_DIR}/${RUN_ID}-${DIRECTION}-container-id.txt")"
EFFECTIVE_NETWORK_MODE="$(cat "${REPORTS_DIR}/${RUN_ID}-${DIRECTION}-network-mode.txt")"
COMPLETION_MECHANISM=default-timeout
COMPLETION_STOP_REASON=""
COMPLETION_STOP_STATUS=0
if [[ "$DIRECTION" == client ]]; then
  COMPLETION_MECHANISM_PATH="${REPORTS_DIR}/${RUN_ID}-client-completion-mechanism.txt"
  COMPLETION_STOP_REASON_PATH="${REPORTS_DIR}/${RUN_ID}-client-completion-stop-reason.txt"
  COMPLETION_STOP_STATUS_PATH="${REPORTS_DIR}/${RUN_ID}-client-completion-stop-status.txt"
  [[ -f "$COMPLETION_MECHANISM_PATH" ]] && COMPLETION_MECHANISM="$(cat "$COMPLETION_MECHANISM_PATH")"
  [[ -f "$COMPLETION_STOP_REASON_PATH" ]] && COMPLETION_STOP_REASON="$(cat "$COMPLETION_STOP_REASON_PATH")"
  [[ -f "$COMPLETION_STOP_STATUS_PATH" ]] && COMPLETION_STOP_STATUS="$(cat "$COMPLETION_STOP_STATUS_PATH")"
fi
RUNNER_TIMEOUT="$SERVER_TIMEOUT"; [[ "$DIRECTION" == client ]] && RUNNER_TIMEOUT="$CLIENT_TIMEOUT"
(cd "$ROOT_DIR" && go run ./autobahn/provenance -run-id "$RUN_ID" -profile feature -direction "$DIRECTION" -agent "$AGENT" -index "${REPORTS_DIR}/${INDEX_SUBTREE}/index.json" -output "${REPORTS_DIR}/${INDEX_SUBTREE}/provenance.json" -command "$FULL_INVOCATION" -application-command "$APP_COMMAND" -application-receipt "$RECEIPT" -report-root "$REPORTS_DIR" -container-id "$CONTAINER_ID" -runner-timeout "$RUNNER_TIMEOUT" -application-timeout "$APP_TIMEOUT" -network-mode "$EFFECTIVE_NETWORK_MODE" -case-delay "$EFFECTIVE_CASE_DELAY" -completion-file "$COMPLETION_FILE" -completion-mechanism "$COMPLETION_MECHANISM" -completion-stop-reason "$COMPLETION_STOP_REASON" -completion-stop-status "$COMPLETION_STOP_STATUS" -status 0 -image "$IMAGE" -image-id "$IMAGE_ID" -started "$RUN_STARTED" -generator "$GENERATOR_EVIDENCE")
APP_PID=""; RUNNER_PID=""; RUNNER_OWNED=0
