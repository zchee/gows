# Sourced by run.sh and feature-run.sh; not executable on its own.

# verify_generator_evidence checks that $2 is <absolute-path>@sha256:<64
# lowercase hex> naming a regular file, reached without symlinks, whose
# SHA-256 is that digest. $1 is the subject that starts each error message,
# so each script keeps its own wording.
verify_generator_evidence() {
  local subject="$1" evidence="$2"
  [[ "$evidence" =~ ^(/.*)@sha256:([0-9a-f]{64})$ ]] || { echo "${subject} must be <absolute-path>@sha256:<64 lowercase hex>" >&2; return 1; }
  local path="${BASH_REMATCH[1]}" sha="${BASH_REMATCH[2]}"
  [[ -f "$path" && "$(realpath "$path")" == "$path" && "$(shasum -a 256 "$path" | awk '{print $1}')" == "$sha" ]] || { echo "${subject} file/hash mismatch" >&2; return 1; }
}
