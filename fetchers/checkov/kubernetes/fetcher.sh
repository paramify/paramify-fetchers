#!/bin/bash
#
# Checkov — Kubernetes IaC security scan
#
# Clones a git repo (generic — any host) and runs the local `checkov` CLI over its
# Kubernetes manifests (.yaml/.yml), emitting structured JSON evidence. One repo
# per invocation; the runner fans out across repos (supports_targets: true).
#
# Output: $EVIDENCE_DIR/checkov_kubernetes_<repo>.json
# Target env (per repo): CHECKOV_REPO_URL (required), CHECKOV_CLONE_BRANCH
# Secret (per repo):     GIT_CLONE_TOKEN (omit for public repos)
# Config env:            CHECKOV_SOFT_FAIL, CHECKOV_COMPACT, CHECKOV_SKIP_CHECKS,
#                        CHECKOV_SKIP_PATHS, CHECKOV_K8S_CHECKS, CHECKOV_EXTERNAL_CHECKS_DIR,
#                        CHECKOV_REPO_ID, CHECKOV_GIT_USERNAME
# Required tools:        git, checkov, jq
#
# Exit codes: 0 = scan completed (findings present or not — findings are evidence);
#             1 = could not acquire source / checkov failed to run / missing input.
#
set -o pipefail

COMPONENT="checkov_kubernetes"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Interim v0.x: load .env for the dev loop if present. The runner injects env directly.
[ -f .env ] && { set -a; . .env; set +a; }

. "$SCRIPT_DIR/../_shared/clone.sh"
# The one place a fetcher reports WHY it failed (docs/fetcher_contract_guide.md, step 6).
source "$(dirname "$0")/../../_lib/status.sh"
FETCHER="$COMPONENT"   # attributes report_failure's log line to this fetcher

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

log_info()  { printf '%s INFO %s %s\n'  "$(date -u +'%Y-%m-%d %H:%M:%S')" "$COMPONENT" "$*" >&2; }
log_error() { printf '%s ERROR %s %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$COMPONENT" "$*" >&2; }

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

CLONE_DIR=""; RAW=""; ERR=""; NORM=""
cleanup() {
    [ -n "$CLONE_DIR" ] && rm -rf "$CLONE_DIR"
    for f in "$RAW" "$ERR" "$NORM"; do [ -n "$f" ] && rm -f "$f"; done
}
trap cleanup EXIT

# --- inputs ---
REPO_URL="${CHECKOV_REPO_URL:-}"
BRANCH="${CHECKOV_CLONE_BRANCH:-main}"
TOKEN="${GIT_CLONE_TOKEN:-}"
GIT_USER="${CHECKOV_GIT_USERNAME:-oauth2}"
REPO_ID="${CHECKOV_REPO_ID:-evidence-fetchers-kubernetes}"

if [ -z "$REPO_URL" ]; then
    report_failure "CHECKOV_REPO_URL is not set" bad_config
    exit 1
fi
# checkov_require_tools names the missing tool(s) on stderr; report_failure gets
# the reason into $FETCHER_STATUS_FILE too.
checkov_require_tools "$COMPONENT" || {
    report_failure "required tool missing from PATH (this fetcher needs git, checkov and jq)" internal_error
    exit 1
}

_TARGET_ID="$(printf '%s' "$REPO_URL" | sed -e 's#^https\{0,1\}://##' -e 's#\.git$##' | tr -c 'A-Za-z0-9._-' '_')"
OUTPUT_JSON="$OUTPUT_DIR/${COMPONENT}_${_TARGET_ID}.json"

write_status_json() {
    local status="$1" message="$2" sha="${3:-unknown}"
    jq -n --arg repo "$REPO_URL" --arg branch "$BRANCH" --arg sha "$sha" --arg ts "$TIMESTAMP" \
          --arg status "$status" --arg msg "$message" --arg src "$REPO_URL" \
       '{
          metadata: {repo_url: $repo, branch: $branch, commit_sha: $sha, scan_timestamp: $ts},
          framework: "kubernetes", scan_timestamp: $ts, source_type: "git", source: $src,
          status: $status, message: $msg,
          summary: {passed_checks: 0, failed_checks: 0, skipped_checks: 0, total_checks: 0, aggregate_percentage: 0},
          results: []
        }' > "$OUTPUT_JSON"
}

# --- acquire source ---
if ! checkov_clone_repo "$REPO_URL" "$BRANCH" "$TOKEN" "$GIT_USER" "$COMPONENT"; then
    write_status_json error "git clone failed" "unknown"
    # No code: clone.sh discards git's stderr (it can carry a credentialed URL),
    # so a bad token, a missing repo and an unreachable host are indistinguishable.
    report_failure "git clone of $REPO_URL (branch $BRANCH, then default branch) failed - check the repo URL, the branch and GIT_CLONE_TOKEN"
    exit 1
fi
log_info "Cloned $REPO_URL @ ${COMMIT_SHA:0:12} (branch $BRANCH)"

# No manifests is meaningful evidence (not a failure).
if [ -z "$(find "$CLONE_DIR" \( -name '*.yaml' -o -name '*.yml' \) -type f -print -quit 2>/dev/null)" ]; then
    log_info "No Kubernetes manifest files found in $REPO_URL"
    write_status_json no_files "No Kubernetes manifest files found" "$COMMIT_SHA"
    exit 0
fi

# --- build checkov args ---
# No --quiet: it strips passed_checks, skipped_checks and parsing_errors from the JSON.
CHECKOV_ARGS="--framework kubernetes --output json --repo-id $REPO_ID --branch $BRANCH"
[ "${CHECKOV_SOFT_FAIL:-true}" = "true" ] && CHECKOV_ARGS="$CHECKOV_ARGS --soft-fail"
[ "${CHECKOV_COMPACT:-true}" = "true" ]   && CHECKOV_ARGS="$CHECKOV_ARGS --compact"
[ -n "${CHECKOV_K8S_CHECKS:-}" ]          && CHECKOV_ARGS="$CHECKOV_ARGS --check $CHECKOV_K8S_CHECKS"
if [ -n "${CHECKOV_EXTERNAL_CHECKS_DIR:-}" ] && [ -d "$CHECKOV_EXTERNAL_CHECKS_DIR" ]; then
    CHECKOV_ARGS="$CHECKOV_ARGS --external-checks-dir $CHECKOV_EXTERNAL_CHECKS_DIR"
fi

# Merge skip-checks: defaults file + CHECKOV_SKIP_CHECKS (k8s-prefixed only),
# minus any explicitly-requested checks.
SKIP_CHECKS_LIST=""
REQUESTED_CHECKS="${CHECKOV_K8S_CHECKS:-}"
add_skip() {
    local c="$1"; [ -z "$c" ] && return
    case ",$REQUESTED_CHECKS," in *",$c,"*) return ;; esac
    SKIP_CHECKS_LIST="${SKIP_CHECKS_LIST:+$SKIP_CHECKS_LIST,}$c"
}
DEFAULT_SKIP_CHECKS_FILE="$SCRIPT_DIR/../_shared/skip-checks-k8s.default.txt"
if [ -f "$DEFAULT_SKIP_CHECKS_FILE" ]; then
    while IFS= read -r c || [ -n "$c" ]; do
        c="$(printf '%s' "$c" | xargs)"; [ -z "$c" ] && continue
        case "$c" in \#*) continue ;; esac
        add_skip "$c"
    done < "$DEFAULT_SKIP_CHECKS_FILE"
fi
if [ -n "${CHECKOV_SKIP_CHECKS:-}" ]; then
    IFS=',' read -ra _U <<< "$CHECKOV_SKIP_CHECKS"
    for c in "${_U[@]}"; do
        c="$(printf '%s' "$c" | xargs)"
        case "$c" in CKV_K8S_*|CKV2_K8S_*) add_skip "$c" ;; esac
    done
fi
[ -n "$SKIP_CHECKS_LIST" ] && CHECKOV_ARGS="$CHECKOV_ARGS --skip-check $SKIP_CHECKS_LIST"

if [ -n "${CHECKOV_SKIP_PATHS:-}" ]; then
    for p in $(echo "$CHECKOV_SKIP_PATHS" | tr ',' ' '); do CHECKOV_ARGS="$CHECKOV_ARGS --skip-path $p"; done
fi

# --- run checkov ---
RAW="$(mktemp)"; ERR="$(mktemp)"; NORM="$(mktemp)"
log_info "Scanning Kubernetes manifests"
checkov --directory "$CLONE_DIR" $CHECKOV_ARGS > "$RAW" 2> "$ERR"

if ! jq -e '(if type=="array" then (.[0] // {}) else . end) | has("summary")' "$RAW" >/dev/null 2>&1; then
    ERR_HEAD="$(head -c 500 "$ERR" | tr '\n' ' ')"
    write_status_json error "checkov scan failed: $ERR_HEAD" "$COMMIT_SHA"
    report_failure "checkov produced no parseable result for $REPO_URL: $ERR_HEAD" internal_error
    exit 1
fi
# The kubernetes framework emits an array (one element per check_type); take the first.
jq 'if type=="array" then .[0] else . end' "$RAW" > "$NORM"

PASSED=$(jq '(.results.passed_checks // []) | length' "$NORM")
FAILED=$(jq '(.results.failed_checks // []) | length' "$NORM")
SKIPPED=$(jq '(.results.skipped_checks // []) | length' "$NORM")
TOTAL=$((PASSED + FAILED + SKIPPED))
PCT=$(awk "BEGIN { if ($TOTAL > 0) printf \"%.2f\", ($PASSED / $TOTAL) * 100; else print 0 }")

jq --arg repo "$REPO_URL" --arg branch "$BRANCH" --arg sha "$COMMIT_SHA" --arg ts "$TIMESTAMP" \
   --arg src "$REPO_URL" \
   --argjson passed "$PASSED" --argjson failed "$FAILED" --argjson skipped "$SKIPPED" \
   --argjson total "$TOTAL" --argjson pct "$PCT" \
   '. + {
       metadata: {repo_url: $repo, branch: $branch, commit_sha: $sha, scan_timestamp: $ts},
       framework: "kubernetes", scan_timestamp: $ts, source_type: "git", source: $src,
       status: "success",
       summary: ((.summary // {}) + {
           passed_checks: $passed, failed_checks: $failed, skipped_checks: $skipped,
           total_checks: $total, aggregate_percentage: $pct
       })
   }' "$NORM" > "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON (passed=$PASSED failed=$FAILED skipped=$SKIPPED)"
exit 0
