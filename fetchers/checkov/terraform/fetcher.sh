#!/bin/bash
#
# Checkov — Terraform IaC security scan
#
# Clones a git repo (generic — any host) and runs the local `checkov` CLI over its
# Terraform files, emitting structured JSON evidence. One repo per invocation; the
# runner fans out across repos (fetcher.yaml: supports_targets: true).
#
# Output: $EVIDENCE_DIR/checkov_terraform_<repo>.json
# Target env (per repo): CHECKOV_REPO_URL (required), CHECKOV_CLONE_BRANCH
# Secret (per repo):     GIT_CLONE_TOKEN (omit for public repos)
# Config env:            CHECKOV_SOFT_FAIL, CHECKOV_COMPACT, CHECKOV_SKIP_CHECKS,
#                        CHECKOV_USE_DEFAULT_SKIP_CHECKS, CHECKOV_SKIP_RESOURCES,
#                        CHECKOV_SKIP_PATHS, CHECKOV_TERRAFORM_CHECKS,
#                        CHECKOV_DOWNLOAD_EXTERNAL_MODULES, CHECKOV_EVALUATE_VARIABLES,
#                        CHECKOV_EXTERNAL_CHECKS_DIR, CHECKOV_EXTERNAL_MODULES_PATH,
#                        CHECKOV_REPO_ID, CHECKOV_GIT_USERNAME, CHECKOV_TERRAFORM_PLAN_FILE,
#                        CHECKOV_DEEP_ANALYSIS
# Required tools:        git, checkov, jq
#
# Exit codes: 0 = scan completed (findings present or not — findings are evidence);
#             1 = could not acquire source / checkov failed to run / missing input.
#
set -o pipefail

COMPONENT="checkov_terraform"
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

CLONE_DIR=""; RAW=""; ERR=""; NORM=""; PAT=""
cleanup() {
    [ -n "$CLONE_DIR" ] && rm -rf "$CLONE_DIR"
    for f in "$RAW" "$ERR" "$NORM" "$PAT"; do [ -n "$f" ] && rm -f "$f"; done
}
trap cleanup EXIT

# --- inputs ---
REPO_URL="${CHECKOV_REPO_URL:-}"
BRANCH="${CHECKOV_CLONE_BRANCH:-main}"
TOKEN="${GIT_CLONE_TOKEN:-}"
GIT_USER="${CHECKOV_GIT_USERNAME:-oauth2}"
REPO_ID="${CHECKOV_REPO_ID:-evidence-fetchers-terraform}"

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

# Per-repo output filename.
_TARGET_ID="$(printf '%s' "$REPO_URL" | sed -e 's#^https\{0,1\}://##' -e 's#\.git$##' | tr -c 'A-Za-z0-9._-' '_')"
OUTPUT_JSON="$OUTPUT_DIR/${COMPONENT}_${_TARGET_ID}.json"

# --- skip-checks: the shipped defaults file (unless use_default_skip_checks is
# false) + CHECKOV_SKIP_CHECKS, minus any explicitly-requested checks. A check
# passed to --skip-check is absent from checkov's output (not even under
# skipped_checks), so the effective list is recorded in metadata.
SKIP_CHECKS_LIST=""
REQUESTED_CHECKS="${CHECKOV_TERRAFORM_CHECKS:-}"
add_skip() {
    local c="$1"; [ -z "$c" ] && return
    case ",$REQUESTED_CHECKS," in *",$c,"*) return ;; esac
    case ",$SKIP_CHECKS_LIST," in *",$c,"*) return ;; esac
    SKIP_CHECKS_LIST="${SKIP_CHECKS_LIST:+$SKIP_CHECKS_LIST,}$c"
}
DEFAULT_SKIPS_APPLIED=true
[ "${CHECKOV_USE_DEFAULT_SKIP_CHECKS:-true}" = "false" ] && DEFAULT_SKIPS_APPLIED=false
DEFAULT_SKIP_CHECKS_FILE="$SCRIPT_DIR/../_shared/skip-checks.default.txt"
if [ "$DEFAULT_SKIPS_APPLIED" = "true" ] && [ -f "$DEFAULT_SKIP_CHECKS_FILE" ]; then
    while IFS= read -r c || [ -n "$c" ]; do
        c="$(printf '%s' "$c" | xargs)"; [ -z "$c" ] && continue
        case "$c" in \#*) continue ;; esac
        add_skip "$c"
    done < "$DEFAULT_SKIP_CHECKS_FILE"
fi
if [ -n "${CHECKOV_SKIP_CHECKS:-}" ]; then
    IFS=',' read -ra _U <<< "$CHECKOV_SKIP_CHECKS"
    for c in "${_U[@]}"; do add_skip "$(printf '%s' "$c" | xargs)"; done
fi

# --- skip-resources (defaults file + config), applied post-scan ---
SKIP_RESOURCES_LIST=""
DEFAULT_SKIP_RES_FILE="$SCRIPT_DIR/../_shared/skip-resources.default.txt"
if [ -f "$DEFAULT_SKIP_RES_FILE" ]; then
    while IFS= read -r r || [ -n "$r" ]; do
        r="$(printf '%s' "$r" | xargs)"; [ -z "$r" ] && continue
        case "$r" in \#*) continue ;; esac
        SKIP_RESOURCES_LIST="${SKIP_RESOURCES_LIST:+$SKIP_RESOURCES_LIST,}$r"
    done < "$DEFAULT_SKIP_RES_FILE"
fi
[ -n "${CHECKOV_SKIP_RESOURCES:-}" ] && SKIP_RESOURCES_LIST="${SKIP_RESOURCES_LIST:+$SKIP_RESOURCES_LIST,}$CHECKOV_SKIP_RESOURCES"

# What was actually checked out; checkov_clone_repo overwrites these.
SCANNED_BRANCH="$BRANCH"; BRANCH_FALLBACK=false

# Provenance + scan configuration, shared by every result this fetcher writes.
metadata_json() {
    jq -n --arg repo "$REPO_URL" --arg branch "$SCANNED_BRANCH" --arg requested "$BRANCH" \
          --argjson fallback "$BRANCH_FALLBACK" --arg sha "${1:-unknown}" --arg ts "$TIMESTAMP" \
          --arg skips "$SKIP_CHECKS_LIST" --argjson defaults "$DEFAULT_SKIPS_APPLIED" \
          --arg skipres "$SKIP_RESOURCES_LIST" \
       '{repo_url: $repo, branch: $branch, requested_branch: $requested, branch_fallback: $fallback,
         commit_sha: $sha, scan_timestamp: $ts,
         skip_checks: ($skips | split(",") | map(select(. != ""))),
         default_skip_checks_applied: $defaults,
         skip_resources: ($skipres | split(",") | map(select(. != "")))}'
}

# Emit a minimal (no-findings / error) result. The runner wraps payloads in the envelope.
write_status_json() {
    local status="$1" message="$2" sha="${3:-unknown}"
    jq -n --argjson meta "$(metadata_json "$sha")" --arg ts "$TIMESTAMP" \
          --arg status "$status" --arg msg "$message" --arg src "$REPO_URL" \
       '{
          metadata: $meta,
          framework: "terraform", scan_timestamp: $ts, source_type: "git", source: $src,
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
log_info "Cloned $REPO_URL @ ${COMMIT_SHA:0:12} (branch $SCANNED_BRANCH)"

# --- scan mode: plan file vs directory ---
SCAN_MODE="directory"
PLAN_FILE=""
if [ -n "${CHECKOV_TERRAFORM_PLAN_FILE:-}" ] && [ -f "$CLONE_DIR/$CHECKOV_TERRAFORM_PLAN_FILE" ]; then
    PLAN_FILE="$CLONE_DIR/$CHECKOV_TERRAFORM_PLAN_FILE"; SCAN_MODE="plan"
elif [ -f "$CLONE_DIR/tfplan.json" ]; then
    PLAN_FILE="$CLONE_DIR/tfplan.json"; SCAN_MODE="plan"
fi

# In directory mode, no .tf files is meaningful evidence (not a failure).
if [ "$SCAN_MODE" = "directory" ] && \
   [ -z "$(find "$CLONE_DIR" \( -name '*.tf' -o -name '*.tf.json' \) -type f -print -quit 2>/dev/null)" ]; then
    log_info "No Terraform files found in $REPO_URL"
    write_status_json no_files "No Terraform files found" "$COMMIT_SHA"
    exit 0
fi

# --- build checkov args ---
CHECKOV_ARGS="--framework terraform --output json --quiet --repo-id $REPO_ID --branch $SCANNED_BRANCH"
[ "${CHECKOV_SOFT_FAIL:-true}" = "true" ] && CHECKOV_ARGS="$CHECKOV_ARGS --soft-fail"
[ "${CHECKOV_COMPACT:-true}" = "true" ]   && CHECKOV_ARGS="$CHECKOV_ARGS --compact"
[ "${CHECKOV_DOWNLOAD_EXTERNAL_MODULES:-true}" = "true" ] && export DOWNLOAD_EXTERNAL_MODULES=True
[ "${CHECKOV_EVALUATE_VARIABLES:-true}" = "true" ]        && export CKV_EVAL_VARS=True
[ -n "${CHECKOV_EXTERNAL_MODULES_PATH:-}" ] && CHECKOV_ARGS="$CHECKOV_ARGS --external-modules-download-path $CHECKOV_EXTERNAL_MODULES_PATH"
[ -n "${CHECKOV_TERRAFORM_CHECKS:-}" ]      && CHECKOV_ARGS="$CHECKOV_ARGS --check $CHECKOV_TERRAFORM_CHECKS"
if [ -n "${CHECKOV_EXTERNAL_CHECKS_DIR:-}" ] && [ -d "$CHECKOV_EXTERNAL_CHECKS_DIR" ]; then
    CHECKOV_ARGS="$CHECKOV_ARGS --external-checks-dir $CHECKOV_EXTERNAL_CHECKS_DIR"
fi

[ -n "$SKIP_CHECKS_LIST" ] && CHECKOV_ARGS="$CHECKOV_ARGS --skip-check $SKIP_CHECKS_LIST"

if [ -n "${CHECKOV_SKIP_PATHS:-}" ]; then
    for p in $(echo "$CHECKOV_SKIP_PATHS" | tr ',' ' '); do CHECKOV_ARGS="$CHECKOV_ARGS --skip-path $p"; done
fi

if [ "$SCAN_MODE" = "plan" ]; then
    CHECKOV_ARGS="$CHECKOV_ARGS --repo-root-for-plan-enrichment $CLONE_DIR"
    [ "${CHECKOV_DEEP_ANALYSIS:-false}" = "true" ] && CHECKOV_ARGS="$CHECKOV_ARGS --deep-analysis"
fi

# --- run checkov ---
RAW="$(mktemp)"; ERR="$(mktemp)"; NORM="$(mktemp)"
if [ "$SCAN_MODE" = "plan" ]; then
    log_info "Scanning Terraform plan file ($PLAN_FILE)"
    checkov --file "$PLAN_FILE" $CHECKOV_ARGS > "$RAW" 2> "$ERR"
else
    log_info "Scanning Terraform directory"
    checkov --directory "$CLONE_DIR" $CHECKOV_ARGS > "$RAW" 2> "$ERR"
fi

# Success is "checkov produced a parseable result with a summary" — robust whether
# or not --soft-fail is on. checkov may emit a single object or a per-framework array.
if ! jq -e '(if type=="array" then (.[0] // {}) else . end) | has("summary")' "$RAW" >/dev/null 2>&1; then
    ERR_HEAD="$(head -c 500 "$ERR" | tr '\n' ' ')"
    write_status_json error "checkov scan failed: $ERR_HEAD" "$COMMIT_SHA"
    report_failure "checkov produced no parseable result for $REPO_URL: $ERR_HEAD" internal_error
    exit 1
fi
jq 'if type=="array" then .[0] else . end' "$RAW" > "$NORM"

# --- post-scan skip-resources filter, recompute summary ---
# A failed check on a matching resource is moved to skipped_checks, marked
# SKIPPED with the pattern that matched, so it stays in total_checks and the
# aggregate percentage. Deleting it would raise the pass rate.
RESOURCE_SKIPPED=0
if [ -n "$SKIP_RESOURCES_LIST" ]; then
    PAT="$(mktemp)"
    FAILED_BEFORE=$(jq '(.results.failed_checks // []) | length' "$NORM")
    # Empty entries (a trailing comma) are dropped: an empty pattern matches everything.
    echo "$SKIP_RESOURCES_LIST" | tr ',' '\n' | jq -R 'select(length > 0) | {pattern: ., regex: gsub("\\*"; ".*")}' | jq -s . > "$PAT"
    jq --slurpfile pats "$PAT" '
        def match_pattern($r): first($pats[0][] | select(. as $p | $r | test($p.regex)) | .pattern) // null;
        ((.results.failed_checks // []) | map(. + {_skip_pattern: (
            (.resource // "") as $r | if $r == "" then null else match_pattern($r) end)})) as $failed
        | .results.failed_checks = ($failed | map(select(._skip_pattern == null) | del(._skip_pattern)))
        | .results.skipped_checks = ((.results.skipped_checks // []) + ($failed
            | map(select(._skip_pattern != null)
                  | ._skip_pattern as $p
                  | del(._skip_pattern)
                  | .check_result = ((.check_result // {}) + {
                        result: "SKIPPED",
                        suppress_comment: ("resource matches skip_resources pattern " + $p)}))))
    ' "$NORM" > "$NORM.f" && mv "$NORM.f" "$NORM"
    RESOURCE_SKIPPED=$(( FAILED_BEFORE - $(jq '(.results.failed_checks // []) | length' "$NORM") ))
fi

PASSED=$(jq '(.results.passed_checks // []) | length' "$NORM")
FAILED=$(jq '(.results.failed_checks // []) | length' "$NORM")
SKIPPED=$(jq '(.results.skipped_checks // []) | length' "$NORM")
TOTAL=$((PASSED + FAILED + SKIPPED))
PCT=$(awk "BEGIN { if ($TOTAL > 0) printf \"%.2f\", ($PASSED / $TOTAL) * 100; else print 0 }")

jq --argjson meta "$(metadata_json "$COMMIT_SHA")" --arg ts "$TIMESTAMP" \
   --arg src "$REPO_URL" --arg mode "$SCAN_MODE" \
   --argjson passed "$PASSED" --argjson failed "$FAILED" --argjson skipped "$SKIPPED" \
   --argjson total "$TOTAL" --argjson pct "$PCT" --argjson resskipped "$RESOURCE_SKIPPED" \
   '. + {
       metadata: $meta,
       framework: "terraform", scan_timestamp: $ts, source_type: "git", source: $src, scan_mode: $mode,
       status: "success",
       summary: ((.summary // {}) + {
           passed_checks: $passed, failed_checks: $failed, skipped_checks: $skipped,
           total_checks: $total, aggregate_percentage: $pct,
           skipped_by_resource_filter: $resskipped
       })
   }' "$NORM" > "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON (passed=$PASSED failed=$FAILED skipped=$SKIPPED, $RESOURCE_SKIPPED of them by skip_resources)"
exit 0
