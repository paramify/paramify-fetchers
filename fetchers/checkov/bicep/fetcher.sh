#!/bin/bash
#
# Checkov — Bicep / ARM IaC security scan
#
# Clones a git repo (generic — any host, including Azure DevOps), or with source_type
# tfvc downloads an Azure DevOps TFVC folder through the REST API, and runs the local
# `checkov` CLI over its Bicep files and ARM templates, emitting structured JSON
# evidence. One source per invocation; the runner fans out across targets.
#
# Output: $EVIDENCE_DIR/checkov_bicep_<source>.json
# Target env (per source): CHECKOV_REPO_URL (required), CHECKOV_CLONE_BRANCH, CHECKOV_SOURCE_TYPE,
#                          CHECKOV_TFVC_PATH, CHECKOV_TFVC_VERSION
# Secret (per source):     GIT_CLONE_TOKEN (git) or TFVC_TOKEN (tfvc); omit for public sources
# Config env:            CHECKOV_SOFT_FAIL, CHECKOV_COMPACT, CHECKOV_SKIP_CHECKS,
#                        CHECKOV_USE_DEFAULT_SKIP_CHECKS, CHECKOV_SKIP_RESOURCES,
#                        CHECKOV_SKIP_PATHS, CHECKOV_BICEP_CHECKS,
#                        CHECKOV_EXTERNAL_CHECKS_DIR, CHECKOV_REPO_ID, CHECKOV_GIT_USERNAME
# Required tools:        checkov, jq, plus git (git source) or curl + unzip (tfvc source)
#
# Exit codes: 0 = at least one check ran and every Bicep/ARM file parsed (findings are evidence);
#             1 = could not fetch the source / checkov failed / nothing to scan / zero checks ran /
#                 some files could not be parsed. Nothing scanned must never read as clean.
#
set -o pipefail

COMPONENT="checkov_bicep"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Interim v0.x: load .env for the dev loop if present. The runner injects env directly.
[ -f .env ] && { set -a; . .env; set +a; }

. "$SCRIPT_DIR/../_shared/clone.sh"
. "$SCRIPT_DIR/../_shared/tfvc.sh"
source "$(dirname "$0")/../../_lib/status.sh"
FETCHER="$COMPONENT"

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

log_info()  { printf '%s INFO %s %s\n'  "$(date -u +'%Y-%m-%d %H:%M:%S')" "$COMPONENT" "$*" >&2; }

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# A private repo with no token must fail, not wait on a credential prompt.
export GIT_TERMINAL_PROMPT=0

CLONE_DIR=""; RAW=""; ERR=""; NORM=""
cleanup() {
    [ -n "$CLONE_DIR" ] && rm -rf "$CLONE_DIR"
    for f in "$RAW" "$ERR" "$NORM" "${NORM:+$NORM.f}"; do [ -n "$f" ] && rm -f "$f"; done
}
trap cleanup EXIT

# --- inputs ---
# Azure DevOps clone URLs carry an org@ prefix that breaks token injection; drop any userinfo.
REPO_URL="$(printf '%s' "${CHECKOV_REPO_URL:-}" | sed -E 's#^(https?://)[^/@]*@#\1#')"
SOURCE_TYPE="$(printf '%s' "${CHECKOV_SOURCE_TYPE:-git}" | tr '[:upper:]' '[:lower:]')"
BRANCH="${CHECKOV_CLONE_BRANCH:-main}"
TOKEN="${GIT_CLONE_TOKEN:-}"
GIT_USER="${CHECKOV_GIT_USERNAME:-oauth2}"
TFVC_PATH="${CHECKOV_TFVC_PATH:-}"
TFVC_VERSION="${CHECKOV_TFVC_VERSION:-latest}"
REPO_ID="${CHECKOV_REPO_ID:-evidence-fetchers-bicep}"

if [ -z "$REPO_URL" ]; then
    report_failure "CHECKOV_REPO_URL is not set" bad_config
    exit 1
fi
case "$SOURCE_TYPE" in
    git)
        TOOLS="git checkov jq" ;;
    tfvc)
        TOOLS="curl unzip checkov jq"
        REPO_URL="${REPO_URL%/}"
        case "$REPO_URL" in https://*|http://*) ;; *)
            report_failure "source_type tfvc needs repo_url to be the Azure DevOps project URL (https://dev.azure.com/<org>/<project>), got $REPO_URL" bad_config
            exit 1 ;;
        esac
        case "$TFVC_PATH" in '$/'?*) ;; *)
            report_failure "source_type tfvc needs tfvc_path, a TFVC server path such as \$/<project>/infra (got '${TFVC_PATH}')" bad_config
            exit 1 ;;
        esac
        TFVC_VERSION="$(printf '%s' "$TFVC_VERSION" | tr '[:upper:]' '[:lower:]')"
        if ! [[ "$TFVC_VERSION" =~ ^(latest|c?[0-9]+)$ ]]; then
            report_failure "tfvc_version must be latest or a changeset number such as 1234 (got '$TFVC_VERSION')" bad_config
            exit 1
        fi
        TFVC_VERSION="${TFVC_VERSION#c}" ;;
    *)
        report_failure "source_type must be git or tfvc (got '$SOURCE_TYPE')" bad_config
        exit 1 ;;
esac
# shellcheck disable=SC2086
checkov_require_tools "$COMPONENT" $TOOLS || {
    report_failure "required tool missing from PATH (a $SOURCE_TYPE source needs ${TOOLS// /, })" internal_error
    exit 1
}

_TARGET_SRC="$REPO_URL"; [ "$SOURCE_TYPE" = "tfvc" ] && _TARGET_SRC="$REPO_URL/$TFVC_PATH"
_TARGET_ID="$(printf '%s' "$_TARGET_SRC" | sed -e 's#^https\{0,1\}://##' -e 's#\.git$##' | tr -c 'A-Za-z0-9._-' '_')"
OUTPUT_JSON="$OUTPUT_DIR/${COMPONENT}_${_TARGET_ID}.json"

# --- skip-checks: the shipped defaults (unless use_default_skip_checks is false) + CHECKOV_SKIP_CHECKS,
# minus explicitly-requested checks. --skip-check leaves no trace in checkov's output, so it goes in metadata.
SKIP_CHECKS_LIST=""
REQUESTED_CHECKS="${CHECKOV_BICEP_CHECKS:-}"
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

# What was actually fetched; checkov_clone_repo / checkov_fetch_tfvc overwrite these.
SCANNED_BRANCH="$BRANCH"; BRANCH_FALLBACK=false; COMMIT_SHA=unknown; CHANGESET=""; CHANGESET_DATE=""

# Provenance + scan configuration, shared by every result this fetcher writes. A tfvc source
# records its folder and changeset where a git source records its branch and commit.
metadata_json() {
    jq -n --arg type "$SOURCE_TYPE" --arg repo "$REPO_URL" --arg branch "$SCANNED_BRANCH" --arg requested "$BRANCH" \
          --argjson fallback "$BRANCH_FALLBACK" --arg sha "$COMMIT_SHA" --arg ts "$TIMESTAMP" \
          --arg path "$TFVC_PATH" --arg version "$TFVC_VERSION" \
          --argjson changeset "${CHANGESET:-null}" --arg csdate "$CHANGESET_DATE" \
          --arg skips "$SKIP_CHECKS_LIST" --argjson defaults "$DEFAULT_SKIPS_APPLIED" \
          --arg skipres "$SKIP_RESOURCES_LIST" --arg skippaths "${CHECKOV_SKIP_PATHS:-}" \
       '{source_type: $type, repo_url: $repo}
        + (if $type == "tfvc" then
             {tfvc_path: $path, requested_version: $version, changeset: $changeset,
              changeset_date: (if $csdate == "" then null else $csdate end)}
           else
             {branch: $branch, requested_branch: $requested, branch_fallback: $fallback, commit_sha: $sha}
           end)
        + {scan_timestamp: $ts, partial_failure: false, api_failures: [],
         skip_checks: ($skips | split(",") | map(select(. != ""))),
         default_skip_checks_applied: $defaults,
         skip_resources: ($skipres | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != ""))),
         skip_paths: ($skippaths | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != "")))}'
}

# A result with nothing scanned: counts are null, not 0, so no reader can take it for a clean scan.
write_status_json() {
    local status="$1" message="$2" bicep="${3:-null}" arm="${4:-null}"
    jq -n --argjson meta "$(metadata_json)" --arg repo "$REPO_URL" --arg ts "$TIMESTAMP" \
          --arg status "$status" --arg msg "$message" --argjson bicep "$bicep" --argjson arm "$arm" \
       '{
          metadata: $meta,
          framework: "bicep,arm", scan_timestamp: $ts, source_type: $meta.source_type, source: $repo,
          file_counts: {bicep: $bicep, arm_templates: $arm},
          status: $status, message: $msg,
          summary: {passed_checks: null, failed_checks: null, skipped_checks: null, total_checks: null,
                    aggregate_percentage: null, parsing_errors: null, resource_count: null,
                    skipped_by_resource_filter: null, by_framework: {}},
          results: {passed_checks: [], failed_checks: [], skipped_checks: [], parsing_errors: []}
        }' > "$OUTPUT_JSON"
}

# --- acquire source ---
if [ "$SOURCE_TYPE" = "tfvc" ]; then
    if ! checkov_fetch_tfvc "$REPO_URL" "$TFVC_PATH" "$TFVC_VERSION" "${TFVC_TOKEN:-}"; then
        write_status_json error "TFVC download failed: $TFVC_ERROR"
        report_failure "TFVC download of $TFVC_PATH from $REPO_URL (version $TFVC_VERSION) failed: $TFVC_ERROR" "$TFVC_ERROR_CODE"
        exit 1
    fi
    WHERE="$TFVC_PATH in $REPO_URL (changeset $CHANGESET)"
    log_info "Downloaded $WHERE"
else
    if ! checkov_clone_repo "$REPO_URL" "$BRANCH" "$TOKEN" "$GIT_USER" "$COMPONENT"; then
        write_status_json error "git clone failed"
        # No code: clone.sh discards git's stderr (it can carry a credentialed URL).
        report_failure "git clone of $REPO_URL (branch $BRANCH, then default branch) failed - check the repo URL, the branch and GIT_CLONE_TOKEN"
        exit 1
    fi
    WHERE="$REPO_URL (branch $SCANNED_BRANCH, commit ${COMMIT_SHA:0:12})"
    log_info "Cloned $REPO_URL @ ${COMMIT_SHA:0:12} (branch $SCANNED_BRANCH)"
fi

# checkov's ARM runner reads every .json; only deploymentTemplate schemas are templates (not parameter files).
BICEP_FILES=$(find "$CLONE_DIR" -path "$CLONE_DIR/.git" -prune -o -type f -name '*.bicep' -print | wc -l | tr -d ' ')
ARM_FILES=$(grep -rlIiE --include='*.json' --exclude-dir=.git 'deploymentTemplate\.json' "$CLONE_DIR" 2>/dev/null | wc -l | tr -d ' ')

if [ "$BICEP_FILES" -eq 0 ] && [ "$ARM_FILES" -eq 0 ]; then
    MSG="No Bicep (.bicep) or ARM template (.json with a deploymentTemplate \$schema) files in $WHERE; nothing was scanned"
    write_status_json no_files "$MSG" 0 0
    log_info "Evidence saved to $OUTPUT_JSON (status=no_files)"
    report_failure "$MSG - check the source and its path or branch, or use checkov_terraform if this repo is Terraform" bad_config
    exit 1
fi

# --- build checkov args ---
# An array, so a value with spaces (a skip path, the checks dir) stays one argument.
# No --quiet: it strips passed_checks, skipped_checks and parsing_errors from the JSON.
CHECKOV_ARGS=(--framework bicep,arm --output json --repo-id "$REPO_ID")
[ "$SOURCE_TYPE" = "git" ]                && CHECKOV_ARGS+=(--branch "$SCANNED_BRANCH")
[ "${CHECKOV_SOFT_FAIL:-true}" = "true" ] && CHECKOV_ARGS+=(--soft-fail)
[ "${CHECKOV_COMPACT:-true}" = "true" ]   && CHECKOV_ARGS+=(--compact)
[ -n "${CHECKOV_BICEP_CHECKS:-}" ]        && CHECKOV_ARGS+=(--check "$CHECKOV_BICEP_CHECKS")
if [ -n "${CHECKOV_EXTERNAL_CHECKS_DIR:-}" ] && [ -d "$CHECKOV_EXTERNAL_CHECKS_DIR" ]; then
    CHECKOV_ARGS+=(--external-checks-dir "$CHECKOV_EXTERNAL_CHECKS_DIR")
fi

[ -n "$SKIP_CHECKS_LIST" ] && CHECKOV_ARGS+=(--skip-check "$SKIP_CHECKS_LIST")

# Each comma-separated entry, trimmed, is one --skip-path; metadata.skip_paths splits the same way.
if [ -n "${CHECKOV_SKIP_PATHS:-}" ]; then
    IFS=',' read -ra _P <<< "$CHECKOV_SKIP_PATHS"
    for p in "${_P[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"; p="${p%"${p##*[![:space:]]}"}"
        [ -n "$p" ] && CHECKOV_ARGS+=(--skip-path "$p")
    done
fi

# --- run checkov ---
RAW="$(mktemp)"; ERR="$(mktemp)"; NORM="$(mktemp)"
log_info "Scanning $BICEP_FILES Bicep and $ARM_FILES ARM template files"
checkov --directory "$CLONE_DIR" "${CHECKOV_ARGS[@]}" > "$RAW" 2> "$ERR"

# One report per framework with results: an array for both, an object for one, a bare summary for none.
if ! jq -e 'if type=="array" then all(.[]; type=="object" and has("summary"))
            elif type=="object" then has("summary") or has("passed") else false end' "$RAW" >/dev/null 2>&1; then
    ERR_TAIL="$(tail -c 500 "$ERR" | tr '\n' ' ')"
    write_status_json error "checkov scan failed: $ERR_TAIL" "$BICEP_FILES" "$ARM_FILES"
    report_failure "checkov produced no parseable result for $WHERE: $ERR_TAIL" internal_error
    exit 1
fi

# Merge the per-framework reports, tagging each check with its framework and making paths repo-relative.
jq --arg root "$CLONE_DIR/" '
    (if type=="array" then . elif has("check_type") then [.] else [] end) as $reports
    | def tagged($k): [$reports[] | .check_type as $t | (.results[$k] // [])[] | . + {check_type: $t}];
    {
      resource_counts: ($reports | map({key: .check_type, value: (.summary.resource_count // 0)}) | from_entries),
      results: {
        passed_checks: tagged("passed_checks"),
        failed_checks: tagged("failed_checks"),
        skipped_checks: tagged("skipped_checks"),
        parsing_errors: [$reports[] | .check_type as $t | (.results.parsing_errors // [])[]
                         | {check_type: $t, file_path: (if startswith($root) then "/" + ltrimstr($root) else . end)}]
      }
    }' "$RAW" > "$NORM" || {
    write_status_json error "could not merge checkov's framework reports" "$BICEP_FILES" "$ARM_FILES"
    report_failure "could not merge checkov's bicep/arm reports for $WHERE" internal_error
    exit 1
}

# --- post-scan skip-resources filter ---
# A failed check on a matching resource moves to skipped_checks (SKIPPED, naming the pattern), so it
# stays in total_checks; deleting it would raise the pass rate. Each pattern is a whole-name glob, * the only wildcard.
RESOURCE_SKIPPED=0
if [ -n "$SKIP_RESOURCES_LIST" ]; then
    if ! jq --arg list "$SKIP_RESOURCES_LIST" '
        ($list | split(",") | map(gsub("^\\s+|\\s+$"; "") | select(length > 0)
            | {pattern: ., regex: ("^" + (gsub("(?<c>[.+?^${}()|\\[\\]\\\\])"; "\\\(.c)") | gsub("\\*"; ".*")) + "$")})) as $pats
        | def matched($r): first($pats[] | select(. as $p | $r | test($p.regex)) | .pattern) // null;
        (.results.failed_checks | map(. + {_skip: ((.resource // "") as $r | if $r == "" then null else matched($r) end)})) as $failed
        | .results.failed_checks = ($failed | map(select(._skip == null) | del(._skip)))
        | .results.skipped_checks += ($failed | map(select(._skip != null) | ._skip as $p | del(._skip)
            | .check_result = ((.check_result // {}) + {result: "SKIPPED",
                                suppress_comment: ("resource matches skip_resources pattern " + $p)})))
    ' "$NORM" > "$NORM.f"; then
        MSG="skip_resources filter failed for patterns: $SKIP_RESOURCES_LIST"
        write_status_json error "$MSG" "$BICEP_FILES" "$ARM_FILES"
        report_failure "$MSG" bad_config
        exit 1
    fi
    RESOURCE_SKIPPED=$(( $(jq '.results.failed_checks | length' "$NORM") - $(jq '.results.failed_checks | length' "$NORM.f") ))
    mv "$NORM.f" "$NORM"
fi

PASSED=$(jq '.results.passed_checks | length' "$NORM")
FAILED=$(jq '.results.failed_checks | length' "$NORM")
SKIPPED=$(jq '.results.skipped_checks | length' "$NORM")
PARSE_ERRORS=$(jq '.results.parsing_errors | length' "$NORM")
TOTAL=$((PASSED + FAILED + SKIPPED))
FILES=$((BICEP_FILES + ARM_FILES))

if [ "$TOTAL" -eq 0 ]; then
    STATUS="no_checks"
    MSG="checkov evaluated 0 checks over $BICEP_FILES Bicep and $ARM_FILES ARM template files in $WHERE; nothing was scanned ($PARSE_ERRORS of them failed to parse; resources declared only through registry modules such as br/public:avm are not visible to checkov)"
elif [ "$PARSE_ERRORS" -gt 0 ]; then
    STATUS="partial"
    MSG="checkov could not parse $PARSE_ERRORS of $FILES Bicep/ARM files in $WHERE, so they were not scanned (listed in results.parsing_errors; once reviewed, exclude them with skip_paths)"
else
    STATUS="success"
    MSG=""
fi

jq --argjson meta "$(metadata_json)" --arg repo "$REPO_URL" --arg ts "$TIMESTAMP" \
   --arg status "$STATUS" --arg msg "$MSG" --argjson resskipped "$RESOURCE_SKIPPED" \
   --argjson bicep "$BICEP_FILES" --argjson arm "$ARM_FILES" \
   '(.results.parsing_errors | map({operation: "checkov_parse", type: "parsing_error",
                                    message: "\(.check_type): \(.file_path)"})) as $failures
    | .results as $r
    | def count($k; $t): [$r[$k][] | select(.check_type == $t)] | length;
    {
      metadata: ($meta + {partial_failure: ($failures | length > 0), api_failures: $failures}),
      framework: "bicep,arm", scan_timestamp: $ts, source_type: $meta.source_type, source: $repo,
      file_counts: {bicep: $bicep, arm_templates: $arm},
      status: $status, message: $msg,
      summary: (
        ($r.passed_checks | length) as $p | ($r.failed_checks | length) as $f | ($r.skipped_checks | length) as $s
        | {
            passed_checks: $p, failed_checks: $f, skipped_checks: $s, total_checks: ($p + $f + $s),
            aggregate_percentage: (if ($p + $f + $s) > 0 then ($p * 10000 / ($p + $f + $s) | round / 100) else null end),
            parsing_errors: ($r.parsing_errors | length),
            resource_count: ([.resource_counts[]] | add // 0),
            skipped_by_resource_filter: $resskipped,
            by_framework: (.resource_counts | to_entries | map({key: .key, value: {
                passed_checks: count("passed_checks"; .key), failed_checks: count("failed_checks"; .key),
                skipped_checks: count("skipped_checks"; .key), parsing_errors: count("parsing_errors"; .key),
                resource_count: .value}}) | from_entries)
          }),
      results: $r
    }' "$NORM" > "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON (status=$STATUS passed=$PASSED failed=$FAILED skipped=$SKIPPED, $RESOURCE_SKIPPED of them by skip_resources, parsing_errors=$PARSE_ERRORS)"
case "$STATUS" in
    no_checks) report_failure "$MSG"; exit 1 ;;
    partial)   report_failure "$MSG" partial_failure; exit 1 ;;
esac
exit 0
