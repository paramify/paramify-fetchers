#!/bin/bash
#
# KnowBe4 — Module-Based Training Summary
#
# Aggregates all active training enrollments by module name with per-module
# assignment and completion metrics. Used for compliance evidence where completion
# does not map cleanly to a single campaign.
#
# This fetcher takes no group or campaign config: it reports on whatever the tenant
# has, so it works against any tenant as-is.
#
# Output: $EVIDENCE_DIR/knowbe4_module_based_summary.json
# Required env: KNOWBE4_API_KEY, KNOWBE4_REGION

set -o pipefail

# Interim v0.x: load .env if present. Runner + secret resolver replaces this.
[ -f .env ] && { set -a; . .env; set +a; }

FETCHER=knowbe4_module_based_summary

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_JSON="$OUTPUT_DIR/${FETCHER}.json"

_FAILURE_LOG="$(mktemp -t ${FETCHER}_fail.XXXXXX)"
# Large jq inputs go in by FILE, never as an argv string: Linux caps a single
# argument at MAX_ARG_STRLEN (128KB), so --argjson with a full enrollments array
# fails execve with E2BIG and jq never runs — leaving an empty evidence file.
# macOS has no per-argument cap, which is exactly how this hid during local dev.
_TMP_ENROLLMENTS="$(mktemp -t ${FETCHER}_enroll.XXXXXX)"
trap 'rm -f "$_FAILURE_LOG" "$_TMP_ENROLLMENTS"' EXIT

log_info()  { printf '%s INFO %s %s\n'  "$(date -u +'%Y-%m-%d %H:%M:%S')" "$FETCHER" "$*" >&2; }
log_error() { printf '%s ERROR %s %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$FETCHER" "$*" >&2; }

# The shared failure path: report_failure logs the reason AND writes it to
# $FETCHER_STATUS_FILE, so the runner reports why instead of the stderr tail.
source "$(dirname "$0")/../../_lib/status.sh"

if [ -z "${KNOWBE4_API_KEY:-}" ]; then
    report_failure "KNOWBE4_API_KEY is not set" bad_config
    exit 1
fi
if [ -z "${KNOWBE4_REGION:-}" ]; then
    report_failure "KNOWBE4_REGION is not set" bad_config
    exit 1
fi

# printf '%s', never echo: bash's echo leaves backslashes alone but sh's and zsh's
# do not, and KnowBe4 module titles are free text.
make_api_call() {
    local endpoint=$1
    local url="https://${KNOWBE4_REGION}.api.knowbe4.com/v1/${endpoint}"
    local response
    if ! response=$(curl -sf -H "Authorization: Bearer ${KNOWBE4_API_KEY}" \
                         -H "Content-Type: application/json" "${url}"); then
        printf 'GET %s\n' "$endpoint" >> "$_FAILURE_LOG"
        printf '%s' '[]'
        return 1
    fi
    # Anything that is not a JSON array is an error body, not a page. Recording it
    # rather than treating it as data is what stops pagination looping forever on a
    # 200-with-error-payload.
    if ! printf '%s' "$response" | jq -e 'type == "array"' >/dev/null 2>&1; then
        printf 'GET %s (response was not a JSON array)\n' "$endpoint" >> "$_FAILURE_LOG"
        printf '%s' '[]'
        return 1
    fi
    printf '%s' "$response"
}

_MAX_PAGES=1000

make_paginated_api_call() {
    local endpoint="$1"
    local page=1 all_results="[]" response count separator
    if [[ "$endpoint" == *\?* ]]; then separator="&"; else separator="?"; fi

    while [ "$page" -le "$_MAX_PAGES" ]; do
        if ! response=$(make_api_call "${endpoint}${separator}page=${page}"); then
            break
        fi
        count=$(printf '%s' "$response" | jq 'length')
        [ "$count" -eq 0 ] && break
        all_results=$(jq -s '.[0] + .[1]' \
            <(printf '%s' "$all_results") <(printf '%s' "$response"))
        page=$((page + 1))
    done
    if [ "$page" -gt "$_MAX_PAGES" ]; then
        printf 'GET %s (stopped at the %s-page cap)\n' "$endpoint" "$_MAX_PAGES" >> "$_FAILURE_LOG"
    fi
    printf '%s' "$all_results"
}

enrollments_response=$(make_paginated_api_call \
    "training/enrollments?exclude_archived_users=true&include_campaign_id=true")

# One jq pass builds the whole document. The previous version appended each record
# by re-running jq over the growing output file, which was quadratic: 1500
# enrollments took 69s and 3000 took over 120s, so a mid-size tenant blew the
# runner's 600s cap.
printf '%s' "$enrollments_response" > "$_TMP_ENROLLMENTS"

jq -n --slurpfile enrollments "$_TMP_ENROLLMENTS" '
    [ $enrollments[0][] | del(.policy_acknowledged) ] as $rows
    | {
        results: {
          enrollments: $rows,
          summary: {
            training_module_summary: (
              $rows
              | group_by(.module_name)
              | map({
                  key: (.[0].module_name // "(unnamed module)"),
                  value: {
                    assigned: length,
                    passed: (map(select(.status == "Passed")) | length),
                    completion_rate: (
                      if length > 0
                      then (((map(select(.status == "Passed")) | length) * 100 / length) | floor)
                      else 0 end)
                  }
                })
              # from_entries on [] gives {} — an empty tenant is an empty map, not
              # the null the previous `add` produced.
              | from_entries
            )
          }
        }
      }
' > "$OUTPUT_JSON"

if [ ! -s "$OUTPUT_JSON" ]; then
    report_failure "failed to assemble the evidence document" internal_error
    exit 1
fi

failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}
if [ "$failure_count" -gt 0 ]; then
    report_failure "encountered $failure_count API failure(s) during collection" partial_failure
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
exit 0
