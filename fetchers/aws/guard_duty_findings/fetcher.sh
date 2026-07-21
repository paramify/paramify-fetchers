#!/bin/bash
# Lists AWS GuardDuty findings updated within a lookback window (list-findings
# + get-findings per detector). Complements aws_guard_duty (detector config
# only). No detectors, or no findings in the window, is valid evidence (not a
# failure). Stateless: each run re-derives "recent" from finding timestamps —
# no local state file is kept between runs.
# Output: $EVIDENCE_DIR/aws_guard_duty_findings_<target>.json
# Optional env (else the CLI's ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Optional env: GUARD_DUTY_FINDINGS_LOOKBACK_DAYS (default 7)
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI's own credential chain (see aws_guard_duty).
source "$(dirname "$0")/../_shared/aws.sh"

LOOKBACK_DAYS="${GUARD_DUTY_FINDINGS_LOOKBACK_DAYS:-7}"
case "$LOOKBACK_DAYS" in
    ''|*[!0-9]*) LOOKBACK_DAYS=7 ;;
esac

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_guard_duty_findings_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_guard_duty_findings.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_guard_duty_findings_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_guard_duty_findings %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_guard_duty_findings %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# updatedAt window, in epoch milliseconds. `date +%s` (no -d/-v flags) is
# portable across GNU and BSD/macOS date, so plain arithmetic avoids the
# GNU-vs-BSD date flag mismatch entirely.
NOW_EPOCH_S=$(date -u +%s)
SINCE_EPOCH_MS=$(( (NOW_EPOCH_S - LOOKBACK_DAYS * 86400) * 1000 ))

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  --argjson lookback_days "$LOOKBACK_DAYS" --argjson since_epoch_ms "$SINCE_EPOCH_MS" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime,
                  "account_id": $account_id, "arn": $arn,
                  "lookback_days": $lookback_days, "since_epoch_ms": $since_epoch_ms},
    "results": {"detectors": [], "findings": [], "summary": {}}}' \
  > "$OUTPUT_JSON"

# --- Get detector IDs. No detectors is valid evidence (GuardDuty not enabled),
# not a failure -- same reasoning as aws_guard_duty. ---
_LIST_ERR="$(mktemp -t aws_guard_duty_findings_list.XXXXXX)"
detectors=$(aws guardduty list-detectors --query 'DetectorIds[*]' --output json 2>"$_LIST_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if grep -q 'SubscriptionRequiredException' "$_LIST_ERR"; then
        log_info "GuardDuty not enabled in $REGION (SubscriptionRequiredException) -- recording as no findings"
    else
        echo "aws guardduty list-detectors failed (exit=$ec): $(tr '\n' ' ' < "$_LIST_ERR")" >> "$_FAILURE_LOG"
    fi
    detectors='[]'
fi
rm -f "$_LIST_ERR"
if [ -z "$detectors" ] || ! echo "$detectors" | jq . >/dev/null 2>&1; then
    detectors='[]'
fi

jq --argjson detectors "$detectors" '.results.detectors = ($detectors // [])' \
   "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

detector_count="$(echo "$detectors" | jq 'length')"
if [ "$detector_count" -eq 0 ]; then
    log_info "No GuardDuty detectors found (GuardDuty not enabled in $REGION)"
fi

CRITERIA="$(jq -n --argjson since "$SINCE_EPOCH_MS" '{"Criterion":{"updatedAt":{"Gte":$since}}}')"

echo "$detectors" | jq -r '.[]' | while read -r detector_id; do
    [ -z "$detector_id" ] && continue
    log_info "Listing findings for detector $detector_id (updated within ${LOOKBACK_DAYS}d)..."

    finding_ids='[]'
    next_token=""
    page=1
    while :; do
        if [ -n "$next_token" ]; then
            page_result=$(aws guardduty list-findings \
                --detector-id "$detector_id" \
                --finding-criteria "$CRITERIA" \
                --max-results 50 \
                --next-token "$next_token" \
                --output json 2>/dev/null)
        else
            page_result=$(aws guardduty list-findings \
                --detector-id "$detector_id" \
                --finding-criteria "$CRITERIA" \
                --max-results 50 \
                --output json 2>/dev/null)
        fi
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws guardduty list-findings ($detector_id page $page) failed (exit=$ec)" >> "$_FAILURE_LOG"
            break
        fi

        page_ids=$(echo "$page_result" | jq -c '.FindingIds // []')
        finding_ids=$(jq -c -n --argjson a "$finding_ids" --argjson b "$page_ids" '$a + $b')
        next_token=$(echo "$page_result" | jq -r '.NextToken // empty')
        page=$((page + 1))

        [ -z "$next_token" ] && break
        if [ "$page" -ge 50 ]; then
            log_info "Reached maximum page limit for detector $detector_id"
            break
        fi
    done

    id_count=$(echo "$finding_ids" | jq 'length')
    if [ "$id_count" -eq 0 ]; then
        log_info "No findings updated in the last ${LOOKBACK_DAYS}d for detector $detector_id"
        continue
    fi
    log_info "$id_count finding(s) to expand for detector $detector_id"

    # get-findings accepts at most 50 ids per call; chunk accordingly.
    i=0
    while [ "$i" -lt "$id_count" ]; do
        chunk=$(echo "$finding_ids" | jq -c ".[$i:$((i + 50))]")
        chunk_args=()
        while IFS= read -r fid; do
            chunk_args+=("$fid")
        done < <(echo "$chunk" | jq -r '.[]')

        chunk_result=$(aws guardduty get-findings \
            --detector-id "$detector_id" \
            --finding-ids "${chunk_args[@]}" \
            --output json 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws guardduty get-findings ($detector_id offset $i) failed (exit=$ec)" >> "$_FAILURE_LOG"
            i=$((i + 50))
            continue
        fi

        findings=$(echo "$chunk_result" | jq -c '.Findings // []')
        jq --argjson findings "$findings" '.results.findings += $findings' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

        i=$((i + 50))
    done
done

# Summary: counts by severity bucket, type, and archived (disposition) status.
# AWS severity buckets: 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High.
summary=$(jq '
  .results.findings as $f
  | {
      total: ($f | length),
      by_severity: {
        low: ($f | map(select(.Severity < 4)) | length),
        medium: ($f | map(select(.Severity >= 4 and .Severity < 7)) | length),
        high: ($f | map(select(.Severity >= 7)) | length)
      },
      by_type: ($f | group_by(.Type) | map({key: .[0].Type, value: length}) | from_entries),
      archived: ($f | map(select(.Service.Archived == true)) | length),
      active: ($f | map(select(.Service.Archived != true)) | length)
    }
' "$OUTPUT_JSON")

jq --argjson summary "$summary" '.results.summary = $summary' \
   "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}

if [ "$failure_count" -gt 0 ]; then
    log_error "Encountered $failure_count API failures during collection"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
