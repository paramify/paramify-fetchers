#!/bin/bash
# Lists AWS GuardDuty detectors and their configuration plus a health summary.
# No detectors is valid evidence that GuardDuty is not enabled (not a failure).
# Output: $EVIDENCE_DIR/aws_guard_duty.json
# Optional env (else the CLI's ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI's own credential chain. A manifest target
# may set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account / multi-region fanout);
# when unset, the CLI uses the ambient identity/region. The helper sets PROFILE
# and REGION (for metadata) and provides aws_target_id (for the filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Per-target output filename (profile+region, or "ambient") so fanout runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_guard_duty_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_guard_duty.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_guard_duty_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_guard_duty %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_guard_duty %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"detectors": [], "detector_details": {}, "summary": {}}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# Get detector IDs. GuardDuty not enabled is valid evidence, not a failure — and it
# surfaces two ways depending on the account: an empty DetectorIds list (exit 0), OR
# a SubscriptionRequiredException (the account/region was never subscribed, so the
# call errors). Treat both as "not enabled"; only OTHER API errors (AccessDenied,
# throttling, …) are real collection failures. Capture stderr so we can tell them apart.
_LIST_ERR="$(mktemp -t aws_guard_duty_list.XXXXXX)"
detectors=$(aws guardduty list-detectors --query 'DetectorIds[*]' --output json 2>"$_LIST_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if grep -q 'SubscriptionRequiredException' "$_LIST_ERR"; then
        log_info "GuardDuty not enabled in $REGION (SubscriptionRequiredException) — recording as not enabled"
    else
        echo "aws guardduty list-detectors failed (exit=$ec): $(tr '\n' ' ' < "$_LIST_ERR")" >> "$_FAILURE_LOG"
    fi
    detectors='[]'
fi
rm -f "$_LIST_ERR"
if [ -z "$detectors" ] || ! echo "$detectors" | jq . >/dev/null 2>&1; then
    detectors='[]'
fi

# Populate detector_details for each detector.
if [ "$(echo "$detectors" | jq 'length')" -gt 0 ]; then
    echo "$detectors" | jq -r '.[]' | while read -r detector_id; do
        detector_details=$(aws guardduty get-detector --detector-id "$detector_id" --output json 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ] || [ -z "$detector_details" ] || ! echo "$detector_details" | jq . >/dev/null 2>&1; then
            echo "aws guardduty get-detector ($detector_id) failed (exit=$ec)" >> "$_FAILURE_LOG"
            continue
        fi

        jq --arg id "$detector_id" \
           --argjson details "$detector_details" \
           '.results.detector_details[$id] = $details' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
else
    log_info "No GuardDuty detectors found (GuardDuty not enabled in $REGION)"
fi

# Update detectors list in JSON
jq --argjson detectors "$detectors" '.results.detectors = ($detectors // [])' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# Main processing loop: build up a summary JSON object
summary_json='{"detectors":{}}'
detector_count=0
all_enabled=true
overall_data_sources=""

while read -r detector_id; do
    [ -z "$detector_id" ] && continue

    detector_details=$(aws guardduty get-detector --detector-id "$detector_id" --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$detector_details" ] || ! echo "$detector_details" | jq . >/dev/null 2>&1; then
        echo "aws guardduty get-detector ($detector_id) failed (exit=$ec)" >> "$_FAILURE_LOG"
        continue
    fi
    detector_count=$((detector_count+1))

    # Check if detector is enabled
    if [ "$(echo "$detector_details" | jq -r '.Status')" != "ENABLED" ]; then
        all_enabled=false
    fi

    # Collect data source statuses with more detail (as JSON, not string)
    data_sources_status=$(echo "$detector_details" | jq '{
        cloudtrail: { status: .DataSources.CloudTrail.Status },
        dns_logs: { status: .DataSources.DNSLogs.Status },
        flow_logs: { status: .DataSources.FlowLogs.Status },
        s3_logs: { status: .DataSources.S3Logs.Status },
        kubernetes: { status: (if .DataSources.Kubernetes.AuditLogs.Status then .DataSources.Kubernetes.AuditLogs.Status else "DISABLED" end) }
    }')

    # Store the data sources status for the overall summary (first detector only)
    if [ -z "$overall_data_sources" ]; then
        overall_data_sources="$data_sources_status"
    fi

    # Create summary JSON for this detector
    detector_summary=$(jq -n \
        --arg id "$detector_id" \
        --arg status "$(echo "$detector_details" | jq -r '.Status')" \
        --arg created "$(echo "$detector_details" | jq -r '.CreatedAt')" \
        --arg updated "$(echo "$detector_details" | jq -r '.UpdatedAt')" \
        --arg freq "$(echo "$detector_details" | jq -r '.FindingPublishingFrequency')" \
        --argjson sources "$data_sources_status" \
        '{
            "detector_id": $id,
            "status": $status,
            "created_at": $created,
            "updated_at": $updated,
            "finding_publishing_frequency": $freq,
            "data_sources": $sources
        }')

    # Add detector summary to summary_json
    summary_json=$(echo "$summary_json" | jq --arg id "$detector_id" --argjson detsum "$detector_summary" '.detectors[$id] = $detsum')
done < <(echo "$detectors" | jq -r '.[]')

# Count the number of detectors in summary_json for summary output
summary_detector_count=$(echo "$summary_json" | jq '.detectors | length')

# Create overall summary JSON and combine with detector summaries
if [ -n "$overall_data_sources" ]; then
    # Use process substitution rather than a scratch file in $OUTPUT_DIR — a file
    # there would leak into the run dir (and get enveloped/uploaded) on a mid-run failure.
    summary_json=$(echo "$summary_json" | jq --arg count "$summary_detector_count" \
        --arg health "$(if [ "$all_enabled" = true ]; then echo "HEALTHY"; else echo "REQUIRES_ATTENTION"; fi)" \
        --slurpfile sources <(echo "$overall_data_sources") \
        '{
            detector_count: $count,
            health_status: $health,
            issues: (if $health == "REQUIRES_ATTENTION" then ["detectors_disabled"] else [] end),
            data_sources: $sources[0]
        } + .')
else
    summary_json=$(echo "$summary_json" | jq --arg count "$summary_detector_count" \
        --arg health "$(if [ "$all_enabled" = true ]; then echo "HEALTHY"; else echo "REQUIRES_ATTENTION"; fi)" \
        '{
            detector_count: $count,
            health_status: $health,
            issues: (if $health == "REQUIRES_ATTENTION" then ["detectors_disabled"] else [] end)
        } + .')
fi

# Update JSON with combined summary
jq --argjson summary "$summary_json" '.results.summary = $summary' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}
if [ "$failure_count" -gt 0 ]; then
    # Report WHICH calls failed before the log is discarded on exit; the count
    # alone cannot be acted on. See aws_report_failures in ../_shared/aws.sh.
    aws_report_failures "$_FAILURE_LOG" "$failure_count"
    log_error "Encountered $failure_count AWS API failures during collection"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
