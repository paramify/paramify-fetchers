#!/bin/bash
#
# AWS — SQS Queue Encryption at Rest
#
# For each SQS queue in the region, reports server-side encryption status
# (KMS master key id or SQS-managed SSE). Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_sqs_encryption_status.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI credential chain. A manifest target may
# set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account / multi-region fanout); when
# unset, the CLI uses the ambient identity/region. The helper sets PROFILE/REGION
# (for metadata) and provides aws_target_id (for the output filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Per-target output filename (profile+region) so multi-target runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_sqs_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_sqs_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_sqs_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_sqs_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_sqs_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"queues": [], "summary": {}}}' \
  > "$OUTPUT_JSON"

total_queues=0
encrypted_queues=0

queue_urls=$(aws sqs list-queues --query 'QueueUrls[]' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws sqs list-queues (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list SQS queues"
else
    for queue_url in $(aws_text_list "$queue_urls"); do
        total_queues=$((total_queues + 1))
        queue_name="${queue_url##*/}"

        attributes=$(aws sqs get-queue-attributes \
            --queue-url "$queue_url" \
            --attribute-names KmsMasterKeyId SqsManagedSseEnabled \
            --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws sqs get-queue-attributes ($queue_name) failed" >> "$_FAILURE_LOG"
            continue
        fi

        kms_key_id=$(echo "$attributes" | jq -r '.Attributes.KmsMasterKeyId // "None"')
        sqs_managed=$(echo "$attributes" | jq -r '.Attributes.SqsManagedSseEnabled // "false"')

        encrypted=false
        if [ "$kms_key_id" != "None" ] || [ "$sqs_managed" = "true" ]; then
            encrypted=true
            encrypted_queues=$((encrypted_queues + 1))
        fi

        queue_data=$(jq -n --arg name "$queue_name" --arg url "$queue_url" \
            --argjson enc "$encrypted" --arg kms "$kms_key_id" --arg sse "$sqs_managed" \
            '{name: $name, url: $url, encrypted: $enc, kms_master_key_id: $kms, sqs_managed_sse_enabled: $sse}')

        jq --argjson data "$queue_data" '.results.queues += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

percentage=0
[ $total_queues -gt 0 ] && percentage=$(( (encrypted_queues * 100) / total_queues ))

jq --arg total "$total_queues" --arg encrypted "$encrypted_queues" --arg percentage "$percentage" \
    '.results.summary = {total_queues: ($total | tonumber), encrypted_queues: ($encrypted | tonumber), encryption_percentage: ($percentage | tonumber)}' \
    "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

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
