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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

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

# get-queue-attributes has no batch form, so each queue still costs one call.
# What the loop no longer does is spawn jq or rewrite the output file per
# queue: each readable queue's URL and raw attributes are appended in order,
# and one jq pass below builds the records and the summary.
total_queues=0
_QUEUE_URLS="$(mktemp -t aws_sqs_encryption_status_urls.XXXXXX)"
_QUEUE_ATTRIBUTES="$(mktemp -t aws_sqs_encryption_status_attributes.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_QUEUE_URLS" "$_QUEUE_ATTRIBUTES"' EXIT

queue_urls=$(aws sqs list-queues --query 'QueueUrls[]' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws sqs list-queues (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list SQS queues"
else
    for queue_url in $(aws_text_list "$queue_urls"); do
        # An unreadable queue is logged and left out of the queue list, but it
        # stays in total_queues -- the denominator counts every listed queue.
        total_queues=$((total_queues + 1))
        queue_name="${queue_url##*/}"

        attributes=$(aws sqs get-queue-attributes \
            --queue-url "$queue_url" \
            --attribute-names KmsMasterKeyId SqsManagedSseEnabled \
            --output json 2>/dev/null)
        if [ $? -ne 0 ] || [ -z "$attributes" ]; then
            echo "aws sqs get-queue-attributes ($queue_name) failed" >> "$_FAILURE_LOG"
            continue
        fi

        printf '%s\n' "$queue_url" >> "$_QUEUE_URLS"
        printf '%s\n' "$attributes" >> "$_QUEUE_ATTRIBUTES"
    done
fi

jq --rawfile urls "$_QUEUE_URLS" --slurpfile attributes "$_QUEUE_ATTRIBUTES" --argjson total "$total_queues" '
    ($urls | split("\n")) as $urls
    | [range(0; $attributes | length) as $i
        | ($attributes[$i].Attributes.KmsMasterKeyId // "None" | tostring) as $kms
        | ($attributes[$i].Attributes.SqsManagedSseEnabled // "false" | tostring) as $sse
        | {name: ($urls[$i] | split("/") | last), url: $urls[$i],
           encrypted: ($kms != "None" or $sse == "true"),
           kms_master_key_id: $kms, sqs_managed_sse_enabled: $sse}] as $queues
    | ([$queues[] | select(.encrypted)] | length) as $encrypted
    | .results.queues += $queues
    | .results.summary = {total_queues: $total, encrypted_queues: $encrypted,
        encryption_percentage: (if $total > 0 then ($encrypted * 100 / $total | floor) else 0 end)}
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
