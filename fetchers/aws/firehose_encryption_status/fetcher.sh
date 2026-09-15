#!/bin/bash
#
# AWS — Firehose Delivery Stream Encryption
#
# For each Firehose delivery stream in the account/region, reports server-side
# encryption status (DeliveryStreamEncryptionConfiguration) and KMS key ARN.
#
# Output: $EVIDENCE_DIR/aws_firehose_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_firehose_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_firehose_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_firehose_encryption_status_fail.XXXXXX)"
_ERR=""
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_ERR" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_firehose_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_firehose_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": []}' \
  > "$OUTPUT_JSON"

# firehose list-delivery-streams has NO automatic paginator (only --limit). The
# API caps each page and signals more via HasMoreDeliveryStreams, so we paginate
# manually with ExclusiveStartDeliveryStreamName, exactly like the Prowler service.
stream_names=""
list_failed=0
service_unavailable=0
_exclusive_start=""
_ERR="$(mktemp -t aws_firehose_encryption_status_err.XXXXXX)"
while true; do
    if [ -n "$_exclusive_start" ]; then
        page=$(aws firehose list-delivery-streams \
            --exclusive-start-delivery-stream-name "$_exclusive_start" \
            --output json 2>"$_ERR")
    else
        page=$(aws firehose list-delivery-streams --output json 2>"$_ERR")
    fi
    list_exit=$?
    if [ $list_exit -ne 0 ]; then
        if aws_service_unavailable "$_ERR"; then
            log_info "Firehose is not in use for this account/region (not subscribed/enabled); recording not-enabled status"
            service_unavailable=1
        else
            echo "aws firehose list-delivery-streams (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
            log_error "Failed to list Firehose delivery streams"
        fi
        list_failed=1
        break
    fi

    page_names=$(echo "$page" | jq -r '.DeliveryStreamNames[]?')
    if [ -n "$page_names" ]; then
        stream_names="${stream_names}${stream_names:+$'\n'}${page_names}"
    fi

    has_more=$(echo "$page" | jq -r '.HasMoreDeliveryStreams // false')
    if [ "$has_more" != "true" ]; then
        break
    fi

    # Next page starts after the last name in this batch (alphabetical order).
    _exclusive_start=$(echo "$page_names" | tail -n 1)
    if [ -z "$_exclusive_start" ]; then
        break
    fi
done

if [ $service_unavailable -eq 1 ]; then
    jq '.results += [{"status": "NOT_ENABLED", "detail": "Firehose is not in use for this account/region (not subscribed/enabled)"}]' \
        "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

if [ $list_failed -eq 0 ]; then
    while IFS= read -r stream_name; do
        [ -z "$stream_name" ] && continue
        stream_details=$(aws firehose describe-delivery-stream --delivery-stream-name "$stream_name" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws firehose describe-delivery-stream ($stream_name) failed" >> "$_FAILURE_LOG"
            continue
        fi

        stream_data=$(echo "$stream_details" | jq \
            '.DeliveryStreamDescription as $d | {
                name: $d.DeliveryStreamName,
                arn: $d.DeliveryStreamARN,
                delivery_stream_type: $d.DeliveryStreamType,
                encryption_status: ($d.DeliveryStreamEncryptionConfiguration.Status // "DISABLED"),
                kms_key_arn: ($d.DeliveryStreamEncryptionConfiguration.KeyARN // "None")
            }')

        jq --argjson data "$stream_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done <<< "$stream_names"
fi

aws_finish
