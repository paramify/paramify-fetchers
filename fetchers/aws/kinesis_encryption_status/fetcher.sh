#!/bin/bash
#
# AWS — Kinesis Data Stream Encryption at Rest
#
# For each Kinesis data stream in the account/region, reports server-side
# encryption type (NONE/KMS) and the KMS key id. Maps to KSI-SVC-SIN.
#
# Output: $EVIDENCE_DIR/aws_kinesis_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_kinesis_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_kinesis_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_kinesis_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "${_ERR:-}"' EXIT

log_info() { printf '%s INFO aws_kinesis_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_kinesis_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

_ERR="$(mktemp -t aws_kinesis_encryption_status_err.XXXXXX)"
stream_names=$(aws kinesis list-streams --query 'StreamNames[*]' --output text 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ]; then
    if aws_service_unavailable "$_ERR"; then
        log_info "Kinesis not in use for this account (not subscribed / not enabled); recording not-enabled status"
        jq '.results += [{"status": "not_enabled", "note": "Kinesis service not in use for this account"}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    else
        echo "aws kinesis list-streams (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
        log_error "Failed to list Kinesis streams"
    fi
    rm -f "$_ERR"
else
    rm -f "$_ERR"
    for stream_name in $(aws_text_list "$stream_names"); do
        summary=$(aws kinesis describe-stream-summary --stream-name "$stream_name" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws kinesis describe-stream-summary ($stream_name) failed" >> "$_FAILURE_LOG"
            continue
        fi

        arn=$(echo "$summary" | jq -r '.StreamDescriptionSummary.StreamARN // "None"')
        status=$(echo "$summary" | jq -r '.StreamDescriptionSummary.StreamStatus // "None"')
        encryption_type=$(echo "$summary" | jq -r '.StreamDescriptionSummary.EncryptionType // "NONE"')
        kms_key_id=$(echo "$summary" | jq -r '.StreamDescriptionSummary.KeyId // "None"')

        stream_data=$(jq -n --arg name "$stream_name" --arg arn "$arn" --arg status "$status" \
            --arg enc "$encryption_type" --arg kms "$kms_key_id" \
            '{name: $name, arn: $arn, status: $status, encryption_type: $enc, kms_key_id: $kms, encrypted_at_rest: ($enc == "KMS")}')

        jq --argjson data "$stream_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

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
