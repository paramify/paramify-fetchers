#!/bin/bash
#
# AWS — DynamoDB Encryption at Rest
#
# For each DynamoDB table in the account/region, reports server-side encryption
# (SSE type and KMS key ARN). Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_dynamodb_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_dynamodb_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_dynamodb_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_dynamodb_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_dynamodb_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_dynamodb_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

total_tables=0
encrypted_tables=0

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"tables": [], "summary": {}}}' \
  > "$OUTPUT_JSON"

tables=$(aws dynamodb list-tables --query 'TableNames[*]' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws dynamodb list-tables (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list DynamoDB tables"
else
    for table in $(aws_text_list "$tables"); do
        total_tables=$((total_tables + 1))
        table_details=$(aws dynamodb describe-table --table-name "$table" --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws dynamodb describe-table ($table) failed" >> "$_FAILURE_LOG"
            continue
        fi

        # SSEType is absent for AWS-owned-key encryption (the default); present as
        # KMS or AES256 when SSE is explicitly configured.
        sse_type=$(echo "$table_details" | jq -r '.Table.SSEDescription.SSEType // "AWS_OWNED"')
        kms_arn=$(echo "$table_details" | jq -r '.Table.SSEDescription.KMSMasterKeyArn // "None"')
        sse_status=$(echo "$table_details" | jq -r '.Table.SSEDescription.Status // "DEFAULT"')

        # Customer-managed/AWS-managed KMS encryption is the hardened state for KSI-SVC-SIN.
        [ "$sse_type" = "KMS" ] && encrypted_tables=$((encrypted_tables + 1))

        table_data=$(jq -n --arg name "$table" --arg sse "$sse_type" \
            --arg kms "$kms_arn" --arg status "$sse_status" \
            '{name: $name, sse_type: $sse, kms_arn: $kms, sse_status: $status}')

        jq --argjson data "$table_data" '.results.tables += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

percentage=0
[ $total_tables -gt 0 ] && percentage=$(( (encrypted_tables * 100) / total_tables ))

jq --argjson total "$total_tables" --argjson kms_encrypted "$encrypted_tables" --argjson percentage "$percentage" \
    '.results.summary = {total_tables: $total, kms_encrypted_tables: $kms_encrypted, kms_encryption_percentage: $percentage}' \
    "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
