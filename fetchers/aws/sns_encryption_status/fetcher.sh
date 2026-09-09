#!/bin/bash
#
# AWS — SNS Encryption at Rest
#
# For each SNS topic in the account/region, reports server-side encryption
# status (KmsMasterKeyId). Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_sns_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_sns_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_sns_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_sns_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_sns_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_sns_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"topics": [], "summary": {"total_topics": 0, "encrypted_topics": 0, "encryption_percentage": 0}}}' \
  > "$OUTPUT_JSON"

total_topics=0
encrypted_topics=0

topic_arns=$(aws sns list-topics --query 'Topics[*].TopicArn' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws sns list-topics (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list SNS topics"
else
    for topic_arn in $(aws_text_list "$topic_arns"); do
        total_topics=$((total_topics + 1))
        name="${topic_arn##*:}"

        attributes=$(aws sns get-topic-attributes --topic-arn "$topic_arn" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws sns get-topic-attributes ($topic_arn) failed" >> "$_FAILURE_LOG"
            continue
        fi

        kms_key_id=$(echo "$attributes" | jq -r '.Attributes.KmsMasterKeyId // "None"')
        if [ "$kms_key_id" = "None" ]; then
            encrypted=false
        else
            encrypted=true
            encrypted_topics=$((encrypted_topics + 1))
        fi

        topic_data=$(jq -n --arg name "$name" --arg arn "$topic_arn" \
            --argjson enc "$encrypted" --arg kms "$kms_key_id" \
            '{name: $name, arn: $arn, encrypted: $enc, kms_master_key_id: $kms}')

        jq --argjson data "$topic_data" '.results.topics += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

percentage=0
[ $total_topics -gt 0 ] && percentage=$(( (encrypted_topics * 100) / total_topics ))

jq --arg total "$total_topics" --arg encrypted "$encrypted_topics" --arg percentage "$percentage" \
    '.results.summary = {total_topics: ($total | tonumber), encrypted_topics: ($encrypted | tonumber), encryption_percentage: ($percentage | tonumber)}' \
    "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
