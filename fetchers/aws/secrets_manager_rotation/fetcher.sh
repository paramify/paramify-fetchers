#!/bin/bash
#
# AWS — Secrets Manager Rotation
#
# For each Secrets Manager secret in the region, reports automatic rotation
# status, rotation interval in days, last-rotated date, and the KMS key used.
#
# Output: $EVIDENCE_DIR/aws_secrets_manager_rotation.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_secrets_manager_rotation_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_secrets_manager_rotation.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_secrets_manager_rotation_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_secrets_manager_rotation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_secrets_manager_rotation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

secret_arns=$(aws secretsmanager list-secrets --query 'SecretList[*].ARN' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws secretsmanager list-secrets failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list secrets"
else
    for secret_arn in $(aws_text_list "$secret_arns"); do
        [ -z "$secret_arn" ] && continue

        secret_details=$(aws secretsmanager describe-secret --secret-id "$secret_arn" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws secretsmanager describe-secret ($secret_arn) failed" >> "$_FAILURE_LOG"
            secret_details='{}'
        fi

        secret_data=$(echo "$secret_details" | jq '{
            arn: (.ARN // "Unknown"),
            name: (.Name // "Unknown"),
            rotation_enabled: (.RotationEnabled // false),
            rotation_interval_days: (.RotationRules.AutomaticallyAfterDays // null),
            last_rotated_date: (.LastRotatedDate // null),
            kms_key_id: (.KmsKeyId // null)
        }')

        jq --argjson data "$secret_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
