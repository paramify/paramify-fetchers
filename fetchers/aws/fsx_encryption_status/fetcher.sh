#!/bin/bash
#
# AWS — FSx Encryption at Rest
#
# For each FSx file system in the account/region, reports encryption status
# (KMS key id and file-system type). Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_fsx_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_fsx_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_fsx_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_fsx_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_fsx_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_fsx_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"file_systems": [], "summary": {"total_file_systems": 0, "encrypted_file_systems": 0, "encryption_percentage": 0}}}' \
  > "$OUTPUT_JSON"

service_status="enabled"

_ERR="$(mktemp -t aws_fsx_encryption_status_err.XXXXXX)"
# One describe returns every file system's KMS key and type; the per-id
# describe this replaced re-fetched them one CLI process at a time.
file_systems=$(aws fsx describe-file-systems --query 'FileSystems[*].{FileSystemId:FileSystemId,FileSystemType:FileSystemType,KmsKeyId:KmsKeyId}' --output json 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ] && aws_service_unavailable "$_ERR"; then
    log_info "FSx not in use for this account/region (not subscribed / not enabled); recording not-enabled status"
    service_status="not-enabled"
    file_systems='[]'
elif [ $list_exit -ne 0 ]; then
    echo "aws fsx describe-file-systems (list) failed (exit=$list_exit): $(tr '\n\r\t' '   ' < "$_ERR" | tr -s ' ' | cut -c1-500)" >> "$_FAILURE_LOG"
    log_error "Failed to list FSx file systems"
    file_systems='[]'
fi
rm -f "$_ERR"

printf '%s' "$file_systems" | jq --slurpfile fss /dev/stdin --arg status "$service_status" '
    [$fss[0][]? | (.KmsKeyId // "None") as $kms
        | {id: .FileSystemId, type: (.FileSystemType // "unknown"), encrypted: ($kms != "None"), kms_key_id: $kms}] as $rows
    | ($rows | length) as $total
    | ([$rows[] | select(.encrypted)] | length) as $encrypted
    | .results.file_systems += $rows
    | .results.summary = {status: $status, total_file_systems: $total, encrypted_file_systems: $encrypted,
        encryption_percentage: (if $total > 0 then ($encrypted * 100 / $total | floor) else 0 end)}
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
