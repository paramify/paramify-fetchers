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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

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

total_file_systems=0
encrypted_file_systems=0
service_status="enabled"

_ERR="$(mktemp -t aws_fsx_encryption_status_err.XXXXXX)"
file_systems=$(aws fsx describe-file-systems --query 'FileSystems[*].FileSystemId' --output text 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ] && aws_service_unavailable "$_ERR"; then
    log_info "FSx not in use for this account/region (not subscribed / not enabled); recording not-enabled status"
    service_status="not-enabled"
    rm -f "$_ERR"
elif [ $list_exit -ne 0 ]; then
    cat "$_ERR" >> "$_FAILURE_LOG"
    echo "aws fsx describe-file-systems (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list FSx file systems"
    rm -f "$_ERR"
else
    rm -f "$_ERR"
    for fs_id in $(aws_text_list "$file_systems"); do
        total_file_systems=$((total_file_systems + 1))
        fs_details=$(aws fsx describe-file-systems --file-system-ids "$fs_id" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws fsx describe-file-systems ($fs_id) failed" >> "$_FAILURE_LOG"
            continue
        fi
        kms_key_id=$(echo "$fs_details" | jq -r '.FileSystems[0].KmsKeyId // "None"')
        fs_type=$(echo "$fs_details" | jq -r '.FileSystems[0].FileSystemType // "unknown"')
        encrypted=false
        [ "$kms_key_id" != "None" ] && encrypted=true

        fs_data=$(jq -n --arg id "$fs_id" --arg type "$fs_type" \
            --argjson enc "$encrypted" --arg kms "$kms_key_id" \
            '{id: $id, type: $type, encrypted: $enc, kms_key_id: $kms}')
        jq --argjson data "$fs_data" '.results.file_systems += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        [ "$encrypted" = "true" ] && encrypted_file_systems=$((encrypted_file_systems + 1))
    done
fi

percentage=0
[ $total_file_systems -gt 0 ] && percentage=$(( (encrypted_file_systems * 100) / total_file_systems ))

jq --arg total "$total_file_systems" --arg encrypted "$encrypted_file_systems" --arg percentage "$percentage" --arg status "$service_status" \
    '.results.summary = {status: $status, total_file_systems: ($total | tonumber), encrypted_file_systems: ($encrypted | tonumber), encryption_percentage: ($percentage | tonumber)}' \
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
