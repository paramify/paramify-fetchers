#!/bin/bash
#
# AWS — Athena Workgroup Query-Result Encryption
#
# For each Athena workgroup in the account/region, reports the query-result
# encryption configuration (SSE_S3/SSE_KMS/CSE_KMS) and whether the workgroup
# configuration is enforced.
#
# Output: $EVIDENCE_DIR/aws_athena_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_athena_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_athena_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_athena_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_athena_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_athena_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

workgroups=$(aws athena list-work-groups --query 'WorkGroups[*].Name' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws athena list-work-groups (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list Athena workgroups"
else
    for wg in $(aws_text_list "$workgroups"); do
        wg_details=$(aws athena get-work-group --work-group "$wg" --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws athena get-work-group ($wg) failed" >> "$_FAILURE_LOG"
            continue
        fi

        name=$(echo "$wg_details" | jq -r '.WorkGroup.Name')
        state=$(echo "$wg_details" | jq -r '.WorkGroup.State // "UNKNOWN"')
        enforce=$(echo "$wg_details" | jq -r '.WorkGroup.Configuration.EnforceWorkGroupConfiguration // false')
        encryption_option=$(echo "$wg_details" | jq -r '.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption // ""')

        encrypted=false
        case "$encryption_option" in
            SSE_S3|SSE_KMS|CSE_KMS) encrypted=true ;;
        esac

        wg_data=$(jq -n --arg name "$name" --arg state "$state" \
            --argjson enforce "$enforce" --arg enc_option "$encryption_option" --argjson encrypted "$encrypted" \
            '{name: $name, state: $state, enforce_workgroup_configuration: $enforce, encryption_option: $enc_option, encrypted: $encrypted}')

        jq --argjson data "$wg_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
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
