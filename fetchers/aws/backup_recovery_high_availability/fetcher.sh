#!/bin/bash
#
# AWS — Backup and Recovery High Availability
#
# Lists EBS snapshots owned by this account and DLM lifecycle policies.
#
# Output: $EVIDENCE_DIR/aws_backup_recovery_high_availability.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_backup_recovery_high_availability_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_backup_recovery_high_availability.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_backup_recovery_high_availability_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_backup_recovery_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_backup_recovery_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

snapshots=$(aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*]' --output json 2>/dev/null)
snap_exit=$?
if [ $snap_exit -ne 0 ]; then
    echo "aws ec2 describe-snapshots failed (exit=$snap_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to describe EBS snapshots"
else
    echo "$snapshots" | jq -c '.[]' | while read -r snapshot; do
        jq --argjson snapshot "$snapshot" \
           '.results += [{"Type": "EBS_Snapshot", "SnapshotInfo": $snapshot}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

dlm_policies=$(aws dlm get-lifecycle-policies --query 'Policies[*]' --output json 2>/dev/null)
dlm_exit=$?
if [ $dlm_exit -ne 0 ]; then
    echo "aws dlm get-lifecycle-policies failed (exit=$dlm_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list DLM policies"
else
    echo "$dlm_policies" | jq -c '.[]' | while read -r policy; do
        jq --argjson policy "$policy" \
           '.results += [{"Type": "DLM_Policy", "PolicyInfo": $policy}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
