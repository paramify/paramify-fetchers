#!/bin/bash
#
# AWS — EFS High Availability
#
# Lists EFS file systems and their mount targets in the configured region.
# Per-AZ distribution of mount targets is evidence for HA.
#
# Output: $EVIDENCE_DIR/aws_efs_high_availability.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_efs_high_availability_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_efs_high_availability.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_efs_high_availability_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_efs_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_efs_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
caller_exit=$?
if [ $caller_exit -ne 0 ]; then
    echo "aws sts get-caller-identity failed (exit=$caller_exit)" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg profile "$PROFILE" \
  --arg region "$REGION" \
  --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" \
  --arg arn "$ARN" \
  '{
    "metadata": {
      "profile": $profile,
      "region": $region,
      "datetime": $datetime,
      "account_id": $account_id,
      "arn": $arn
    },
    "results": []
  }' > "$OUTPUT_JSON"

efs_filesystems=$(aws efs describe-file-systems --query 'FileSystems[*]' --output json 2>/dev/null)
efs_exit=$?
if [ $efs_exit -ne 0 ]; then
    echo "aws efs describe-file-systems failed (exit=$efs_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list EFS file systems"
else
    echo "$efs_filesystems" | jq -c '.[]' | while read -r efs; do
        fs_id=$(echo "$efs" | jq -r '.FileSystemId')

        mount_targets=$(aws efs describe-mount-targets --file-system-id "$fs_id" --query 'MountTargets[*]' --output json 2>/dev/null)
        mt_exit=$?
        if [ $mt_exit -ne 0 ]; then
            echo "aws efs describe-mount-targets ($fs_id) failed (exit=$mt_exit)" >> "$_FAILURE_LOG"
            mount_targets='[]'
        fi

        jq --argjson efs "$efs" --argjson targets "$mount_targets" \
           '.results += [{"Type": "EFS_FileSystem", "EFSInfo": $efs, "MountTargets": $targets}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
