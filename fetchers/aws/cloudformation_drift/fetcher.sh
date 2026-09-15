#!/bin/bash
#
# AWS — CloudFormation Drift
#
# Lists CloudFormation stacks with drift status, last drift-check timestamp,
# and termination-protection setting.
#
# Output: $EVIDENCE_DIR/aws_cloudformation_drift.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_cloudformation_drift_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_cloudformation_drift.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_cloudformation_drift_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_cloudformation_drift %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_cloudformation_drift %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# The bulk describe-stacks (list-all) call returns StackStatus and DriftInformation,
# but NOT EnableTerminationProtection — that field is only populated when you
# describe a single stack by name (see Prowler's two-pass CloudFormation service).
# So we list first, then describe each stack by name to capture termination protection.
stacks=$(aws cloudformation describe-stacks \
    --query 'Stacks[*].{StackName:StackName, StackId:StackId, StackStatus:StackStatus, StackDriftStatus:DriftInformation.StackDriftStatus, LastDriftCheckTimestamp:DriftInformation.LastCheckTimestamp}' \
    --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws cloudformation describe-stacks (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list CloudFormation stacks"
    stacks='[]'
fi
stacks="${stacks:-[]}"

stack_count=$(echo "$stacks" | jq 'length')
i=0
while [ "$i" -lt "$stack_count" ]; do
    stack=$(echo "$stacks" | jq ".[$i]")
    i=$((i + 1))
    stack_name=$(echo "$stack" | jq -r '.StackName')

    # Per-stack describe to obtain EnableTerminationProtection (absent in the list form).
    term_protection=$(aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --query 'Stacks[0].EnableTerminationProtection' \
        --output json 2>/dev/null)
    detail_exit=$?
    if [ $detail_exit -ne 0 ]; then
        echo "aws cloudformation describe-stacks ($stack_name detail) failed (exit=$detail_exit)" >> "$_FAILURE_LOG"
        term_protection='null'
    fi
    term_protection="${term_protection:-null}"

    record=$(echo "$stack" | jq --argjson tp "$term_protection" '. + {"EnableTerminationProtection": $tp}')
    jq --argjson rec "$record" '.results += [$rec]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done
unset i

aws_finish
