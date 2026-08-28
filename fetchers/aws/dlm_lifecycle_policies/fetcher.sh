#!/bin/bash
#
# AWS — Data Lifecycle Manager (DLM) Lifecycle Policies
#
# Lists DLM lifecycle policies in the target region and, for each, captures the
# state, type, target tags, schedules, and retention rules that govern automated
# EBS snapshot / AMI backup lifecycles.
#
# Output: $EVIDENCE_DIR/aws_dlm_lifecycle_policies_<target>.json
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
# DLM is a regional service, so the region is part of the target id.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_dlm_lifecycle_policies_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_dlm_lifecycle_policies.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_dlm_lifecycle_policies_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_dlm_lifecycle_policies %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_dlm_lifecycle_policies %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# --- per-script data collection ---

# Summary list of all DLM policies in the region (id, state, type, tags).
policies=$(aws dlm get-lifecycle-policies --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws dlm get-lifecycle-policies failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list DLM lifecycle policies"
    policies='{"Policies": []}'
fi
if [ -z "$policies" ] || ! echo "$policies" | jq . >/dev/null 2>&1; then
    policies='{"Policies": []}'
fi

policy_count=$(echo "$policies" | jq -r '.Policies | length')
if [ "$policy_count" -gt 0 ]; then
    log_info "Found $policy_count DLM lifecycle policies"
    while read -r summary; do
        policy_id=$(echo "$summary" | jq -r '.PolicyId')
        [ -z "$policy_id" ] && continue

        # Full policy detail: PolicyDetails carries Schedules (with RetainRule)
        # and TargetTags for KSI-RPL-ABO retention/lifecycle evidence.
        detail=$(aws dlm get-lifecycle-policy --policy-id "$policy_id" --output json 2>/dev/null)
        detail_exit=$?
        if [ $detail_exit -ne 0 ]; then
            echo "aws dlm get-lifecycle-policy ($policy_id) failed (exit=$detail_exit)" >> "$_FAILURE_LOG"
            detail='{}'
        fi
        if [ -z "$detail" ] || ! echo "$detail" | jq . >/dev/null 2>&1; then
            detail='{}'
        fi

        jq --argjson summary "$summary" --argjson detail "$detail" \
           '.results += [{
              "PolicyId": $summary.PolicyId,
              "State": ($summary.State // ($detail.Policy.State // null)),
              "PolicyType": ($summary.PolicyType // ($detail.Policy.PolicyDetails.PolicyType // null)),
              "Description": ($detail.Policy.Description // null),
              "Tags": ($summary.Tags // ($detail.Policy.Tags // {})),
              "TargetTags": ($detail.Policy.PolicyDetails.TargetTags // []),
              "ResourceTypes": ($detail.Policy.PolicyDetails.ResourceTypes // []),
              "Schedules": ($detail.Policy.PolicyDetails.Schedules // []),
              "PolicyDetails": ($detail.Policy.PolicyDetails // {})
           }]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done < <(echo "$policies" | jq -c '.Policies[]')
else
    log_info "No DLM lifecycle policies found"
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
