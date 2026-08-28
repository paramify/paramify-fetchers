#!/bin/bash
# Lists SSM managed instances and their patch compliance status, summarizing
# compliant vs non-compliant counts.
# Output: $EVIDENCE_DIR/aws_ssm_patch_compliance.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_ssm_patch_compliance_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_ssm_patch_compliance.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_ssm_patch_compliance_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_ssm_patch_compliance %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_ssm_patch_compliance %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"managed_instances": [], "patch_compliance": [], "summary": {}}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from prowler ssm_service) ---

log_info "Collecting SSM managed instances and patch compliance"

# SSM managed instances (describe_instance_information -> ManagedInstance: id/arn/region).
managed=$(aws ssm describe-instance-information \
    --query 'InstanceInformationList[*].{InstanceId:InstanceId,PingStatus:PingStatus,PlatformName:PlatformName,PlatformVersion:PlatformVersion,ResourceType:ResourceType}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ssm describe-instance-information failed" >> "$_FAILURE_LOG"
    managed='[]'
fi

# Patch compliance per resource (list_resource_compliance_summaries -> ComplianceResource:
# id/status COMPLIANT|NON_COMPLIANT), scoped to ComplianceType=Patch for KSI-SVC-EIS.
compliance=$(aws ssm list-resource-compliance-summaries \
    --filters Key=ComplianceType,Values=Patch \
    --query 'ResourceComplianceSummaryItems[*].{ResourceId:ResourceId,ResourceType:ResourceType,Status:Status,OverallSeverity:OverallSeverity}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ssm list-resource-compliance-summaries failed" >> "$_FAILURE_LOG"
    compliance='[]'
fi

# Compute summary counts before the single jq write so summary is never missing.
managed_count=$(echo "$managed" | jq 'length')
compliant_count=$(echo "$compliance" | jq '[.[] | select(.Status == "COMPLIANT")] | length')
non_compliant_count=$(echo "$compliance" | jq '[.[] | select(.Status == "NON_COMPLIANT")] | length')

jq --argjson instances "$managed" \
   --argjson compliance "$compliance" \
   --arg managed_count "$managed_count" \
   --arg compliant_count "$compliant_count" \
   --arg non_compliant_count "$non_compliant_count" \
   '.results = {
       "managed_instances": ($instances // []),
       "patch_compliance": ($compliance // []),
       "summary": {
         "managed_instance_count": ($managed_count | tonumber),
         "compliant_count": ($compliant_count | tonumber),
         "non_compliant_count": ($non_compliant_count | tonumber)
       }
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Managed instances: $managed_count; compliant: $compliant_count; non-compliant: $non_compliant_count"

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
