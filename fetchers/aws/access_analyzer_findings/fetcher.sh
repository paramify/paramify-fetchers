#!/bin/bash
# KSI-IAM-ELP: IAM Access Analyzer analyzers and active external-access findings.
# Lists analyzers (arn, name, status, type) and, for each ACTIVE analyzer, its
# active findings (id, status, resource, resource type, external principal).
# No analyzers or no active findings is valid evidence (not a failure).
# Output: $EVIDENCE_DIR/aws_access_analyzer_findings_<target>.json
# Optional env (else the CLI's ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
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
OUTPUT_JSON="$OUTPUT_DIR/aws_access_analyzer_findings_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_access_analyzer_findings.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_access_analyzer_findings_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_access_analyzer_findings %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_access_analyzer_findings %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# --- per-script data collection (ported from upstream accessanalyzer_service) ---

# List analyzers. No analyzers is valid evidence (Access Analyzer not enabled in
# this region), not a failure.
analyzers=$(aws accessanalyzer list-analyzers \
    --query 'analyzers[*].{arn:arn,name:name,status:status,type:type}' \
    --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws accessanalyzer list-analyzers failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    analyzers='[]'
fi
if [ -z "$analyzers" ] || ! echo "$analyzers" | jq . >/dev/null 2>&1; then
    analyzers='[]'
fi

if [ "$(echo "$analyzers" | jq 'length')" -eq 0 ]; then
    log_info "No Access Analyzer analyzers found in ${REGION:-ambient region}"
fi

# For each analyzer, attach its active findings (only ACTIVE analyzers can be
# queried for findings; upstream skips non-ACTIVE analyzers).
while read -r analyzer; do
    [ -z "$analyzer" ] && continue
    analyzer_arn=$(echo "$analyzer" | jq -r '.arn')
    analyzer_status=$(echo "$analyzer" | jq -r '.status')

    analyzer_data=$(echo "$analyzer" | jq '. + {"findings": []}')

    if [ "$analyzer_status" = "ACTIVE" ]; then
        findings=$(aws accessanalyzer list-findings \
            --analyzer-arn "$analyzer_arn" \
            --filter '{"status":{"eq":["ACTIVE"]}}' \
            --query 'findings[*].{id:id,status:status,resource:resource,resourceType:resourceType,principal:principal,isPublic:isPublic}' \
            --output json 2>/dev/null)
        findings_exit=$?
        if [ $findings_exit -ne 0 ]; then
            echo "aws accessanalyzer list-findings ($analyzer_arn) failed (exit=$findings_exit)" >> "$_FAILURE_LOG"
            findings='[]'
        fi
        if [ -z "$findings" ] || ! echo "$findings" | jq . >/dev/null 2>&1; then
            findings='[]'
        fi
        analyzer_data=$(echo "$analyzer_data" | jq --argjson f "$findings" '.findings = $f')
    fi

    jq --argjson data "$analyzer_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done < <(echo "$analyzers" | jq -c '.[]')

aws_finish
