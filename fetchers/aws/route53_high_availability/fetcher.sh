#!/bin/bash
#
# AWS — Route 53 High Availability
#
# Lists Route 53 health checks and current status (DNS failover evidence).
#
# Output: $EVIDENCE_DIR/aws_route53_high_availability.json
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
REGION="${REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"

# Per-account output filename (profile) — global service, region not part of identity.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_route53_high_availability_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_route53_high_availability.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_route53_high_availability_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_route53_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_route53_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

health_checks=$(aws route53 list-health-checks --query 'HealthChecks[*]' --output json 2>/dev/null)
hc_exit=$?
if [ $hc_exit -ne 0 ]; then
    echo "aws route53 list-health-checks failed (exit=$hc_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list health checks"
else
    echo "$health_checks" | jq -c '.[]' | while read -r hc; do
        hc_id=$(echo "$hc" | jq -r '.Id')

        hc_status=$(aws route53 get-health-check-status --health-check-id "$hc_id" --query 'HealthCheckObservations[*]' --output json 2>/dev/null)
        status_exit=$?
        if [ $status_exit -ne 0 ]; then
            echo "aws route53 get-health-check-status ($hc_id) failed (exit=$status_exit)" >> "$_FAILURE_LOG"
            hc_status='[]'
        fi

        jq --argjson hc "$hc" --argjson status "$hc_status" \
           '.results += [{"Type": "Route53_HealthCheck", "HealthCheckInfo": $hc, "Status": $status}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
