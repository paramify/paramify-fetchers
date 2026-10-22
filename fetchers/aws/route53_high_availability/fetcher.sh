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
_HC_JSON="$(mktemp -t aws_route53_high_availability_health_checks.XXXXXX)"
_ITEMS_JSON="$(mktemp -t aws_route53_high_availability_statuses.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_HC_JSON" "$_ITEMS_JSON"' EXIT

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
    # get-health-check-status is genuinely one call per health check (no batch
    # form). Each response is appended raw, in list order, and zipped with its
    # health check in the one jq pass below -- not a jq process and an output
    # rewrite per check.
    printf '%s' "$health_checks" > "$_HC_JSON"
    while read -r hc_id; do
        hc_status=$(aws route53 get-health-check-status --health-check-id "$hc_id" --query 'HealthCheckObservations[*]' --output json 2>/dev/null)
        status_exit=$?
        if [ $status_exit -ne 0 ]; then
            echo "aws route53 get-health-check-status ($hc_id) failed (exit=$status_exit)" >> "$_FAILURE_LOG"
            hc_status='[]'
        fi
        # Empty output could not be read as JSON, which dropped the check.
        [ -n "$hc_status" ] || hc_status='{"__skipped__": true}'
        printf '%s\n' "$hc_status" >> "$_ITEMS_JSON"
    done < <(jq -r '.[] | .Id' "$_HC_JSON" 2>/dev/null)

    jq --slurpfile hcs "$_HC_JSON" --slurpfile statuses "$_ITEMS_JSON" '
        .results += [range(0; $statuses | length) as $i | $statuses[$i] as $s
            | select(($s | type) != "object" or $s.__skipped__ != true)
            | {"Type": "Route53_HealthCheck", "HealthCheckInfo": $hcs[0][$i], "Status": $s}]' \
       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
