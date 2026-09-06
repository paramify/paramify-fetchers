#!/bin/bash
#
# AWS — Load Balancer High Availability
#
# Lists ELBv2 load balancers (ALB, NLB) and per-LB target groups, attributes,
# and availability zones.
#
# Output: $EVIDENCE_DIR/aws_load_balancer_high_availability.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_load_balancer_high_availability_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_load_balancer_high_availability.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_load_balancer_high_availability_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_load_balancer_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_load_balancer_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

load_balancers=$(aws elbv2 describe-load-balancers --query 'LoadBalancers[*]' --output json 2>/dev/null)
lb_exit=$?
if [ $lb_exit -ne 0 ]; then
    echo "aws elbv2 describe-load-balancers failed (exit=$lb_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to describe load balancers"
else
    echo "$load_balancers" | jq -c '.[]' | while read -r lb; do
        lb_arn=$(echo "$lb" | jq -r '.LoadBalancerArn')
        lb_azs=$(echo "$lb" | jq -r '.AvailabilityZones[]' 2>/dev/null | tr '\n' ' ')

        target_groups=$(aws elbv2 describe-target-groups --load-balancer-arn "$lb_arn" --query 'TargetGroups[*]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws elbv2 describe-target-groups ($lb_arn) failed" >> "$_FAILURE_LOG"
            target_groups='[]'
        fi

        lb_attributes=$(aws elbv2 describe-load-balancer-attributes --load-balancer-arn "$lb_arn" --query 'Attributes[*]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws elbv2 describe-load-balancer-attributes ($lb_arn) failed" >> "$_FAILURE_LOG"
            lb_attributes='[]'
        fi

        jq --argjson lb "$lb" --arg azs "$lb_azs" --argjson targets "$target_groups" --argjson attrs "$lb_attributes" \
           '.results += [{"Type": "LoadBalancer", "LoadBalancerInfo": $lb, "AvailabilityZones": $azs, "TargetGroups": $targets, "Attributes": $attrs}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
