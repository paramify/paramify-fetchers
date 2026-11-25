#!/bin/bash
# Lists EC2 instances with their state, type, platform, and network configuration
# as an inventory of compute resources in the target region.
# Output: $EVIDENCE_DIR/aws_ec2_instance_inventory.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

source "$(dirname "$0")/../_shared/aws.sh"

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_ec2_instance_inventory_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_ec2_instance_inventory.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_ec2_instance_inventory_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info()  { printf '%s INFO  aws_ec2_instance_inventory %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_ec2_instance_inventory %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata":{"profile":$profile,"region":$region,"datetime":$datetime,"account_id":$account_id,"arn":$arn},"results":{"instances":[],"summary":{}}}' \
  > "$OUTPUT_JSON"

log_info "Collecting EC2 instance inventory"

# Flatten reservations: each reservation holds one or more instances.
instances=$(aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{InstanceId:InstanceId,InstanceType:InstanceType,State:State.Name,Platform:Platform,PlatformDetails:PlatformDetails,LaunchTime:LaunchTime,SubnetId:SubnetId,VpcId:VpcId,PrivateIpAddress:PrivateIpAddress,PublicIpAddress:PublicIpAddress,Tags:Tags}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 describe-instances failed" >> "$_FAILURE_LOG"
    instances='[[]]'
fi

# Flatten the outer reservation grouping (array-of-arrays → flat array).
instances_flat=$(echo "$instances" | jq '[.[] | .[]]')

total_count=$(echo "$instances_flat" | jq 'length')
running_count=$(echo "$instances_flat" | jq '[.[] | select(.State == "running")] | length')
stopped_count=$(echo "$instances_flat" | jq '[.[] | select(.State == "stopped")] | length')

_INSTANCES_JSON="$(mktemp -t aws_ec2_instances.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_INSTANCES_JSON"' EXIT
printf '%s' "$instances_flat" > "$_INSTANCES_JSON"

jq --slurpfile instances "$_INSTANCES_JSON" \
   --arg total   "$total_count" \
   --arg running "$running_count" \
   --arg stopped "$stopped_count" \
   '.results = {
       "instances": ($instances[0] // []),
       "summary": {
         "total_instances":   ($total   | tonumber),
         "running_instances": ($running | tonumber),
         "stopped_instances": ($stopped | tonumber)
       }
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON (total: $total_count, running: $running_count, stopped: $stopped_count)"

aws_finish
