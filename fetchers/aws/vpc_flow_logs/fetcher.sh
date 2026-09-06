#!/bin/bash
#
# AWS — VPC Flow Logs
#
# Lists each VPC and whether flow logging is enabled, plus the flow log
# destination and traffic type when present. Maps to KSI-MLA-LET.
#
# Output: $EVIDENCE_DIR/aws_vpc_flow_logs.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_vpc_flow_logs_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_vpc_flow_logs.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_vpc_flow_logs_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_vpc_flow_logs %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_vpc_flow_logs %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

vpc_ids=$(aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws ec2 describe-vpcs (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list VPCs"
else
    for vpc_id in $(aws_text_list "$vpc_ids"); do
        vpc_attrs=$(aws ec2 describe-vpcs \
            --vpc-ids "$vpc_id" \
            --query "Vpcs[0].{Id:VpcId,IsDefault:IsDefault,CidrBlock:CidrBlock,Name:Tags[?Key=='Name']|[0].Value}" \
            --output json 2>/dev/null)
        attrs_exit=$?
        if [ $attrs_exit -ne 0 ]; then
            echo "aws ec2 describe-vpcs ($vpc_id attrs) failed" >> "$_FAILURE_LOG"
            continue
        fi

        flow_logs=$(aws ec2 describe-flow-logs \
            --filter "Name=resource-id,Values=$vpc_id" \
            --query "FlowLogs[*].{Destination:LogDestinationType,LogDestination:LogDestination,TrafficType:TrafficType,Status:FlowLogStatus}" \
            --output json 2>/dev/null)
        fl_exit=$?
        if [ $fl_exit -ne 0 ]; then
            echo "aws ec2 describe-flow-logs ($vpc_id) failed" >> "$_FAILURE_LOG"
            continue
        fi

        vpc_data=$(jq -n --argjson attrs "$vpc_attrs" --argjson fl "$flow_logs" \
            '{"Id": $attrs.Id, "Name": ($attrs.Name // ""), "Default": $attrs.IsDefault, "CidrBlock": $attrs.CidrBlock, "FlowLogsEnabled": (($fl | length) > 0), "FlowLogs": $fl}')

        jq --argjson data "$vpc_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
