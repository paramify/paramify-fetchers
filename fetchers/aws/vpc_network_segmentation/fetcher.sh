#!/bin/bash
#
# AWS — VPC Network Segmentation
#
# Lists VPCs, subnets, peering connections, and endpoints to document
# network topology and segmentation.
#
# Output: $EVIDENCE_DIR/aws_vpc_network_segmentation_<target>.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_vpc_network_segmentation_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_vpc_network_segmentation.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_vpc_network_segmentation_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_vpc_network_segmentation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_vpc_network_segmentation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# VPCs — top-level network boundaries (id, CIDR, default flag).
vpcs=$(aws ec2 describe-vpcs \
    --query 'Vpcs[*].{VpcId:VpcId,CidrBlock:CidrBlock,IsDefault:IsDefault,State:State,Tags:Tags}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 describe-vpcs failed" >> "$_FAILURE_LOG"
    log_error "Failed to describe VPCs"
else
    jq --argjson data "$vpcs" '.results += [{"ResourceType":"Vpcs","Items":$data}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

# Subnets — segmentation within a VPC (CIDR, AZ, public-IP-on-launch).
subnets=$(aws ec2 describe-subnets \
    --query 'Subnets[*].{SubnetId:SubnetId,VpcId:VpcId,CidrBlock:CidrBlock,AvailabilityZone:AvailabilityZone,DefaultForAz:DefaultForAz,MapPublicIpOnLaunch:MapPublicIpOnLaunch,Tags:Tags}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 describe-subnets failed" >> "$_FAILURE_LOG"
    log_error "Failed to describe subnets"
else
    jq --argjson data "$subnets" '.results += [{"ResourceType":"Subnets","Items":$data}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

# Peering connections — cross-VPC reachability that crosses segmentation boundaries.
peerings=$(aws ec2 describe-vpc-peering-connections \
    --query 'VpcPeeringConnections[*].{VpcPeeringConnectionId:VpcPeeringConnectionId,Status:Status.Code,RequesterVpc:RequesterVpcInfo.VpcId,RequesterCidr:RequesterVpcInfo.CidrBlock,AccepterVpc:AccepterVpcInfo.VpcId,AccepterCidr:AccepterVpcInfo.CidrBlock,Tags:Tags}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 describe-vpc-peering-connections failed" >> "$_FAILURE_LOG"
    log_error "Failed to describe VPC peering connections"
else
    jq --argjson data "$peerings" '.results += [{"ResourceType":"VpcPeeringConnections","Items":$data}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

# Endpoints — private service access paths into the VPC.
endpoints=$(aws ec2 describe-vpc-endpoints \
    --query 'VpcEndpoints[*].{VpcEndpointId:VpcEndpointId,VpcId:VpcId,ServiceName:ServiceName,VpcEndpointType:VpcEndpointType,State:State,SubnetIds:SubnetIds,OwnerId:OwnerId,Tags:Tags}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ec2 describe-vpc-endpoints failed" >> "$_FAILURE_LOG"
    log_error "Failed to describe VPC endpoints"
else
    jq --argjson data "$endpoints" '.results += [{"ResourceType":"VpcEndpoints","Items":$data}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
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
