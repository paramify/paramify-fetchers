#!/bin/bash
#
# AWS — Network ACLs
#
# Lists EC2 network ACLs and inbound/outbound entries for each.
#
# Output: $EVIDENCE_DIR/aws_network_acls.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_network_acls_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_network_acls.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_network_acls_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_network_acls %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_network_acls %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

nacl_ids=$(aws ec2 describe-network-acls --query 'NetworkAcls[*].NetworkAclId' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws ec2 describe-network-acls (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list network ACLs"
else
    for nacl_id in $(aws_text_list "$nacl_ids"); do
        nacl_detail=$(aws ec2 describe-network-acls \
            --network-acl-ids "$nacl_id" \
            --query 'NetworkAcls[0].{Id:NetworkAclId,VpcId:VpcId,IsDefault:IsDefault,Entries:Entries}' \
            --output json 2>/dev/null)
        detail_exit=$?
        if [ $detail_exit -ne 0 ]; then
            echo "aws ec2 describe-network-acls ($nacl_id) failed" >> "$_FAILURE_LOG"
            continue
        fi

        nacl_data=$(echo "$nacl_detail" | jq '{
            "NetworkAclId": .Id,
            "VpcId": .VpcId,
            "IsDefault": .IsDefault,
            "Entries": [.Entries[] | {
                "RuleNumber": .RuleNumber,
                "Direction": (if .Egress then "OUTBOUND" else "INBOUND" end),
                "Protocol": .Protocol,
                "RuleAction": .RuleAction,
                "FromPort": (.PortRange.From // null),
                "ToPort": (.PortRange.To // null),
                "CidrBlock": (.CidrBlock // .Ipv6CidrBlock // null)
            }]
        }')

        jq --argjson data "$nacl_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
