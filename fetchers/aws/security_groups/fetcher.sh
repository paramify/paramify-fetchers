#!/bin/bash
#
# AWS — Security Groups
#
# Lists EC2 security groups and inbound/outbound rules for each.
#
# Output: $EVIDENCE_DIR/aws_security_groups.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_security_groups_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_security_groups.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_security_groups_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_security_groups %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_security_groups %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

sg_ids=$(aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws ec2 describe-security-groups (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list security groups"
else
    for sg_id in $sg_ids; do
        group_data=$(jq -n --arg id "$sg_id" '{"GroupId": $id, "Rules": []}')

        for direction in inbound outbound; do
            if [ "$direction" == "inbound" ]; then
                query_path='IpPermissions'
                label="INBOUND RULES"
            else
                query_path='IpPermissionsEgress'
                label="OUTBOUND RULES"
            fi

            rules=$(aws ec2 describe-security-groups \
                --group-ids "$sg_id" \
                --query "SecurityGroups[0].$query_path[*].[IpProtocol,FromPort,ToPort,join(', ', IpRanges[*].CidrIp)]" \
                --output text 2>/dev/null)
            rules_exit=$?
            if [ $rules_exit -ne 0 ]; then
                echo "aws ec2 describe-security-groups ($sg_id $direction) failed" >> "$_FAILURE_LOG"
                continue
            fi

            if [ -n "$rules" ]; then
                while IFS=$'\t' read -r protocol from to cidrs; do
                    group_data=$(echo "$group_data" | jq --arg dir "$label" --arg p "$protocol" --arg f "${from:-null}" --arg t "${to:-null}" --arg c "${cidrs:-}" \
                        '.Rules += [{"Direction":$dir, "Protocol":$p, "FromPort":($f|tonumber?), "ToPort":($t|tonumber?), "CIDRs":$c}]')
                done <<< "$rules"
            fi
        done

        jq --argjson data "$group_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
