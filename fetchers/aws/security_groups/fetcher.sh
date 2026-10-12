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

# One describe for every group's rules. The list call already carries
# IpPermissions and IpPermissionsEgress; re-describing each group once per
# direction cost two CLI processes per group.
_SG_JSON="$(mktemp -t aws_security_groups_list.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_SG_JSON"' EXIT
aws ec2 describe-security-groups --query 'SecurityGroups[*].{GroupId:GroupId,IpPermissions:IpPermissions,IpPermissionsEgress:IpPermissionsEgress}' --output json > "$_SG_JSON" 2>/dev/null
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws ec2 describe-security-groups (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list security groups"
else
    # Validators match on this rule shape by key order, so keys are only ever
    # appended: Direction, Protocol, FromPort, ToPort, CIDRs (IPv4 ranges joined
    # with ", "), then IPv6CIDRs (IPv6 ranges, joined the same way).
    #
    # A rule with no ports -- protocol -1, "All traffic" -- is kept with FromPort
    # and ToPort null. Before 0.3.0 it was dropped, which hid an inbound
    # all-traffic rule from 0.0.0.0/0 and every default allow-all egress rule.
    # Before 0.3.0 IPv6 ranges were not read at all, so a rule open to ::/0
    # looked closed.
    jq --slurpfile groups "$_SG_JSON" '
        def rules($perms; $label):
            [$perms[]?
             | {"Direction": $label, "Protocol": (.IpProtocol | if . == null then "None" else tostring end),
                "FromPort": .FromPort, "ToPort": .ToPort,
                "CIDRs": ([.IpRanges[]?.CidrIp | select(. != null)] | join(", ")),
                "IPv6CIDRs": ([.Ipv6Ranges[]?.CidrIpv6 | select(. != null)] | join(", "))}];
        .results += [$groups[0][]? | {"GroupId": .GroupId,
            "Rules": (rules(.IpPermissions; "INBOUND RULES") + rules(.IpPermissionsEgress; "OUTBOUND RULES"))}]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
