#!/bin/bash
#
# AWS — IAM Policies
#
# Lists customer-managed IAM policies and per-policy default version document
# + attached entities.
#
# Output: $EVIDENCE_DIR/aws_iam_policies.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_iam_policies_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_iam_policies.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_iam_policies_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_iam_policies %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_iam_policies %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# Two paginated calls cover every customer-managed policy, instead of three per
# policy (get-policy, get-policy-version, list-entities-for-policy), which ran
# past the runner's timeout in accounts with hundreds of policies.
# get-account-authorization-details returns each policy's metadata and every
# version's document, plus each user, group and role with what it attaches; the
# entity lists are that relation inverted. It needs
# iam:GetAccountAuthorizationDetails (in ReadOnlyAccess and SecurityAudit).
_POLICIES_JSON="$(mktemp -t aws_iam_policies_list.XXXXXX.json)"
_GAAD_JSON="$(mktemp -t aws_iam_policies_gaad.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_POLICIES_JSON" "$_GAAD_JSON"' EXIT

aws iam list-policies --scope Local --query 'Policies[*].Arn' --output json > "$_POLICIES_JSON" 2>/dev/null
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws iam list-policies failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM policies"
elif [ "$(jq 'length' "$_POLICIES_JSON" 2>/dev/null || echo 0)" -eq 0 ]; then
    :  # no customer-managed policies: nothing to describe
elif ! aws iam get-account-authorization-details --filter LocalManagedPolicy User Group Role \
        --query '{Policies:Policies,Users:UserDetailList[*].{Name:UserName,Attached:AttachedManagedPolicies[*].PolicyArn,Boundary:PermissionsBoundary.PermissionsBoundaryArn},Groups:GroupDetailList[*].{Name:GroupName,Attached:AttachedManagedPolicies[*].PolicyArn},Roles:RoleDetailList[*].{Name:RoleName,Attached:AttachedManagedPolicies[*].PolicyArn,Boundary:PermissionsBoundary.PermissionsBoundaryArn}}' \
        --output json > "$_GAAD_JSON" 2>/dev/null; then
    # Without it no policy can be described -- as when get-policy failed for each.
    echo "aws iam get-account-authorization-details (policies) failed" >> "$_FAILURE_LOG"
else
    # list-entities-for-policy, with no usage filter, named entities that attach
    # the policy OR use it as their permissions boundary; both are kept.
    jq --slurpfile arns "$_POLICIES_JSON" --slurpfile gaad "$_GAAD_JSON" '
        $gaad[0] as $g
        | (reduce $g.Policies[]? as $p ({}; .[$p.Arn] = $p)) as $by_arn
        | def using($entities; $arn): [$entities[]? | select(any((.Attached // [])[]; . == $arn) or .Boundary == $arn) | .Name];
          .results += [$arns[0][]? | . as $arn | $by_arn[$arn] | select(. != null)
            | {
                "PolicyName": .PolicyName,
                "PolicyId": .PolicyId,
                "Arn": .Arn,
                "CreateDate": .CreateDate,
                "UpdateDate": .UpdateDate,
                "Description": .Description,
                "PolicyDocument": (first(.PolicyVersionList[]? | select(.IsDefaultVersion) | .Document) // {}),
                "AttachedGroups": using($g.Groups; $arn),
                "AttachedUsers": using($g.Users; $arn),
                "AttachedRoles": using($g.Roles; $arn)
            }]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
