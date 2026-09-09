#!/bin/bash
#
# AWS — IAM Roles
#
# Lists IAM roles with trust policy, attached managed policies, instance
# profiles, and tags. Also captures the account password policy.
#
# Optional env: EXCLUDE_AWS_MANAGED_ROLES=true|false (default false). When
# true, skips roles with arn:aws:iam::aws:role/* (AWS-managed).
#
# Output: $EVIDENCE_DIR/aws_iam_roles.json
# Optional env (else ambient identity; region defaults to us-east-1): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity comes from the AWS CLI's own credential chain. A manifest target may
# set AWS_PROFILE (per-account fanout); when unset, the CLI uses the ambient
# identity. The helper sets PROFILE (for metadata) and provides aws_target_id.
source "$(dirname "$0")/../_shared/aws.sh"

# Global service: region only selects the API endpoint, never part of identity.
# IAM still needs *a* region resolvable, so default it and export for the CLI.
REGION="${REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$REGION"
EXCLUDE_AWS_ROLES="${EXCLUDE_AWS_MANAGED_ROLES:-false}"

# Per-account output filename (profile, or "ambient") — global service, no region.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_iam_roles_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_iam_roles.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_iam_roles_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_iam_roles %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_iam_roles %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

roles=$(aws iam list-roles --query 'Roles[*].[RoleName,Arn,CreateDate]' --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws iam list-roles failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM roles"
else
    echo "$roles" | jq -c '.[]' | while read -r role; do
        role_name=$(echo "$role" | jq -r '.[0]')
        role_arn=$(echo "$role" | jq -r '.[1]')

        if [ "$EXCLUDE_AWS_ROLES" = "true" ] && [[ "$role_arn" == arn:aws:iam::aws:role/* ]]; then
            continue
        fi

        role_data=$(aws iam get-role --role-name "$role_name" --query 'Role' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam get-role ($role_name) failed" >> "$_FAILURE_LOG"
            continue
        fi
        trust_policy=$(echo "$role_data" | jq '.AssumeRolePolicyDocument')

        attached_policies=$(aws iam list-attached-role-policies --role-name "$role_name" --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-attached-role-policies ($role_name) failed" >> "$_FAILURE_LOG"
            attached_policies='[]'
        fi

        instance_profiles=$(aws iam list-instance-profiles-for-role --role-name "$role_name" --query 'InstanceProfiles[*].[InstanceProfileName,InstanceProfileId]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-instance-profiles-for-role ($role_name) failed" >> "$_FAILURE_LOG"
            instance_profiles='[]'
        fi

        role_tags=$(aws iam list-role-tags --role-name "$role_name" --query 'Tags[*]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-role-tags ($role_name) failed" >> "$_FAILURE_LOG"
            role_tags='[]'
        fi

        role_info=$(jq -n \
            --argjson role "$role_data" \
            --argjson trust "$trust_policy" \
            --argjson policies "$attached_policies" \
            --argjson profiles "$instance_profiles" \
            --argjson tags "$role_tags" \
            '{
                "RoleName": $role.RoleName,
                "Arn": $role.Arn,
                "CreateDate": $role.CreateDate,
                "Description": $role.Description,
                "MaxSessionDuration": $role.MaxSessionDuration,
                "TrustPolicy": $trust,
                "AttachedPolicies": $policies,
                "InstanceProfiles": $profiles,
                "Tags": $tags
            }')

        jq --argjson role "$role_info" '.results += [$role]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

password_policy=$(aws iam get-account-password-policy --query 'PasswordPolicy' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    # Note: no policy set returns NoSuchEntity, which is meaningful absence, not a network failure.
    password_policy='null'
fi
jq --argjson policy "$password_policy" '.results += [{"Type": "PasswordPolicy", "Policy": $policy}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
