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

# Two paginated calls cover every role, instead of four per role (get-role,
# list-attached-role-policies, list-instance-profiles-for-role, list-role-tags),
# which ran past the runner's timeout in accounts with hundreds of roles.
# list-roles carries the Role fields get-role returned that are used here
# (Description, MaxSessionDuration, the trust policy); get-account-authorization-
# details carries the attachments, instance profiles and tags. It needs
# iam:GetAccountAuthorizationDetails (in ReadOnlyAccess and SecurityAudit).
_ROLES_JSON="$(mktemp -t aws_iam_roles_list.XXXXXX.json)"
_GAAD_JSON="$(mktemp -t aws_iam_roles_gaad.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_ROLES_JSON" "$_GAAD_JSON"' EXIT

aws iam list-roles --query 'Roles[*]' --output json > "$_ROLES_JSON" 2>/dev/null
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws iam list-roles failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM roles"
else
    # A failed details call keeps the roles and falls back to [] for what it
    # would have supplied -- the default each per-role call used on failure.
    if ! aws iam get-account-authorization-details --filter Role \
            --query 'RoleDetailList[*].{RoleName:RoleName,AttachedManagedPolicies:AttachedManagedPolicies,InstanceProfileList:InstanceProfileList,Tags:Tags}' \
            --output json > "$_GAAD_JSON" 2>/dev/null; then
        echo "aws iam get-account-authorization-details (roles) failed" >> "$_FAILURE_LOG"
        echo '[]' > "$_GAAD_JSON"
    fi

    jq --slurpfile roles "$_ROLES_JSON" --slurpfile details "$_GAAD_JSON" --arg exclude "$EXCLUDE_AWS_ROLES" '
        (reduce $details[0][]? as $d ({}; .[$d.RoleName] = $d)) as $by_name
        | .results += [$roles[0][]?
            | select(($exclude == "true" and (.Arn | startswith("arn:aws:iam::aws:role/"))) | not)
            | ($by_name[.RoleName] // {}) as $d
            | {
                "RoleName": .RoleName,
                "Arn": .Arn,
                "CreateDate": .CreateDate,
                "Description": .Description,
                "MaxSessionDuration": .MaxSessionDuration,
                "TrustPolicy": .AssumeRolePolicyDocument,
                "AttachedPolicies": [($d.AttachedManagedPolicies // [])[] | [.PolicyName, .PolicyArn]],
                "InstanceProfiles": [($d.InstanceProfileList // [])[] | [.InstanceProfileName, .InstanceProfileId]],
                "Tags": ($d.Tags // [])
            }]
    ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

password_policy=$(aws iam get-account-password-policy --query 'PasswordPolicy' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    # Note: no policy set returns NoSuchEntity, which is meaningful absence, not a network failure.
    password_policy='null'
fi
jq --argjson policy "$password_policy" '.results += [{"Type": "PasswordPolicy", "Policy": $policy}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
