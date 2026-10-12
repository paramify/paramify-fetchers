#!/bin/bash
# Inventories IAM users (groups, access keys, MFA devices, login profile) and
# IAM groups (attached policies) for access-review evidence.
# Output: $EVIDENCE_DIR/aws_iam_users_groups.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_iam_users_groups_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_iam_users_groups.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_iam_users_groups_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_iam_users_groups %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_iam_users_groups %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"users": [], "groups": []}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

_USERS_JSON="$(mktemp -t aws_iam_users_groups_users.XXXXXX.json)"
_GROUPS_JSON="$(mktemp -t aws_iam_users_groups_groups.XXXXXX.json)"
_GAAD_JSON="$(mktemp -t aws_iam_users_groups_gaad.XXXXXX.json)"
_PER_USER_JSON="$(mktemp -t aws_iam_users_groups_per_user.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_USERS_JSON" "$_GROUPS_JSON" "$_GAAD_JSON" "$_PER_USER_JSON"' EXIT

# Get all IAM users. list-users carries every field get-user was read for.
log_info "Retrieving IAM users"
aws iam list-users --query 'Users[*].{UserName:UserName,CreateDate:CreateDate,PasswordLastUsed:PasswordLastUsed}' --output json > "$_USERS_JSON" 2>/dev/null
users_ec=$?
if [ $users_ec -ne 0 ]; then
    echo "aws iam list-users failed (exit=$users_ec)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM users"
    echo '[]' > "$_USERS_JSON"
fi

# Get all IAM groups
log_info "Retrieving IAM groups"
aws iam list-groups --query 'Groups[*].{GroupName:GroupName,CreateDate:CreateDate}' --output json > "$_GROUPS_JSON" 2>/dev/null
groups_ec=$?
if [ $groups_ec -ne 0 ]; then
    echo "aws iam list-groups failed (exit=$groups_ec)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM groups"
    echo '[]' > "$_GROUPS_JSON"
fi

# Each user's group memberships and each group's attached policies, in one
# paginated call instead of list-groups-for-user per user and get-group +
# list-attached-group-policies per group. Needs iam:GetAccountAuthorizationDetails
# (in ReadOnlyAccess and SecurityAudit). On failure both fall back to [], the
# default the per-item calls used.
if [ "$(jq 'length' "$_USERS_JSON")" -gt 0 ] || [ "$(jq 'length' "$_GROUPS_JSON")" -gt 0 ]; then
    if ! aws iam get-account-authorization-details --filter User Group \
            --query '{Users:UserDetailList[*].{UserName:UserName,GroupList:GroupList},Groups:GroupDetailList[*].{GroupName:GroupName,AttachedManagedPolicies:AttachedManagedPolicies}}' \
            --output json > "$_GAAD_JSON" 2>/dev/null; then
        echo "aws iam get-account-authorization-details (users, groups) failed" >> "$_FAILURE_LOG"
        echo '{}' > "$_GAAD_JSON"
    fi
else
    echo '{}' > "$_GAAD_JSON"
fi

# Access keys, MFA devices and the login profile have no bulk source that is
# current (the credential report can be four hours old), so they stay one call
# each per user. Their raw responses are appended in a fixed order and joined
# in one jq pass below -- no jq process or output rewrite per user.
while read -r username; do
    [ -z "$username" ] && continue

    access_keys=$(aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output json 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$access_keys" ]; then
        echo "aws iam list-access-keys ($username) failed" >> "$_FAILURE_LOG"
        access_keys='[]'
    fi

    mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[*].[SerialNumber,EnableDate]' --output json 2>/dev/null)
    if [ $? -ne 0 ] || [ -z "$mfa_devices" ]; then
        echo "aws iam list-mfa-devices ($username) failed" >> "$_FAILURE_LOG"
        mfa_devices='[]'
    fi

    # Check for login profile. Absence (NoSuchEntity) is valid evidence
    # ("no console password"), not a collection failure -> not logged.
    has_login_profile=false
    if aws iam get-login-profile --user-name "$username" > /dev/null 2>&1; then
        has_login_profile=true
    fi

    printf '%s\n%s\n%s\n' "$access_keys" "$mfa_devices" "$has_login_profile" >> "$_PER_USER_JSON"
done < <(jq -r '.[].UserName' "$_USERS_JSON")

jq --slurpfile users "$_USERS_JSON" --slurpfile groups "$_GROUPS_JSON" --slurpfile gaad "$_GAAD_JSON" --slurpfile per_user "$_PER_USER_JSON" '
    (reduce ($gaad[0].Users // [])[] as $u ({}; .[$u.UserName] = [($u.GroupList // [])[]])) as $user_groups
    | (reduce ($gaad[0].Groups // [])[] as $g ({}; .[$g.GroupName] = [($g.AttachedManagedPolicies // [])[] | [.PolicyName, .PolicyArn]])) as $group_policies
    | .results.users += [range(0; $users[0] | length) as $i | $users[0][$i]
        | {
            "UserName": .UserName,
            "CreateDate": .CreateDate,
            "PasswordLastUsed": .PasswordLastUsed,
            "Groups": ($user_groups[.UserName] // []),
            "AccessKeys": $per_user[3 * $i],
            "MFADevices": $per_user[3 * $i + 1],
            "HasLoginProfile": $per_user[3 * $i + 2]
        }]
    | .results.groups += [$groups[0][]
        | {
            "GroupName": .GroupName,
            "CreateDate": .CreateDate,
            "Policies": ($group_policies[.GroupName] // [])
        }]
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
