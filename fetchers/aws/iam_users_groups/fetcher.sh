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
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

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

# Get all IAM users
log_info "Retrieving IAM users"
users=$(aws iam list-users --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws iam list-users failed (exit=$ec)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM users"
else
    echo "$users" | jq -c '.[]' | while read -r user; do
        username=$(echo "$user" | jq -r '.[0]')

        # Get user details
        user_data=$(aws iam get-user --user-name "$username" --query 'User' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam get-user ($username) failed" >> "$_FAILURE_LOG"
            continue
        fi

        # Get user groups
        groups=$(aws iam list-groups-for-user --user-name "$username" --query 'Groups[*].GroupName' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-groups-for-user ($username) failed" >> "$_FAILURE_LOG"
            groups='[]'
        fi

        # Get access keys
        access_keys=$(aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-access-keys ($username) failed" >> "$_FAILURE_LOG"
            access_keys='[]'
        fi

        # Get MFA devices
        mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[*].[SerialNumber,EnableDate]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-mfa-devices ($username) failed" >> "$_FAILURE_LOG"
            mfa_devices='[]'
        fi

        # Check for login profile. Absence (NoSuchEntity) is valid evidence
        # ("no console password"), not a collection failure -> not logged.
        has_login_profile=false
        if aws iam get-login-profile --user-name "$username" > /dev/null 2>&1; then
            has_login_profile=true
        fi

        # Combine all user data
        user_info=$(jq -n \
            --argjson user "$user_data" \
            --argjson groups "$groups" \
            --argjson access_keys "$access_keys" \
            --argjson mfa_devices "$mfa_devices" \
            --arg has_login "$has_login_profile" \
            '{
                "UserName": $user.UserName,
                "CreateDate": $user.CreateDate,
                "PasswordLastUsed": $user.PasswordLastUsed,
                "Groups": $groups,
                "AccessKeys": $access_keys,
                "MFADevices": $mfa_devices,
                "HasLoginProfile": ($has_login | test("true"))
            }')

        jq --argjson user "$user_info" '.results.users += [$user]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

# Get all IAM groups
log_info "Retrieving IAM groups"
groups=$(aws iam list-groups --query 'Groups[*].[GroupName,CreateDate]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws iam list-groups failed (exit=$ec)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM groups"
else
    echo "$groups" | jq -c '.[]' | while read -r group; do
        groupname=$(echo "$group" | jq -r '.[0]')

        # Get group details
        group_data=$(aws iam get-group --group-name "$groupname" --query 'Group' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam get-group ($groupname) failed" >> "$_FAILURE_LOG"
            continue
        fi

        # Get group policies
        policies=$(aws iam list-attached-group-policies --group-name "$groupname" --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-attached-group-policies ($groupname) failed" >> "$_FAILURE_LOG"
            policies='[]'
        fi

        # Combine all group data
        group_info=$(jq -n \
            --argjson group "$group_data" \
            --argjson policies "$policies" \
            '{
                "GroupName": $group.GroupName,
                "CreateDate": $group.CreateDate,
                "Policies": $policies
            }')

        jq --argjson group "$group_info" '.results.groups += [$group]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
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
