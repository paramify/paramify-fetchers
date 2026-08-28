#!/bin/bash
# Reports MFA enforcement for the root account and every IAM user, including
# whether each MFA device is hardware or virtual, for MFA evidence.
# Output: $EVIDENCE_DIR/aws_iam_mfa_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_iam_mfa_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_iam_mfa_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_iam_mfa_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_iam_mfa_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_iam_mfa_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"root_account": {}, "users": []}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# Root account MFA posture. get-account-summary reports whether the root user
# has any MFA device; list-virtual-mfa-devices distinguishes virtual vs hardware
# (a root virtual MFA device has SerialNumber ending in ":mfa/root-account-mfa-device").
log_info "Retrieving root account MFA status"
account_summary=$(aws iam get-account-summary --query 'SummaryMap' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws iam get-account-summary failed" >> "$_FAILURE_LOG"
    account_summary='{}'
fi

# All virtual MFA device serials in the account — used to classify each user's
# devices as virtual, and to detect a root virtual MFA device.
virtual_serials=$(aws iam list-virtual-mfa-devices --query 'VirtualMFADevices[*].SerialNumber' --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws iam list-virtual-mfa-devices failed" >> "$_FAILURE_LOG"
    virtual_serials='[]'
fi

root_info=$(jq -n \
    --argjson summary "$account_summary" \
    --argjson virtual "$virtual_serials" \
    '{
        "RootMFAEnabled": (($summary.AccountMFAEnabled // 0) == 1),
        "RootHardwareMFA": (
            (($summary.AccountMFAEnabled // 0) == 1)
            and (([$virtual[] | select(endswith(":mfa/root-account-mfa-device"))] | length) == 0)
        )
    }')
jq --argjson root "$root_info" '.results.root_account = $root' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# Per-user MFA status.
log_info "Retrieving IAM users"
usernames=$(aws iam list-users --query 'Users[*].UserName' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws iam list-users failed (exit=$ec)" >> "$_FAILURE_LOG"
    log_error "Failed to list IAM users"
else
    echo "$usernames" | jq -r '.[]' | while read -r username; do
        # MFA devices for the user. SerialNumber shape decides the type: an ARN
        # (arn:aws:iam::<acct>:mfa/<name>) is a VIRTUAL device; anything else
        # (a bare hardware serial like GAHT12345678) is a HARDWARE device —
        # mirrors Prowler's serial-number classification.
        mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[*].[SerialNumber,EnableDate]' --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws iam list-mfa-devices ($username) failed" >> "$_FAILURE_LOG"
            continue
        fi

        user_info=$(jq -n \
            --arg name "$username" \
            --argjson devices "$mfa_devices" \
            '{
                "UserName": $name,
                "MFAEnabled": (($devices | length) > 0),
                "MFADevices": [
                    $devices[] | {
                        "SerialNumber": .[0],
                        "EnableDate": .[1],
                        "Type": (if (.[0] | startswith("arn:")) then "virtual" else "hardware" end)
                    }
                ]
            }')

        jq --argjson user "$user_info" '.results.users += [$user]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
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
