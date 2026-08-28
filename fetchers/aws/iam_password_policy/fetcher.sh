#!/bin/bash
# Captures the IAM account password policy (minimum length, complexity
# requirements, reuse prevention, max age, change/expiry settings) for
# password-strength evidence.
# Output: $EVIDENCE_DIR/aws_iam_password_policy.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_iam_password_policy_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_iam_password_policy.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_iam_password_policy_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_iam_password_policy %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_iam_password_policy %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

# Retrieve the account password policy. A missing policy (NoSuchEntity) is valid
# evidence ("no custom policy; account uses the IAM default"), not a collection
# failure -> not logged. Capture stderr so we can distinguish NoSuchEntity from
# real errors (AccessDenied, network, etc.).
log_info "Retrieving IAM account password policy"
_POLICY_ERR="$(mktemp -t aws_iam_password_policy_err.XXXXXX)"
policy=$(aws iam get-account-password-policy --query 'PasswordPolicy' --output json 2>"$_POLICY_ERR")
ec=$?
if [ $ec -eq 0 ]; then
    jq --argjson policy "$policy" \
        '.results = {
            "PasswordPolicyExists": true,
            "MinimumPasswordLength": $policy.MinimumPasswordLength,
            "RequireSymbols": $policy.RequireSymbols,
            "RequireNumbers": $policy.RequireNumbers,
            "RequireUppercaseCharacters": $policy.RequireUppercaseCharacters,
            "RequireLowercaseCharacters": $policy.RequireLowercaseCharacters,
            "AllowUsersToChangePassword": $policy.AllowUsersToChangePassword,
            "ExpirePasswords": $policy.ExpirePasswords,
            "MaxPasswordAge": (if ($policy|has("MaxPasswordAge")) then $policy.MaxPasswordAge else null end),
            "PasswordReusePrevention": (if ($policy|has("PasswordReusePrevention")) then $policy.PasswordReusePrevention else null end),
            "HardExpiry": (if ($policy|has("HardExpiry")) then $policy.HardExpiry else null end)
        }' \
        "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
elif grep -q "NoSuchEntity" "$_POLICY_ERR"; then
    log_info "No custom password policy set; account uses the IAM default"
    jq '.results = {"PasswordPolicyExists": false}' \
        "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
else
    echo "aws iam get-account-password-policy failed (exit=$ec)" >> "$_FAILURE_LOG"
    log_error "Failed to get IAM account password policy"
fi
rm -f "$_POLICY_ERR"

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
