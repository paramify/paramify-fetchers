#!/bin/bash
# Reports AWS Shield Advanced subscription status and the list of protected resources.
# No active subscription is valid evidence that Shield Advanced is not enabled (not a failure).
# Output: $EVIDENCE_DIR/aws_shield_dos_protection.json
# Optional env (else the CLI's ambient identity): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Shield Advanced is a GLOBAL service whose API endpoint lives in us-east-1. Pin the
# region for the CLI (via env, not a --region flag) when the target/ambient env left it
# unset, so the call reaches the correct endpoint regardless of where this runs.
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Identity/region come from the AWS CLI credential chain. A manifest target may
# set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account fanout); when unset, the CLI
# uses the ambient identity. The helper sets PROFILE/REGION (for metadata) and
# provides aws_target_id (for the output filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Per-target output filename. Shield is global, so the id is profile-scoped only
# (no region appended) and fanout runs across accounts don't overwrite.
_TARGET_ID="$(aws_target_id)"
OUTPUT_JSON="$OUTPUT_DIR/aws_shield_dos_protection_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_shield_dos_protection.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_shield_dos_protection_fail.XXXXXX)"
_ERR="$(mktemp -t aws_shield_dos_protection_err.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_ERR" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_shield_dos_protection %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_shield_dos_protection %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"subscription_state": null, "subscription_active": false, "protections": []}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream shield_service.py) ---

# Subscription state. Shield Advanced not subscribed is valid evidence, not a failure.
# An account that never opted in returns SubscriptionRequiredException (a non-zero exit),
# while an opted-in-then-cancelled account returns "INACTIVE" (exit 0); both mean "not
# enabled". Capture stderr so aws_service_unavailable can tell the not-in-use case (record
# not enabled, skip list-protections, exit 0) apart from a genuine failure (AccessDenied,
# throttling, … — logged to the failure log for a real exit 1).
subscription_state=$(aws shield get-subscription-state --query 'SubscriptionState' --output text 2>"$_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if aws_service_unavailable "$_ERR"; then
        log_info "Shield Advanced not subscribed for this account — recording as not enabled"
        subscription_state="INACTIVE"
        subscription_active=false
        jq --arg state "$subscription_state" --argjson active "$subscription_active" \
           '.results.subscription_state = $state | .results.subscription_active = $active' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        log_info "Evidence saved to $OUTPUT_JSON"
        exit 0
    fi
    echo "aws shield get-subscription-state failed (exit=$ec)" >> "$_FAILURE_LOG"
    subscription_state="UNKNOWN"
fi
[ -z "$subscription_state" ] && subscription_state="UNKNOWN"

if [ "$subscription_state" = "ACTIVE" ]; then subscription_active=true; else subscription_active=false; fi

jq --arg state "$subscription_state" --argjson active "$subscription_active" \
   '.results.subscription_state = $state | .results.subscription_active = $active' \
   "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# List protected resources only when the subscription is active (mirrors upstream, which
# only lists protections when enabled). list-protections paginates; --output json returns
# the full Protections array.
if [ "$subscription_active" = true ]; then
    protections=$(aws shield list-protections --query 'Protections[*]' --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$protections" ] || ! echo "$protections" | jq . >/dev/null 2>&1; then
        echo "aws shield list-protections failed (exit=$ec)" >> "$_FAILURE_LOG"
        protections='[]'
    fi

    echo "$protections" | jq -c '.[]' | while read -r protection; do
        [ -z "$protection" ] && continue
        record=$(echo "$protection" | jq '{
            id: .Id,
            name: .Name,
            resource_arn: .ResourceArn,
            protection_arn: .ProtectionArn
        }')
        jq --argjson p "$record" '.results.protections += [$p]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
else
    log_info "Shield Advanced not active (subscription_state=$subscription_state) — recording as not enabled"
fi

aws_finish
