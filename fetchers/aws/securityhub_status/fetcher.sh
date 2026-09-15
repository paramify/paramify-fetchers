#!/bin/bash
# Reports AWS Security Hub status for the target region: enabled/not-subscribed,
# enabled standards subscriptions, and enabled third-party product integrations.
# Security Hub not subscribed is valid evidence that it is not enabled (not a failure).
# Output: $EVIDENCE_DIR/aws_securityhub_status_<target>.json
# Optional env (else the CLI's ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI's own credential chain. A manifest target
# may set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account / multi-region fanout);
# when unset, the CLI uses the ambient identity/region. The helper sets PROFILE
# and REGION (for metadata) and provides aws_target_id (for the filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Per-target output filename (profile+region) so fanout runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_securityhub_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_securityhub_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_securityhub_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_securityhub_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_securityhub_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"status": "UNKNOWN", "hub": {}, "standards": [], "integrations": []}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream prowler securityhub_service) ---

# Determine whether Security Hub is enabled in this region. The service simply not
# being in use is valid evidence ("not enabled"), not a collection failure. It can
# surface in several ways — never subscribed in this region (InvalidAccessException),
# the service not opted-in (SubscriptionRequiredException / OptInRequired), the org
# not in use, the resource not found, etc. The shared aws_service_unavailable helper
# matches all of those; only OTHER API errors (AccessDenied, throttling, …) are real
# failures. Capture stderr so we can tell them apart.
_HUB_ERR="$(mktemp -t aws_securityhub_status_hub.XXXXXX)"
hub=$(aws securityhub describe-hub --output json 2>"$_HUB_ERR")
ec=$?
if [ $ec -ne 0 ]; then
    if aws_service_unavailable "$_HUB_ERR"; then
        log_info "Security Hub not in use in ${REGION:-ambient} ($(tr '\n' ' ' < "$_HUB_ERR")) — recording as not enabled, skipping dependent calls"
        jq '.results.status = "NOT_AVAILABLE"' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    else
        echo "aws securityhub describe-hub failed (exit=$ec): $(tr '\n' ' ' < "$_HUB_ERR")" >> "$_FAILURE_LOG"
    fi
    rm -f "$_HUB_ERR"
else
    rm -f "$_HUB_ERR"
    # Security Hub is active in this region. Record the hub config (ARN, auto-enable flags).
    jq --argjson hub "$hub" '.results.status = "ACTIVE" | .results.hub = $hub' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

    # Enabled standards subscriptions (which compliance standards are turned on).
    standards=$(aws securityhub get-enabled-standards --query 'StandardsSubscriptions[*].{StandardsArn:StandardsArn,SubscriptionArn:StandardsSubscriptionArn,StandardsStatus:StandardsStatus}' --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$standards" ] || ! echo "$standards" | jq . >/dev/null 2>&1; then
        echo "aws securityhub get-enabled-standards failed (exit=$ec)" >> "$_FAILURE_LOG"
    else
        jq --argjson standards "$standards" '.results.standards = ($standards // [])' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi

    # Enabled third-party product integrations (ProductSubscriptions). Prowler ignores
    # Security Hub's integration with itself (.../aws/securityhub).
    integrations=$(aws securityhub list-enabled-products-for-import --query 'ProductSubscriptions[*]' --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$integrations" ] || ! echo "$integrations" | jq . >/dev/null 2>&1; then
        echo "aws securityhub list-enabled-products-for-import failed (exit=$ec)" >> "$_FAILURE_LOG"
    else
        jq --argjson integrations "$integrations" \
           '.results.integrations = [($integrations // [])[] | select(contains("/aws/securityhub") | not)]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi
fi

aws_finish
