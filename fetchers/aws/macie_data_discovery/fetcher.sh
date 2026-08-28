#!/bin/bash
# Reports Amazon Macie data-discovery posture in a region: session enabled status,
# automated sensitive-data discovery status, classification jobs, and a findings summary.
# A disabled Macie session is valid evidence that Macie is not enabled (not a failure).
# Output: $EVIDENCE_DIR/aws_macie_data_discovery.json
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

# Per-target output filename (profile+region) so fanout runs don't overwrite. Macie
# (macie2) is a regional service, so the region is part of the target id.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_macie_data_discovery_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_macie_data_discovery.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_macie_data_discovery_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_macie_data_discovery %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_macie_data_discovery %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"session": {}, "automated_discovery": {}, "classification_jobs": [], "findings_summary": {}}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (Macie data-discovery posture) ---

# Macie session status. Macie not being in use is valid evidence, not a failure: the
# call errors with a not-enabled / not-subscribed / not-opted-in / org-not-in-use
# message when the account/region was never opted in. Treat that as DISABLED; only
# OTHER API errors (throttling, genuine AccessDenied on an enabled account, …) are
# collection failures. Capture stderr so the shared helper can tell them apart.
_SESSION_ERR="$(mktemp -t aws_macie_data_discovery_session.XXXXXX)"
session=$(aws macie2 get-macie-session --output json 2>"$_SESSION_ERR")
ec=$?
macie_enabled=false
if [ $ec -ne 0 ]; then
    if aws_service_unavailable "$_SESSION_ERR"; then
        log_info "Macie not in use in $REGION (service not enabled/subscribed) — recording session as DISABLED"
        session='{"status":"DISABLED"}'
    else
        echo "aws macie2 get-macie-session failed (exit=$ec): $(tr '\n' ' ' < "$_SESSION_ERR")" >> "$_FAILURE_LOG"
        session='{}'
    fi
fi
rm -f "$_SESSION_ERR"
if [ -z "$session" ] || ! echo "$session" | jq . >/dev/null 2>&1; then
    session='{}'
fi
if [ "$(echo "$session" | jq -r '.status // "DISABLED"')" = "ENABLED" ]; then
    macie_enabled=true
fi

jq --argjson session "$session" '.results.session = $session' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

# The remaining calls only make sense (and only succeed) on an enabled Macie session.
if [ "$macie_enabled" = true ]; then
    # Automated sensitive-data discovery configuration.
    auto=$(aws macie2 get-automated-discovery-configuration --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$auto" ] || ! echo "$auto" | jq . >/dev/null 2>&1; then
        echo "aws macie2 get-automated-discovery-configuration failed (exit=$ec)" >> "$_FAILURE_LOG"
    else
        jq --argjson auto "$auto" '.results.automated_discovery = $auto' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi

    # Classification (sensitive-data discovery) jobs.
    jobs=$(aws macie2 list-classification-jobs --query 'items[*].{jobId:jobId,name:name,jobStatus:jobStatus,jobType:jobType,createdAt:createdAt}' --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$jobs" ] || ! echo "$jobs" | jq . >/dev/null 2>&1; then
        echo "aws macie2 list-classification-jobs failed (exit=$ec)" >> "$_FAILURE_LOG"
    else
        jq --argjson jobs "$jobs" '.results.classification_jobs = ($jobs // [])' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi

    # Sensitive-data findings summary, grouped by finding type.
    findings=$(aws macie2 get-finding-statistics --group-by type --output json 2>/dev/null)
    ec=$?
    if [ $ec -ne 0 ] || [ -z "$findings" ] || ! echo "$findings" | jq . >/dev/null 2>&1; then
        echo "aws macie2 get-finding-statistics failed (exit=$ec)" >> "$_FAILURE_LOG"
    else
        jq --argjson findings "$findings" '.results.findings_summary = $findings' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi
else
    log_info "Macie session not ENABLED in $REGION — skipping discovery/jobs/findings collection"
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
