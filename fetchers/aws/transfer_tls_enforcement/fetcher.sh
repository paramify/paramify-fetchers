#!/bin/bash
# Collects AWS Transfer Family server protocols and security policy (TLS enforcement).
# Output: $EVIDENCE_DIR/aws_transfer_tls_enforcement.json
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

# Per-target output filename (profile+region) so multi-target runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_transfer_tls_enforcement_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_transfer_tls_enforcement.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_transfer_tls_enforcement_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_transfer_tls_enforcement %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_transfer_tls_enforcement %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# --- per-script data collection (ported from prowler transfer_service.py) ---

# 1. List Transfer Family servers in the (ambient/target) region.
server_ids=$(aws transfer list-servers \
    --query 'Servers[*].ServerId' \
    --output text 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws transfer list-servers failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list Transfer Family servers"
else
    # 2. Describe each server to capture protocols and security policy (TLS).
    for server_id in $(aws_text_list "$server_ids"); do
        server=$(aws transfer describe-server \
            --server-id "$server_id" \
            --query 'Server.{
                arn:Arn,
                id:ServerId,
                protocols:Protocols,
                security_policy_name:SecurityPolicyName,
                endpoint_type:EndpointType,
                state:State
            }' \
            --output json 2>/dev/null)
        describe_exit=$?
        if [ $describe_exit -ne 0 ]; then
            echo "aws transfer describe-server ($server_id) failed (exit=$describe_exit)" >> "$_FAILURE_LOG"
            continue
        fi

        jq --argjson data "$server" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
