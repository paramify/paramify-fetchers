#!/bin/bash
#
# AWS — DMS Encryption Status
#
# For each DMS replication instance and endpoint in the account/region, reports
# encryption posture: instance KMS key + public accessibility, endpoint SSL mode.
#
# Output: $EVIDENCE_DIR/aws_dms_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_dms_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_dms_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_dms_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_dms_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_dms_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"replication_instances": [], "endpoints": []}}' \
  > "$OUTPUT_JSON"

instances=$(aws dms describe-replication-instances --output json 2>/dev/null)
inst_exit=$?
if [ $inst_exit -ne 0 ]; then
    echo "aws dms describe-replication-instances failed (exit=$inst_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to describe DMS replication instances"
else
    while IFS= read -r instance; do
        [ -z "$instance" ] && continue
        jq --argjson data "$instance" '.results.replication_instances += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done < <(echo "$instances" | jq -c '.ReplicationInstances[] | {id: .ReplicationInstanceIdentifier, arn: .ReplicationInstanceArn, status: .ReplicationInstanceStatus, kms_key_id: (.KmsKeyId // "None"), publicly_accessible: .PubliclyAccessible, multi_az: .MultiAZ}')
fi

endpoints=$(aws dms describe-endpoints --output json 2>/dev/null)
ep_exit=$?
if [ $ep_exit -ne 0 ]; then
    echo "aws dms describe-endpoints failed (exit=$ep_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to describe DMS endpoints"
else
    while IFS= read -r endpoint; do
        [ -z "$endpoint" ] && continue
        jq --argjson data "$endpoint" '.results.endpoints += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done < <(echo "$endpoints" | jq -c '.Endpoints[] | {id: .EndpointIdentifier, arn: .EndpointArn, engine_name: .EngineName, ssl_mode: (.SslMode // "none"), kms_key_id: (.KmsKeyId // "None")}')
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
