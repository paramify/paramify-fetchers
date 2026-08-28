#!/bin/bash
#
# AWS — MSK (Kafka) Encryption Status
#
# For each Amazon MSK (Kafka) cluster in the account/region, reports encryption
# in transit (client-broker setting) and encryption at rest (KMS key).
# Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_kafka_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_kafka_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_kafka_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_kafka_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_kafka_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_kafka_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {"clusters": [], "summary": {}}}' \
  > "$OUTPUT_JSON"

total_clusters=0
encrypted_clusters=0

_ERR="$(mktemp -t aws_kafka_encryption_status_err.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_ERR"' EXIT
cluster_arns=$(aws kafka list-clusters-v2 --query 'ClusterInfoList[*].ClusterArn' --output text 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ] && aws_service_unavailable "$_ERR"; then
    log_info "Amazon MSK (Kafka) is not in use for this account/region (not subscribed / not enabled); recording not-enabled status"
    jq '.results.summary = {total_clusters: 0, encrypted_clusters: 0, encryption_percentage: 0, status: "not_enabled"}' \
        "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    log_info "Evidence saved to $OUTPUT_JSON"
    exit 0
elif [ $list_exit -ne 0 ]; then
    echo "aws kafka list-clusters-v2 (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list MSK clusters"
else
    for cluster_arn in $(aws_text_list "$cluster_arns"); do
        total_clusters=$((total_clusters + 1))
        cluster_details=$(aws kafka describe-cluster-v2 --cluster-arn "$cluster_arn" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws kafka describe-cluster-v2 ($cluster_arn) failed" >> "$_FAILURE_LOG"
            continue
        fi

        cluster_data=$(echo "$cluster_details" | jq '
            .ClusterInfo as $c |
            ($c.ClusterType // "UNKNOWN") as $type |
            (if $type == "SERVERLESS" then $c.Serverless else $c.Provisioned end) as $cfg |
            {
                name: ($c.ClusterName // ""),
                arn: ($c.ClusterArn // ""),
                cluster_type: $type,
                state: ($c.State // ""),
                kafka_version: (if $type == "SERVERLESS" then "SERVERLESS" else ($cfg.CurrentBrokerSoftwareInfo.KafkaVersion // "") end),
                encryption_in_transit_client_broker: (if $type == "SERVERLESS" then "TLS" else ($cfg.EncryptionInfo.EncryptionInTransit.ClientBroker // "PLAINTEXT") end),
                encryption_in_transit_in_cluster: (if $type == "SERVERLESS" then true else ($cfg.EncryptionInfo.EncryptionInTransit.InCluster // false) end),
                encryption_at_rest_kms_key_id: (if $type == "SERVERLESS" then "AWS_MANAGED" else ($cfg.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId // "None") end)
            }')

        client_broker=$(echo "$cluster_data" | jq -r '.encryption_in_transit_client_broker')
        kms_key=$(echo "$cluster_data" | jq -r '.encryption_at_rest_kms_key_id')
        if [ "$client_broker" = "TLS" ] && [ "$kms_key" != "None" ] && [ -n "$kms_key" ]; then
            encrypted_clusters=$((encrypted_clusters + 1))
        fi

        jq --argjson data "$cluster_data" '.results.clusters += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

percentage=0
[ $total_clusters -gt 0 ] && percentage=$(( (encrypted_clusters * 100) / total_clusters ))

jq --arg total "$total_clusters" --arg encrypted "$encrypted_clusters" --arg percentage "$percentage" \
    '.results.summary = {total_clusters: ($total | tonumber), encrypted_clusters: ($encrypted | tonumber), encryption_percentage: ($percentage | tonumber)}' \
    "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

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
