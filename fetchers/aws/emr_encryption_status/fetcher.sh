#!/bin/bash
#
# AWS — EMR Encryption (at rest / in transit)
#
# For each EMR cluster in the account/region, reports the at-rest and in-transit
# encryption settings from its associated security configuration.
#
# Output: $EVIDENCE_DIR/aws_emr_encryption_status_<target>.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_emr_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_emr_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_emr_encryption_status_fail.XXXXXX)"
_ERR="$(mktemp -t aws_emr_encryption_status_err.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_ERR" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_emr_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_emr_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

cluster_ids=$(aws emr list-clusters --active --query 'Clusters[*].Id' --output text 2>"$_ERR")
list_exit=$?
if [ $list_exit -ne 0 ]; then
    if aws_service_unavailable "$_ERR"; then
        log_info "EMR is not in use for this account/region (not subscribed / not enabled); recording not-enabled status"
        jq '.results += [{"service": "emr", "status": "not_enabled"}]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    else
        echo "aws emr list-clusters (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
        log_error "Failed to list EMR clusters"
    fi
else
    for cluster_id in $(aws_text_list "$cluster_ids"); do
        cluster_details=$(aws emr describe-cluster --cluster-id "$cluster_id" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws emr describe-cluster ($cluster_id) failed" >> "$_FAILURE_LOG"
            continue
        fi

        cluster_name=$(echo "$cluster_details" | jq -r '.Cluster.Name // "unknown"')
        cluster_arn=$(echo "$cluster_details" | jq -r '.Cluster.ClusterArn // "unknown"')
        cluster_state=$(echo "$cluster_details" | jq -r '.Cluster.Status.State // "unknown"')
        security_config_name=$(echo "$cluster_details" | jq -r '.Cluster.SecurityConfiguration // ""')

        at_rest_encryption=null
        in_transit_encryption=null
        if [ -n "$security_config_name" ]; then
            security_config=$(aws emr describe-security-configuration --name "$security_config_name" 2>/dev/null)
            if [ $? -ne 0 ]; then
                echo "aws emr describe-security-configuration ($security_config_name) failed" >> "$_FAILURE_LOG"
            else
                config_json=$(echo "$security_config" | jq -r '.SecurityConfiguration // "{}"')
                at_rest_encryption=$(echo "$config_json" | jq '.EncryptionConfiguration.EnableAtRestEncryption // false')
                in_transit_encryption=$(echo "$config_json" | jq '.EncryptionConfiguration.EnableInTransitEncryption // false')
            fi
        fi

        cluster_data=$(jq -n \
            --arg id "$cluster_id" --arg name "$cluster_name" --arg arn "$cluster_arn" \
            --arg state "$cluster_state" --arg sec_config "$security_config_name" \
            --argjson at_rest "${at_rest_encryption:-null}" --argjson in_transit "${in_transit_encryption:-null}" \
            '{id: $id, name: $name, arn: $arn, state: $state, security_configuration: $sec_config, at_rest_encryption: $at_rest, in_transit_encryption: $in_transit}')

        jq --argjson data "$cluster_data" '.results += [$data]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

aws_finish
