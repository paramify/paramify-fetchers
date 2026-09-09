#!/bin/bash
#
# AWS — Redshift Encryption (at rest + in transit)
#
# For each Redshift cluster in the account/region, reports encryption at rest
# (Encrypted, KMS key) and in-transit enforcement (require_ssl parameter group
# setting). Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_redshift_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_redshift_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_redshift_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_redshift_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_redshift_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_redshift_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

_ERR="$(mktemp -t aws_redshift_encryption_status_err.XXXXXX)"
clusters=$(aws redshift describe-clusters --query "Clusters[*].ClusterIdentifier" --output text 2>"$_ERR")
list_exit=$?
service_not_in_use=false
if [ $list_exit -ne 0 ]; then
    if aws_service_unavailable "$_ERR"; then
        service_not_in_use=true
        log_info "Redshift not in use for this account (not subscribed / not enabled); recording not-enabled status"
    else
        echo "aws redshift describe-clusters (list) failed (exit=$list_exit)" >> "$_FAILURE_LOG"
        log_error "Failed to list Redshift clusters"
    fi
fi
rm -f "$_ERR"

if [ "$service_not_in_use" = "false" ] && [ $list_exit -eq 0 ]; then
    for cluster in $(aws_text_list "$clusters"); do
        total_clusters=$((total_clusters + 1))
        cluster_details=$(aws redshift describe-clusters --cluster-identifier "$cluster" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws redshift describe-clusters ($cluster) failed" >> "$_FAILURE_LOG"
            continue
        fi
        encrypted=$(echo "$cluster_details" | jq -r '.Clusters[0].Encrypted // false')
        kms_key_id=$(echo "$cluster_details" | jq -r '.Clusters[0].KmsKeyId // "None"')
        parameter_group_name=$(echo "$cluster_details" | jq -r '.Clusters[0].ClusterParameterGroups[0].ParameterGroupName // ""')

        require_ssl=false
        if [ -n "$parameter_group_name" ]; then
            param_details=$(aws redshift describe-cluster-parameters --parameter-group-name "$parameter_group_name" 2>/dev/null)
            if [ $? -ne 0 ]; then
                echo "aws redshift describe-cluster-parameters ($parameter_group_name) failed" >> "$_FAILURE_LOG"
            else
                ssl_value=$(echo "$param_details" | jq -r '.Parameters[] | select((.ParameterName | ascii_downcase) == "require_ssl") | .ParameterValue // ""' | head -n1)
                [ "$(echo "${ssl_value}" | tr '[:upper:]' '[:lower:]')" = "true" ] && require_ssl=true
            fi
        fi

        cluster_obj=$(jq -n --arg id "$cluster" --argjson enc "$encrypted" \
            --arg kms "$kms_key_id" --arg pg "$parameter_group_name" --argjson ssl "$require_ssl" \
            '{cluster_identifier: $id, encrypted: $enc, kms_key_id: $kms, parameter_group_name: $pg, require_ssl: $ssl}')

        jq --argjson c "$cluster_obj" '.results.clusters += [$c]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        [ "$encrypted" = "true" ] && encrypted_clusters=$((encrypted_clusters + 1))
    done
fi

percentage=0
[ $total_clusters -gt 0 ] && percentage=$(( (encrypted_clusters * 100) / total_clusters ))

if [ "$service_not_in_use" = "true" ]; then
    jq '.results.summary = {service_enabled: false, total_clusters: 0, encrypted_clusters: 0, encryption_percentage: 0}' \
        "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
else
    jq --arg total "$total_clusters" --arg encrypted "$encrypted_clusters" --arg percentage "$percentage" \
        '.results.summary = {service_enabled: true, total_clusters: ($total | tonumber), encrypted_clusters: ($encrypted | tonumber), encryption_percentage: ($percentage | tonumber)}' \
        "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
fi

aws_finish
