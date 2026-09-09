#!/bin/bash
# AWS — Database High Availability
# Collects RDS DB instances and Aurora DB clusters with their Multi-AZ and
# availability-zone configuration.
# Output: $EVIDENCE_DIR/aws_database_high_availability.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_database_high_availability_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_database_high_availability.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_database_high_availability_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_database_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_database_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

# --- per-script data collection (ported from upstream) ---

log_info "Validating Database High Availability"

# Get RDS instances
rds_instances=$(aws rds describe-db-instances --query 'DBInstances[*]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws rds describe-db-instances failed (exit=$ec)" >> "$_FAILURE_LOG"
else
    echo "$rds_instances" | jq -c '.[]' | while read -r instance; do
        instance_id=$(echo "$instance" | jq -r '.DBInstanceIdentifier')
        log_info "Processing RDS instance: $instance_id"

        # Add to JSON
        jq --argjson instance "$instance" \
           '.results += [{"Type": "RDS_Instance", "InstanceInfo": $instance}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

# Get Aurora clusters
aurora_clusters=$(aws rds describe-db-clusters --query 'DBClusters[*]' --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws rds describe-db-clusters failed (exit=$ec)" >> "$_FAILURE_LOG"
else
    echo "$aurora_clusters" | jq -c '.[]' | while read -r cluster; do
        cluster_id=$(echo "$cluster" | jq -r '.DBClusterIdentifier')
        log_info "Processing Aurora cluster: $cluster_id"

        # Add to JSON
        jq --argjson cluster "$cluster" \
           '.results += [{"Type": "Aurora_Cluster", "ClusterInfo": $cluster}]' \
           "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    done
fi

# Generate summary
if [ -f "$OUTPUT_JSON" ]; then
    total_instances=$(jq '.results | length' "$OUTPUT_JSON")
    rds_count=$(jq '.results[] | select(.Type == "RDS_Instance") | .InstanceInfo.DBInstanceIdentifier' "$OUTPUT_JSON" | wc -l)
    aurora_count=$(jq '.results[] | select(.Type == "Aurora_Cluster") | .ClusterInfo.DBClusterIdentifier' "$OUTPUT_JSON" | wc -l)
    multi_az_count=$(jq '.results[] | select(.InstanceInfo.MultiAZ == true) | .InstanceInfo.DBInstanceIdentifier' "$OUTPUT_JSON" | wc -l)
    single_az_count=$(jq '.results[] | select(.InstanceInfo.MultiAZ == false) | .InstanceInfo.DBInstanceIdentifier' "$OUTPUT_JSON" | wc -l)

    log_info "Total Database Resources Found: $total_instances"
    log_info "RDS Instances: $rds_count"
    log_info "Aurora Clusters: $aurora_count"
    log_info "Multi-AZ Deployments: $multi_az_count"
    log_info "Single-AZ Deployments: $single_az_count"
fi

aws_finish
