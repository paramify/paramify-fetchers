#!/bin/bash
#
# AWS — RDS Encryption at Rest
#
# For each RDS instance and Aurora cluster in the account/region, reports
# encryption status. Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_rds_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_rds_encryption_status_${_TARGET_ID}.json"
_FAILURE_LOG="$(mktemp -t aws_rds_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_rds_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_rds_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

total_databases=0
encrypted_databases=0
rds_results=()
aurora_results=()

instances=$(aws rds describe-db-instances --query "DBInstances[*].DBInstanceIdentifier" --output text 2>/dev/null)
inst_list_exit=$?
if [ $inst_list_exit -ne 0 ]; then
    echo "aws rds describe-db-instances (list) failed (exit=$inst_list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list RDS instances"
else
    for instance in $instances; do
        total_databases=$((total_databases + 1))
        instance_details=$(aws rds describe-db-instances --db-instance-identifier "$instance" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws rds describe-db-instances ($instance) failed" >> "$_FAILURE_LOG"
            continue
        fi
        encrypted=$(echo "$instance_details" | jq -r '.DBInstances[0].StorageEncrypted')
        kms_key_id=$(echo "$instance_details" | jq -r '.DBInstances[0].KmsKeyId // "None"')
        engine=$(echo "$instance_details" | jq -r '.DBInstances[0].Engine')

        rds_results+=("$(jq -n --arg name "$instance" --arg type "rds_instance" \
            --argjson enc "$encrypted" --arg kms "$kms_key_id" --arg eng "$engine" \
            '{name: $name, type: $type, encrypted: $enc, kms_key_id: $kms, engine: $eng}')")
        [ "$encrypted" = "true" ] && encrypted_databases=$((encrypted_databases + 1))
    done
fi

clusters=$(aws rds describe-db-clusters --query "DBClusters[*].DBClusterIdentifier" --output text 2>/dev/null)
clus_list_exit=$?
if [ $clus_list_exit -ne 0 ]; then
    echo "aws rds describe-db-clusters (list) failed (exit=$clus_list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list RDS Aurora clusters"
else
    for cluster in $clusters; do
        total_databases=$((total_databases + 1))
        cluster_details=$(aws rds describe-db-clusters --db-cluster-identifier "$cluster" 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws rds describe-db-clusters ($cluster) failed" >> "$_FAILURE_LOG"
            continue
        fi
        encrypted=$(echo "$cluster_details" | jq -r '.DBClusters[0].StorageEncrypted')
        kms_key_id=$(echo "$cluster_details" | jq -r '.DBClusters[0].KmsKeyId // "None"')
        engine=$(echo "$cluster_details" | jq -r '.DBClusters[0].Engine')

        aurora_results+=("$(jq -n --arg name "$cluster" --arg type "rds_aurora" \
            --argjson enc "$encrypted" --arg kms "$kms_key_id" --arg eng "$engine" \
            '{name: $name, type: $type, encrypted: $enc, kms_key_id: $kms, engine: $eng}')")
        [ "$encrypted" = "true" ] && encrypted_databases=$((encrypted_databases + 1))
    done
fi

percentage=0
[ $total_databases -gt 0 ] && percentage=$(( (encrypted_databases * 100) / total_databases ))

jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --argjson rds "[$(IFS=,; echo "${rds_results[*]}")]" \
    --argjson aurora "[$(IFS=,; echo "${aurora_results[*]}")]" \
    --arg total "$total_databases" --arg encrypted "$encrypted_databases" --arg percentage "$percentage" \
    '{
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            storage_inventory: {instances: $rds, clusters: $aurora},
            summary: {
                total_storage: ($total | tonumber),
                encrypted_storage: ($encrypted | tonumber),
                encryption_percentage: ($percentage | tonumber)
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
