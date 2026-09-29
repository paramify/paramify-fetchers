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

# One describe per resource type. The per-id describe-db-instances /
# describe-db-clusters calls this replaced re-fetched fields the list calls
# already return, one CLI process per database. The join reads its inputs from
# files: the old final --argjson carried every row on the command line, which
# Linux caps at 128 KiB per argument.
_INSTANCES_JSON="$(mktemp -t aws_rds_encryption_status_instances.XXXXXX.json)"
_CLUSTERS_JSON="$(mktemp -t aws_rds_encryption_status_clusters.XXXXXX.json)"
trap 'rm -f "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_INSTANCES_JSON" "$_CLUSTERS_JSON"' EXIT

aws rds describe-db-instances --query "DBInstances[*].{Id:DBInstanceIdentifier,StorageEncrypted:StorageEncrypted,KmsKeyId:KmsKeyId,Engine:Engine}" --output json > "$_INSTANCES_JSON" 2>/dev/null
inst_list_exit=$?
if [ $inst_list_exit -ne 0 ]; then
    echo "aws rds describe-db-instances (list) failed (exit=$inst_list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list RDS instances"
    echo '[]' > "$_INSTANCES_JSON"
fi

aws rds describe-db-clusters --query "DBClusters[*].{Id:DBClusterIdentifier,StorageEncrypted:StorageEncrypted,KmsKeyId:KmsKeyId,Engine:Engine}" --output json > "$_CLUSTERS_JSON" 2>/dev/null
clus_list_exit=$?
if [ $clus_list_exit -ne 0 ]; then
    echo "aws rds describe-db-clusters (list) failed (exit=$clus_list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list RDS Aurora clusters"
    echo '[]' > "$_CLUSTERS_JSON"
fi

# engine is `tostring`d because the old code read it with jq -r into --arg,
# so a missing engine was the string "null".
jq -n \
    --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
    --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
    --slurpfile instances "$_INSTANCES_JSON" --slurpfile clusters "$_CLUSTERS_JSON" \
    'def row($type): {name: .Id, type: $type, encrypted: .StorageEncrypted, kms_key_id: (.KmsKeyId // "None"), engine: (.Engine | tostring)};
    [$instances[0][]? | row("rds_instance")] as $rds
    | [$clusters[0][]? | row("rds_aurora")] as $aurora
    | (($rds + $aurora) | length) as $total
    | ([($rds + $aurora)[] | select(.encrypted == true)] | length) as $encrypted
    | {
        metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn},
        results: {
            storage_inventory: {instances: $rds, clusters: $aurora},
            summary: {
                total_storage: $total,
                encrypted_storage: $encrypted,
                encryption_percentage: (if $total > 0 then ($encrypted * 100 / $total | floor) else 0 end)
            }
        }
    }' > "$OUTPUT_JSON"

aws_finish
