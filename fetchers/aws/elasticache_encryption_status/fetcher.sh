#!/bin/bash
#
# AWS — ElastiCache Encryption (at rest + in transit)
#
# For each ElastiCache cache cluster and replication group in the
# account/region, reports at-rest and in-transit encryption status.
# Aggregates a coverage percentage.
#
# Output: $EVIDENCE_DIR/aws_elasticache_encryption_status.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_elasticache_encryption_status_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_elasticache_encryption_status.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_elasticache_encryption_status_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_elasticache_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_elasticache_encryption_status %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{metadata: {profile: $profile, region: $region, datetime: $datetime, account_id: $account_id, arn: $arn}, results: {cache_clusters: [], replication_groups: []}}' \
  > "$OUTPUT_JSON"

# --- Cache clusters (Memcached + standalone Redis nodes): at-rest, in-transit, auth token ---
clusters=$(aws elasticache describe-cache-clusters \
    --query 'CacheClusters[*].[CacheClusterId,Engine,AtRestEncryptionEnabled,TransitEncryptionEnabled,AuthTokenEnabled]' \
    --output text 2>/dev/null)
cl_exit=$?
if [ $cl_exit -ne 0 ]; then
    echo "aws elasticache describe-cache-clusters failed (exit=$cl_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list ElastiCache cache clusters"
else
    if [ -n "$clusters" ]; then
        while IFS=$'\t' read -r id engine at_rest in_transit auth_token; do
            [ -z "$id" ] && continue
            jq --arg id "$id" --arg engine "$engine" \
               --arg at_rest "$at_rest" --arg in_transit "$in_transit" --arg auth_token "$auth_token" \
               '.results.cache_clusters += [{
                   id: $id,
                   engine: $engine,
                   at_rest_encryption_enabled: ($at_rest == "True"),
                   transit_encryption_enabled: ($in_transit == "True"),
                   auth_token_enabled: ($auth_token == "True")
               }]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        done <<< "$clusters"
    fi
fi

# --- Replication groups (Redis clusters): at-rest, in-transit, auth token ---
repl_groups=$(aws elasticache describe-replication-groups \
    --query 'ReplicationGroups[*].[ReplicationGroupId,Status,AtRestEncryptionEnabled,TransitEncryptionEnabled,AuthTokenEnabled]' \
    --output text 2>/dev/null)
rg_exit=$?
if [ $rg_exit -ne 0 ]; then
    echo "aws elasticache describe-replication-groups failed (exit=$rg_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list ElastiCache replication groups"
else
    if [ -n "$repl_groups" ]; then
        while IFS=$'\t' read -r id status at_rest in_transit auth_token; do
            [ -z "$id" ] && continue
            jq --arg id "$id" --arg status "$status" \
               --arg at_rest "$at_rest" --arg in_transit "$in_transit" --arg auth_token "$auth_token" \
               '.results.replication_groups += [{
                   id: $id,
                   status: $status,
                   at_rest_encryption_enabled: ($at_rest == "True"),
                   transit_encryption_enabled: ($in_transit == "True"),
                   auth_token_enabled: ($auth_token == "True")
               }]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
        done <<< "$repl_groups"
    fi
fi

# --- Encryption-coverage summary (a resource counts as encrypted only when both at-rest and in-transit are enabled) ---
jq '
    (.results.cache_clusters + .results.replication_groups) as $all
    | ($all | length) as $total
    | ([$all[] | select(.at_rest_encryption_enabled and .transit_encryption_enabled)] | length) as $encrypted
    | .results.summary = {
        total_resources: $total,
        encrypted_resources: $encrypted,
        encryption_percentage: (if $total > 0 then (($encrypted * 100) / $total | floor) else 0 end)
    }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
