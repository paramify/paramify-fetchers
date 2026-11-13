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

_ERR="$(mktemp -t aws_redshift_encryption_status_err.XXXXXX)"
_PG_SSL_TSV="$(mktemp -t aws_redshift_encryption_status_pg.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_ERR" "$_PG_SSL_TSV"' EXIT
# The list call already returns Encrypted, KmsKeyId and ClusterParameterGroups
# for every cluster, so the per-cluster describe it replaced is gone.
clusters=$(aws redshift describe-clusters --query "Clusters[*].{ClusterIdentifier:ClusterIdentifier,Encrypted:Encrypted,KmsKeyId:KmsKeyId,ParameterGroupName:ClusterParameterGroups[0].ParameterGroupName}" --output json 2>"$_ERR")
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
    clusters='[]'
fi
rm -f "$_ERR"

# require_ssl is a parameter-group setting, so it is read once per distinct
# group rather than once per cluster (clusters commonly share one group). A
# group whose parameters cannot be read gives require_ssl false, as before.
while read -r parameter_group_name; do
    [ -z "$parameter_group_name" ] && continue
    param_details=$(aws redshift describe-cluster-parameters --parameter-group-name "$parameter_group_name" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "aws redshift describe-cluster-parameters ($parameter_group_name) failed" >> "$_FAILURE_LOG"
        continue
    fi
    require_ssl=$(echo "$param_details" | jq -r '[.Parameters[]? | select((.ParameterName // "" | ascii_downcase) == "require_ssl") | .ParameterValue // ""] | (.[0] // "") | ascii_downcase == "true"')
    printf '%s\t%s\n' "$parameter_group_name" "$require_ssl" >> "$_PG_SSL_TSV"
done < <(printf '%s' "$clusters" | jq -r '[.[]? | .ParameterGroupName // empty] | unique[]')

printf '%s' "$clusters" | jq --slurpfile clusters /dev/stdin --rawfile pg_ssl "$_PG_SSL_TSV" --arg not_in_use "$service_not_in_use" '
    ($pg_ssl | split("\n") | map(select(length > 0) | split("\t") | {(.[0]): (.[1] == "true")}) | add // {}) as $ssl
    | [$clusters[0][]? | (.ParameterGroupName // "") as $pg
        | {cluster_identifier: .ClusterIdentifier, encrypted: (.Encrypted // false), kms_key_id: (.KmsKeyId // "None"),
           parameter_group_name: $pg, require_ssl: ($ssl[$pg] // false)}] as $rows
    | ($rows | length) as $total
    | ([$rows[] | select(.encrypted == true)] | length) as $encrypted
    | .results.clusters += $rows
    | .results.summary = (if $not_in_use == "true"
        then {service_enabled: false, total_clusters: 0, encrypted_clusters: 0, encryption_percentage: 0}
        else {service_enabled: true, total_clusters: $total, encrypted_clusters: $encrypted,
              encryption_percentage: (if $total > 0 then ($encrypted * 100 / $total | floor) else 0 end)} end)
' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

aws_finish
