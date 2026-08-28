#!/bin/bash
#
# AWS — EKS Least Privilege and Security Configuration
#
# For each EKS cluster, collects logging configuration, pod-identity
# associations, and installed add-ons. Aggregates a per-account summary.
#
# Output: $EVIDENCE_DIR/aws_eks_least_privilege.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_eks_least_privilege_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_eks_least_privilege.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_eks_least_privilege_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_eks_least_privilege %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_eks_least_privilege %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": [], "summary": {"clusters": {"total": 0, "logging_enabled": 0, "pod_identities": 0}}}' \
  > "$OUTPUT_JSON"

clusters=$(aws eks list-clusters --query "clusters" --output json 2>/dev/null)
list_exit=$?
if [ $list_exit -ne 0 ]; then
    echo "aws eks list-clusters failed (exit=$list_exit)" >> "$_FAILURE_LOG"
    log_error "Failed to list EKS clusters"
else
    total_clusters=0
    logging_enabled=0
    total_pod_identities=0

    while read -r cluster_name; do
        total_clusters=$((total_clusters + 1))

        logging_config=$(aws eks describe-cluster --name "$cluster_name" --query "cluster.logging" --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws eks describe-cluster ($cluster_name) failed" >> "$_FAILURE_LOG"
            logging_config='{}'
        fi

        pod_identities=$(aws eks list-pod-identity-associations --cluster-name "$cluster_name" --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws eks list-pod-identity-associations ($cluster_name) failed" >> "$_FAILURE_LOG"
            pod_identities='{"associations":[]}'
        fi

        addons=$(aws eks list-addons --cluster-name "$cluster_name" --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            echo "aws eks list-addons ($cluster_name) failed" >> "$_FAILURE_LOG"
            addons='{"addons":[]}'
        fi

        if echo "$logging_config" | jq -e '.clusterLogging[0].enabled == true' > /dev/null 2>&1; then
            logging_enabled=$((logging_enabled + 1))
        fi
        pod_identity_count=$(echo "$pod_identities" | jq -r '.associations | length // 0')
        total_pod_identities=$((total_pod_identities + pod_identity_count))

        cluster_data=$(jq -n \
            --arg name "$cluster_name" \
            --argjson logging "$logging_config" \
            --argjson identities "$pod_identities" \
            --argjson addons "$addons" \
            '{"clusterName": $name, "loggingConfig": $logging, "podIdentities": $identities, "addons": $addons}')

        jq --argjson cluster "$cluster_data" '.results += [$cluster]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

    done < <(echo "$clusters" | jq -r '.[]')

    jq --arg total "$total_clusters" --arg logging "$logging_enabled" --arg identities "$total_pod_identities" \
       '.summary.clusters = {"total": ($total | tonumber), "logging_enabled": ($logging | tonumber), "pod_identities": ($identities | tonumber)}' \
       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
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
