#!/bin/bash
# AWS — EKS High Availability
# Collects EKS clusters with subnet/AZ distribution and node-group configuration.
# Output: $EVIDENCE_DIR/aws_eks_high_availability.json
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
OUTPUT_JSON="$OUTPUT_DIR/aws_eks_high_availability_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_eks_high_availability.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_eks_high_availability_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_eks_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_eks_high_availability %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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

log_info "Validating EKS Cluster Multi-AZ distribution"

# Get list of EKS clusters
clusters=$(aws eks list-clusters --query "clusters" --output json 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws eks list-clusters failed (exit=$ec)" >> "$_FAILURE_LOG"
elif [ "$(echo "$clusters" | jq -r 'length')" -gt 0 ]; then
    # Process each cluster
    while read -r cluster_name; do
        if [ -n "$cluster_name" ]; then
            log_info "Processing cluster: $cluster_name"

            # Get EKS cluster details
            cluster_info=$(aws eks describe-cluster --name "$cluster_name" --query 'cluster' --output json 2>/dev/null)
            ec=$?
            if [ $ec -ne 0 ]; then
                echo "aws eks describe-cluster ($cluster_name) failed (exit=$ec)" >> "$_FAILURE_LOG"
            else
                # Get subnet IDs from cluster
                subnet_ids=$(echo "$cluster_info" | jq -r '.resourcesVpcConfig.subnetIds[]' 2>/dev/null)

                if [ -n "$subnet_ids" ]; then
                    # Get subnet details with AZs
                    subnet_details=$(aws ec2 describe-subnets --subnet-ids $subnet_ids --query 'Subnets[*].[SubnetId,AvailabilityZone,SubnetArn]' --output json 2>/dev/null)
                    ec=$?
                    if [ $ec -ne 0 ]; then
                        echo "aws ec2 describe-subnets ($cluster_name) failed (exit=$ec)" >> "$_FAILURE_LOG"
                        subnet_details='[]'
                    fi

                    # Get node groups
                    nodegroups=$(aws eks list-nodegroups --cluster-name "$cluster_name" --query 'nodegroups[]' --output json 2>/dev/null)
                    ec=$?
                    if [ $ec -ne 0 ]; then
                        echo "aws eks list-nodegroups ($cluster_name) failed (exit=$ec)" >> "$_FAILURE_LOG"
                        nodegroups='[]'
                    fi

                    # Process each node group
                    echo "$nodegroups" | jq -r '.[]' 2>/dev/null | while read -r nodegroup; do
                        if [ -n "$nodegroup" ]; then
                            nodegroup_info=$(aws eks describe-nodegroup --cluster-name "$cluster_name" --nodegroup-name "$nodegroup" --query 'nodegroup' --output json 2>/dev/null)
                            ec=$?
                            if [ $ec -ne 0 ]; then
                                echo "aws eks describe-nodegroup ($cluster_name/$nodegroup) failed (exit=$ec)" >> "$_FAILURE_LOG"
                                nodegroup_info='{}'
                            fi

                            # Add to JSON
                            jq --argjson cluster "$cluster_info" \
                               --argjson subnets "$subnet_details" \
                               --argjson nodegroup "$nodegroup_info" \
                               --arg name "$nodegroup" \
                               '.results += [{"Type": "EKS_Cluster", "ClusterName": $name, "ClusterInfo": $cluster, "SubnetDetails": $subnets, "NodeGroupInfo": $nodegroup}]' \
                               "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
                        fi
                    done
                else
                    # Add cluster info even without subnets
                    jq --argjson cluster "$cluster_info" \
                       --arg name "$cluster_name" \
                       '.results += [{"Type": "EKS_Cluster", "ClusterName": $name, "ClusterInfo": $cluster}]' \
                       "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
                fi
            fi
        fi
    done < <(echo "$clusters" | jq -r '.[]')
else
    log_info "No EKS clusters found in the account"
fi

# Generate summary
if [ -f "$OUTPUT_JSON" ]; then
    total_clusters=$(jq '.results | length' "$OUTPUT_JSON")
    log_info "Total EKS Clusters Validated: $total_clusters"
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
