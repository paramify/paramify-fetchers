#!/bin/bash
#
# K8s — EKS Microservice Segmentation Validation
#
# For each EKS cluster in $AWS_DEFAULT_REGION (under $AWS_PROFILE), collects:
#   - default-deny network policies
#   - VPC CNI configuration
#   - security group policies
#   - worker node security groups
#   - pod resource limits
#
# Output: $EVIDENCE_DIR/k8s_eks_microservice_segmentation.json
# Optional env (else the AWS CLI's ambient identity/region — EKS IRSA /
#   instance role / SSO / ~/.aws): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, kubectl, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI's own credential chain — env vars when
# the runner sets them, else ambient (EKS IRSA / instance role / SSO / ~/.aws).
# We do NOT pass --profile/--region; the CLI reads AWS_PROFILE / AWS_DEFAULT_REGION
# itself. Recorded in evidence metadata only; empty = ambient.
PROFILE="${AWS_PROFILE:-}"
REGION="${AWS_DEFAULT_REGION:-}"

OUTPUT_JSON="$OUTPUT_DIR/k8s_eks_microservice_segmentation.json"
_FETCHER_TMP_JSON="$(mktemp -t k8s_eks_microservice_segmentation.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON"' EXIT

log_info() { printf '%s INFO k8s_eks_microservice_segmentation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR k8s_eks_microservice_segmentation %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

echo '{
  "metadata": {
    "region": "'"$REGION"'",
    "profile": "'"$PROFILE"'",
    "datetime": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"
  },
  "results": [],
  "summary": {
    "clusters": {
      "total": 0,
      "with_default_deny": 0,
      "with_resource_limits": 0,
      "with_security_groups": 0
    }
  }
}' > "$OUTPUT_JSON"

clusters=$(aws eks list-clusters --query "clusters" --output json 2>&1)
if [ $? -ne 0 ]; then
    log_error "Failed to list EKS clusters: $clusters"
    exit 1
fi

if [ "$(echo "$clusters" | jq -r '. | length')" -eq 0 ]; then
    log_info "No EKS clusters found in region $REGION"
    jq --arg total "0" '.summary.clusters.total = ($total | tonumber)' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    log_info "Evidence saved to $OUTPUT_JSON"
    exit 0
fi

any_cluster_successful=false
error_occurred=false

while read -r cluster_name; do
    log_info "Processing cluster $cluster_name"

    if ! aws eks update-kubeconfig --name "$cluster_name" >/dev/null 2>&1; then
        log_error "Failed to update kubeconfig for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    if ! timeout 10s kubectl cluster-info &> /dev/null; then
        log_error "kubectl not properly configured or cluster $cluster_name not accessible"
        error_occurred=true
        continue
    fi

    any_cluster_successful=true

    # Network policies: separate the kubectl call from the grep so a real
    # kubectl failure is recorded (grep returning "no match" is not a failure).
    if ! network_policies=$(kubectl get networkpolicies -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.policyTypes}{"\n"}{end}' 2>/dev/null); then
        log_error "Failed to get network policies for cluster $cluster_name"
        error_occurred=true
        continue
    fi
    default_deny_policies=$(echo "$network_policies" | grep -i "deny" || true)

    # CNI config and security group policies are optional resources (the CRD may
    # not be installed); absence is not a failure, so these stay best-effort.
    cni_config=$(kubectl describe daemonset aws-node -n kube-system 2>/dev/null | grep -E "ENABLE_NETWORK_POLICY|amazon-vpc-cni:" || true)
    security_group_policies=$(kubectl get securitygrouppolicies.vpcresources.k8s.aws -A -o yaml 2>/dev/null || echo "")

    if ! node_instance_ids=$(aws ec2 describe-instances \
        --filters "Name=tag:kubernetes.io/cluster/$cluster_name,Values=owned" \
        --query "Reservations[*].Instances[*].InstanceId" \
        --output text 2>/dev/null); then
        log_error "Failed to list node instances for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    node_security_groups=""
    for id in $node_instance_ids; do
        sg=$(aws ec2 describe-instances \
            --instance-ids "$id" \
            --query "Reservations[*].Instances[*].SecurityGroups" \
            --output json 2>/dev/null)
        if [ $? -ne 0 ]; then
            log_error "Failed to describe node instance $id for cluster $cluster_name"
            error_occurred=true
        fi
        node_security_groups+="$sg"
    done

    if ! pod_resources=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].resources}{"\n"}{end}' 2>/dev/null); then
        log_error "Failed to get pod resources for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    cluster_data=$(jq -n \
        --arg name "$cluster_name" \
        --arg default_deny "$default_deny_policies" \
        --arg cni_config "$cni_config" \
        --arg security_groups "$security_group_policies" \
        --arg node_sgs "$node_security_groups" \
        --arg pod_resources "$pod_resources" \
        '{
            "clusterName": $name,
            "defaultDenyPolicies": $default_deny,
            "cniConfig": $cni_config,
            "securityGroupPolicies": $security_groups,
            "nodeSecurityGroups": $node_sgs,
            "podResources": $pod_resources
        }')

    if ! jq --argjson cluster "$cluster_data" '.results += [$cluster]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON"; then
        log_error "Failed to add cluster data for $cluster_name"
        error_occurred=true
        continue
    fi
    mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

    if [ -n "$default_deny_policies" ]; then
        jq '.summary.clusters.with_default_deny += 1' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi
    if echo "$pod_resources" | grep -q "limits\|requests"; then
        jq '.summary.clusters.with_resource_limits += 1' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi
    if [ -n "$security_group_policies" ]; then
        jq '.summary.clusters.with_security_groups += 1' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
    fi

done < <(echo "$clusters" | jq -r '.[]')

jq --arg total "$(echo "$clusters" | jq -r '. | length')" \
   '.summary.clusters.total = ($total | tonumber)' \
   "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

if [ "$any_cluster_successful" = false ]; then
    log_error "No clusters were successfully processed"
    exit 1
fi

if [ "$error_occurred" = true ]; then
    log_error "Some clusters had processing errors"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
