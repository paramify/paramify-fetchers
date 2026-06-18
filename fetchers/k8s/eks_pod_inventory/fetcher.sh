#!/bin/bash
#
# K8s — EKS Pod Inventory
#
# For each EKS cluster in $AWS_DEFAULT_REGION (under $AWS_PROFILE), lists
# all pods with cluster/namespace/node/status/images.
#
# NOTE: this port drops the upstream's `aws sso login` step. The caller must
# already be authenticated (via SSO session cache, instance profile, OIDC,
# pre-exported AWS credentials, etc.) before invoking.
#
# Output: $EVIDENCE_DIR/k8s_eks_pod_inventory.json
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

OUTPUT_JSON="$OUTPUT_DIR/k8s_eks_pod_inventory.json"
_FETCHER_TMP_JSON="$(mktemp -t k8s_eks_pod_inventory.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON"' EXIT

log_info() { printf '%s INFO k8s_eks_pod_inventory %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR k8s_eks_pod_inventory %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

echo "[]" > "$OUTPUT_JSON"

if ! clusters=$(aws eks list-clusters --query "clusters[]" --output text 2>&1); then
    log_error "Failed to list EKS clusters: $clusters"
    exit 1
fi

any_cluster_successful=false
error_occurred=false

for cluster in $clusters; do
    log_info "Fetching pods for cluster $cluster"

    if ! aws eks update-kubeconfig --name "$cluster" >/dev/null 2>&1; then
        log_error "Failed to update kubeconfig for cluster $cluster"
        error_occurred=true
        continue
    fi

    if ! pod_data=$(kubectl get pods --all-namespaces -o json 2>&1); then
        log_error "Failed to fetch pods from cluster $cluster: $pod_data"
        error_occurred=true
        continue
    fi

    any_cluster_successful=true

    pod_data=$(echo "$pod_data" | jq --arg cluster "$cluster" '[.items[] | {
        cluster: $cluster,
        namespace: .metadata.namespace,
        pod_name: .metadata.name,
        node_name: .spec.nodeName,
        status: .status.phase,
        images: [.spec.containers[].image] | join(";")
    }]')

    jq --argjson newData "$pod_data" '. + $newData' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"
done

if [ "$any_cluster_successful" = false ]; then
    log_error "No clusters were successfully processed"
    exit 1
fi

if [ "$error_occurred" = true ]; then
    log_error "Some clusters had processing errors"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
