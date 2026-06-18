#!/bin/bash
#
# K8s — Kubernetes Security Configuration Validation
#
# For each EKS cluster in $AWS_DEFAULT_REGION (under $AWS_PROFILE), collects:
#   - pod security contexts
#   - validating webhook configurations
#   - network policies
# Aggregates a least-privilege summary.
#
# Output: $EVIDENCE_DIR/k8s_kubectl_security.json
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

OUTPUT_JSON="$OUTPUT_DIR/k8s_kubectl_security.json"
_FETCHER_TMP_JSON="$(mktemp -t k8s_kubectl_security.XXXXXX.json)"
_TMP_SUMMARY="$(mktemp -t k8s_kubectl_security_summary.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_TMP_SUMMARY"' EXIT

log_info() { printf '%s INFO k8s_kubectl_security %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR k8s_kubectl_security %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        return 1
    fi
    if ! timeout 10s kubectl cluster-info &> /dev/null; then
        log_error "kubectl is not properly configured or cluster is not accessible"
        return 1
    fi
    if ! timeout 10s kubectl get nodes &> /dev/null; then
        log_error "Cannot access cluster nodes"
        return 1
    fi
    return 0
}

echo '{
  "metadata": {
    "region": "'"$REGION"'",
    "profile": "'"$PROFILE"'",
    "datetime": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"
  },
  "results": [],
  "summary": {
    "least_privilege_summary": {
      "total_containers": 0,
      "run_as_non_root": 0,
      "allow_privilege_escalation_false": 0,
      "read_only_root_filesystem": 0,
      "drop_all_capabilities": 0,
      "privileged_containers": [],
      "missing_context_containers": [],
      "excessive_capabilities_containers": []
    },
    "formatted_summary": ""
  }
}' > "$OUTPUT_JSON"

if ! clusters=$(aws eks list-clusters --query "clusters" --output json 2>/dev/null); then
    log_error "Failed to list EKS clusters"
    exit 1
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

    if ! check_kubectl; then
        log_error "kubectl configuration check failed for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    any_cluster_successful=true

    if ! pod_security_contexts=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{range .spec.containers[*]} container: {.name}{"\n"} securityContext: {.securityContext}{"\n"}{end}{"\n"}{end}'); then
        log_error "Failed to retrieve pod security contexts for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    if ! webhook_configs=$(kubectl get validatingwebhookconfigurations -A -o yaml); then
        log_error "Failed to retrieve webhook configurations for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    if ! network_policies=$(kubectl get networkpolicies -A -o yaml); then
        log_error "Failed to retrieve network policies for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    if ! echo "$pod_security_contexts" | jq -R -s '
      split("\n\n")[] |
      select(length > 0) |
      split("\n") as $lines |
      {
        pod: ($lines[0]),
        container: ($lines[1] | sub("container: "; "")),
        context: ($lines[2] | sub("securityContext: "; "") | fromjson? // {})
      }' | jq -s '
      reduce .[] as $item (
        {
          total: 0,
          runAsNonRoot: 0,
          allowPrivilegeEscalationFalse: 0,
          readOnlyRootFilesystem: 0,
          dropAllCaps: 0,
          privilegedContainers: [],
          missingContextContainers: [],
          excessiveCapsContainers: []
        };
        .total += 1
        |
        if ($item.context | length == 0) then
          .missingContextContainers += [($item.container)]
        else (
          if $item.context.runAsNonRoot == true then .runAsNonRoot += 1 end
          |
          if $item.context.allowPrivilegeEscalation == false then .allowPrivilegeEscalationFalse += 1 end
          |
          if $item.context.readOnlyRootFilesystem == true then .readOnlyRootFilesystem += 1 end
          |
          if ($item.context.capabilities?.drop // []) | index("ALL") then .dropAllCaps += 1 end
          |
          if $item.context.privileged == true then .privilegedContainers += [($item.container)] end
          |
          if ($item.context.capabilities?.add // []) | length > 0 then .excessiveCapsContainers += [($item.container)] end
        )
      )' > "$_TMP_SUMMARY"; then
        log_error "Failed to process security contexts for cluster $cluster_name"
        error_occurred=true
        continue
    fi

    if ! jq --slurpfile summary "$_TMP_SUMMARY" '.summary.least_privilege_summary = {
        "total_containers": $summary[0].total,
        "run_as_non_root": $summary[0].runAsNonRoot,
        "allow_privilege_escalation_false": $summary[0].allowPrivilegeEscalationFalse,
        "read_only_root_filesystem": $summary[0].readOnlyRootFilesystem,
        "drop_all_capabilities": $summary[0].dropAllCaps,
        "privileged_containers": $summary[0].privilegedContainers,
        "missing_context_containers": $summary[0].missingContextContainers,
        "excessive_capabilities_containers": $summary[0].excessiveCapsContainers
    }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON"; then
        log_error "Failed to update JSON summary for cluster $cluster_name"
        error_occurred=true
        continue
    fi
    mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

    cluster_data=$(jq -n \
        --arg name "$cluster_name" \
        --arg contexts "$pod_security_contexts" \
        --arg webhooks "$webhook_configs" \
        --arg network "$network_policies" \
        '{
            "clusterName": $name,
            "podSecurityContexts": $contexts,
            "validatingWebhooks": $webhooks,
            "networkPolicies": $network
        }')

    if ! jq --argjson cluster "$cluster_data" '.results += [$cluster]' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON"; then
        log_error "Failed to add cluster data for $cluster_name"
        error_occurred=true
        continue
    fi
    mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

    formatted_summary=$(jq -r '
      .summary.least_privilege_summary |
      "Least Privilege Summary for Cluster '"$cluster_name"':\n" +
      "- Total Containers: \(.total_containers)\n" +
      "- With '\''runAsNonRoot'\'': \(.run_as_non_root)\n" +
      "- With '\''allowPrivilegeEscalation: false'\'': \(.allow_privilege_escalation_false)\n" +
      "- With '\''readOnlyRootFilesystem'\'': \(.read_only_root_filesystem)\n" +
      "- With '\''capabilities: drop [ALL]'\'': \(.drop_all_capabilities)\n" +
      "- Privileged: \(.privileged_containers | length)\n" +
      "- Missing securityContext: \(.missing_context_containers | length)\n" +
      "- Excessive capabilities: \(.excessive_capabilities_containers | length)"
    ' "$OUTPUT_JSON")

    jq --arg summary "$formatted_summary" '.summary.formatted_summary = $summary' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

done < <(echo "$clusters" | jq -r '.[]')

if [ "$any_cluster_successful" = false ]; then
    log_error "No clusters were successfully processed"
    exit 1
fi

if [ "$error_occurred" = true ]; then
    log_error "Some clusters had processing errors"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
