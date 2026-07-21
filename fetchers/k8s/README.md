# Kubernetes (EKS)

Kubernetes fetchers target Amazon EKS clusters. They use the AWS CLI to enumerate clusters and update kubeconfig, then use `kubectl` to collect pod inventory, network policy configuration, and security posture data.

## Authentication

K8s fetchers authenticate to AWS using the same credential chain as the [AWS fetchers](../aws/README.md) — no separate Kubernetes token is needed. Each fetcher calls `aws eks update-kubeconfig` per cluster using your AWS identity, then queries the cluster via `kubectl`.

See [AWS credential setup](../aws/README.md) for how to configure a named profile or use ambient credentials (EKS IRSA / instance role).

## Prerequisites

Install the required CLI tools before running K8s fetchers:

```bash
# AWS CLI v2
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# kubectl
# https://kubernetes.io/docs/tasks/tools/

# jq
brew install jq   # macOS; or use your distro's package manager
```

All three are included in the [Docker image](../../deploy/README.md) if you're using the containerized deployment.

## Required permissions

### AWS IAM

- `eks:ListClusters`
- `eks:DescribeCluster`
- `ec2:DescribeInstances` (required by `k8s_eks_microservice_segmentation`)

### Kubernetes RBAC

Your AWS identity must be mapped into each cluster (via `aws-auth` ConfigMap or EKS access entries) with read access to:

- Pods (all namespaces)
- NetworkPolicies (all namespaces)
- Nodes (cluster-scoped)
- ValidatingWebhookConfigurations (cluster-scoped)

A `ClusterRole` with `get`/`list`/`watch` on these resources is sufficient.

## Wiring into a manifest

K8s fetchers declare no secrets — credentials flow through the ambient AWS credential chain, not the manifest:

```bash
paramify manifest add k8s_eks_pod_inventory
# No set-secret needed
paramify validate manifest.yaml
paramify run manifest.yaml
```

Make sure the AWS environment variables are set in the shell running `paramify run`:

```bash
export AWS_PROFILE=your-profile
export AWS_DEFAULT_REGION=us-east-1
```

## Smoke test

```bash
# Verify AWS identity
aws sts get-caller-identity --profile your-profile

# Verify EKS access
aws eks list-clusters --profile your-profile --region us-east-1

# Update kubeconfig and verify kubectl access
aws eks update-kubeconfig --name your-cluster-name \
  --profile your-profile --region us-east-1
kubectl get nodes
```

## Notes

- EKS auth errors usually mean the AWS identity is not mapped in the cluster. Check the `aws-auth` ConfigMap or EKS access entries and ensure the required RBAC permissions are granted.
- For in-cluster deployment with IRSA, no profile configuration is needed — the web identity token is automatically passed through via `auth.passthrough_env` in `fetchers/_categories/k8s.yaml`.
