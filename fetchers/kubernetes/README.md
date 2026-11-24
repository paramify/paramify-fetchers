# Kubernetes fetchers (any cluster)

Read workloads through a cluster's own Kubernetes API, for any conformant cluster (AKS, EKS, GKE and others). They use
GET and LIST only.

How this differs from `fetchers/k8s/`: those fetchers reach EKS through AWS credentials and the aws CLI. These need no
cloud credentials, only access to the Kubernetes API.

## Access

The fetcher reads the kubeconfig in `KUBECONFIG` (or `~/.kube/config`), with the context in `KUBERNETES_CONTEXT` when
set. With no kubeconfig, inside a pod, it uses the pod's service account. On AKS with Microsoft Entra ID, a kubeconfig
that signs in through `kubelogin` works unchanged; set `AAD_LOGIN_METHOD` and the matching `AZURE_*` variables for a
non-interactive sign-in.

`KUBERNETES_EXCLUDED_NAMESPACES` (default `kube-system,kube-public,kube-node-lease`) leaves out the cluster's own
workloads; set it to an empty value to include every namespace.

For `kubernetes_workload_resilience`, give the identity this read-only access and nothing else. It reads no secrets,
can't exec into pods and writes nothing. Change the subject to your user, group or service account.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: workload-resilience-reader}
rules:
- apiGroups: [apps]
  resources: [deployments, replicasets, statefulsets]
  verbs: [list]
- apiGroups: [policy]
  resources: [poddisruptionbudgets]
  verbs: [list]
- apiGroups: [autoscaling]
  resources: [horizontalpodautoscalers]
  verbs: [list]
- apiGroups: [""]
  resources: [pods, nodes]
  verbs: [list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: workload-resilience-reader}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: workload-resilience-reader}
subjects: [{kind: User, name: workload-reader, apiGroup: rbac.authorization.k8s.io}]
```

A refused call names the permission it needs, so a run with missing access says exactly what to add.
