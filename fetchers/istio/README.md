# Istio fetchers

Read an Istio service mesh through the Kubernetes API of the cluster it runs in. They work with any conformant
cluster (AKS, EKS, GKE and others) and use GET and LIST only.

## Access

The fetcher reads the kubeconfig in `KUBECONFIG` (or `~/.kube/config`), with the context in `ISTIO_KUBE_CONTEXT` when
set. With no kubeconfig, inside a pod, it uses the pod's service account. On AKS with Microsoft Entra ID, a kubeconfig
that signs in through `kubelogin` works unchanged; set `AAD_LOGIN_METHOD` and the matching `AZURE_*` variables for a
non-interactive sign-in.

Give the identity this read-only access and nothing else. It reads no secrets and writes nothing. Change
`istio-system` if the root namespace is different (`ISTIO_ROOT_NAMESPACE`), and the subject to your user, group or
service account.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: istio-mesh-reader}
rules:
- apiGroups: [""]
  resources: [namespaces]
  verbs: [list]
- apiGroups: [security.istio.io]
  resources: [peerauthentications, authorizationpolicies]
  verbs: [list]
- apiGroups: [networking.istio.io]
  resources: [gateways, virtualservices, destinationrules]
  verbs: [list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: istio-mesh-reader}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: istio-mesh-reader}
subjects: [{kind: User, name: istio-reader, apiGroup: rbac.authorization.k8s.io}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: istio-mesh-reader, namespace: istio-system}
rules:
- apiGroups: [""]
  resources: [configmaps]
  resourceNames: [istio, istio-ca-root-cert]
  verbs: [get]
- apiGroups: [apps]
  resources: [deployments]
  verbs: [list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: istio-mesh-reader, namespace: istio-system}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: istio-mesh-reader}
subjects: [{kind: User, name: istio-reader, apiGroup: rbac.authorization.k8s.io}]
```

A refused call names the permission it needs, so a run with missing access says exactly what to add.
