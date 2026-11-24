# Istio fetchers

Read an Istio service mesh through the Kubernetes API of the cluster it runs in. They work with any conformant
cluster (AKS, EKS, GKE and others) and use GET and LIST only.

## Requirements

Istio 1.22 or later. The fetcher reads the `v1` Istio APIs, which Istio added in 1.22. On an older mesh, every Istio
read fails with HTTP 404 and all the Istio fields are null.

## Settings

| Setting | Environment variable | Default | What it is |
|---|---|---|---|
| `context` | `ISTIO_KUBE_CONTEXT` | current context | The kubeconfig context to use. |
| `control_plane_namespace` | `ISTIO_CONTROL_PLANE_NAMESPACE` | `istio-system` | Where istiod runs. The fetcher reads the mesh config, the root certificate and istiod here. |
| `mesh_configmap` | `ISTIO_MESH_CONFIGMAP` | `istio` | The mesh config ConfigMap. For a revisioned install, set it to `istio-<revision>`. |
| `root_namespace` | `ISTIO_ROOT_NAMESPACE` | unset | Where mesh-wide policies live. Leave it unset. The fetcher uses `rootNamespace` from the mesh config. It uses this setting only when it cannot read the mesh config. |

## Access

The fetcher reads the kubeconfig in `KUBECONFIG` (or `~/.kube/config`), with the context in `ISTIO_KUBE_CONTEXT` when
set. With no kubeconfig, inside a pod, it uses the pod's service account. On AKS with Microsoft Entra ID, a kubeconfig
that signs in through `kubelogin` works unchanged; set `AAD_LOGIN_METHOD` and the matching `AZURE_*` variables for a
non-interactive sign-in.

Give the identity this read-only access and nothing else. It reads no secrets and writes nothing. Change
`istio-system` if the control-plane namespace is different, `istio` to `istio-<revision>` for a revisioned install, and
the subject to your user, group or service account. The root namespace for mesh-wide policy needs no extra access: the
cluster-wide lists cover it.

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
