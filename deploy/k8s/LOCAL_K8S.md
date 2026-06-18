# Run the collector on local Kubernetes (apply-and-watch)

A `CronJob` spins
up a throwaway Pod, secrets land as env vars, the collector runs collect→upload,
the Pod disappears, evidence is transient. **~90% of this YAML is what runs on
real EKS** — the two prod differences are flagged as `PROD SWAP #1/#2` in
[`cronjob.yaml`](cronjob.yaml) and recapped at the bottom.

> Not on the beta critical path — this is to build intuition. Budget ~an afternoon.
> All commands run from the **repo root**.

> **Collecting AWS instead of Okta?** The AWS fetchers use the AWS credential
> chain (ambient single-account, or multi-account assume-role), which is a
> different wiring — see [`AWS_MULTI_ACCOUNT.md`](AWS_MULTI_ACCOUNT.md) and
> [`cronjob-aws.yaml`](cronjob-aws.yaml).

## How the pieces fit

| Piece | Local (here) | Real EKS |
|---|---|---|
| **Scheduler** | the `CronJob` controller | same |
| **What runs** | the `:beta` image you loaded | a registry image (SWAP #2) |
| **AWS identity** (reads Secrets Manager) | static creds in the `aws-creds` Secret | IRSA-annotated ServiceAccount (SWAP #1) |
| **App tokens** (Okta, upload) | hydrated from Secrets Manager by `entrypoint.sh` | same |
| **The manifest** | a `ConfigMap`, mounted (not baked in) | same |
| **Evidence** | `emptyDir` — written, uploaded, gone with the Pod | same |

The `aws-creds` Secret is **not** for an AWS fetcher. Its only job is to let the
entrypoint read AWS Secrets Manager (exactly like the Docker run in
[`../README.md`](../README.md)), which hydrates the
`OKTA_*` + `PARAMIFY_UPLOAD_API_TOKEN` the `minimal_run.yaml` manifest references. On
EKS, IRSA replaces those static creds — that's SWAP #1.

> This walkthrough schedules the shipped sample `examples/minimal_run.yaml`, which
> collects an Okta target plus two GitLab targets. Without `GITLAB_TOKEN_*` in your
> secret the GitLab targets just report a missing secret — harmless for proving the
> plumbing. Point the CronJob at any manifest you like; your own live in `manifests/`
> (baked into the image), and you swap the ConfigMap source + mount path to match.

## Prerequisites

- A cluster is up and `kubectl` points at it (`kubectl get nodes` shows `Ready`).
- The image is visible to the cluster:
  - **kind**: `kind load docker-image paramify-fetchers:beta`
  - **Docker Desktop**: nothing to do — it shares your local image. (`imagePullPolicy: Never` in the CronJob covers both.)
- The **test Secrets Manager secret** from the Docker run exists (a flat JSON
  object of `VAR -> value`, e.g. `{"PARAMIFY_UPLOAD_API_TOKEN":"…","OKTA_API_TOKEN":"…","OKTA_ORG_URL":"…"}`).
- **Temporary AWS creds** handy: `aws configure export-credentials --format env-no-export`.

> No Secrets Manager secret? Use the **[no-Secrets-Manager alternative](#alternative-no-secrets-manager)** below — put the app tokens straight into a K8s Secret.

## 1. Create the AWS-creds Secret (the local IRSA stand-in)

The cleanest way to feed your current creds in without copying/pasting each value:

```bash
# Pull current temp creds into the shell, then create the Secret from them.
eval "$(aws configure export-credentials --format env-no-export | sed 's/^/export /')"
kubectl create secret generic aws-creds \
  --from-literal=AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  --from-literal=AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN" \
  --from-literal=AWS_REGION="${AWS_REGION:-us-east-1}"
```

> These creds are short-lived. If a run later fails to read the secret, they
> expired — `kubectl delete secret aws-creds` and re-run this block.

## 2. Create the manifest ConfigMap

This is the step that bit earlier — the flag is `--from-file=KEY=PATH`, with an
**`=`** (not `/`) between the key and the path, and the path is from the repo root
(here a shipped sample; for your own use `manifests/<name>.yaml`):

```bash
kubectl create configmap paramify-manifest \
  --from-file=minimal_run.yaml=examples/minimal_run.yaml
```

`minimal_run.yaml` is the key (the filename the Pod sees); `examples/minimal_run.yaml`
is the file on disk. Verify it landed:

```bash
kubectl describe configmap paramify-manifest   # shows a `minimal_run.yaml:` data key
```

This is the "manifest via ConfigMap" lesson: edit the ConfigMap (or recreate it
from an edited file) and re-trigger to change what's collected — no image rebuild.

## 3. Apply the CronJob

Point `PARAMIFY_SECRETS_ID` at your real SM secret first (edit the value in
[`cronjob.yaml`](cronjob.yaml), or patch it after applying):

```bash
kubectl apply -f deploy/k8s/cronjob.yaml
# if you didn't edit the file, set your secret id now:
kubectl set env cronjob/paramify-collector PARAMIFY_SECRETS_ID=<your-sm-secret-id-or-arn>
```

The CronJob is created **suspended** (`suspend: true`) so it won't fire on the
02:00 schedule mid-exercise — you trigger it by hand.

## 4. Trigger a run on demand

```bash
kubectl create job --from=cronjob/paramify-collector test-1
```

## 5. Watch the lifecycle

```bash
kubectl get pods -w           # Pending → ContainerCreating → Running → Completed
```

In **k9s**: your stuff is in the `default` namespace (press `1` to scope to it, or
`0` for all namespaces — the control plane lives in `kube-system`). Press `l` on
the Pod for logs, `d` to describe.

Read the logs (works while running or after it completes):

```bash
kubectl logs -f job/test-1
```

You should see, in order:
1. `[entrypoint] loading secrets from AWS Secrets Manager: …` — the static creds reading SM
2. `==> collect: examples/minimal_run.yaml` — `paramify run` over the ConfigMap manifest
3. `==> upload latest run -> https://stage.paramify.com/api/v0` — the uploader

> A fetcher that reaches a real tool and **fails with 401/DNS** still proves the
> plumbing (secret hydration → collect → upload). Exit 0 with empty data would be
> the bug. `run-and-upload.sh` uploads partial results even when a fetcher fails.

## 6. Observe what just happened

- The Pod went `Completed` and then ages out (per `successfulJobsHistoryLimit`).
- There was **no persistent volume** and **no long-running process** — the Pod was
  born to do one collection, shipped the evidence to Paramify, and died. The
  evidence on `/app/evidence` is gone with it. That's the model.

## 7. Teardown

```bash
kubectl delete -f deploy/k8s/cronjob.yaml          # CronJob + ServiceAccount
kubectl delete configmap paramify-manifest
kubectl delete secret aws-creds
kubectl delete job test-1                           # if it's still around
# and: kind delete cluster   (or disable Docker Desktop → Kubernetes)
```

## The two changes for real EKS

Both are flagged inline in [`cronjob.yaml`](cronjob.yaml):

1. **`PROD SWAP #1` — identity.** Delete the `aws-creds` Secret and its `envFrom`;
   uncomment the `eks.amazonaws.com/role-arn` annotation on the ServiceAccount.
   The Pod's AWS identity (which reads Secrets Manager) comes from IRSA, so there
   are **no static keys in the cluster**. IRSA is EKS-only — can't be tested here.
2. **`PROD SWAP #2` — image.** Replace `paramify-fetchers:beta` with your registry
   image and set `imagePullPolicy: IfNotPresent` (or `Always`).

Everything else — the CronJob, the ConfigMap-mounted manifest, the env contract,
the `emptyDir` evidence scratch — is identical.

## Alternative: no Secrets Manager

If you'd rather not involve SM at all, put the app tokens directly in a K8s Secret
and skip the AWS plumbing:

```bash
kubectl create secret generic paramify-secrets \
  --from-literal=PARAMIFY_UPLOAD_API_TOKEN=... \
  --from-literal=OKTA_API_TOKEN=... \
  --from-literal=OKTA_ORG_URL=...
```

Then in [`cronjob.yaml`](cronjob.yaml): remove the `PARAMIFY_SECRETS_ID` env and
the `aws-creds` `envFrom`, and uncomment the `paramify-secrets` `envFrom` block.
(On real EKS this is the External Secrets Operator / Secrets Store CSI path —
SM → a K8s Secret → `envFrom` — see [`../README.md`](../README.md) option 2.)

## What to internalize

- **Kubernetes is the scheduler** (the `CronJob` controller) — there's no host process you run.
- **Each run is an ephemeral Pod** — secrets and evidence live and die with it; no persistent volume, no long-running process.
- **Manifest via ConfigMap** = change what's collected without rebuilding the image.
- **The YAML here is what runs on real EKS**, give or take the two `PROD SWAP`s above (an IRSA-annotated ServiceAccount instead of static creds; a registry image).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `ImagePullBackOff` / `ErrImageNeverPull` | Image not on the node. kind: `kind load docker-image paramify-fetchers:beta`. Confirm the tag matches `:beta`. |
| Pod stuck `CreateContainerConfigError` | A referenced Secret/ConfigMap is missing. `kubectl describe pod <name>` names it — you skipped step 1 or 2. |
| `[entrypoint] ERROR: cannot read secret …` | AWS creds expired or wrong region → recreate `aws-creds` (step 1); or wrong `PARAMIFY_SECRETS_ID`. |
| `secret … must be a flat JSON object` | The SM secret isn't `{"VAR":"value", …}` — fix the secret's shape. |
| Fetcher logs "missing secret" | A `${env:VAR}` in `minimal_run.yaml` has no matching key in your SM secret — align the names. |
| k9s shows nothing | You're on the empty `default` namespace before triggering, or looking at `kube-system`. Trigger step 4, then watch `default`. |
