# Deploying the fetchers in a container (beta)

A hand-rolled Docker bundle for running the fetchers on a cadence and uploading
the evidence to Paramify. It's deliberately simple so you can poke at it and see
how the pieces fit — it's also the template the future `paramify package` command
would generate.

> All commands below are run from the **repo root**.

> **Just want to try it end-to-end on your laptop (with a test AWS secret)?**
> Follow [`LOCAL_TESTING.md`](LOCAL_TESTING.md) — a step-by-step local run.

## What's in here

| File | What it is |
|---|---|
| `Dockerfile` | The image: Python + the tool + the system binaries fetchers need (`jq`, `aws`, `kubectl`, `git`, `curl`, `checkov`) |
| `docker-compose.yml` | Two services: `collector` (run-and-exit) and `scheduler` (cron) |
| `entrypoint.sh` | Runs whatever command you pass; `scheduler` mode starts cron |
| `crontab` | The cadence schedule (daily / weekly) |
| `run-and-upload.sh` | Chains `paramify run <manifest>` → upload to Paramify |
| `manifests/{daily,weekly}.yaml` | **Example** cadence manifests — edit to your stack |
| `.env.example` | Template for the secrets you inject at run time |

## 1. Configure secrets

```bash
cp deploy/.env.example deploy/.env
# edit deploy/.env — at minimum PARAMIFY_UPLOAD_API_TOKEN
```

Secrets are injected at run time and **never baked into the image**. To see the
exact env vars a manifest needs, ask the tool (see step 3).

### Where secrets come from (source-agnostic)
The tool only reads env vars — it never talks to a secret store. "Pull from X"
means "get the values into the container's environment before `paramify run`."
Three options, in order of preference:

1. **AWS Secrets Manager via this bundle (built in).** Store one SM secret as a
   JSON object of `VAR -> value`, then set `PARAMIFY_SECRETS_ID` (a secret ID/ARN,
   or comma-separated list) + `AWS_REGION`. The entrypoint fetches it at startup
   (using the `aws` + `jq` already in the image) and exports each key. Auth uses
   the container's **AWS role** — IRSA on EKS, the task role on ECS, the instance
   role on EC2 — *never* static keys. Example secret value:
   ```json
   {"PARAMIFY_UPLOAD_API_TOKEN":"…","OKTA_API_TOKEN":"…","GITLAB_TOKEN_1":"…"}
   ```
   ```bash
   PARAMIFY_SECRETS_ID=paramify/fetchers/beta
   AWS_REGION=us-east-1
   ```
   The role needs `secretsmanager:GetSecretValue` on that secret. (The same role
   also serves as the AWS *fetchers'* identity — they don't use SM, they use the
   role directly via `auth.passthrough_env`.)

2. **Orchestrator-native injection (cleaner on ECS/EKS).** Skip the entrypoint
   fetch and let the platform map SM → env vars: on **ECS**, the task definition's
   `secrets:` field (SM ARN → env var); on **EKS**, the External Secrets Operator
   or Secrets Store CSI driver (SM → a K8s Secret → `envFrom`). No app change.

3. **Plain values in `deploy/.env`** — fine for local dev; not for production.

> Caveats for the long-running `scheduler`: SM is read once at container start, so
> rotated secrets need a restart; and the cron env-snapshot writes secrets to a
> file inside the container (`/tmp`). Both are reasons to prefer option 2 +
> CronJobs for production.

## 2. Build

```bash
docker compose -f deploy/docker-compose.yml build
```

First build pulls `aws-cli`, `kubectl`, and (by default) `checkov`, so it takes a
few minutes. For a faster local image without the checkov scanners:

```bash
docker compose -f deploy/docker-compose.yml build --build-arg INSTALL_EXTRAS=tui
```

## 3. Play with it

```bash
# prove the image works (no secrets needed)
docker compose -f deploy/docker-compose.yml run --rm collector paramify list

# see what a manifest requires (it reports missing secrets/config)
docker compose -f deploy/docker-compose.yml run --rm collector \
    paramify run deploy/manifests/daily.yaml

# collect + upload one cadence
docker compose -f deploy/docker-compose.yml run --rm collector \
    ./deploy/run-and-upload.sh daily

# explore runs/evidence with your own TUI, inside the container
docker compose -f deploy/docker-compose.yml run --rm collector paramify tui

# drop into a shell
docker compose -f deploy/docker-compose.yml run --rm collector bash
```

Collected evidence appears on your host in **`./evidence/run-<timestamp>/`** (the
volume mount), so you can inspect it without entering the container.

## 4. Run it on a cadence

```bash
docker compose -f deploy/docker-compose.yml up -d scheduler     # cron, per deploy/crontab
docker compose -f deploy/docker-compose.yml logs -f scheduler   # watch runs
docker compose -f deploy/docker-compose.yml exec scheduler bash # get inside it
```

Edit `deploy/crontab` to change cadences and `deploy/manifests/*.yaml` to change
what runs. Times are **UTC** (the container clock).

## How to interact with a running container

You don't SSH in — use Docker:

| Want to… | Command |
|---|---|
| Get a shell | `docker compose -f deploy/docker-compose.yml exec scheduler bash` |
| Run something once | `... run --rm collector paramify run deploy/manifests/daily.yaml` |
| See output | `... logs -f scheduler` |
| Open the TUI inside | `... run --rm collector paramify tui` |
| Get evidence out | it's already on the host in `./evidence/` (or `docker cp`) |

## Gotchas this bundle handles for you

- **System binaries** — `pip` only installs Python deps; the `Dockerfile` adds
  `jq`/`aws`/`kubectl`/`git`/`checkov` that the fetchers shell out to.
- **cron strips the environment** — `entrypoint.sh` snapshots it and `crontab`
  restores it per-job via `BASH_ENV`, with output sent to `docker logs`.
- **Ephemeral filesystem** — evidence is written to a mounted volume, and
  `run-and-upload.sh` ships it to Paramify so nothing is lost when the run ends.
- **cwd matters** — jobs `cd /app` so the tool can find its root.

## Before you hand this to customers

- **Validate the upload against a real Paramify tenant.** The uploader has only
  been mock-tested. Confirm the `base_url` and resolve whether ingestion wants
  the enveloped file or the bare payload — set `artifact_payload: envelope|payload`
  in an uploader config if needed (see `examples/upload.yaml`).
- **Pin the source.** This image `COPY`s your working tree. For reproducible
  customer images, build from a tagged commit.
- **Prefer compose/K8s scheduling for production.** In-container cron is fine for
  a single host; on Kubernetes use a `CronJob` per cadence (same image, secrets
  via K8s Secrets, AWS via IRSA).
