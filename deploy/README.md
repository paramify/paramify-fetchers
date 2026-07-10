# Deploying the fetchers in a container (beta)

A hand-rolled Docker bundle for running the fetchers on a schedule and uploading
the evidence to Paramify. It's deliberately simple so you can poke at it and see
how the pieces fit — it's also the template the future `paramify package` command
would generate.

> All commands below are run from the **repo root**.

This README is both the reference and the hands-on guide: sections 1–4 are the
reference; [**Walk through it end-to-end on your laptop**](#walk-through-it-end-to-end-on-your-laptop-docker-desktop--a-test-aws-secret)
is a guided run against a test AWS Secrets Manager secret.

## What's in here

| File | What it is |
|---|---|
| `Dockerfile` | The image: Python + the tool + the system binaries fetchers need (`jq`, `aws`, `kubectl`, `git`, `curl`, `checkov`) |
| `docker-compose.yml` | Two services: `collector` (run-and-exit) and `scheduler` (cron) |
| `entrypoint.sh` | Runs whatever command you pass; `scheduler` mode starts cron |
| `crontab` | The schedule — maps a time to a manifest path |
| `run-and-upload.sh` | Chains `paramify run <manifest>` → upload to Paramify |
| `.env.example` | Template for the secrets you inject at run time |

### Where manifests come from
There's one source: the repo-root `manifests/` — the same folder `paramify tui`
builds into. **They're baked into the image at build time** (`docker compose build`
copies your working tree), so build and test your manifests *before* you build the
image; rebuild to pick up changes. Name them however makes sense for your schedule.

`manifests/` is gitignored (your manifests are yours, not committed), so a fresh
clone has none — the repo ships ready-to-run samples in `examples/` (also baked in)
that every command below uses, so the bundle works before you've built your own.

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

2. **Orchestrator-native injection.** Skip the entrypoint fetch and let your
   platform map secrets → env vars directly (most schedulers and orchestrators can
   inject a secret store into a task's environment). No app change.

3. **Plain values in `deploy/.env`** — fine for local dev; not for production.

> Caveats for the long-running `scheduler`: SM is read once at container start, so
> rotated secrets need a restart; and the cron env-snapshot writes secrets to a
> file inside the container (`/tmp`). Both are reasons to prefer option 2 for
> production.

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
    paramify run examples/minimal_run.yaml

# collect + upload one manifest
docker compose -f deploy/docker-compose.yml run --rm collector \
    ./deploy/run-and-upload.sh examples/minimal_run.yaml

# explore runs/evidence with your own TUI, inside the container
docker compose -f deploy/docker-compose.yml run --rm collector paramify tui

# drop into a shell
docker compose -f deploy/docker-compose.yml run --rm collector bash
```

Collected evidence appears on your host in **`./evidence/run-<timestamp>/`** (the
volume mount), so you can inspect it without entering the container.

## 4. Run it on a schedule

```bash
docker compose -f deploy/docker-compose.yml up -d scheduler     # cron, per deploy/crontab
docker compose -f deploy/docker-compose.yml logs -f scheduler   # watch runs
docker compose -f deploy/docker-compose.yml exec scheduler bash # get inside it
```

Edit `deploy/crontab` to change the schedule (each line maps a time to a manifest
path). The active example runs a shipped `examples/` sample; point a line at your
own `manifests/<name>.yaml` once you've built it and rebuilt the image (manifests
are baked in — see [Where manifests come from](#where-manifests-come-from)).
Times are **UTC** (the container clock).

## Walk through it end-to-end on your laptop (Docker Desktop + a test AWS secret)

A guided run: build the image, pull secrets from **AWS Secrets Manager**, run a
fetcher, see evidence on disk, and (optionally) upload to Paramify — all locally.
To save typing: `alias pf='docker compose -f deploy/docker-compose.yml'`.

**Prerequisites:** Docker Desktop running; `aws` CLI v2 on the host, logged into
the **test** account (`aws sso login` or a configured profile — confirm with
`aws sts get-caller-identity`); your identity has `secretsmanager:GetSecretValue`
on the test secret; the secret stores a flat **JSON object** of `VAR -> value`
(use the var names the manifest you'll run references), e.g.
`{ "PARAMIFY_UPLOAD_API_TOKEN": "…", "OKTA_API_TOKEN": "…", "OKTA_ORG_URL": "…" }`.

```bash
# 1. Host-side sanity check — prove you can read the secret. If this prints your
#    JSON, the container can read it too.
aws secretsmanager get-secret-value \
  --secret-id <your-secret-name-or-arn> \
  --region <region> --query SecretString --output text

# 2. Configure deploy/.env: which secret to load, the region, and TEMPORARY AWS
#    creds (no instance role locally — re-run the last line when they expire).
cp deploy/.env.example deploy/.env
cat >> deploy/.env <<'EOF'
PARAMIFY_SECRETS_ID=<your-secret-name-or-arn>
AWS_REGION=<region>
EOF
aws configure export-credentials --format env-no-export >> deploy/.env
# deploy/.env is gitignored and never enters the image — injected at run time only.

# 3. Build.
pf build

# 4. Verify secret hydration BEFORE running anything real (prints presence, not the value).
pf run --rm collector bash -lc '[ -n "$PARAMIFY_UPLOAD_API_TOKEN" ] && echo "secret loaded ✅" || echo "MISSING ❌"'

# 5. Run a collection and look at the evidence (appears on your host).
pf run --rm collector paramify list
pf run --rm collector paramify run examples/minimal_run.yaml
ls -R evidence/

# 6. (Optional) Full chain — collect AND upload. Hits real Paramify; uses
#    PARAMIFY_UPLOAD_API_TOKEN from the secret (PARAMIFY_API_BASE_URL defaults to production).
pf run --rm collector ./deploy/run-and-upload.sh examples/minimal_run.yaml

# 7. Confirm no secrets are baked into the image (prints nothing = good).
docker run --rm paramify-fetchers:beta sh -c 'find / -name ".env" 2>/dev/null' || true
```

Point the manifest at a fetcher whose creds are in your test
secret. A fetcher that reaches a real tool and **fails with 401/DNS** still proves
the secret plumbing works — exit 0 with empty data would be the bug. If upload
ingestion rejects the file, try `artifact_payload: payload` in an uploader config
(see `examples/upload.yaml`) — that's the open envelope-vs-payload question.

## How to interact with a running container

You don't SSH in — use Docker:

| Want to… | Command |
|---|---|
| Get a shell | `docker compose -f deploy/docker-compose.yml exec scheduler bash` |
| Run something once | `... run --rm collector paramify run examples/minimal_run.yaml` |
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

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Cannot connect to the Docker daemon` | Start Docker Desktop |
| `[entrypoint] ERROR: cannot read secret …` | AWS creds expired → re-run the `aws configure export-credentials` line; or wrong `AWS_REGION` |
| `AccessDenied … GetSecretValue` | Your identity lacks `secretsmanager:GetSecretValue` on that secret |
| `secret … must be a flat JSON object` | The secret isn't `{"VAR":"value", …}` — fix its shape |
| Fetcher exits with "missing secret" | A `${env:VAR}` in the manifest has no matching key in the secret — align the names |
| Evidence not on host | Run from the repo root so `./evidence` maps correctly |
| `unzip` / `bad CRC` during image build (aws-cli step) | Corrupted download of the ~50MB AWS CLI zip — common on fresh Docker Desktop installs. Retry the build; if it persists, `docker builder prune -f` then rebuild. The Dockerfile retries and tests the zip before installing. |

## Before you hand this to customers

- **Validate the upload against a real Paramify tenant.** The uploader has only
  been mock-tested. Confirm the `base_url` and resolve whether ingestion wants
  the enveloped file or the bare payload — set `artifact_payload: envelope|payload`
  in an uploader config if needed (see `examples/upload.yaml`).
- **Pin the source.** This image `COPY`s your working tree. For reproducible
  customer images, build from a tagged commit.
- **In-container cron is single-host.** It's fine for one machine; for production,
  schedule the container with your platform's own scheduler (a managed cron / task
  scheduler) so each run is an isolated, ephemeral task.
