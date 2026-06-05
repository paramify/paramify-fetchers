# Testing the full process locally (Docker Desktop + a test AWS secret)

Goal: build the image, pull secrets from **AWS Secrets Manager**, run a fetcher,
see evidence on disk, and (optionally) upload to Paramify — all on your laptop.

Run everything from the **repo root**. To save typing:

```bash
alias pf='docker compose -f deploy/docker-compose.yml'
```

## Prerequisites
- Docker Desktop running.
- `aws` CLI v2 on your host, logged into the **test** account (`aws sso login`
  or a configured profile). Confirm: `aws sts get-caller-identity`.
- Your identity has `secretsmanager:GetSecretValue` on the test secret.
- The test secret stores a **JSON object** of `VAR -> value`, e.g.:
  ```json
  { "PARAMIFY_UPLOAD_API_TOKEN": "…", "OKTA_API_TOKEN": "…", "OKTA_ORG_URL": "…" }
  ```
  (Use the var names the manifest you'll run actually references.)

## 1. Host-side sanity check (prove you can read the secret)
```bash
aws secretsmanager get-secret-value \
  --secret-id <your-secret-name-or-arn> \
  --region <region> --query SecretString --output text
```
If that prints your JSON, the container will be able to read it too.

## 2. Configure `deploy/.env`
```bash
cp deploy/.env.example deploy/.env

# Tell the container which secret to load + the region:
cat >> deploy/.env <<'EOF'
PARAMIFY_SECRETS_ID=<your-secret-name-or-arn>
AWS_REGION=<region>
EOF

# Give the container TEMPORARY AWS creds (no instance role locally).
# Re-run this whenever they expire (SSO/STS creds are short-lived).
aws configure export-credentials --format env-no-export >> deploy/.env
```
`deploy/.env` is gitignored and never enters the image — it's only injected at
run time.

## 3. Build
```bash
pf build
```
First build is a few minutes (it pulls aws-cli, kubectl, checkov).

## 4. Verify the secret hydration — *before* running anything real
```bash
# You should see "[entrypoint] loading secrets from AWS Secrets Manager: …"
# and the expected var present (this prints presence, NOT the value):
pf run --rm collector bash -lc '[ -n "$PARAMIFY_UPLOAD_API_TOKEN" ] && echo "secret loaded ✅" || echo "MISSING ❌"'
```

## 5. Run a collection and look at the evidence
```bash
pf run --rm collector paramify list                       # tool works?
pf run --rm collector paramify run deploy/manifests/daily.yaml
ls -R evidence/                                            # appears on your host
```
Edit `deploy/manifests/daily.yaml` to a fetcher whose creds are in your test
secret. (A fetcher that reaches a real tool and **fails with a 401/DNS** still
proves the secret plumbing works — exit 0 with empty data would be the bug.)

## 6. (Optional) Full chain — collect **and** upload to Paramify
```bash
# Uses PARAMIFY_UPLOAD_API_TOKEN from the secret; PARAMIFY_API_BASE_URL defaults to stage.
pf run --rm collector ./deploy/run-and-upload.sh daily
```
This hits real Paramify. If ingestion rejects the file, try setting
`artifact_payload: payload` in an uploader config (see `examples/upload.yaml`) —
that's the open envelope-vs-payload question.

## 7. Confirm no secrets are baked into the image
```bash
docker run --rm paramify-fetchers:beta sh -c 'find / -name ".env" 2>/dev/null' || true
# (prints nothing = good)
```

## Interacting with it
```bash
pf run --rm collector bash          # shell inside the container
pf run --rm collector paramify tui  # your TUI, inside the container
pf up -d scheduler && pf logs -f scheduler   # try the cron cadence
pf down                             # stop the scheduler
```

## Troubleshooting
| Symptom | Likely cause / fix |
|---|---|
| `Cannot connect to the Docker daemon` | Start Docker Desktop |
| `[entrypoint] ERROR: cannot read secret …` | Creds expired → re-run the `export-credentials` line; or wrong `AWS_REGION` |
| `AccessDenied … GetSecretValue` | Your test identity lacks `secretsmanager:GetSecretValue` on that secret |
| `secret … must be a flat JSON object` | The secret isn't a JSON object — store it as `{"VAR":"value", …}` |
| Fetcher exits with "missing secret" | The manifest's `${env:VAR}` name doesn't match a key in the secret — align them |
| Evidence not on host | Run from the repo root so `./evidence` maps correctly |
