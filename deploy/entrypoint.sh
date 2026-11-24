#!/usr/bin/env bash
#
# Container entrypoint. Two roles:
#   1. Pass-through runner  — `docker compose run --rm collector paramify run ...`
#      (also: bash, paramify tui, python ..., anything). This is the default.
#   2. Scheduler            — `... scheduler` runs cron on the schedule in crontab.
#
# Two images use this file: deploy/Dockerfile (Debian, runs as root, Debian cron)
# and deploy/Dockerfile.wolfi (runs as UID 65532, supercronic).
#
set -euo pipefail
cd /app

# The Wolfi image runs as a non-root user. A host folder mounted on the evidence
# directory keeps its host owner, and on a Linux host that owner is usually not
# this user. Say so now, not when the first run fails to write its output.
_evidence_dir="${EVIDENCE_DIR:-/app/evidence}"
if [ -d "$_evidence_dir" ] && [ ! -w "$_evidence_dir" ]; then
  echo "[entrypoint] WARNING: $_evidence_dir is not writable by UID $(id -u)." >&2
  echo "[entrypoint]   Runs cannot save evidence. On the host, run: sudo chown -R $(id -u):$(id -g) ./evidence" >&2
fi
unset _evidence_dir

# Default upload host if the caller didn't set one. Must be https (the uploader
# refuses to send the bearer token over cleartext to a non-loopback host).
export PARAMIFY_API_BASE_URL="${PARAMIFY_API_BASE_URL:-https://app.paramify.com/api/v0}"

# Read-only `paramify` subcommands only inspect the local fetcher catalog, so
# they need no secrets. Skip hydration for them (and for help/empty, which falls
# through to `paramify list`) — otherwise the `paramify list` sanity check would
# fail whenever PARAMIFY_SECRETS_ID is set but AWS creds are absent/expired.
_needs_secrets=1
case "${1:-}" in
  ""|-h|--help) _needs_secrets=0 ;;
  paramify)
    case "${2:-}" in
      list|catalog|describe|manifests) _needs_secrets=0 ;;
    esac
    ;;
esac

# --- Optional: hydrate env from AWS Secrets Manager (source-agnostic) ---------
# Set PARAMIFY_SECRETS_ID to one secret ID/ARN (or a comma-separated list), each
# holding a JSON object of VAR->value, e.g.
#   {"OKTA_API_TOKEN":"...","GITLAB_TOKEN_1":"...","PARAMIFY_UPLOAD_API_TOKEN":"..."}
# Inert unless set. Auth uses the container's AWS role (IRSA / ECS task role /
# EC2 instance role) — never static keys; requires AWS_REGION. Uses the aws + jq
# already in the image. (On ECS/EKS, prefer the orchestrator's native secret
# injection over this — see deploy/README.md.)
if [ -n "${PARAMIFY_SECRETS_ID:-}" ] && [ "$_needs_secrets" = 1 ]; then
  IFS=',' read -ra _sids <<< "$PARAMIFY_SECRETS_ID"
  for _sid in "${_sids[@]}"; do
    _sid="$(echo "$_sid" | xargs)"        # trim surrounding whitespace
    [ -z "$_sid" ] && continue
    echo "[entrypoint] loading secrets from AWS Secrets Manager: $_sid"
    if ! _json="$(aws secretsmanager get-secret-value --secret-id "$_sid" --query SecretString --output text)"; then
      echo "[entrypoint] ERROR: cannot read secret '$_sid' (check the container's AWS role + AWS_REGION)" >&2
      exit 1
    fi
    # @sh shell-quotes each value so it survives spaces/quotes safely.
    if ! _exports="$(printf '%s' "$_json" | jq -r 'to_entries[] | "export \(.key)=\(.value|@sh)"')"; then
      echo "[entrypoint] ERROR: secret '$_sid' must be a flat JSON object of key/value pairs" >&2
      exit 1
    fi
    eval "$_exports"
  done
  unset _sids _sid _json _exports
fi

case "${1:-}" in
  scheduler)
    echo "[entrypoint] starting cron scheduler (times are UTC inside the container)"
    # Wolfi image: supercronic runs as this user, reads deploy/crontab directly,
    # and passes this environment (with any secrets loaded above) to each job.
    # It writes no env snapshot, so BASH_ENV in the crontab names a file that
    # does not exist, and bash ignores it.
    if command -v supercronic >/dev/null 2>&1; then
      echo "[entrypoint] schedule (deploy/crontab):"
      grep -Ev '^[[:space:]]*(#|$)' /app/deploy/crontab | sed 's/^/    /'
      # -no-reap: tini is PID 1 and reaps child processes.
      exec supercronic -no-reap /app/deploy/crontab
    fi
    # Debian image: cron does NOT inherit the container's environment. Snapshot
    # it so each job can restore it via BASH_ENV (see deploy/crontab). NOTE: values containing
    # single quotes won't survive this simple snapshot — fine for typical tokens.
    printenv | sed -E "s/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/export \1='\2'/" > /tmp/container-env.sh
    crontab /app/deploy/crontab
    echo "[entrypoint] installed crontab:"
    crontab -l | sed 's/^/    /'
    exec cron -f
    ;;
  ""|-h|--help)
    echo "usage: <command>            run any command (default: paramify list)"
    echo "       scheduler            run cron on the schedule in deploy/crontab"
    echo
    echo "examples:"
    echo "   docker compose run --rm collector paramify list"
    echo "   docker compose run --rm collector paramify run examples/minimal_run.yaml"
    echo "   docker compose run --rm collector ./deploy/run-and-upload.sh examples/minimal_run.yaml"
    echo "   docker compose run --rm collector paramify tui"
    echo "   docker compose run --rm collector bash"
    exec paramify list
    ;;
  *)
    exec "$@"
    ;;
esac
