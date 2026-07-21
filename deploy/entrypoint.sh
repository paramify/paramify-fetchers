#!/usr/bin/env bash
#
# Container entrypoint. Two roles:
#   1. Pass-through runner  — `docker compose run --rm collector paramify run ...`
#      (also: bash, paramify tui, python ..., anything). This is the default.
#   2. Scheduler            — `... scheduler` runs cron on the schedule in crontab.
#
set -euo pipefail
cd /app

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
    # cron does NOT inherit the container's environment. Snapshot it so each job
    # can restore it via BASH_ENV (see deploy/crontab). NOTE: values containing
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
