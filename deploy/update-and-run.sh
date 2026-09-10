#!/usr/bin/env bash
#
# Update, rebuild, collect. The glue a scheduled host runs:
#
#   1. git pull       — pick up new/changed fetcher scripts and framework code
#   2. docker build   — bake that code (and ./manifests) into the image
#   3. run a manifest — collect, then upload, inside the fresh image
#
#   ./deploy/update-and-run.sh manifests/azure.yaml
#   ./deploy/update-and-run.sh --branch main --no-upload manifests/aws-demo.yaml
#
# The manifest is a REPO-RELATIVE path: it has to resolve both on this host (so
# we can validate before a long build) and inside the container at /app.
#
# Secrets are NOT pulled by this script. They arrive at run time from
# deploy/.env, the orchestrator, or PARAMIFY_SECRETS_ID -> AWS Secrets Manager
# (see deploy/entrypoint.sh). Nothing here bakes a credential into the image.
set -uo pipefail

BRANCH="${PARAMIFY_DEPLOY_BRANCH:-main}"
DO_PULL=1
DO_BUILD=1
DO_UPLOAD=1
PULL_BASE=0
MANIFEST=""

usage() {
    cat <<'USAGE'
usage: ./deploy/update-and-run.sh [options] <manifest>

  <manifest>      repo-relative path, e.g. manifests/azure.yaml

options:
  --branch REF    git ref to deploy (default: $PARAMIFY_DEPLOY_BRANCH or main)
  --no-pull       skip the git update (build + run what is on disk)
  --no-build      skip the image rebuild (run the existing image)
  --no-upload     collect only; do not upload to Paramify
  --pull-base     also refresh the python base image (docker build --pull)
  -h, --help      this text
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --branch)     BRANCH="${2:-}"; shift 2 ;;
        --no-pull)    DO_PULL=0; shift ;;
        --no-build)   DO_BUILD=0; shift ;;
        --no-upload)  DO_UPLOAD=0; shift ;;
        --pull-base)  PULL_BASE=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        -*)           echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)            [ -n "$MANIFEST" ] && { echo "one manifest at a time" >&2; exit 2; }
                      MANIFEST="$1"; shift ;;
    esac
done

[ -n "$MANIFEST" ] || { usage >&2; exit 2; }

cd "$(dirname "$0")/.." || exit 1   # repo root
REPO_ROOT="$PWD"
COMPOSE=(docker compose -f deploy/docker-compose.yml)

log() { printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { printf '[%s] ERROR: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; exit 1; }

# --- single-flight ---------------------------------------------------------
# A slow collection must not have the rug pulled out by the next cron tick
# rebuilding the image underneath it. mkdir is the portable atomic lock.
# Keyed to THIS checkout: two manifests from the same tree share an image and
# must serialize, but an unrelated checkout on the same host should not block.
LOCK="${TMPDIR:-/tmp}/paramify-update-and-run-$(printf '%s' "$REPO_ROOT" | cksum | cut -d' ' -f1).lock"
if ! mkdir "$LOCK" 2>/dev/null; then
    die "another run holds $LOCK (stale? remove it by hand)"
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

command -v docker >/dev/null || die "docker not on PATH"
docker compose version >/dev/null 2>&1 || die "docker compose v2 required"

# ---------------------------------------------------------------------------
# 1. Update the checkout
# ---------------------------------------------------------------------------
if [ "$DO_PULL" -eq 1 ]; then
    before="$(git rev-parse HEAD)"
    if ! git diff --quiet HEAD -- 2>/dev/null; then
        die "tracked files are modified — commit, stash, or run with --no-pull"
    fi
    log "fetching origin/$BRANCH"
    git fetch --quiet --prune origin "$BRANCH" || die "git fetch failed"
    git checkout --quiet "$BRANCH" || die "cannot check out $BRANCH"
    git merge --ff-only --quiet "origin/$BRANCH" \
        || die "cannot fast-forward $BRANCH (local commits? reset the deploy checkout)"
    after="$(git rev-parse HEAD)"
    if [ "$before" = "$after" ]; then
        log "already current at ${after:0:12}"
    else
        log "updated ${before:0:12} -> ${after:0:12}"
        git --no-pager log --oneline "$before..$after" | sed 's/^/    /'
    fi
else
    log "skipping git update (--no-pull); HEAD $(git rev-parse --short HEAD)"
fi

# The manifest check happens AFTER the pull (the pull may add it) and BEFORE the
# build (a typo shouldn't cost a rebuild).
case "$MANIFEST" in
    /*) die "use a repo-relative manifest path; '$MANIFEST' won't exist inside the container" ;;
esac
[ -f "$REPO_ROOT/$MANIFEST" ] || die "no such manifest: $MANIFEST"

# ---------------------------------------------------------------------------
# 2. Rebuild the image
# ---------------------------------------------------------------------------
# Everything the run executes — fetcher scripts, framework, validators, AND
# ./manifests — is COPYed in at build time, so a rebuild is how new or edited
# scripts reach the container. It is cheap when nothing changed: the apt /
# aws-cli / kubectl layers are cached and only the COPY + pip install re-run.
if [ "$DO_BUILD" -eq 1 ]; then
    log "building paramify-fetchers:beta"
    # Seeded with the service name so the array is never empty: bash 3.2 (what
    # macOS ships) treats "${empty[@]}" under `set -u` as an unbound variable.
    build_args=(collector)
    [ "$PULL_BASE" -eq 1 ] && build_args=(--pull collector)
    "${COMPOSE[@]}" build "${build_args[@]}" || die "image build failed"
else
    log "skipping build (--no-build)"
fi

# ---------------------------------------------------------------------------
# 3. Validate, then collect
# ---------------------------------------------------------------------------
# Validate inside the image, not on the host: it is the just-built code and the
# baked-in copy of the manifest that will actually run.
log "validating $MANIFEST"
"${COMPOSE[@]}" run --rm -T collector paramify validate "$MANIFEST" \
    || die "manifest failed validation against the new build"

if [ "$DO_UPLOAD" -eq 1 ]; then
    log "collect + upload: $MANIFEST"
    "${COMPOSE[@]}" run --rm -T collector ./deploy/run-and-upload.sh "$MANIFEST"
else
    log "collect only: $MANIFEST"
    "${COMPOSE[@]}" run --rm -T collector paramify run "$MANIFEST"
fi
rc=$?

# Exit code is the run's, so cron/monitoring alerts on a failing fetcher rather
# than on this wrapper. Non-zero here means "collected, but something failed" —
# evidence for the fetchers that did work is already on the host in ./evidence.
if [ "$rc" -eq 0 ]; then
    log "done (evidence in $REPO_ROOT/evidence)"
else
    log "run exited $rc — see the output above; partial evidence in $REPO_ROOT/evidence"
fi
exit "$rc"
