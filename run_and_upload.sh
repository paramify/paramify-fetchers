#!/usr/bin/env bash
#
# Customer orchestration glue: collect evidence (runner) then upload it (uploader).
# The framework keeps these as SEPARATE stages on purpose; this script just chains
# them — the kind of thing that lives in your CI job / cron, not in the framework.
#
# Secrets must already be in the environment before running (never put values here):
#   KNOWBE4_API_KEY, KNOWBE4_REGION   — for collection
#   PARAMIFY_API_TOKEN                — for upload
#
# Config (non-secret) is set here / overridable via env:
#   MANIFEST                 (default: manifest.yaml)
#   PARAMIFY_API_BASE_URL    (default: production; export to override — e.g. a stage URL)

set -uo pipefail
cd "$(dirname "$0")"   # repo root

MANIFEST="${MANIFEST:-manifest.yaml}"
# Upload target is the uploader's own default (production: app.paramify.com).
# Export PARAMIFY_API_BASE_URL before running to point elsewhere (e.g. stage);
# the uploader subprocess inherits it. We deliberately do NOT default it to
# stage here — the README points customers at this script, and a silent stage
# default would route real evidence to staging.

echo "==> collect: $MANIFEST"
# Requires the package installed in the venv: pip install -e .
.venv/bin/paramify run "$MANIFEST"
collect_rc=$?
if [ $collect_rc -ne 0 ]; then
    echo "WARN: collect exited $collect_rc (a fetcher reported failures); uploading whatever was produced" >&2
fi

echo "==> upload latest run -> ${PARAMIFY_API_BASE_URL:-<production default>}"
.venv/bin/python uploaders/paramify_evidence/uploader.py
