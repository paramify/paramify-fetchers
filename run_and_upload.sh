#!/usr/bin/env bash
#
# Customer orchestration glue: collect evidence (runner) then upload that run.
# The framework keeps these as SEPARATE stages on purpose; this script just chains
# them — the kind of thing that lives in your CI job / cron, not in the framework.
#
# Secrets must already be in the environment before running (never put values here):
#   KNOWBE4_API_KEY, KNOWBE4_REGION   — for collection
#   PARAMIFY_UPLOAD_API_TOKEN         — for upload
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
summary=$(.venv/bin/paramify run "$MANIFEST" --json)
collect_rc=$?
if [ $collect_rc -ne 0 ]; then
    echo "WARN: collect exited $collect_rc (a fetcher reported failures); uploading whatever was produced" >&2
fi
run_dir=$(printf '%s' "$summary" | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin)["run_dir"])' 2>/dev/null)
if [ -z "$run_dir" ]; then
    echo "collect produced no run directory; nothing to upload" >&2
    printf '%s\n' "$summary" >&2
    if [ $collect_rc -ne 0 ]; then exit $collect_rc; fi
    exit 1
fi

echo "==> upload $run_dir -> ${PARAMIFY_API_BASE_URL:-<production default>}"
.venv/bin/paramify upload "$run_dir"
upload_rc=$?

# Surface the worst non-zero so cron/monitoring can alert.
if [ $collect_rc -ne 0 ]; then exit $collect_rc; fi
exit $upload_rc
