#!/usr/bin/env bash
#
# Collect a manifest, then upload the resulting run to Paramify.
# These are two SEPARATE framework stages; this script just chains them — the
# kind of glue that lives in your cron/CI, not in the framework itself.
#
#   ./deploy/run-and-upload.sh <manifest>     # e.g. manifests/minimal.yaml
#
# <manifest> is a path (relative to the repo root, or absolute) — the same value
# you'd pass to `paramify run`. There is one source of manifests (./manifests/,
# what the TUI builds); name them however makes sense for your schedule.
#
# Secrets must already be in the environment (the manifest references them as
# ${env:VAR}); PARAMIFY_API_TOKEN is required for the upload step.
set -uo pipefail
cd "$(dirname "$0")/.."   # repo root (/app in the image)

manifest="${1:-}"
if [ -z "$manifest" ]; then
    echo "usage: ./deploy/run-and-upload.sh <manifest>   (e.g. manifests/minimal.yaml)" >&2
    exit 2
fi
if [ ! -f "$manifest" ]; then
    echo "no such manifest: '$manifest' (run from the repo root; see ./manifests/)" >&2
    exit 2
fi

echo "==> collect: $manifest"
paramify run "$manifest"
collect_rc=$?
if [ "$collect_rc" -ne 0 ]; then
    echo "WARN: collect exited $collect_rc (a fetcher reported failures); uploading whatever was produced" >&2
fi

echo "==> upload latest run -> ${PARAMIFY_API_BASE_URL:-<default>}"
python uploaders/paramify_evidence/uploader.py
upload_rc=$?

# Surface the worst non-zero so cron/monitoring can alert.
if [ "$collect_rc" -ne 0 ]; then exit "$collect_rc"; fi
exit "$upload_rc"
