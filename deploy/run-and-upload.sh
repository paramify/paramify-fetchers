#!/usr/bin/env bash
#
# Collect a manifest, then upload the resulting run to Paramify.
# These are two SEPARATE framework stages; this script just chains them — the
# kind of glue that lives in your cron/CI, not in the framework itself.
#
#   ./deploy/run-and-upload.sh <manifest> [stack]    # e.g. manifests/minimal.yaml
#
# [stack] is optional: a stack name or id, passed to `paramify upload --stack`
# (it overrides the manifest's run.paramify.stack for this upload).
#
# <manifest> is a path (relative to the repo root, or absolute) — the same value
# you'd pass to `paramify run`. There is one source of manifests (./manifests/,
# what the TUI builds); name them however makes sense for your schedule.
#
# The upload step sends the run the collect step just made, not whichever run is
# newest on disk: `paramify run --print-run-dir` prints its directory to stdout.
# It prints the rest of its output (each fetcher's result, why one failed, every
# skipped entry, setup error and note) to stderr, so all of it reaches the log.
#
# Secrets must already be in the environment (the manifest references them as
# ${env:VAR}); PARAMIFY_UPLOAD_API_TOKEN is required for the upload step.
set -uo pipefail
cd "$(dirname "$0")/.."   # repo root (/app in the image)

manifest="${1:-}"
stack="${2:-}"
if [ -z "$manifest" ]; then
    echo "usage: ./deploy/run-and-upload.sh <manifest> [stack]   (e.g. manifests/minimal.yaml)" >&2
    exit 2
fi
if [ ! -f "$manifest" ]; then
    echo "no such manifest: '$manifest' (run from the repo root; see ./manifests/)" >&2
    exit 2
fi

echo "==> collect: $manifest"
run_dir=$(paramify run "$manifest" --print-run-dir)
collect_rc=$?
if [ "$collect_rc" -ne 0 ]; then
    echo "WARN: collect exited $collect_rc (a fetcher reported failures); uploading whatever was produced" >&2
fi
if [ -z "$run_dir" ]; then
    echo "collect produced no run directory; nothing to upload" >&2
    exit "$([ "$collect_rc" -ne 0 ] && echo "$collect_rc" || echo 1)"
fi

echo "==> upload $run_dir -> ${PARAMIFY_API_BASE_URL:-<default>}"
upload_args=("$run_dir")
if [ -n "$stack" ]; then upload_args+=(--stack "$stack"); fi
paramify upload "${upload_args[@]}"
upload_rc=$?

# Surface the worst non-zero so cron/monitoring can alert.
if [ "$collect_rc" -ne 0 ]; then exit "$collect_rc"; fi
exit "$upload_rc"
