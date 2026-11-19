#!/usr/bin/env python3
"""Deprecated entry point: use `paramify upload` (docs/uploader_guide.md).

This path-loaded script is kept so existing schedules and imports keep working.
It no longer uploads anything itself: `upload_run` and `main` hand the run to
the same plan/apply engine `paramify upload` uses (framework/api.upload_run),
which sends one batch per fetcher entry, or sends the entry direct when a batch
cannot be used.

Auth: PARAMIFY_UPLOAD_API_TOKEN (source-agnostic env — .env, secret manager, CI).
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Callable, Dict, Optional

from dotenv import load_dotenv

# This file is also runnable directly (`python uploaders/paramify_evidence/uploader.py`)
# from any cwd, where only its own directory lands on sys.path. Its position in the
# repo is fixed, so derive the root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from framework import api, upload_config  # noqa: E402
from framework.sync.providers.desired import (  # noqa: E402,F401
    artifact_content,
    artifact_note,
    artifact_title,
    is_enveloped,
    override_for,
    resolve_evidence_set,
)

logger = logging.getLogger("paramify_evidence_uploader")

DEPRECATION = "paramify_evidence/uploader.py is deprecated; use 'paramify upload'"


def _upload(run_dir, config, token, base_url, dry_run, on_event, custom_tags, deprecations) -> Dict:
    return api.upload_run(
        Path(run_dir), _REPO_ROOT, None, dry_run=dry_run, on_event=on_event,
        custom_tags=custom_tags, upload_cfg=config or {}, token=token, base_url=base_url,
        deprecations=deprecations,
    )


def upload_run(
    run_dir: Path,
    *,
    config: Optional[Dict] = None,
    token: Optional[str] = None,
    base_url: Optional[str] = None,
    dry_run: bool = False,
    on_event: Optional[Callable[[dict], None]] = None,
    custom_tags: bool = True,
) -> Dict:
    """Upload one completed run directory through the sync engine.

    Delegates to `framework.api.upload_run`; see it for the summary and the
    events. `config` is the uploader config as a dict (nothing is read from
    disk for it); `token` and `base_url`, when given, win over the environment.
    `custom_tags=False` is the `--no-tags` switch. Raises ValueError for setup
    errors, as it always has.
    """
    return _upload(run_dir, config, token, base_url, dry_run, on_event, custom_tags, ())


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()
    print(DEPRECATION, file=sys.stderr)

    parser = argparse.ArgumentParser(description="Upload enveloped evidence to Paramify (deprecated: use 'paramify upload')")
    parser.add_argument("run_dir", nargs="?", help="Run directory to upload (default: latest under --output-dir)")
    parser.add_argument("--output-dir", default="./evidence", help="Base dir to find the latest run in (default ./evidence)")
    parser.add_argument("--config", help="Uploader config YAML (base_url, overrides, skip_failed, artifact_payload, tags)")
    parser.add_argument("--dry-run", action="store_true", help="Resolve and report what would upload; no API calls")
    args = parser.parse_args(argv)

    latest = None if args.run_dir else api.latest_run(args.output_dir, kind="evidence")
    run_dir = Path(args.run_dir) if args.run_dir else (Path(latest["dir"]) if latest else None)
    if not run_dir or not run_dir.is_dir():
        logger.error(
            "No run directory to upload (looked for %s)",
            args.run_dir or f"latest run-* under {args.output_dir}",
        )
        return 1
    try:
        summary = _upload(run_dir, upload_config.load(args.config), None, None, args.dry_run, None, True, [DEPRECATION])
    except ValueError as e:  # setup errors
        logger.error("%s", e)
        return 1
    except Exception as e:  # API and unexpected errors end the run too
        logger.error("%s: %s", type(e).__name__, e)
        logger.debug("traceback", exc_info=True)
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
