#!/usr/bin/env python3
"""Deprecated entry point: use `paramify upload` (docs/uploader_guide.md).

This path-loaded script is kept so existing schedules and imports keep working.
It no longer uploads anything itself: `upload_run` and `main` hand the run to
the same plan/apply engine `paramify upload` uses (framework/api.upload_run),
which sends one batch per fetcher entry and needs Paramify API 0.14.0 or later.

Auth: PARAMIFY_UPLOAD_API_TOKEN (source-agnostic env — .env, secret manager, CI).
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Callable, Dict, Optional

import yaml
from dotenv import load_dotenv

# This file is also runnable directly (`python uploaders/paramify_evidence/uploader.py`)
# from any cwd, where only its own directory lands on sys.path. Its position in the
# repo is fixed, so derive the root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from framework import api  # noqa: E402
from framework.run_files import is_evidence_file  # noqa: E402
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


def find_latest_run(output_dir: Path) -> Optional[Path]:
    """The newest run that holds evidence — not simply the newest run, which is
    often a pipeline manifest's (issue reports only) sharing the same output dir."""
    if not output_dir.is_dir():
        return None
    runs = sorted((p for p in output_dir.glob("run-*") if p.is_dir()), reverse=True)
    return next((r for r in runs if any(iter_evidence_files(r))), None)


def iter_evidence_files(run_dir: Path):
    for p in sorted(run_dir.glob("*.json")):
        if is_evidence_file(p):
            yield p


def load_config(path: Optional[str]) -> Dict:
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text())
    return data or {}


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

    run_dir = Path(args.run_dir) if args.run_dir else find_latest_run(Path(args.output_dir))
    if not run_dir or not run_dir.is_dir():
        logger.error(
            "No run directory to upload (looked for %s)",
            args.run_dir or f"latest run-* under {args.output_dir}",
        )
        return 1
    try:
        summary = _upload(run_dir, load_config(args.config), None, None, args.dry_run, None, True, [DEPRECATION])
    except Exception as e:  # setup errors (ValueError) and API errors both end the run
        logger.error("%s", e)
        return 1
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
