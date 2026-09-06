"""Launch the TUI: python -m framework.tui [--manifest PATH] [--at ROOT]

Both this module entry point and the unified CLI's `paramify tui` subcommand
call launch(), so the two paths stay in lock-step.
"""

import argparse
from pathlib import Path
from typing import Optional

from framework import api
from framework.tui.app import FetcherApp


def launch(manifest: Optional[str] = None, at: Optional[str] = None) -> None:
    """Run the terminal UI. Shared by `paramify tui` and `python -m framework.tui`.

    A --manifest value is resolved the same way the CLI resolves -f, and a miss
    exits rather than opening the console on something else. The app used to take
    the string verbatim: read_manifest returns an EMPTY manifest for a path that
    is not there, so `--manifest demo` opened a blank console with no warning,
    and the first edit wrote a brand-new ./demo while manifests/demo.yaml sat
    untouched — the same fork the CLI had, on the surface where it is hardest to
    notice, because a fresh manifest is exactly what a new user expects to see.
    """
    if manifest:
        try:
            manifest = str(api.resolve_manifest_path(api.find_repo_root(Path(at) if at else None), manifest))
        except api.ManifestNotFound as e:
            tried = "\n  ".join(str(t) for t in e.tried)
            raise SystemExit(f"{e}\n  looked in:\n  {tried}") from None
    FetcherApp(manifest_path=manifest, root_override=at).run()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="framework.tui", description="Fetcher console (terminal UI)"
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="manifest to open directly, skipping the welcome screen "
        "(default: show the welcome / manifest picker)",
    )
    parser.add_argument(
        "--at",
        default=None,
        help="repo root override (default: discovered by walking up)",
    )
    args = parser.parse_args()
    launch(args.manifest, args.at)


if __name__ == "__main__":
    main()
