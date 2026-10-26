"""Turn on cassette replay in a fetcher subprocess.

Python imports `sitecustomize` automatically at startup, so putting this
directory on PYTHONPATH patches the SDK's HTTP layer before the fetcher's own
imports run. That is why no fetcher needs a test hook of its own.

It lives under `tests/` rather than beside the cassettes because everything
under `fetchers/<category>/` is shipped code: `test_category_requires` reads
every .py there and requires its imports to be declared dependencies of the
category, which this file's import of `tools/oci_cassette` is not. The cassettes
themselves stay in `fetchers/oci/tests/cassettes/` — they are data, and the
review of PR #42 asked for fixtures under the category rather than a new
top-level fixtures tree.
"""

import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[2] / "tools"
if _TOOLS.is_dir():
    sys.path.insert(0, str(_TOOLS))
    try:
        from oci_cassette import install_from_env

        install_from_env()
    except Exception as exc:  # a broken bootstrap must be loud, not silent
        print(f"cassette bootstrap failed: {exc}", file=sys.stderr)
        raise
