"""One YAML reader for the framework.

Every YAML this repo reads is trusted, schema-validated repo content or an
operator's own manifest, so the safe subset is what we want — but PyYAML's
default `safe_load` is the *pure-Python* parser, and discovery parses 187
fetcher.yaml files on a cold path that both the CLI and the TUI sit behind.

Measured on this repo's corpus (187 files):

    SafeLoader   226.3 ms
    CSafeLoader   24.3 ms

libyaml ships with the PyYAML wheel on every platform we support, so the C
loader is normally there. It is not guaranteed — a source build without
libyaml headers produces a PyYAML with no `CSafeLoader` — hence the getattr
rather than a hard import. Both loaders implement the same YAML 1.1 safe
subset; the C one is stricter about a few malformed-document edge cases,
which is not a behaviour we want to preserve.
"""

from pathlib import Path
from typing import Any

import yaml

# Resolved once at import. `yaml.CSafeLoader` exists only when PyYAML was
# built against libyaml.
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

#: True when the fast C loader is in use. Read by `paramify doctor` so a
#: slow install is visible rather than merely felt.
USING_LIBYAML = _LOADER is not yaml.SafeLoader


def load(text: str) -> Any:
    """Parse a YAML document from a string. Raises yaml.YAMLError on malformed input."""
    return yaml.load(text, Loader=_LOADER)


def load_path(path: Path) -> Any:
    """Read and parse a YAML file. Propagates OSError and yaml.YAMLError."""
    return yaml.load(Path(path).read_text(), Loader=_LOADER)
