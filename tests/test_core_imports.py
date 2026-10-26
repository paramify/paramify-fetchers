"""Everything `framework/` imports must be something we actually depend on.

`framework/cli_style.py` shipped with `import click` and passed locally, because a
`[all]` install had pulled click in as some other package's transitive dependency.
It is not one of ours: typer >= 0.26 vendors click as `typer._click` and does not
require the standalone distribution, so CI — which installs exactly what pyproject
declares — died on ModuleNotFoundError at the entry point. A green local suite is
not evidence here, and nothing else in the tree checks it.

So: resolve every third-party module the framework imports to its distribution, and
require that distribution to be inside the dependency closure of what pyproject
declares. Transitively-guaranteed packages (rich, which typer requires) pass because
they are genuinely in the closure; incidentally-present ones (click) do not.

Static over the source tree, like tests/test_category_requires.py: importing the
modules to see what resolves would pass vacuously in the very environment this
exists to police.
"""

from __future__ import annotations

import ast
import sys
from importlib import metadata
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMEWORK = REPO_ROOT / "framework"

# Import root -> distribution, where the two names differ.
_DIST_ALIASES = {
    "dotenv": "python-dotenv",
    "yaml": "pyyaml",
}

# Not third party: the package under test, and anything vendored inside it.
_FIRST_PARTY = {"framework"}


def _declared(extra: str | None = None) -> list[str]:
    """Distributions pyproject declares for the core install, or for one extra.

    Bucketed rather than pooled, because which bucket a package sits in decides
    whether an import of it is safe. `pip install -e .` — what the smoke job runs
    before importing framework.cli — installs the core bucket and nothing else, so
    the core modules may only reach core. The azure / gcp / checkov extras are
    fetcher *runtime* dependencies; the framework itself must never need them, and
    pooling them here is what let click through: checkov requires it.
    """
    dist = metadata.distribution("paramify-fetchers")
    names = []
    for raw in dist.requires or []:
        r = Requirement(raw)
        if extra is None:
            in_bucket = r.marker is None or r.marker.evaluate({"extra": ""})
        else:
            in_bucket = r.marker is not None and r.marker.evaluate({"extra": extra})
        if in_bucket:
            names.append(canonicalize_name(r.name))
    return names


def _closure(names: list[str]) -> set[str]:
    """Every distribution reachable from `names` by following requires metadata."""
    seen: set[str] = set()
    queue = list(names)
    while queue:
        name = canonicalize_name(queue.pop())
        if name in seen:
            continue
        seen.add(name)
        try:
            reqs = metadata.distribution(name).requires or []
        except metadata.PackageNotFoundError:
            # An extra we did not install (azure, gcp). Its absence is not the
            # thing under test, and its own requirements cannot be read.
            continue
        for raw in reqs:
            r = Requirement(raw)
            # Skip requirements gated on an extra we are not asking for: they are
            # not guaranteed present, which is exactly the property being checked.
            if r.marker is not None and not r.marker.evaluate({"extra": ""}):
                continue
            queue.append(r.name)
    return seen


def _is_tui(rel: Path) -> bool:
    return rel.parts[:2] == ("framework", "tui")


def _imported_roots() -> dict[str, set[Path]]:
    """Top-level module name -> the framework files importing it."""
    roots: dict[str, set[Path]] = {}
    for py in sorted(FRAMEWORK.rglob("*.py")):
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import — first party by definition.
                if node.level or not node.module:
                    continue
                mods = [node.module]
            else:
                continue
            for m in mods:
                roots.setdefault(m.split(".")[0], set()).add(py.relative_to(REPO_ROOT))
    return roots


def test_framework_imports_only_declared_distributions() -> None:
    core = _closure(_declared())
    # framework/tui is reachable only from `paramify tui`, which the install hint and
    # CI both gate behind the tui extra, so it may additionally reach that closure.
    with_tui = core | _closure(_declared("tui"))
    offenders: dict[str, set[Path]] = {}

    for root, files in _imported_roots().items():
        if root in _FIRST_PARTY or root in sys.stdlib_module_names:
            continue
        dist = canonicalize_name(_DIST_ALIASES.get(root, root))
        bad = {f for f in files if dist not in (with_tui if _is_tui(f) else core)}
        if bad:
            offenders[root] = bad

    assert not offenders, (
        "framework/ imports modules outside the declared dependency closure — they "
        "are present in this environment by accident and will be missing where only "
        "pyproject's dependencies are installed:\n"
        + "\n".join(
            f"  {mod}: " + ", ".join(str(f) for f in sorted(files))
            for mod, files in sorted(offenders.items())
        )
    )


def test_the_check_can_fail() -> None:
    """The closure must not be so permissive that nothing could ever fail it.

    click is the specific case that got through: importable in a `[all]` environment,
    required by nothing the core install declares. If this starts passing, either click
    became a real dependency (declare it explicitly then) or the closure walk broke.
    """
    core = _closure(_declared())
    assert canonicalize_name("click") not in core
    assert canonicalize_name("typer") in core             # declared
    assert canonicalize_name("rich") in core              # transitive via typer
    # textual is the tui extra's, and must not be reachable from core.
    assert canonicalize_name("textual") not in core
    assert canonicalize_name("textual") in _closure(_declared("tui"))


def test_stdlib_names_are_available() -> None:
    """sys.stdlib_module_names is the whole basis for skipping stdlib imports."""
    assert "json" in sys.stdlib_module_names
