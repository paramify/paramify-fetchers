"""Every category's `requires:` block must cover what its fetchers actually need.

`paramify doctor` is only as trustworthy as these declarations. It reports a
category ready when the binaries and distributions listed in
fetchers/_categories/<name>.yaml are present, so anything a fetcher imports or
shells out to that is NOT declared produces the exact failure doctor exists to
prevent: a green preflight, then a run that dies on ImportError or "command not
found". Nothing else enforces the declarations, which is what these tests are
for.

Deliberately static — no imports of the SDKs themselves. CI installs only the
core dependencies (`pip install -e ".[dev]"`), not requirements.txt, so a test
that resolved modules through the installed environment would pass vacuously
there. These read the source tree and the declarations instead.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPO_ROOT = Path(__file__).resolve().parent.parent
CATEGORY_DIR = REPO_ROOT / "fetchers" / "_categories"

# Import roots whose distribution name is not derivable from the module name.
# Kept small on purpose: everything else goes through the prefix rule below,
# which covers the azure-* and google-cloud-* families without enumeration.
_DIST_ALIASES = {
    "dotenv": "python-dotenv",
    "yaml": "pyyaml",
    "googleapiclient": "google-api-python-client",
    "msgraph": "msgraph-sdk",
    "msgraph_core": "msgraph-sdk",
    "kiota_abstractions": "msgraph-sdk",
    "kiota_authentication_azure": "msgraph-sdk",
}

# Binaries a fetcher could plausibly shell out to. A closed vocabulary, because
# the alternative — treating every bare word in a command position as a binary —
# flags shell builtins, functions and variables.
_KNOWN_TOOLS = (
    "aws", "az", "gcloud", "gsutil", "kubectl", "helm", "jq", "yq", "curl",
    "wget", "git", "gh", "checkov", "terraform", "openssl", "docker", "psql",
    "dig", "nslookup",
)
# A tool only counts when it appears where a command goes: start of line, or
# after a pipe, semicolon, &&/||, or the opening of a substitution. Otherwise
# `--framework terraform` reads as a dependency on Terraform.
_COMMAND_POSITION = re.compile(
    r"(?:^|[|;&]|\$\(|`|\bthen\b|\bdo\b|\belse\b|\bif\b|\bwhile\b)\s*"
    r"(?:sudo\s+)?(" + "|".join(_KNOWN_TOOLS) + r")\b"
)


def _core_dependencies() -> set[str]:
    """The distributions installed with the framework itself.

    A fetcher importing one of these needs no category declaration: installing
    the package installs them, so doctor checking for them would be theatre.
    """
    text = (REPO_ROOT / "pyproject.toml").read_text()
    try:
        import tomllib
    except ModuleNotFoundError:
        # 3.11+ only, and the framework supports 3.10 — where there is no stdlib
        # TOML parser and no reason to take a dependency on one for a single
        # array. The fallback reads that array directly.
        return _dependencies_without_toml(text)
    deps = tomllib.loads(text)["project"]["dependencies"]
    return {canonicalize_name(Requirement(d).name) for d in deps}


def _dependencies_without_toml(text: str) -> set:
    """Pull [project] dependencies out of pyproject.toml without a TOML parser."""
    match = re.search(r"^dependencies = \[(.*?)\]", text, re.DOTALL | re.MULTILINE)
    assert match, "could not find [project] dependencies in pyproject.toml"
    names = re.findall(r"""["']([^"']+)["']""", match.group(1))
    assert names, "found no dependencies to parse in pyproject.toml"
    return {canonicalize_name(Requirement(n).name) for n in names}


def _categories() -> list[str]:
    return sorted(
        p.stem for p in CATEGORY_DIR.glob("*.yaml")
        if (REPO_ROOT / "fetchers" / p.stem).is_dir()
    )


def _declared(category: str) -> dict:
    data = yaml.safe_load((CATEGORY_DIR / f"{category}.yaml").read_text()) or {}
    return data.get("requires") or {}


def _local_modules() -> set[str]:
    """Module names that resolve to a sibling file in the fetcher tree.

    The _shared helpers (azure_common, gcp_common, okta_iam_core, …) are imported
    by plain name because the runner executes a fetcher from its own directory.
    """
    return {p.stem for p in (REPO_ROOT / "fetchers").rglob("*.py")}


def _import_roots(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError):  # a fetcher that will not parse is another test's problem
        return set()
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _covered(root: str, dists: set[str]) -> bool:
    """Is this import root plausibly provided by one of these distributions?

    Exact match after canonicalising, or a family prefix — `azure` is covered by
    azure-identity, `google` by google-cloud-storage. Prefix matching is what
    keeps this from becoming a hand-maintained module->distribution table.
    """
    candidate = canonicalize_name(_DIST_ALIASES.get(root, root))
    return candidate in dists or any(d.startswith(f"{candidate}-") for d in dists)


def _strip_comments(text: str) -> str:
    return "\n".join(re.sub(r"(?:^|\s)#.*$", "", line) for line in text.splitlines())


def test_the_toml_free_dependency_parse_agrees_with_tomllib():
    """The fallback is the path CI's oldest interpreter takes, so hold it to the
    real parser's answer wherever both are available."""
    pytest.importorskip("tomllib")
    assert _dependencies_without_toml((REPO_ROOT / "pyproject.toml").read_text()) == _core_dependencies()


@pytest.mark.parametrize("category", _categories())
def test_python_imports_are_declared_or_core(category):
    """Every third-party import in a category's fetchers is declared or is core."""
    allowed = {canonicalize_name(d) for d in (_declared(category).get("python_packages") or [])}
    allowed |= _core_dependencies()
    local = _local_modules()

    undeclared: dict[str, set[str]] = {}
    for py in (REPO_ROOT / "fetchers" / category).rglob("*.py"):
        # A fetcher's own tests/ run in the developer's environment, not on a
        # customer's runner, so their imports (pytest) are not runtime requirements.
        if "tests" in py.relative_to(REPO_ROOT / "fetchers" / category).parts:
            continue
        for root in _import_roots(py):
            if root in sys.stdlib_module_names or root in local or root == "__future__":
                continue
            if not _covered(root, allowed):
                undeclared.setdefault(root, set()).add(str(py.relative_to(REPO_ROOT)))

    assert not undeclared, (
        f"{category} fetchers import packages its requires: block does not declare — "
        f"doctor would call the category ready and the run would fail on ImportError:\n"
        + "\n".join(f"  {mod}  ({', '.join(sorted(files))})" for mod, files in sorted(undeclared.items()))
    )


@pytest.mark.parametrize("category", _categories())
def test_shelled_out_binaries_are_declared(category):
    """Every known binary a bash fetcher invokes appears in requires.tools."""
    declared = set(_declared(category).get("tools") or [])

    invoked: dict[str, set[str]] = {}
    for sh in (REPO_ROOT / "fetchers" / category).rglob("*.sh"):
        body = _strip_comments(sh.read_text())
        for tool in _COMMAND_POSITION.findall(body):
            if tool not in declared:
                invoked.setdefault(tool, set()).add(str(sh.relative_to(REPO_ROOT)))

    assert not invoked, (
        f"{category} fetchers invoke binaries its requires: block does not declare — "
        f"doctor would report no missing CLIs and the run would fail on 'command not found':\n"
        + "\n".join(f"  {tool}  ({', '.join(sorted(files))})" for tool, files in sorted(invoked.items()))
    )


@pytest.mark.parametrize("category", _categories())
def test_declared_packages_are_installable_from_requirements(category):
    """A declared package must be in requirements.txt, which is what doctor tells you to run.

    Without this, doctor can demand a distribution that `pip install -r
    requirements.txt` does not install — an instruction that cannot fix the
    problem it reports. requirements.txt also stays the only source of version
    pins, so an undeclared package silently loses its pin check too.
    """
    declared = {canonicalize_name(d) for d in (_declared(category).get("python_packages") or [])}
    if not declared:
        pytest.skip(f"{category} declares no python packages")

    pinned: set[str] = set()
    for line in (REPO_ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        try:
            pinned.add(canonicalize_name(Requirement(line).name))
        except Exception:
            continue

    missing = sorted(declared - pinned)
    assert not missing, (
        f"{category} declares packages absent from requirements.txt, so doctor's "
        f"'pip install -r requirements.txt' cannot fix what it reports: {missing}"
    )
