"""Installed-layout tests (phase 2 of docs/distribution_design.md §12).

Build the wheel, install it into an isolated target dir, and drive the CLI
from an empty cwd with no checkout on disk — the "green in dev, broken
installed" gap that every clone-based test misses. The installed copy is put
first on PYTHONPATH so it, not the editable dev install, is what runs; the
run-time deps (typer, yaml, …) still come from the test venv.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def installed_site(tmp_path_factory) -> Path:
    """Build the wheel and install it (no deps) into a bare target dir."""
    wheel_dir = tmp_path_factory.mktemp("wheel")
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
         "--quiet", "-w", str(wheel_dir), str(REPO_ROOT)],
        check=True, capture_output=True, text=True,
    )
    [wheel] = wheel_dir.glob("*.whl")
    site = tmp_path_factory.mktemp("site")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--quiet",
         "--target", str(site), str(wheel)],
        check=True, capture_output=True, text=True,
    )
    return site


def paramify(site: Path, cwd: Path, *args: str, env: dict | None = None):
    """Run the installed CLI: `python -c` shim so no console script is needed."""
    e = {k: v for k, v in os.environ.items()
         if k not in ("PARAMIFY_HOME", "PARAMIFY_FETCHERS_PATH", "PYTHONPATH")}
    e["PYTHONPATH"] = str(site)
    if env:
        e.update(env)
    code = "import sys; from framework.cli import app; sys.argv = ['paramify'] + sys.argv[1:]; app()"
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=cwd, env=e, capture_output=True, text=True,
    )


def test_installed_copy_is_the_one_running(installed_site, tmp_path):
    out = subprocess.run(
        [sys.executable, "-c", "import framework; print(framework.__file__)"],
        cwd=tmp_path, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(installed_site)},
    )
    assert str(installed_site) in out.stdout


def test_catalog_from_bundle_no_checkout(installed_site, tmp_path):
    res = paramify(installed_site, tmp_path, "catalog", "--json")
    assert res.returncode == 0, res.stderr
    cat = json.loads(res.stdout)
    assert cat["fetcher_count"] == 109
    assert cat["roots"] == [str(installed_site / "framework" / "_bundled" / "fetchers")]
    assert cat["shadows"] == []
    categories = {c["name"] for c in cat["categories"]}
    assert {"aws", "okta", "demo", "checkov"} <= categories


def test_run_bundled_demo_fetcher_no_checkout(installed_site, tmp_path):
    (tmp_path / "manifest.yaml").write_text(
        "run:\n  output_dir: ./evidence\n  fetchers:\n    - use: demo_hello\n"
    )
    res = paramify(installed_site, tmp_path, "run", "manifest.yaml")
    assert res.returncode == 0, res.stderr

    [run_dir] = (tmp_path / "evidence").glob("run-*")
    evidence = json.loads((run_dir / "demo_hello.json").read_text())
    assert evidence["metadata"]["fetcher_name"] == "demo_hello"
    assert evidence["metadata"]["status"] == "success"
    assert evidence["payload"]


def test_user_dir_shadows_bundled_builtin(installed_site, tmp_path):
    """The override mechanism, installed: a user copy of a built-in wins over
    the bundle (no checkout → user dir is the highest content root)."""
    home = tmp_path / "home"
    src = installed_site / "framework" / "_bundled" / "fetchers" / "demo" / "hello"
    dst = home / "fetchers" / "demo" / "hello"
    dst.mkdir(parents=True)
    for f in src.iterdir():
        if f.is_file():  # skip __pycache__ from pip's install-time compile
            (dst / f.name).write_bytes(f.read_bytes())

    res = paramify(installed_site, tmp_path, "catalog", "--json",
                   env={"PARAMIFY_HOME": str(home)})
    assert res.returncode == 0, res.stderr
    cat = json.loads(res.stdout)
    assert cat["fetcher_count"] == 109  # shadowed, not duplicated
    [shadow] = cat["shadows"]
    assert shadow["name"] == "demo_hello"
    assert str(home) in shadow["winner"]
    assert "_bundled" in shadow["shadowed"]
