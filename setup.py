"""Build-time assembly of the shipped content bundle (docs/distribution_design.md §8).

The wheel carries the content built-ins run from: framework/_bundled/, copied
from fetchers/ and examples/ during build_py. Assembling inside the build
backend — not a release workflow — keeps `pip install` from a source tarball
working: every build path produces the bundle. The bundle is written straight
into build_lib, so the source tree is never touched and a dev checkout never
grows a stale _bundled/ (framework.roots treats its absence as "dev tree").
"""

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

HERE = Path(__file__).resolve().parent

# Content dirs shipped as framework/_bundled/<name>. fetchers/logos/ stays out:
# README furniture, unused at run time.
BUNDLED = ("fetchers", "examples")
_EXCLUDED_NAMES = {"__pycache__", "logos", ".DS_Store"}


def _ignore(_src, names):
    return {n for n in names if n in _EXCLUDED_NAMES or n.endswith((".pyc", ".pyo"))}


class build_py_with_bundle(build_py):
    def run(self):
        super().run()
        dest = Path(self.build_lib) / "framework" / "_bundled"
        if dest.exists():
            shutil.rmtree(dest)
        for name in BUNDLED:
            src = HERE / name
            if not src.is_dir():
                raise RuntimeError(
                    f"cannot assemble framework/_bundled: {src} missing from the source tree"
                )
            shutil.copytree(src, dest / name, ignore=_ignore)


setup(cmdclass={"build_py": build_py_with_bundle})
