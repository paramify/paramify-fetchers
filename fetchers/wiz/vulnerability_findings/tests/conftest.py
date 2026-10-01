import sys
from pathlib import Path

import pytest

_WIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_WIZ / "_shared"))
sys.path.insert(0, str(_WIZ.parent / "_lib"))

from fake_wiz import FakeWiz  # noqa: E402


@pytest.fixture
def fake():
    wiz = FakeWiz().start()
    yield wiz
    wiz.stop()
