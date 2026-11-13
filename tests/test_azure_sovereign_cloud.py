"""The management endpoint follows the credential's authority, not the default.

Every azure.mgmt client used to be built as `Client(credential, subscription_id)`
with no endpoint, which resolves to commercial Azure. Against a Gov Cloud
subscription ARM answers `SubscriptionNotFound` — so the failure named the
subscription and read as a bad id or a permissions problem, not as a request sent
to the wrong cloud. Every management-plane Azure fetcher was affected; the Entra
ones were not, because `entra_graph.graph_host()` already derived its host the
way `arm_endpoint()` does now.

Pure functions over an env var: no SDK, no credentials, no network.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
_SHARED = REPO_ROOT / "fetchers" / "azure" / "_shared"


def _azure_common():
    """Import the module by path — it lives in the fetcher tree, not the package."""
    sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
    spec = importlib.util.spec_from_file_location(
        "azure_common_under_test", _SHARED / "azure_common.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ac = _azure_common()


@pytest.mark.parametrize(
    "authority,expected",
    [
        (None, "https://management.azure.com"),
        ("", "https://management.azure.com"),
        ("https://login.microsoftonline.com", "https://management.azure.com"),
        ("https://login.microsoftonline.us", "https://management.usgovcloudapi.net"),
        # Trailing slash and case are how the value actually arrives from a manifest.
        ("https://LOGIN.microsoftonline.us/", "https://management.usgovcloudapi.net"),
        ("https://login.microsoftonline.de", "https://management.microsoftazure.de"),
        ("https://login.chinacloudapi.cn", "https://management.chinacloudapi.cn"),
    ],
)
def test_endpoint_follows_the_authority(monkeypatch, authority, expected):
    monkeypatch.delenv("AZURE_AUTHORITY_HOST", raising=False)
    if authority is not None:
        monkeypatch.setenv("AZURE_AUTHORITY_HOST", authority)
    assert ac.arm_endpoint() == expected


def test_unrecognized_authority_warns_and_falls_back(monkeypatch, caplog):
    """Falling back silently would collect against the wrong cloud, which for most
    calls returns an empty list rather than an error — valid-looking empty evidence."""
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.example.invalid")
    with caplog.at_level("WARNING"):
        assert ac.arm_endpoint() == "https://management.azure.com"
    assert "not a recognized sovereign authority" in caplog.text


def test_scope_and_endpoint_always_agree(monkeypatch):
    """Both keys or neither: base_url alone sends a commercially-scoped token to the
    sovereign endpoint, which rejects it — trading one failure for another."""
    monkeypatch.setenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.us")
    kwargs = ac.arm_client_kwargs()
    assert kwargs == {
        "base_url": "https://management.usgovcloudapi.net",
        "credential_scopes": ["https://management.usgovcloudapi.net/.default"],
    }


def test_every_management_client_passes_the_kwargs():
    """A new fetcher that omits them is broken in every sovereign cloud, and passes
    every test and review that only ever runs against commercial Azure."""
    offenders = []
    for fetcher in sorted((REPO_ROOT / "fetchers" / "azure").glob("*/fetcher.py")):
        body = fetcher.read_text()
        for line_no, line in enumerate(body.splitlines(), 1):
            if "credential=cred, subscription_id=subscription_id" not in line:
                continue
            # the kwargs may sit on this line or close the call on the next
            window = "\n".join(body.splitlines()[line_no - 1 : line_no + 1])
            if "arm_client_kwargs()" not in window:
                offenders.append(f"{fetcher.parent.name}:{line_no}")
    assert not offenders, (
        "management clients built without **arm_client_kwargs() — these resolve to "
        "commercial Azure and fail with SubscriptionNotFound in Gov Cloud:\n  "
        + "\n  ".join(offenders)
    )
