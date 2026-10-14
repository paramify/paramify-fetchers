"""fedramp_marketplace: state, class and name matching over synthetic FedRAMP files."""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "fedramp_marketplace_shared", ROOT / "fetchers" / "fedramp_marketplace" / "_shared" / "marketplace.py"
)
mp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mp)


def product(pid, cso, status="FedRAMP Authorized", impact="Moderate", csp="Vendor"):
    return {"id": pid, "csp": csp, "cso": cso, "name": csp, "status": status, "impact_level": impact,
            "fedramp_msg": "N/A", "auth_type": "Agency", "fedramp_auth": "2025-01-01T00:00:00.000Z"}


def row(pid, to_status, date, cert_class="Unknown"):
    return {"product_id": pid, "to_status": to_status, "from_status": "", "cert_class": cert_class,
            "cert_type": "Rev5", "transition_date": date, "recorded_date": date, "comments": ""}


@pytest.fixture
def market():
    products = [
        product("FR0000000001", "Good Cloud", impact="High"),
        product("FR0000000002", "Ready Cloud", status="FedRAMP Ready"),
        product("FR0000000003", "Still Listed", impact="LI-SaaS"),
        product("FR0000000004A", "Reissued Cloud"),
        product("FR0000000005", "Twin Cloud", status="FedRAMP Ready", impact="High"),
        product("FR0000000005XL", "Twin Cloud", impact="20x Moderate"),
        product("FR0000000006", "Lagging Cloud", status="FedRAMP In Process"),
        product("FR0000000007", "Fixing Cloud"),
        product("FR0000000008", "Pair Cloud", impact="High"),
        product("FR0000000009", "Pair Cloud", impact="Low"),
    ]
    rows = [
        row("FR0000000001", "FedRAMP Certified", "2024-01-01", "Class D"),
        row("FR0000000003", "FedRAMP Certified", "2024-01-01"),
        row("FR0000000003", "No Status Found (Delisted)", "2026-05-01"),
        row("FR0000000004", "FedRAMP Certified", "2021-01-01", "Class C"),
        row("FR0000000004", "No Status Found (Delisted)", "2026-05-05", "Class C"),
        row("FR0000000006", "FedRAMP In Process", "2025-01-01"),
        row("FR0000000006", "FedRAMP Certified", "2026-09-01"),
        row("FR0000000007", "FedRAMP Certified (In Remediation)", "2026-07-22"),
    ]
    data = {"meta": {"last_change": "2026-10-12T02:00:00Z"}, "data": {"Products": products}}
    changelog = {"metadata": {"export_timestamp": "2026-10-12T20:00:00Z"}, "data": {"certprocessstatuschangelog": rows}}
    cso = {"data": {"frc-cso-pkg": [{"serviceIdentification": {"fedRampPackageId": "FR0000000005XL", "certificationClass": "C"}}]}}
    return mp.Marketplace(data, changelog, cso, source_urls={},
                          now=datetime(2026, 10, 13, 2, 0, tzinfo=timezone.utc))


@pytest.mark.parametrize("pid,state", [
    ("FR0000000001", mp.CERTIFIED),
    ("FR0000000002", mp.READY),
    ("FR0000000003", mp.DELISTED),        # listed, but the changelog says delisted
    ("FR0000000004", mp.DELISTED),        # dropped from data.json
    ("FR0000000006", mp.CERTIFIED),       # changelog newer than data.json
    ("FR0000000007", mp.IN_REMEDIATION),
    ("FR9999999999", mp.NOT_LISTED),
])
def test_state(market, pid, state):
    assert market.state(pid)[0] == state


def test_changelog_disagreement_is_flagged(market):
    assert market.state("FR0000000006") == (mp.CERTIFIED, True)


@pytest.mark.parametrize("pid,expected", [
    ("FR0000000005XL", ("C", "cso_pkg")),
    ("FR0000000001", ("D", "changelog")),
    ("FR0000000003", ("A", "derived")),   # LI-SaaS, changelog class Unknown
    ("FR0000000002", ("C", "derived")),
    ("FR9999999999", (None, None)),
])
def test_class_source_order(market, pid, expected):
    assert market.certification_class(pid) == expected


def test_replaced_id_is_suggested_not_substituted(market):
    record = market.record("Reissued", "FR0000000004")
    assert record["certification_state"] == mp.DELISTED
    assert record["package_id_resolves"] is False
    assert record["suggested_package_ids"] == ["FR0000000004A"]
    assert record["marketplace_url"] == "https://www.fedramp.gov/marketplace/products/FR0000000004/"


def test_name_match_prefers_certified_listing(market):
    assert market.match_name("Twin Cloud - 20x Moderate")[:2] == ("FR0000000005XL", "name_preferred_state")
    assert market.match_name("Twin Cloud")[:2] == ("FR0000000005XL", "name_preferred_state")


def test_name_match_uses_impact_level_then_gives_up(market):
    assert market.match_name("Pair Cloud - High")[:2] == ("FR0000000008", "name_impact_level")
    pid, how, candidates = market.match_name("Pair Cloud")
    assert (pid, how) == (None, "ambiguous") and candidates == ["FR0000000008", "FR0000000009"]
    assert market.match_name("Nobody")[:2] == (None, "unmatched")


def test_summary_and_feed(market):
    records = [market.record(n, p) for n, p in [("a", "FR0000000001"), ("b", "FR0000000002"),
                                                 ("c", "FR0000000004"), ("d", "FR0000000007")]]
    s = mp.summarize(records)
    assert (s["vendors_not_certified"], s["vendors_not_certified_or_in_process"]) == (3, 2)
    assert (s["vendors_delisted_or_not_listed"], s["vendors_in_remediation"], s["vendors_unresolved"]) == (1, 1, 1)
    assert market.feed()["feed_age_hours"] == 24


def test_parse_pairs():
    assert mp.parse_pairs("Okta Gov=fr2131856836, A=B=FR1", "X") == [("Okta Gov", "FR2131856836"), ("A=B", "FR1")]
    with pytest.raises(mp.CollectionError):
        mp.parse_pairs("no id here", "X")
