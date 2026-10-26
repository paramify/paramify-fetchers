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
        row("FR0000000011", "FedRAMP In Process", "2026-08-01"),
        row("FR0000000011", "FedRAMP Certified", "2026-10-20"),
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
    ("FR0000000004", mp.DELISTED),        # dropped from data.json, changelog says delisted
    ("FR0000000011", mp.CERTIFIED),       # certified in the changelog, not in data.json yet
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
    ("FR0000000003", ("B", "derived")),   # LI-SaaS, changelog class Unknown: B, as FedRAMP classes LI-SaaS
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


# -- review fixes ------------------------------------------------------------

def test_class_keeps_a_trailing_qualifier():
    assert mp.normalize_class("Class B (Low)") == "B"
    assert mp.normalize_class("C") == "C"
    assert mp.normalize_class("Unknown") is None


def test_feed_age_is_never_negative(market):
    market.now = datetime(2026, 10, 12, 1, 55, tzinfo=timezone.utc)  # 5 minutes before the older stamp
    assert market.feed()["feed_age_hours"] == 0


@pytest.mark.parametrize("pid", ["FR1", "MSO365MTA", "AGENCYHUDSAAS"])
def test_no_reissue_for_a_non_standard_id(market, pid):
    for lookalike in ("FR1000000001", "MSO365MT", "AGENCYHUD"):  # certified listings sharing a prefix
        market.products[lookalike] = mp_product(lookalike, "Lookalike")
    assert market.replacements(pid) == []


def test_reissue_must_be_base_plus_letters(market):
    market.products["FR00000000041"] = mp_product("FR00000000041", "Lookalike")  # 11 digits: not a re-issue
    assert market.replacements("FR0000000004") == ["FR0000000004A"]


def test_id_in_name(market):
    market.products["FR260215856"] = mp_product("FR260215856", "Nine Digit Cloud")
    market.products["MSO365MTA"] = mp_product("MSO365MTA", "Odd Id Cloud")
    assert market.id_in_name("Paramify Cloud (FR2428769635XL)") == "FR2428769635XL"
    assert market.id_in_name("Nine Digit Cloud (FR260215856)") == "FR260215856"
    assert market.id_in_name("Office (MSO365MTA)") == "MSO365MTA"
    assert market.id_in_name("Good Cloud") is None


def test_impact_hint_prefers_the_most_specific_level(market):
    market.products["FR0000000010"] = mp_product("FR0000000010", "Dual Cloud", impact="Moderate")
    market.products["FR0000000010XL"] = mp_product("FR0000000010XL", "Dual Cloud", impact="20x Moderate")
    assert market.match_name("Dual Cloud - 20x Moderate")[:2] == ("FR0000000010XL", "name_impact_level")
    assert market.match_name("Dual Cloud - Moderate")[:2] == ("FR0000000010", "name_impact_level")


def test_per_vendor_file_names_do_not_collide(market, tmp_path):
    records = [market.record("Okta (Gov)", "FR0000000001"), market.record("Okta Gov", "FR0000000002")]
    paths = mp.write_outputs(tmp_path, "stem", records, market, "per_vendor")
    assert len({p.name for p in paths}) == 2
    assert sorted(p.name for p in tmp_path.iterdir()) == ["stem_okta_gov.json", "stem_okta_gov_fr0000000002.json"]


def test_output_mode_rejects_unknown(monkeypatch):
    monkeypatch.setenv("FEDRAMP_OUTPUT_MODE", "per_project")
    with pytest.raises(mp.CollectionError) as err:
        mp.output_mode_from_env()
    assert err.value.code == "bad_config"


def mp_product(pid, cso, impact="Moderate"):
    return product(pid, cso, impact=impact)


# -- workspace fetcher -------------------------------------------------------

_ws_spec = importlib.util.spec_from_file_location(
    "fedramp_workspace_fetcher",
    ROOT / "fetchers" / "fedramp_marketplace" / "workspace_vendor_certification_status" / "fetcher.py",
)
ws = importlib.util.module_from_spec(_ws_spec)
_ws_spec.loader.exec_module(ws)


def element(name, eid, subtype="COM_FEDRAMP_SYSTEM"):
    return {"id": eid, "name": name, "subtype": subtype}


def test_build_records(market):
    elements = [
        element("Good Cloud", "e1"),
        element("Good Cloud", "e2"),                       # same name: one vendor
        element("Pinned (FR0000000002)", "e3"),            # ID in the name
        element("Ready Cloud", "e4"),                      # override beats the name match
        element("Nobody Cloud", "e5"),                     # matches nothing
        element("Some SaaS", "e6", subtype="COM_SAAS"),    # subtype not selected
    ]
    records = ws.build_records(market, elements, ["COM_FEDRAMP_SYSTEM"], {"ready cloud": "FR0000000001"})
    by_name = {r["vendor_name"]: r for r in records}
    assert sorted(by_name) == ["Good Cloud", "Nobody Cloud", "Pinned (FR0000000002)", "Ready Cloud"]
    assert by_name["Good Cloud"]["paramify_element_ids"] == ["e1", "e2"]
    assert by_name["Good Cloud"]["match_method"] == "name"
    assert (by_name["Pinned (FR0000000002)"]["match_method"], by_name["Pinned (FR0000000002)"]["package_id"]) == ("id_in_name", "FR0000000002")
    assert (by_name["Ready Cloud"]["match_method"], by_name["Ready Cloud"]["package_id"]) == ("config_override", "FR0000000001")
    unmatched = by_name["Nobody Cloud"]
    assert (unmatched["package_id"], unmatched["certification_state"], unmatched["package_id_resolves"]) == (None, mp.NOT_LISTED, False)
    s = mp.summarize(records)
    assert (s["vendors_total"], s["vendors_unresolved"], s["vendors_delisted_or_not_listed"]) == (4, 1, 1)


class FakeResponse:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.text = body if isinstance(body, str) else ""

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not json")
        return self._body


@pytest.mark.parametrize("status,body,code", [
    (401, {}, "auth_failed"),
    (403, {}, "not_authorized"),
    (500, "boom", "target_unreachable"),
    (200, "<html>", "target_unreachable"),
    (200, [], "target_unreachable"),
    (200, {"elements": [element("A", "1")], "nextCursor": "abc"}, "partial_failure"),
    (200, {"elements": [element("A", "1")], "total": 40}, "partial_failure"),
])
def test_fetch_elements_failures(monkeypatch, status, body, code):
    monkeypatch.setattr(ws.requests, "get", lambda *a, **k: FakeResponse(status, body))
    with pytest.raises(ws.CollectionError) as err:
        ws.fetch_elements("https://example.test/api/v0", "t", 5)
    assert err.value.code == code


def test_fetch_elements_single_page(monkeypatch):
    body = {"elements": [element("A", "1"), element("B", "2")], "total": 2, "hasMore": False}
    monkeypatch.setattr(ws.requests, "get", lambda *a, **k: FakeResponse(200, body))
    assert len(ws.fetch_elements("https://example.test/api/v0", "t", 5)) == 2


def test_absent_from_data_json_is_not_delisted(market):
    record = market.record("New", "FR0000000011")
    assert (record["certification_state"], record["status_sources_disagree"]) == (mp.CERTIFIED, True)
    assert (record["package_id_resolves"], record["suggested_package_ids"]) == (True, [])


# -- final-audit fixes ---------------------------------------------------------

def add_company(market):
    """Two products from one company, as data.json has them: `name` is the company."""
    market.products["FR0000000020"] = product("FR0000000020", "Acme Mail", impact="High", csp="Acme Corp")
    market.products["FR0000000021"] = product("FR0000000021", "Acme Docs", status="FedRAMP Ready", csp="Acme Corp")


@pytest.mark.parametrize("name", ["Acme Corp (Gmail)", "Acme Corp - Unlisted Product", "Acme Corp", "acme corp: storage"])
def test_company_name_alone_is_not_a_match(market, name):
    add_company(market)
    assert market.match_name(name) == (None, "company_only", ["FR0000000020", "FR0000000021"])


def test_product_names_still_match(market):
    add_company(market)
    assert market.match_name("Acme Mail")[:2] == ("FR0000000020", "name")
    assert market.match_name("Acme Corp Acme Mail")[:2] == ("FR0000000020", "name")
    assert market.match_name("Acme Corp - Acme Docs")[:2] == ("FR0000000021", "name")
    assert market.match_name("Acme Mail (High)")[:2] == ("FR0000000020", "name")


@pytest.mark.parametrize("raw,stripped", [
    ("Cloud-Native Platform", "Cloud-Native Platform"),   # unspaced hyphen is part of the name
    ("A - B - C", "A - B"),                               # last segment only
    ("Acme Mail – High", "Acme Mail"),                    # en dash
    ("Acme Mail: Moderate", "Acme Mail"),
    ("Acme Mail (FR0000000020)", "Acme Mail"),
    ("Plain Name", "Plain Name"),
])
def test_strip_qualifier(raw, stripped):
    assert mp.strip_qualifier(raw) == stripped


def test_unrecognised_latest_status_is_unknown(market):
    market.changelog["FR0000000001"].append(row("FR0000000001", "FedRAMP Certified (Revoked)", "2026-10-25"))
    record = market.record("Good", "FR0000000001")
    assert (record["certification_state"], record["package_id_resolves"]) == (mp.UNKNOWN, True)
    assert record["latest_status_change"]["to_status"] == "FedRAMP Certified (Revoked)"
    s = mp.summarize([record])
    assert (s["vendors_not_certified"], s["vendors_not_certified_or_in_process"], s["vendors_status_unknown"]) == (1, 1, 1)


def test_build_records_reports_company_only_as_unmatched(market):
    add_company(market)
    records = ws.build_records(market, [element("Acme Corp (Gmail)", "e1")], ["COM_FEDRAMP_SYSTEM"], {})
    (r,) = records
    assert (r["package_id"], r["match_method"], r["certification_state"], r["package_id_resolves"]) == (
        None, "company_only", mp.NOT_LISTED, False)
    assert r["suggested_package_ids"] == ["FR0000000020", "FR0000000021"]
