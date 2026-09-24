"""wiz_stig_compliance_report: read-only STIG checklist CSV from Wiz GraphQL.

Mocks only the HTTP boundary (requests.post in the shared Wiz client), so the
real client, its read-only guard, paging and failure tracking all run.
"""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "wiz" / "stig_compliance_report" / "fetcher.py"
AUTH = "https://auth.app.wiz.us/oauth/token"
API = "https://api.us2.app.wiz.us/graphql"
FW = {"id": "wf-id-305", "name": "Okta IDaaS STIG (Ver 1, Rel 2)", "enabled": True}
OTHER_FW = {"id": "wf-id-1", "name": "Wiz for Risk Assessment", "enabled": True}


def load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("wiz_stig_under_test", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fetcher = load()
wiz_client = sys.modules["wiz_client"]


class Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.headers = {}
        self.text = json.dumps(body)

    def json(self):
        return self._body


def sub(control, title, fw_id):
    return {"externalId": control, "title": title, "category": {"framework": {"id": fw_id}}}


def cloud(i, result, controls, fw_id="wf-id-305"):
    return {
        "id": f"cf-{i}", "result": result, "severity": "MEDIUM", "status": "OPEN" if result == "FAIL" else "RESOLVED",
        "firstSeenAt": "2026-09-01T00:00:00Z", "analyzedAt": "2026-09-23T00:00:00Z",
        "rule": {"id": f"r{i}", "shortId": f"OKTA-{i:03}", "name": f"Okta rule {i}",
                 "remediationInstructions": f"Fix rule {i} in the Okta admin console.",
                 "securitySubCategories": [sub(c, t, fw_id) for c, t in controls]},
        "resource": {"id": "okta-1", "name": "paramify.okta.com", "type": "TENANT", "nativeType": "oktaOrg",
                     "region": None, "cloudPlatform": "Okta",
                     "subscription": {"name": "Okta", "externalId": "00o1"}},
    }


class FakeWiz:
    def __init__(self):
        self.frameworks = [FW, OTHER_FW]
        self.cloud_pages: List[List[Dict[str, Any]]] = [[]]
        self.host: List[Dict[str, Any]] = []
        self.host_rules: Dict[str, List[Dict[str, Any]]] = {}
        self.errors: Dict[str, str] = {}
        self.fail_subcats = False
        self.reject_remediation = False
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, url, data=None, json=None, headers=None, timeout=None, allow_redirects=True):
        if url == AUTH:
            return Resp(200, {"access_token": "tok", "expires_in": 900})
        assert url == API
        q = json["query"]
        assert "mutation" not in q.split("{", 1)[0]
        self.calls.append(json)
        v = json.get("variables") or {}
        root = next(r for r in ("securityFrameworks", "configurationFindings", "hostConfigurationRuleAssessments",
                                "hostConfigurationRules") if r + "(" in q)
        if root in self.errors:
            return Resp(200, {"data": None, "errors": [{"message": self.errors[root]}]})
        if self.reject_remediation and "remediationInstructions" in q:
            return Resp(200, {"data": None, "errors": [{"message":
                    'Cannot query field "remediationInstructions" on type "CloudConfigurationRule".'}]})
        if root == "securityFrameworks":
            return page(root, [self.frameworks], v)
        if root == "configurationFindings":
            assert v["filterBy"] == {"securityFramework": "wf-id-305", "result": ["PASS", "FAIL"]}
            if self.fail_subcats and "securitySubCategories" in q:
                return Resp(200, {"data": None, "errors": [{"message": "An internal error has occurred"}]})
            return page(root, self.cloud_pages, v)
        if root == "hostConfigurationRuleAssessments":
            want = v["filterBy"]["result"]
            assert isinstance(want, str)
            return page(root, [[n for n in self.host if n["result"] == want]], v)
        ids = v["filterBy"]["id"]
        nodes = [{"id": i, "securitySubCategories": self.host_rules[i], "remediationInstructions": f"Fix {i}"}
                 for i in ids if i in self.host_rules]
        if "remediationInstructions" not in q:
            for n in nodes:
                n.pop("remediationInstructions")
        return page(root, [nodes], v)


def page(root, pages, v):
    idx = int(v.get("after") or 0)
    has_next = idx + 1 < len(pages)
    return Resp(200, {"data": {root: {"nodes": pages[idx],
                                      "pageInfo": {"hasNextPage": has_next,
                                                   "endCursor": str(idx + 1) if has_next else None}}}})


@pytest.fixture
def fake(monkeypatch, tmp_path):
    f = FakeWiz()
    monkeypatch.setattr(wiz_client.requests, "post", f)
    monkeypatch.setattr(wiz_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(wiz_client, "load_dotenv", lambda *a, **k: False)
    for k, val in {"WIZ_CLIENT_ID": "id", "WIZ_CLIENT_SECRET": "s3cret", "WIZ_API_ENDPOINT_URL": API,
                   "WIZ_AUTH_URL": AUTH, "WIZ_MIN_REQUEST_INTERVAL": "0", "EVIDENCE_DIR": str(tmp_path),
                   "FETCHER_STATUS_FILE": str(tmp_path / "status.json"), "WIZ_STIG_FRAMEWORK": "wf-id-305"}.items():
        monkeypatch.setenv(k, val)
    return f


def out(tmp_path):
    return tmp_path / "wiz_stig_compliance_report_wf-id-305.csv"


def rows(tmp_path):
    return list(csv.DictReader(io.StringIO(out(tmp_path).read_text())))


def status(tmp_path):
    return json.loads((tmp_path / "status.json").read_text())


def test_one_row_per_control_with_fixed_columns(fake, tmp_path):
    fake.cloud_pages = [[cloud(1, "PASS", [("V-273186", "SRG-APP-000003")])],
                        [cloud(2, "FAIL", [("V-273188", "SRG-APP-000025"), ("V-273189", "SRG-APP-000065")])]]
    assert fetcher.main() == 0
    got = rows(tmp_path)
    assert list(got[0].keys()) == fetcher.COLUMNS
    assert [(r["Control ID"], r["Result"]) for r in got] == [
        ("V-273186", "PASS"), ("V-273188", "FAIL"), ("V-273189", "FAIL")]
    assert got[1]["Record ID"] == "cf-2:V-273188" and got[1]["Framework"] == FW["name"]
    assert got[1]["Rule Type"] == "Cloud Configuration" and got[1]["Resource Type"] == "oktaOrg"


def test_controls_from_other_frameworks_are_not_rows(fake, tmp_path):
    f = cloud(1, "FAIL", [("V-1", "SRG-1")])
    f["rule"]["securitySubCategories"].append(sub("AC-2", "Account Management", "wf-id-1"))
    fake.cloud_pages = [[f]]
    assert fetcher.main() == 0
    assert [r["Control ID"] for r in rows(tmp_path)] == ["V-1"]


def test_output_is_deterministic(fake, tmp_path):
    fake.cloud_pages = [[cloud(2, "FAIL", [("V-2", "b")]), cloud(1, "PASS", [("V-1", "a")])]]
    fetcher.main()
    first = out(tmp_path).read_bytes()
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")]), cloud(2, "FAIL", [("V-2", "b")])]]
    fetcher.main()
    assert out(tmp_path).read_bytes() == first


def test_host_rows_kept_only_when_rule_maps_to_framework(fake, tmp_path):
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")])]]
    fake.host = [
        {"id": "h1", "result": "FAIL", "severity": "HIGH", "status": "OPEN", "firstSeen": None, "analyzedAt": None,
         "rule": {"id": "hr1", "name": "SSH root login disabled", "shortName": "RHEL8.DISA.STIG/1", "externalId": "RHEL-08-010550"},
         "resource": {"id": "i-1", "name": "node-a", "type": "VIRTUAL_MACHINE"}},
        {"id": "h2", "result": "PASS", "severity": "LOW", "status": "RESOLVED", "firstSeen": None, "analyzedAt": None,
         "rule": {"id": "hr2", "name": "Kubelet anon auth off", "shortName": "K8S/1", "externalId": "hcr-kub-id-1"},
         "resource": {"id": "i-2", "name": "node-b", "type": "VIRTUAL_MACHINE"}},
    ]
    fake.host_rules = {"hr1": [sub("V-230296", "SRG-OS-000109", "wf-id-305")], "hr2": [sub("x", "y", "wf-id-1")]}
    assert fetcher.main() == 0
    host = [r for r in rows(tmp_path) if r["Rule Type"] == "Host Configuration"]
    assert [(r["Control ID"], r["Resource Name"], r["Rule ID"]) for r in host] == [("V-230296", "node-a", "RHEL-08-010550")]


def test_host_can_be_skipped(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_STIG_INCLUDE_HOST", "false")
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")])]]
    assert fetcher.main() == 0
    assert not any("hostConfiguration" in c["query"] for c in fake.calls)


def test_framework_by_exact_name(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_STIG_FRAMEWORK", "okta idaas stig (ver 1, rel 2)")
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")])]]
    assert fetcher.main() == 0
    assert (tmp_path / "wiz_stig_compliance_report_okta_idaas_stig_ver_1_rel_2.csv").exists()


def test_unknown_framework_is_bad_config_and_lists_stigs(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_STIG_FRAMEWORK", "Okta")
    assert fetcher.main() == 1
    s = status(tmp_path)
    assert s["code"] == "bad_config" and "Okta IDaaS STIG" in s["error"]


def test_disabled_framework_is_refused(fake, tmp_path):
    fake.frameworks = [{**FW, "enabled": False}]
    assert fetcher.main() == 1
    assert "not enabled" in status(tmp_path)["error"]


def test_empty_report_is_never_written(fake, tmp_path):
    assert fetcher.main() == 1
    assert not out(tmp_path).exists()
    assert status(tmp_path)["code"] == "partial_failure"


def test_any_wiz_error_fails_without_writing(fake, tmp_path):
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")])]]
    fake.errors["hostConfigurationRuleAssessments"] = "You are not authorized to perform this action"
    assert fetcher.main() == 1
    assert not out(tmp_path).exists()
    assert status(tmp_path)["code"] == "not_authorized"


def test_rows_without_control_mapping_are_refused(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WIZ_PAGE_SIZE", "10")
    fake.fail_subcats = True
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")])]]
    assert fetcher.main() == 1
    assert "control" in status(tmp_path)["error"].lower()
    assert not out(tmp_path).exists()


def test_row_cap_is_a_failure(fake, tmp_path, monkeypatch):
    monkeypatch.setattr(fetcher, "WIZ_ROW_CAP", 2)
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")]), cloud(2, "PASS", [("V-2", "a")])]]
    assert fetcher.main() == 1
    assert "10,000" in status(tmp_path)["error"]


def test_missing_framework_setting(fake, tmp_path, monkeypatch):
    monkeypatch.delenv("WIZ_STIG_FRAMEWORK")
    assert fetcher.main() == 1
    assert status(tmp_path)["code"] == "bad_config"


def test_every_query_is_read_only():
    for q in [fetcher.FRAMEWORKS_QUERY, fetcher.CLOUD_QUERY, fetcher.HOST_QUERY, fetcher.HOST_RULES_QUERY,
              fetcher.CLOUD_QUERY_WITH_REMEDIATION, fetcher.HOST_RULES_QUERY_WITH_REMEDIATION,
              *fetcher.CLOUD_FALLBACKS, *fetcher.HOST_FALLBACKS]:
        wiz_client.WizClient._assert_read_only(q)  # raises on a mutation


def test_remediation_column_is_filled(fake, tmp_path):
    fake.cloud_pages = [[cloud(1, "FAIL", [("V-1", "a")])]]
    assert fetcher.main() == 0
    r = rows(tmp_path)[0]
    assert r["Remediation"] == "Fix rule 1 in the Okta admin console."
    assert fetcher.COLUMNS.index("Remediation") == fetcher.COLUMNS.index("Rule Name") + 1


def test_rejected_remediation_field_leaves_column_blank_not_failed(fake, tmp_path):
    fake.reject_remediation = True
    f = cloud(1, "FAIL", [("V-1", "a")])
    del f["rule"]["remediationInstructions"]
    fake.cloud_pages = [[f]]
    assert fetcher.main() == 0
    assert rows(tmp_path)[0]["Remediation"] == ""
    assert not (tmp_path / "status.json").exists() or "error" not in status(tmp_path)


def test_host_rows_carry_remediation(fake, tmp_path):
    fake.cloud_pages = [[cloud(1, "PASS", [("V-1", "a")])]]
    fake.host = [{"id": "h1", "result": "FAIL", "severity": "HIGH", "status": "OPEN", "firstSeen": None,
                  "analyzedAt": None, "rule": {"id": "hr1", "name": "SSH root login", "shortName": "x",
                                               "externalId": "RHEL-08-010550"},
                  "resource": {"id": "i-1", "name": "node-a", "type": "VIRTUAL_MACHINE"}}]
    fake.host_rules = {"hr1": [sub("V-230296", "SRG-OS-000109", "wf-id-305")]}
    assert fetcher.main() == 0
    host = [r for r in rows(tmp_path) if r["Rule Type"] == "Host Configuration"]
    assert host[0]["Remediation"] == "Fix hr1"
