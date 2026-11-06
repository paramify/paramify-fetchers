"""Synthetic HTTP-boundary tests: run the real client, joins, and CSV publication."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import urlencode
from xml.sax.saxutils import escape

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
QUALYS = ROOT / "fetchers/qualys"
sys.path.insert(0, str(QUALYS / "_shared"))
import qualys_client as qc  # noqa: E402
import reports as qr  # noqa: E402

BASE = "https://qualysapi.qualys.com"
DATE = "2026-01-02T03:04:05Z"


def load_entry(name):
    spec = importlib.util.spec_from_file_location(
        f"qualys_{name}_test", QUALYS / name / "fetcher.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vm = load_entry("vmdr_vulnerability_findings")
stig = load_entry("stig_compliance_report")


def xml(root, body):
    return f"<{root}><RESPONSE><DATETIME>{DATE}</DATETIME>{body}</RESPONSE></{root}>".encode()


def warning(path, **params):
    url = escape(BASE + path + "?" + urlencode({"action": "list", **params}))
    return f"<WARNING><CODE>1980</CODE><TEXT>Truncated</TEXT><URL>{url}</URL></WARNING>"


def detection(qid="1001", port="443", status="Active"):
    return (
        f"<DETECTION><QID>{qid}</QID><PORT>{port}</PORT><PROTOCOL>tcp</PROTOCOL><SSL>1</SSL>"
        f"<TYPE>Confirmed</TYPE><STATUS>{status}</STATUS><SEVERITY>5</SEVERITY>"
        "<IS_IGNORED>0</IS_IGNORED><IS_DISABLED>0</IS_DISABLED><RESULTS>synthetic</RESULTS>"
        f"<FIRST_FOUND_DATETIME>{DATE}</FIRST_FOUND_DATETIME>"
        f"<LAST_FIXED_DATETIME>{DATE}</LAST_FIXED_DATETIME>"
        f"<LAST_FOUND_DATETIME>{DATE}</LAST_FOUND_DATETIME></DETECTION>"
    )


def host(host_id="101", detections=None):
    return (
        f"<HOST><ID>{host_id}</ID><IP>192.0.2.10</IP><DNS>host.example.test</DNS>"
        f"<DETECTION_LIST>{detection() if detections is None else detections}</DETECTION_LIST></HOST>"
    )


def kb(qid="1001", cves=("CVE-2026-10001", "CVE-2026-10002")):
    ids = "".join(f"<CVE><ID>{c}</ID></CVE>" for c in cves)
    return (
        f"<VULN><QID>{qid}</QID><TITLE>Synthetic vulnerability</TITLE>"
        f"<CVE_LIST>{ids}</CVE_LIST><DIAGNOSIS>Example diagnosis</DIAGNOSIS>"
        "<SOLUTION>Install the update</SOLUTION><CVSS_V3><BASE>9.8</BASE>"
        "<VECTOR_STRING>CVSS:3.1/AV:N</VECTOR_STRING></CVSS_V3></VULN>"
    )


def qvs(cve="CVE-2026-10001", score="99", due="1706918400000"):
    return {
        cve: {
            "base": {"id": cve, "qvs": score},
            "contributingFactors": {
                "cisaVuln": ["YES"],
                "cisaDueDate": due,
                "cisaAddedDate": "1704067200",
            },
        }
    }


def posture(
    info_id="501",
    control_id="601",
    result="Failed",
    reference="V-100001",
    wrapped=False,
):
    body = (
        f"<INFO_LIST><INFO><ID>{info_id}</ID><HOST_ID>101</HOST_ID><CONTROL_ID>{control_id}</CONTROL_ID>"
        f"<TECHNOLOGY_ID>701</TECHNOLOGY_ID><INSTANCE>os</INSTANCE><STATUS>{result}</STATUS>"
        "<REMEDIATION>Configure the setting</REMEDIATION>"
        f"<EVALUATION_DATE>{DATE}</EVALUATION_DATE>"
        "<EXCEPTION><STATUS>Approved</STATUS><END_DATETIME>2027-01-01T00:00:00Z</END_DATETIME></EXCEPTION>"
        "</INFO></INFO_LIST><GLOSSARY><HOST_LIST><HOST><ID>101</ID><IP>192.0.2.10</IP>"
        "<DNS_DATA><FQDN>host.example.test</FQDN></DNS_DATA></HOST></HOST_LIST>"
        f"<CONTROL_LIST><CONTROL><ID>{control_id}</ID><STATEMENT>Synthetic control</STATEMENT>"
        f"<REFERENCE>{reference}</REFERENCE><CRITICALITY><LABEL>HIGH</LABEL><VALUE>4</VALUE>"
        "</CRITICALITY></CONTROL></CONTROL_LIST><TECHNOLOGY_LIST><TECHNOLOGY><ID>701</ID>"
        "<NAME>Example OS</NAME></TECHNOLOGY></TECHNOLOGY_LIST></GLOSSARY>"
    )
    return f"<POLICY><ID>301</ID>{body}</POLICY>" if wrapped else body


class Response:
    def __init__(self, body=b"", status=200, headers=None, interrupted=False):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status_code = status
        self.headers = headers or {}
        self.interrupted = interrupted

    def iter_content(self, size):
        yield self.body[:10]
        if self.interrupted:
            raise requests.ConnectionError("must not log response or credential")
        yield self.body[10:]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class Session:
    def __init__(self, replies):
        self.replies = list(replies)
        self.headers = {}
        self.calls = []

    def get(self, url, **kwargs):
        assert kwargs["allow_redirects"] is False
        assert kwargs["params"]["action"] == "list"
        assert url.startswith(BASE)
        self.calls.append((url, kwargs["params"].copy()))
        if not self.replies:
            raise AssertionError("Unexpected API request")
        return self.replies.pop(0)

    def close(self):
        pass


def client(*replies, **kwargs):
    session = Session(replies)
    result = qc.QualysClient(
        BASE,
        "synthetic-user",
        "synthetic-password",
        session=session,
        sleep=lambda _: None,
        interval=0,
        retries=kwargs.pop("retries", 0),
        **kwargs,
    )
    return result


def vm_responses(qvs_body=None):
    return [
        Response(
            xml(
                "HOST_LIST_VM_DETECTION_OUTPUT", "<HOST_LIST>" + host() + "</HOST_LIST>"
            )
        ),
        Response(
            xml(
                "KNOWLEDGE_BASE_VULN_LIST_OUTPUT", "<VULN_LIST>" + kb() + "</VULN_LIST>"
            )
        ),
        Response(qvs() if qvs_body is None else qvs_body),
    ]


def policy_response():
    return Response(
        xml(
            "POLICY_LIST_OUTPUT",
            "<POLICY_LIST><POLICY><ID>301</ID>"
            "<TITLE>Example STIG</TITLE></POLICY></POLICY_LIST>",
        )
    )


def test_vm_pages_enrichment_and_detection_identity():
    first = (
        "<HOST_LIST>"
        + host(detections=detection() + detection(port="8443"))
        + "</HOST_LIST>"
    )
    second = "<HOST_LIST>" + host("102", detection(status="Fixed")) + "</HOST_LIST>"
    c = client(
        Response(
            xml(
                "HOST_LIST_VM_DETECTION_OUTPUT",
                first + warning(qc.DETECTIONS, id_min="102"),
            )
        ),
        Response(xml("HOST_LIST_VM_DETECTION_OUTPUT", second)),
        vm_responses()[1],
        Response({**qvs(), **qvs("CVE-2026-10002", "100", "1704153600")}),
    )
    rows = qr.collect_vm(c, "101-102")
    assert len(rows) == len({r["Record ID"] for r in rows}) == 3
    assert {r["Status"] for r in rows} == {"Active", "Fixed"}
    for row in rows:
        assert row["CISA Due Date"] == "2024-01-02"
        assert row["QVS Maximum"] == "100"
        assert row["CISA KEV"] == "true"
        assert row["QVS Coverage"] == "complete"
        assert row["Qualys Severity"] == "5"
        assert row["CVSS v3 Base"] == "9.8"
        assert len(json.loads(row["CVE Enrichment"])) == 2
    assert c.session.calls[1][1]["ids"] == "101-102"
    assert c.session.calls[1][1]["status"] == "New,Active,Re-Opened,Fixed"
    assert c.session.calls[1][1]["include_ignored"] == 1
    assert c.session.calls[1][1]["include_disabled"] == 1
    assert c.session.calls[1][1]["id_min"] == "102"


def test_qvs_missing_cve_is_explicit_not_a_false_negative():
    row = qr.collect_vm(client(*vm_responses({})))[0]
    assert row["QVS Coverage"] == "unavailable"
    assert row["CISA KEV"] == "unknown"
    assert row["QVS Maximum"] == row["CISA Due Date"] == ""
    assert all(
        e == {"availability": "unavailable"}
        for e in json.loads(row["CVE Enrichment"]).values()
    )


def test_partial_qvs_retains_available_details():
    row = qr.collect_vm(client(*vm_responses()))[0]
    assert row["QVS Coverage"] == "partial"
    assert row["CISA Due Date"] == "2024-02-03"
    assert (
        json.loads(row["CVE Enrichment"])["CVE-2026-10001"]["cisa_added_date"]
        == "2024-01-01"
    )


def test_qvs_batches_deduplicate_and_never_call_with_empty_cves():
    cves = [f"CVE-2026-{i:05}" for i in range(26)]
    c = client(Response({}), Response({}))
    assert qr.qvs_records(c, cves + cves) == {}
    assert [len(params["cve"].split(",")) for _, params in c.session.calls] == [25, 1]
    assert qr.qvs_records(c, []) == {}
    assert len(c.session.calls) == 2


@pytest.mark.parametrize(
    "body",
    [
        b"<html>error</html>",
        {"error": "forbidden"},
        [],
        {"CVE-2026-10001": {}},
        qvs(score="NaN"),
    ],
)
def test_malformed_qvs_fails(body):
    with pytest.raises(qc.QualysError):
        qr.collect_vm(client(*vm_responses(body)))


@pytest.mark.parametrize("raw", ["bad-date", "-1", "99999999999999999999999"])
def test_malformed_cisa_date_fails(raw):
    with pytest.raises(qc.QualysError, match="CISA date"):
        qr.collect_vm(client(*vm_responses(qvs(due=raw))))


@pytest.mark.parametrize("wrapped", [False, True])
def test_stig_all_results_mapping_and_exceptions(wrapped):
    pages = []
    for i, result in enumerate(["Passed", "Failed", "Error"]):
        content = posture(
            str(501 + i),
            str(601 + i),
            result,
            "V-100001, V-100002, SV-123_rule",
            wrapped,
        )
        if i < 2:
            content += warning(qc.POSTURE, id_min=str(502 + i), policy_id="301")
        pages.append(Response(xml("POSTURE_INFO_LIST_OUTPUT", content)))
    c = client(policy_response(), *pages)
    rows = qr.collect_stig(c, "301")
    assert len(rows) == len({r["Record ID"] for r in rows}) == 6
    assert {r["Result"] for r in rows} == {"Passed", "Failed", "Error"}
    assert {r["STIG ID"] for r in rows} == {"V-100001", "V-100002"}
    assert all(r["Exception Status"] == "Approved" for r in rows)
    assert all(r["Host Name"] == "host.example.test" for r in rows)
    assert all("status" not in params for _, params in c.session.calls)


@pytest.mark.parametrize("status", ["New", "Active", "Re-Opened", "Fixed"])
def test_vm_resolution_ignores_historical_fix_for_open_findings(status):
    responses = vm_responses()
    responses[0] = Response(
        xml(
            "HOST_LIST_VM_DETECTION_OUTPUT",
            "<HOST_LIST>" + host(detections=detection(status=status)) + "</HOST_LIST>",
        )
    )
    row = qr.collect_vm(client(*responses))[0]
    assert row["Last Fixed"] == DATE
    assert row["Resolved At"] == (DATE if status == "Fixed" else "")


@pytest.mark.parametrize("result", ["Passed", "Passed*", "Failed", "Error"])
def test_stig_only_unqualified_pass_resolves(result):
    c = client(
        policy_response(),
        Response(
            xml(
                "POSTURE_INFO_LIST_OUTPUT",
                posture(result=result),
            )
        ),
    )
    row = qr.collect_stig(c, "301")[0]
    assert row["Resolved At"] == (DATE if result == "Passed" else "")


@pytest.mark.parametrize("date", ["", "N/A", "not-a-date"])
def test_resolution_requires_source_date(date):
    with pytest.raises(qc.QualysError, match="resolution date"):
        qr.resolved_at(True, date)
    assert qr.resolved_at(False, date) == ""


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.replace("<REFERENCE>V-100001</REFERENCE>", ""),
        lambda s: s.replace("<ID>701</ID>", "<ID>702</ID>"),
        lambda s: s.replace("<ID>101</ID>", "<ID>102</ID>"),
    ],
)
def test_stig_missing_required_joins_fail(mutation):
    c = client(
        policy_response(),
        Response(xml("POSTURE_INFO_LIST_OUTPUT", mutation(posture()))),
    )
    with pytest.raises(qc.QualysError):
        qr.collect_stig(c, "301")


def test_stig_identity_does_not_change_with_result_or_title():
    before = qr.collect_stig(
        client(policy_response(), Response(xml("POSTURE_INFO_LIST_OUTPUT", posture()))),
        "301",
    )[0]
    after = qr.collect_stig(
        client(
            policy_response(),
            Response(
                xml(
                    "POSTURE_INFO_LIST_OUTPUT",
                    posture(result="Passed").replace("Synthetic control", "New title"),
                )
            ),
        ),
        "301",
    )[0]
    assert before["Record ID"] == after["Record ID"]


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/api/2.0/fo/asset/host/vm/detection/?id_min=2",
        BASE + qc.DETECTIONS + "?action=purge&id_min=2",
        BASE + qc.DETECTIONS + "?action=list&id_min=2&ids=999",
        BASE + qc.DETECTIONS + "?action=list&id_min=2&id_min=3",
        BASE + qc.DETECTIONS + "?action=list",
    ],
)
def test_unsafe_or_scope_changing_pagination_is_rejected(url):
    content = f"<WARNING><CODE>1980</CODE><URL>{escape(url)}</URL></WARNING>"
    c = client(Response(xml("HOST_LIST_VM_DETECTION_OUTPUT", content)))
    with pytest.raises(qc.QualysError):
        list(c.pages(qc.DETECTIONS, {"ids": "101"}, "HOST_LIST_VM_DETECTION_OUTPUT"))
    assert len(c.session.calls) == 1


def test_page_limit_and_repeated_cursor_fail():
    reply = Response(
        xml("HOST_LIST_VM_DETECTION_OUTPUT", warning(qc.DETECTIONS, id_min="2"))
    )
    with pytest.raises(qc.QualysError, match="page limit"):
        list(
            client(reply, max_pages=1).pages(
                qc.DETECTIONS, {}, "HOST_LIST_VM_DETECTION_OUTPUT"
            )
        )
    with pytest.raises(qc.QualysError, match="did not advance"):
        list(
            client(reply, reply).pages(
                qc.DETECTIONS, {}, "HOST_LIST_VM_DETECTION_OUTPUT"
            )
        )


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "auth_failed"),
        (403, "not_authorized"),
        (429, "rate_limited"),
        (503, "partial_failure"),
    ],
)
def test_http_failures_have_categories(status, code):
    with pytest.raises(qc.QualysError) as exc:
        client(Response(status=status)).request(qc.QVS, {"action": "list"})
    assert exc.value.code == code


def test_rate_limits_retry_then_succeed():
    limited = xml("SIMPLE_RETURN", "<CODE>1965</CODE><TEXT>rate limit</TEXT>")
    c = client(Response(limited), Response({}), retries=1)
    sleeps = []
    c.sleep = sleeps.append
    assert c.request(qc.QVS, {"action": "list"}) == b"{}"
    assert len(c.session.calls) == 2
    assert 1 in sleeps


def test_long_retry_delay_fails_instead_of_retrying_early():
    c = client(Response(status=429, headers={"Retry-After": "300"}), retries=1)
    with pytest.raises(qc.QualysError, match="60 seconds"):
        c.request(qc.QVS, {"action": "list"})
    assert len(c.session.calls) == 1


def test_entity_expansion_rejected():
    with pytest.raises(qc.QualysError, match="unsafe XML"):
        qc.parse_xml(b'<!DOCTYPE x [<!ENTITY y "secret">]><x>&y;</x>')


def test_client_only_permits_read_operations():
    c = client()
    for path, params in [
        (qc.DETECTIONS, {"action": "purge"}),
        ("/unknown/", {"action": "list"}),
    ]:
        with pytest.raises(qc.QualysError):
            c.request(path, params)
    assert not c.session.calls


@pytest.mark.parametrize("failure", ["later_page", "qvs", "interrupted", "missing_kb"])
def test_entrypoint_never_publishes_partial_report(monkeypatch, tmp_path, failure):
    replies = vm_responses()
    if failure == "later_page":
        replies = [
            Response(
                xml(
                    "HOST_LIST_VM_DETECTION_OUTPUT",
                    "<HOST_LIST>"
                    + host()
                    + "</HOST_LIST>"
                    + warning(qc.DETECTIONS, id_min="102"),
                )
            ),
            Response(status=503),
        ]
    elif failure == "qvs":
        replies[-1] = Response(status=503)
    elif failure == "interrupted":
        replies[0].interrupted = True
    else:
        replies[1] = Response(xml("KNOWLEDGE_BASE_VULN_LIST_OUTPUT", ""))
    monkeypatch.setattr(vm, "build_client", lambda: client(*replies))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    assert vm.main() == 1
    assert not list((tmp_path / "reports").glob("*"))
    assert json.loads((tmp_path / "status.json").read_text())["code"] in {
        "partial_failure",
        "target_unreachable",
    }


def test_atomic_csv_and_empty_results(tmp_path):
    dest = tmp_path / "report.csv"
    with pytest.raises(qc.QualysError, match="No findings"):
        qr.write_report(dest, qr.VM_COLUMNS, [], False)
    assert not dest.exists()
    qr.write_report(dest, qr.VM_COLUMNS, [], True)
    assert list(csv.DictReader(dest.open())) == []
    with pytest.raises(qc.QualysError, match="fresh output"):
        qr.write_report(dest, qr.VM_COLUMNS, [], True)
    dest = tmp_path / "bad.csv"
    with pytest.raises(ValueError):
        qr.write_report(dest, ["ID"], [{"unexpected": "field"}], False)
    assert not dest.exists()
    assert not list(tmp_path.glob("*.part"))


def test_two_policy_targets_write_distinct_csv_files(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setattr(stig, "build_client", lambda: Mock())
    monkeypatch.setattr(
        stig,
        "collect_stig",
        lambda c, p: [{"Record ID": p, "Policy ID": p, "Result": "Error"}],
    )
    for policy_id in ("301", "302"):
        monkeypatch.setenv("QUALYS_POLICY_ID", policy_id)
        assert stig.main() == 0
    assert sorted(p.name for p in tmp_path.glob("*.csv")) == [
        "qualys_stig_compliance_report_301.csv",
        "qualys_stig_compliance_report_302.csv",
    ]


def test_vm_without_cves_makes_no_qvs_call():
    c = client(
        vm_responses()[0],
        Response(
            xml(
                "KNOWLEDGE_BASE_VULN_LIST_OUTPUT",
                "<VULN_LIST>" + kb(cves=()) + "</VULN_LIST>",
            )
        ),
    )
    row = qr.collect_vm(c)[0]
    assert row["QVS Coverage"] == "not_applicable"
    assert len(c.session.calls) == 2


def test_exception_pass_is_not_normalized_to_pass():
    rows = qr.collect_stig(
        client(
            policy_response(),
            Response(xml("POSTURE_INFO_LIST_OUTPUT", posture(result="Passed*"))),
        ),
        "301",
    )
    assert rows[0]["Result"] == "Passed*"
    assert rows[0]["Exception Status"] == "Approved"


@pytest.mark.parametrize(
    "reference", ["SV-100001r123_rule", "SRG-OS-000001-GPOS-00001"]
)
def test_stig_rule_references_are_preserved_without_inventing_v_ids(reference):
    rows = qr.collect_stig(
        client(
            policy_response(),
            Response(xml("POSTURE_INFO_LIST_OUTPUT", posture(reference=reference))),
        ),
        "301",
    )
    assert rows[0]["STIG ID"] == reference
    assert rows[0]["Control ID"] == "601"


def test_record_limit_and_duplicate_identity_fail():
    content = (
        "<HOST_LIST>"
        + host(detections=detection() + detection(port="8443"))
        + "</HOST_LIST>"
    )
    with pytest.raises(qc.QualysError, match="record limit"):
        qr.collect_vm(
            client(
                Response(xml("HOST_LIST_VM_DETECTION_OUTPUT", content)), max_records=1
            )
        )
    content = (
        "<HOST_LIST>" + host(detections=detection() + detection()) + "</HOST_LIST>"
    )
    with pytest.raises(qc.QualysError, match="Duplicate finding identity"):
        qr.collect_vm(client(Response(xml("HOST_LIST_VM_DETECTION_OUTPUT", content))))


def test_stig_empty_requires_zero_summary():
    with pytest.raises(qc.QualysError, match="explicit zero summary"):
        qr.collect_stig(
            client(policy_response(), Response(xml("POSTURE_INFO_LIST_OUTPUT", ""))),
            "301",
        )
    empty = "<SUMMARY><CONTROL_INSTANCES><TOTAL>0</TOTAL></CONTROL_INSTANCES></SUMMARY>"
    assert (
        qr.collect_stig(
            client(policy_response(), Response(xml("POSTURE_INFO_LIST_OUTPUT", empty))),
            "301",
        )
        == []
    )


def test_http_date_retry_after_is_honored(monkeypatch):
    from email.utils import formatdate

    now = 1704067200
    monkeypatch.setattr(qc.time, "time", lambda: now)
    c = client(
        Response(
            status=429, headers={"Retry-After": formatdate(now + 30, usegmt=True)}
        ),
        Response({}),
        retries=1,
    )
    sleeps = []
    c.sleep = sleeps.append
    assert c.request(qc.QVS, {"action": "list"}) == b"{}"
    assert 30 in sleeps


@pytest.mark.parametrize(
    "origin",
    [
        "http://qualys.example.com",
        "https://user:password@qualys.example.com",
        "https://qualys.example.com/api",
        "https://qualys.example.com?token=secret",
    ],
)
def test_invalid_endpoint_configuration_is_rejected(origin):
    with pytest.raises(qc.QualysError) as exc:
        qc.QualysClient(origin, "user", "pass")
    assert exc.value.code == "bad_config"
    assert "password@" not in str(exc.value)
    assert "token=secret" not in str(exc.value)


@pytest.mark.parametrize("raw", ["1;action=purge", "0", "-1", "9-1", "1,", "abc"])
def test_invalid_scope_never_reaches_api(raw):
    with pytest.raises(qc.QualysError) as exc:
        qc.id_list(raw)
    assert exc.value.code == "bad_config"


def test_failure_logs_never_include_response_or_credentials(caplog):
    c = client(
        Response(xml("SIMPLE_RETURN", "<CODE>2000</CODE><TEXT>secret-password</TEXT>"))
    )
    with pytest.raises(qc.QualysError) as exc:
        c.request(qc.DETECTIONS, {"action": "list"})
    qc.report_failure(str(exc.value), exc.value.code)
    assert "secret-password" not in caplog.text
    assert "auth_failed" == exc.value.code


def test_csv_round_trip_preserves_multiline_source_and_cve_json(tmp_path):
    rows = qr.collect_vm(client(*vm_responses()))
    rows[0]["Results"] = 'line one\nline two, "quoted"'
    dest = tmp_path / "report.csv"
    qr.write_report(dest, qr.VM_COLUMNS, rows, False)
    with dest.open(newline="") as handle:
        saved = list(csv.DictReader(handle))
    assert saved == rows
    assert (
        json.loads(saved[0]["CVE Enrichment"])["CVE-2026-10001"]["base"]["qvs"] == "99"
    )


def test_category_secrets_and_config_reach_both_fetcher_contracts():
    from framework.config_loader import discover_fetchers, discover_platforms
    from framework.contract import effective_secrets

    fetchers = discover_fetchers(ROOT)
    platform = discover_platforms(ROOT)["qualys"]
    for name in ("qualys_vmdr_vulnerability_findings", "qualys_stig_compliance_report"):
        f = fetchers[name]
        assert f.is_issue_report
        assert {s.env for s in effective_secrets(f, platform)} == {
            "QUALYS_USERNAME",
            "QUALYS_PASSWORD",
        }
        assert platform.config_schema["api_url"].env == "QUALYS_API_URL"


@pytest.mark.parametrize("status", [200, 409])
@pytest.mark.parametrize("code", ["1960", "1965", "1920", "1981", "1999"])
def test_qualys_error_codes_retry_on_success_and_conflict(status, code):
    body = xml(
        "SIMPLE_RETURN",
        f"<CODE>{code}</CODE><ITEM_LIST><ITEM><KEY>SECONDS_TO_WAIT</KEY><VALUE>7</VALUE></ITEM></ITEM_LIST>",
    )
    c = client(Response(body, status=status), Response({}), retries=1)
    waits = []
    c.sleep = waits.append
    assert c.request(qc.QVS, {"action": "list"}) == b"{}"
    assert 7 in waits


@pytest.mark.parametrize(
    "code,category",
    [("2003", "bad_config"), ("2011", "auth_failed"), ("2012", "not_authorized")],
)
def test_permanent_conflict_errors_do_not_retry_or_leak_body(code, category):
    c = client(
        Response(
            xml("SIMPLE_RETURN", f"<CODE>{code}</CODE><TEXT>private-response</TEXT>"),
            status=409,
        ),
        retries=3,
    )
    with pytest.raises(qc.QualysError) as exc:
        c.request(qc.QVS, {"action": "list"})
    assert exc.value.code == category
    assert "private-response" not in str(exc.value)
    assert len(c.session.calls) == 1


@pytest.mark.parametrize(
    "host", ["qualysapi.qualys.com.evil.test", "example.com", "qualysguard.qualys.com"]
)
def test_credentials_refused_for_unapproved_hosts(host):
    session = Mock()
    with pytest.raises(qc.QualysError):
        qc.QualysClient("https://" + host, "user", "pass", session=session)
    session.get.assert_not_called()


def test_private_cloud_host_requires_explicit_opt_in():
    with pytest.raises(qc.QualysError):
        qc.QualysClient("https://qualysapi.example.test", "user", "pass")
    c = qc.QualysClient(
        "https://qualysapi.example.test",
        "user",
        "pass",
        private_host="qualysapi.example.test",
    )
    c.close()


def test_external_dtd_allowed_but_external_entity_rejected():
    assert (
        qc.parse_xml(
            b'<!DOCTYPE x SYSTEM "https://example.invalid/unused.dtd"><x/>'
        ).tag
        == "x"
    )
    with pytest.raises(qc.QualysError):
        qc.parse_xml(
            b'<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>'
        )


def test_reopening_history_is_retained_without_changing_identity_or_resolution():
    original = qr.collect_vm(client(*vm_responses()))[0]
    replies = vm_responses()
    replies[0].body = replies[0].body.replace(
        b"</DETECTION>",
        f"<LAST_REOPENED_DATETIME>{DATE}</LAST_REOPENED_DATETIME><TIMES_REOPENED>2</TIMES_REOPENED></DETECTION>".encode(),
    )
    c = client(*replies)
    row = qr.collect_vm(c)[0]
    assert row["Record ID"] == original["Record ID"]
    assert row["Resolved At"] == ""
    assert row["Last Reopened"] == DATE
    assert row["Times Reopened"] == "2"
    assert c.session.calls[0][1]["show_reopened_info"] == 1
