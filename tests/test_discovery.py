"""Discovery: a fetcher kind that lists what a platform's credentials can see.

The property every test here circles: a resource type that could not be read
must never look like a resource type with nothing in it. "denied", "error" and
"truncated" are answers of their own, and the document and the fetcher's exit
code both have to keep them apart from "ok, 0".

The KnowBe4 fetcher runs in-process against a fake HTTP session serving canned
Reporting API pages (cursor-paged, as the live API is), so every request goes
through the shared engine's real client code with no network and no tenant. One
subprocess test runs it the way the runner does, to prove it imports standalone.

Run: ``pytest tests/test_discovery.py``
"""

from __future__ import annotations

import importlib.util
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from framework.contract import Fetcher
from framework.discovery import (
    DISCOVERY_DIR,
    find_documents,
    load,
    validate,
)
from framework.runner.executor import invocation_dir

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_DIR = REPO_ROOT / "fetchers" / "knowbe4" / "discovery_beta"
FETCHER_SCHEMA = json.loads((REPO_ROOT / "framework" / "schemas" / "fetcher_schema.json").read_text())


# --------------------------------------------------------------------------- #
# Contract: what a discovery fetcher.yaml may and may not declare
# --------------------------------------------------------------------------- #

def _discovery_yaml(**extra) -> dict:
    doc = yaml.safe_load((FETCHER_DIR / "fetcher.yaml").read_text())
    doc.update(extra)
    return doc


def _schema_errors(doc: dict) -> list:
    return list(Draft202012Validator(FETCHER_SCHEMA).iter_errors(doc))


def test_the_shipped_discovery_fetcher_matches_the_schema():
    assert _schema_errors(_discovery_yaml()) == []


@pytest.mark.parametrize("block", [
    {"evidence_set": {"reference_id": "EVD-X", "name": "X"}},
    {"ksis": ["KSI-CED-RAT"]},
    {"validators": ["x"]},
])
def test_a_discovery_fetcher_cannot_promise_an_upload(block):
    """Discovery output is never uploaded, so an evidence set, KSIs or validators
    on one would advertise a claim nothing will ever make."""
    assert _schema_errors(_discovery_yaml(**block))


def test_a_discovery_fetcher_writes_json():
    doc = _discovery_yaml()
    doc["output"] = {"type": "csv", "path": "x.csv"}
    assert _schema_errors(doc)


def _fetcher(kind: str, path: Path) -> Fetcher:
    return Fetcher(
        name="t", version="0.1.0", description="t", category="t",
        runtime_type="bash", runtime_entry="fetcher.sh", runtime_timeout=None,
        output_type="json", output_path="t.json", output_aggregation=None,
        secrets=[], supports_targets=False, target_schema={}, path=path,
        config_schema={}, evidence_set=None, kind=kind,
    )


def test_the_runner_writes_discovery_into_its_own_subdir(tmp_path):
    """The evidence uploader collects every top-level *.json in a run. The subdir
    is the whole mechanism that keeps discovery output from being uploaded."""
    run_dir = tmp_path / "run-x"
    assert invocation_dir(_fetcher("discovery", tmp_path), run_dir) == run_dir / DISCOVERY_DIR
    assert invocation_dir(_fetcher("evidence", tmp_path), run_dir) == run_dir


# --------------------------------------------------------------------------- #
# The document schema
# --------------------------------------------------------------------------- #

def _doc(*resources) -> dict:
    return {
        "schema_version": "0.1",
        "platform": "knowbe4",
        "identity": "Acme (Diamond)",
        "scope": {"region": "us"},
        "collected_at": "2026-10-07T00:00:00Z",
        "resources": list(resources),
    }


OK_GROUP = {
    "type": "group", "status": "ok", "count": 2, "truncated": False,
    "items": [{"id": "1", "name": "Eng"}, {"id": "2", "name": "Ops | FedRAMP"}],
    "source": "GET /v1/groups",
}
DENIED = {
    "type": "phishing_campaign", "status": "denied", "count": None, "truncated": False,
    "items": None, "reason": "HTTP 403: Forbidden", "source": "GET /v1/phishing/campaigns",
}
TRUNCATED = {
    "type": "user", "status": "error", "count": 500, "truncated": True, "items": None,
    "reason": "HTTP 500: boom", "source": "GET /v1/users",
}


def test_a_well_formed_document_validates():
    assert validate(_doc(OK_GROUP, DENIED, TRUNCATED)) == []


def test_a_failed_resource_must_say_why():
    bad = {k: v for k, v in DENIED.items() if k != "reason"}
    assert validate(_doc(bad))


def test_an_ok_resource_must_have_a_count():
    """ok + null count would be the 'listed, and there was nothing' shape with
    the number missing — exactly the ambiguity the status field exists to remove."""
    assert validate(_doc({**OK_GROUP, "count": None}))


def test_an_unknown_status_is_rejected():
    assert validate(_doc({**OK_GROUP, "status": "empty"}))


# --------------------------------------------------------------------------- #
# Finding documents in a run
# --------------------------------------------------------------------------- #

def test_documents_are_found_in_a_run_dir_and_unwrapped(tmp_path):
    run_dir = tmp_path / "run-x"
    (run_dir / DISCOVERY_DIR).mkdir(parents=True)
    doc_path = run_dir / DISCOVERY_DIR / "knowbe4_discovery_beta.json"
    doc_path.write_text(json.dumps({
        "schema_version": "1.0",
        "metadata": {"run_id": "r1", "exit_code": 0, "fetcher_name": "knowbe4_discovery_beta"},
        "payload": _doc(OK_GROUP),
    }))
    assert find_documents(run_dir) == [doc_path]
    meta, doc = load(doc_path)
    assert meta["run_id"] == "r1" and doc["platform"] == "knowbe4"


# --------------------------------------------------------------------------- #
# The KnowBe4 fetcher, against a fake Reporting API
# --------------------------------------------------------------------------- #

ACCOUNT = {
    "name": "Acme", "type": "paid", "subscription_level": "Diamond",
    "subscription_end_date": "2027-01-01", "number_of_seats": 10,
    "domains": ["acme.example"],
    "admins": [{"id": 1, "first_name": "Ada", "last_name": "Admin", "email": "ada@acme.example"}],
}

USERS = [
    {"id": i, "email": f"user{i}@acme.example", "first_name": f"First{i}",
     "status": "active" if i % 3 else "archived"}
    for i in range(1, 8)
]

# API path -> list of pages
TENANT = {
    "/v1/users": [USERS[:4], USERS[4:]],
    "/v1/groups": [[
        {"id": 10, "name": "Engineering", "group_type": "console_group", "status": "active", "member_count": 3},
        {"id": 11, "name": "Cloud Ops", "group_type": "smart_group", "status": "active", "member_count": 2},
    ]],
    "/v1/training/campaigns": [[
        {"campaign_id": 7, "name": "2026 Annual SAT", "status": "In Progress",
         "start_date": "2026-01-01", "end_date": None,
         "groups": [{"group_id": 10, "name": "Engineering"}], "content": [{}, {}]},
    ]],
    "/v1/training/store_purchases": [[
        {"store_purchase_id": 40, "name": "Security Awareness 2026", "type": "Training Module",
         "content_type": "Store Purchase", "retired": False},
    ]],
    "/v1/training/policies": [[]],
    "/v1/training/enrollments": [[
        {"enrollment_id": 1, "status": "Passed", "user": {"id": 1, "email": "user1@acme.example"}},
        {"enrollment_id": 2, "status": "Not Started", "user": {"id": 2, "email": "user2@acme.example"}},
    ]],
    "/v1/phishing/campaigns": [[
        {"campaign_id": 3, "name": "Monthly phish", "status": "Active", "frequency": "Monthly",
         "last_run": "2026-09-01", "psts_count": 9},
    ]],
    "/v1/phishing/security_tests": [[
        {"pst_id": 99, "name": "Sept phish", "campaign_id": 3, "status": "Closed",
         "started_at": "2026-09-01"},
    ]],
}


class FakeResponse:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeKnowBe4:
    """A requests.Session stand-in serving TENANT by path and cursor.

    `statuses` maps (path, cursor) to (http status, body). `throttle` maps
    (path, cursor) to how many 429s to answer before serving the page.
    """

    def __init__(self, statuses=None, throttle=None):
        self.statuses = dict(statuses or {})
        self.throttle = dict(throttle or {})
        self.requests = []

    def get(self, url, headers=None, params=None, timeout=None):
        params = dict(params or {})
        path = url.split(".api.knowbe4.com", 1)[1]
        self.requests.append((path, params))
        cursor = str(params.get("cursor", "0"))
        key = (path, cursor)
        if self.throttle.get(key, 0) > 0:
            self.throttle[key] -= 1
            return FakeResponse(429, {"message": "Rate limit exceeded"})
        if key in self.statuses:
            code, body = self.statuses[key]
            return FakeResponse(code, body)
        if path == "/v1/account":
            return FakeResponse(200, ACCOUNT)
        pages = TENANT.get(path)
        if pages is None:
            return FakeResponse(404, {"message": "Not Found"})
        i = 0 if cursor == "0" else int(cursor.removeprefix("n"))
        nxt = f"n{i + 1}" if i + 1 < len(pages) else None
        return FakeResponse(200, {"data": pages[i], "pagination": {"perPage": 500, "nextCursor": nxt}})


def _load_fetcher():
    spec = importlib.util.spec_from_file_location("knowbe4_discovery_fetcher", FETCHER_DIR / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_discovery(tmp_path, monkeypatch, session=None, retry_waits="0 0"):
    """Run the fetcher in-process. Returns (exit, document or None, status record or None, session)."""
    session = session or FakeKnowBe4()
    out_dir = tmp_path / "out"
    status_file = tmp_path / "status.json"
    for k, v in {
        "EVIDENCE_DIR": str(out_dir),
        "FETCHER_STATUS_FILE": str(status_file),
        "KNOWBE4_API_KEY": "test-key",
        "KNOWBE4_REGION": "us",
        "DISCOVERY_PACE_SECONDS": "0",
        "DISCOVERY_RETRY_WAITS": retry_waits,
    }.items():
        monkeypatch.setenv(k, v)
    code = _load_fetcher().main(session=session)
    out = out_dir / "knowbe4_discovery_beta.json"
    doc = json.loads(out.read_text()) if out.exists() else None
    status = json.loads(status_file.read_text()) if status_file.exists() else None
    return code, doc, status, session


def _res(doc: dict, type_: str) -> dict:
    return next(r for r in doc["resources"] if r["type"] == type_)


def test_a_readable_tenant_is_listed_in_full(tmp_path, monkeypatch):
    code, doc, status, _ = run_discovery(tmp_path, monkeypatch)
    assert code == 0, status
    assert validate(doc) == []
    assert doc["identity"] == "Acme (Diamond)"
    assert all(r["status"] == "ok" for r in doc["resources"])
    assert [g["name"] for g in _res(doc, "group")["items"]] == ["Engineering", "Cloud Ops"]
    assert _res(doc, "training_campaign")["items"][0]["groups"] == ["Engineering"]
    assert _res(doc, "account")["items"][0]["admin_count"] == 1


def test_users_follow_the_cursor_across_pages(tmp_path, monkeypatch):
    _, doc, _, session = run_discovery(tmp_path, monkeypatch)
    users = _res(doc, "user")
    assert users["count"] == 7
    assert users["summary"] == {"by_status": {"active": 5, "archived": 2}}
    assert ("/v1/users", {"per_page": 500, "cursor": "n1"}) in session.requests


def test_no_request_uses_the_retiring_page_parameter(tmp_path, monkeypatch):
    _, _, _, session = run_discovery(tmp_path, monkeypatch)
    assert session.requests
    assert not [p for _, p in session.requests if "page" in p]


def test_an_empty_collection_is_ok_and_zero(tmp_path, monkeypatch):
    _, doc, _, _ = run_discovery(tmp_path, monkeypatch)
    policies = _res(doc, "training_policy")
    assert (policies["status"], policies["count"], policies["items"]) == ("ok", 0, [])


def test_people_are_counted_never_listed(tmp_path, monkeypatch):
    """Users, enrollments and account admins are people. The document says how
    many, never who: no email or name from those records may appear anywhere."""
    _, doc, _, _ = run_discovery(tmp_path, monkeypatch)
    text = json.dumps(doc)
    assert "@acme.example" not in text
    assert "First1" not in text and "Ada" not in text
    assert _res(doc, "user")["items"] is None
    assert _res(doc, "training_enrollment")["items"] is None


def test_a_denied_type_is_unknown_not_empty_and_does_not_fail_the_run(tmp_path, monkeypatch):
    session = FakeKnowBe4(statuses={("/v1/phishing/campaigns", "0"): (403, {"message": "Forbidden"})})
    code, doc, status, _ = run_discovery(tmp_path, monkeypatch, session)
    assert code == 0, status
    phish = _res(doc, "phishing_campaign")
    assert phish["status"] == "denied"
    assert phish["count"] is None and phish["items"] is None
    assert phish["reason"] == "HTTP 403: Forbidden"
    assert validate(doc) == []


def test_a_failure_mid_listing_is_truncated_and_fails_the_run(tmp_path, monkeypatch):
    """The KnowBe4 evidence fetchers once returned whatever pages they had when a
    later page failed, and the short list read as complete. Discovery must mark
    it: a lower-bound count, truncated, and a non-zero exit with the cause."""
    session = FakeKnowBe4(statuses={("/v1/users", "n1"): (500, {"message": "Internal Server Error"})})
    code, doc, status, _ = run_discovery(tmp_path, monkeypatch, session)
    assert code == 1
    users = _res(doc, "user")
    assert (users["status"], users["count"], users["truncated"]) == ("error", 4, True)
    assert users["reason"] == "HTTP 500: Internal Server Error"
    assert status["code"] == "partial_failure"
    assert "user: HTTP 500" in status["error"]
    assert validate(doc) == []


def test_a_throttled_call_is_retried(tmp_path, monkeypatch, caplog):
    session = FakeKnowBe4(throttle={("/v1/groups", "0"): 2})
    with caplog.at_level(logging.WARNING):
        code, doc, status, _ = run_discovery(tmp_path, monkeypatch, session)
    assert code == 0, status
    assert _res(doc, "group")["count"] == 2
    assert "throttled on GET /v1/groups" in caplog.text


def test_throttling_that_never_clears_is_an_error_not_an_empty_list(tmp_path, monkeypatch):
    session = FakeKnowBe4(throttle={("/v1/groups", "0"): 9})
    code, doc, _, _ = run_discovery(tmp_path, monkeypatch, session, retry_waits="0")
    assert code == 1
    groups = _res(doc, "group")
    assert groups["status"] == "error" and groups["count"] is None
    assert "429" in groups["reason"]


def test_a_key_that_cannot_read_the_account_fails_the_run(tmp_path, monkeypatch):
    session = FakeKnowBe4(statuses={("/v1/account", "0"): (401, {"message": "Invalid token"})})
    code, doc, status, _ = run_discovery(tmp_path, monkeypatch, session)
    assert code == 1
    assert doc is None
    assert status["code"] == "auth_failed"
    assert "Invalid token" in status["error"]


def test_it_runs_standalone_the_way_the_runner_execs_it(tmp_path):
    """The runner execs fetcher.py with cwd set to its own dir and no PYTHONPATH,
    so the _lib imports have to resolve on their own."""
    status_file = tmp_path / "status.json"
    proc = subprocess.run(
        [sys.executable, "fetcher.py"], cwd=FETCHER_DIR, capture_output=True, text=True, timeout=60,
        env={"PATH": "/usr/bin:/bin", "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(status_file)},
    )
    assert proc.returncode == 1, proc.stderr
    assert json.loads(status_file.read_text()) == {"error": "KNOWBE4_API_KEY is not set", "code": "bad_config"}


# --------------------------------------------------------------------------- #
# Scoped entries: one type listed in many places (AWS regions)
# --------------------------------------------------------------------------- #

def _scoped(region: str, status: str = "ok", count=None, items=None, reason=None, truncated=False) -> dict:
    entry = {"type": "ec2_instance", "scope": {"region": region}, "status": status,
             "count": count, "truncated": truncated, "items": items, "source": "aws ec2 describe-instances"}
    if reason:
        entry["reason"] = reason
    return entry


SCOPED = [
    _scoped("us-east-1", count=0, items=[]),
    _scoped("us-east-2", count=2, items=[{"id": "i-1", "name": "web"}, {"id": "i-2", "name": "db"}]),
    _scoped("eu-west-1", "denied", reason="AccessDenied: explicit deny in a service control policy"),
]


def test_a_type_can_be_listed_once_per_scope():
    assert validate(_doc(*SCOPED)) == []


def test_the_same_type_and_scope_twice_is_rejected():
    errors = validate(_doc(SCOPED[0], SCOPED[0]))
    assert any("duplicate entry" in e for e in errors)


# --------------------------------------------------------------------------- #
# The AWS fetcher, against a fake aws CLI
# --------------------------------------------------------------------------- #

AWS_DIR = REPO_ROOT / "fetchers" / "aws" / "discovery_beta"


def _load_aws():
    spec = importlib.util.spec_from_file_location("aws_discovery_fetcher", AWS_DIR / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeAwsCli:
    """Stands in for subprocess.run. `answers` maps (command, region) to either
    a JSON-able result or ("stderr", text) for a failed call; anything absent
    succeeds with an empty list."""

    def __init__(self, answers=None):
        self.answers = dict(answers or {})
        self.calls = []

    def __call__(self, argv, **kwargs):
        region = argv[argv.index("--region") + 1]
        cmd = " ".join(argv[1:3])
        self.calls.append((cmd, region))
        if cmd == "sts get-caller-identity" and (cmd, region) not in self.answers:
            result = {"arn": "arn:aws:iam::111122223333:user/discover", "account": "111122223333"}
        elif cmd == "ec2 describe-regions" and (cmd, region) not in self.answers:
            result = ["us-east-1", "us-east-2", "eu-west-1"]
        else:
            result = self.answers.get((cmd, region), self.answers.get((cmd, "*"), []))
        if isinstance(result, tuple) and result[0] == "stderr":
            return subprocess.CompletedProcess(argv, 254, "", result[1])
        return subprocess.CompletedProcess(argv, 0, json.dumps(result), "")


def run_aws(tmp_path, monkeypatch, answers=None, regions=None, profile=None):
    fake = FakeAwsCli(answers)
    module = _load_aws()
    monkeypatch.setattr(module.subprocess, "run", fake)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("AWS_DISCOVERY_REGIONS", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    if regions:
        monkeypatch.setenv("AWS_DISCOVERY_REGIONS", regions)
    if profile:
        monkeypatch.setenv("AWS_PROFILE", profile)
    code = module.main()
    outs = sorted((tmp_path / "out").glob("*.json")) if (tmp_path / "out").exists() else []
    doc = json.loads(outs[0].read_text()) if outs else None
    status_file = tmp_path / "status.json"
    status = json.loads(status_file.read_text()) if status_file.exists() else None
    return code, doc, status, fake, outs


def _entries(doc, type_):
    return [r for r in doc["resources"] if r["type"] == type_]


def test_aws_lists_regional_types_per_region_with_their_own_status(tmp_path, monkeypatch):
    code, doc, status, _, _ = run_aws(tmp_path, monkeypatch, {
        ("ec2 describe-instances", "us-east-2"): [{"id": "i-1", "name": "web", "state": "running"}],
        ("ec2 describe-instances", "eu-west-1"): ("stderr", "An error occurred (UnauthorizedOperation) when "
                                                  "calling the DescribeInstances operation: You are not authorized"),
    })
    assert code == 0, status
    assert validate(doc) == []
    ec2 = {e["scope"]["region"]: e for e in _entries(doc, "ec2_instance")}
    assert set(ec2) == {"us-east-1", "us-east-2", "eu-west-1"}
    assert (ec2["us-east-2"]["status"], ec2["us-east-2"]["count"]) == ("ok", 1)
    assert (ec2["us-east-1"]["status"], ec2["us-east-1"]["count"]) == ("ok", 0)
    assert (ec2["eu-west-1"]["status"], ec2["eu-west-1"]["count"]) == ("denied", None)
    assert doc["identity"] == "arn:aws:iam::111122223333:user/discover"
    assert doc["scope"] == {"account": "111122223333", "regions": 3}


def test_aws_global_types_are_listed_once_and_unscoped(tmp_path, monkeypatch):
    _, doc, _, fake, _ = run_aws(tmp_path, monkeypatch, {("iam list-roles", "*"): [{"id": "r", "name": "r"}]})
    [roles] = _entries(doc, "iam_role")
    assert "scope" not in roles and roles["count"] == 1
    assert sum(1 for c, _ in fake.calls if c == "iam list-roles") == 1
    assert ("wafv2 list-web-acls", "us-east-1") in fake.calls


def test_aws_iam_users_are_counted_never_listed(tmp_path, monkeypatch):
    _, doc, _, _, _ = run_aws(tmp_path, monkeypatch, {("iam list-users", "*"): ["alice", "bob"]})
    [users] = _entries(doc, "iam_user")
    assert users["count"] == 2 and users["items"] is None
    assert "alice" not in json.dumps(doc)


def test_aws_a_service_that_is_off_is_not_enabled_not_failed(tmp_path, monkeypatch):
    code, doc, _, _, _ = run_aws(tmp_path, monkeypatch, {
        ("securityhub describe-hub", "*"): ("stderr", "An error occurred (InvalidAccessException) when calling "
                                             "the DescribeHub operation: Account is not subscribed to AWS Security Hub"),
        ("organizations describe-organization", "*"): ("stderr", "An error occurred "
                                                         "(AWSOrganizationsNotInUseException)"),
    })
    assert code == 0
    hubs = _entries(doc, "securityhub_hub")
    assert {e["status"] for e in hubs} == {"not_enabled"}
    assert hubs[0]["reason"] == "InvalidAccessException: Account is not subscribed to AWS Security Hub"
    assert _entries(doc, "organization")[0]["status"] == "not_enabled"


def test_aws_an_unexplained_failure_fails_the_run_and_names_where(tmp_path, monkeypatch):
    code, doc, status, _, _ = run_aws(tmp_path, monkeypatch, {
        ("rds describe-db-instances", "eu-west-1"): ("stderr", "Could not connect to the endpoint URL"),
    })
    assert code == 1
    assert status["code"] == "partial_failure"
    assert "rds_instance (eu-west-1): Could not connect" in status["error"]
    assert validate(doc) == []


def test_aws_a_service_not_offered_in_a_region_is_not_enabled_there(tmp_path, monkeypatch):
    """No endpoint looks the same whether the network failed or AWS does not run
    the service there. AWS's published availability decides; only a confirmed
    "not offered" is not_enabled."""
    no_endpoint = ("stderr", 'Could not connect to the endpoint URL: "https://codeartifact.eu-west-1.amazonaws.com/"')
    code, doc, status, _, _ = run_aws(tmp_path, monkeypatch, {
        ("codeartifact list-domains", "eu-west-1"): no_endpoint,
        ("rds describe-db-instances", "us-east-1"): ("stderr", "Could not connect to the endpoint URL: rds"),
        ("ssm get-parameters-by-path", "*"): ["us-east-1", "us-east-2"],
    })
    by_region = {e["scope"]["region"]: e for e in _entries(doc, "codeartifact_domain")}
    assert by_region["eu-west-1"]["status"] == "not_enabled"
    assert by_region["eu-west-1"]["reason"] == "codeartifact is not offered in eu-west-1"
    # RDS is "offered" in us-east-1 by the same answer, so its failure is real.
    rds = {e["scope"]["region"]: e for e in _entries(doc, "rds_instance")}
    assert rds["us-east-1"]["status"] == "error"
    assert code == 1 and "rds_instance (us-east-1)" in status["error"]


def test_aws_resource_explorer_counts_every_type_in_indexed_regions(tmp_path, monkeypatch):
    rows = [{"type": "ec2:subnet", "region": "us-east-2", "service": "ec2"}] * 3 + [
        {"type": "athena:workgroup", "region": "us-east-2", "service": "athena"}]
    _, doc, _, _, _ = run_aws(tmp_path, monkeypatch, {
        ("resource-explorer-2 list-indexes", "*"): [{"region": "us-east-2", "type": "LOCAL"}],
        ("resource-explorer-2 search", "us-east-2"): {"complete": True, "rows": rows},
    })
    sweep = {e["scope"]["region"]: e for e in _entries(doc, "resource_explorer_type")}
    assert set(sweep) == {"us-east-1", "us-east-2", "eu-west-1"}
    assert sweep["us-east-1"]["status"] == "not_enabled"
    assert sweep["us-east-2"]["status"] == "ok" and sweep["us-east-2"]["count"] == 2
    assert sweep["us-east-2"]["items"][0] == {"id": "ec2:subnet", "name": "ec2:subnet",
                                               "service": "ec2", "resources": 3}
    assert sweep["us-east-2"]["summary"] == {"resources_by_service": {"ec2": 3, "athena": 1}}
    assert validate(doc) == []


def test_aws_a_capped_resource_explorer_search_is_a_lower_bound(tmp_path, monkeypatch):
    _, doc, _, _, _ = run_aws(tmp_path, monkeypatch, {
        ("resource-explorer-2 list-indexes", "*"): [{"region": "us-east-2", "type": "LOCAL"}],
        ("resource-explorer-2 search", "us-east-2"): {
            "complete": False, "rows": [{"type": "ec2:subnet", "region": "us-east-2", "service": "ec2"}]},
    })
    [capped] = [e for e in _entries(doc, "resource_explorer_type") if e["scope"]["region"] == "us-east-2"]
    assert capped["truncated"] is True and capped["count"] == 1
    assert "at most 1,000" in capped["reason"]


def test_every_service_an_aws_fetcher_reads_is_discovered():
    """Discovery exists to say which fetchers apply. A fetcher whose service
    discovery never looks at can never be suggested, so adding an AWS fetcher
    for a new service means adding a discovery type for it too."""
    import re as _re

    used = set()
    for script in (REPO_ROOT / "fetchers" / "aws").glob("*/fetcher.sh"):
        used |= set(_re.findall(r"\baws ([a-z0-9-]+) [a-z0-9-]+", script.read_text()))
    module = _load_aws()
    covered = {r.path.split()[0] for r in module.REGIONAL + module.GLOBAL}
    covered.add("resource-explorer-2")  # the Resource Explorer layer
    exempt = {"sts"}  # identity, not a resource
    missing = sorted(used - covered - exempt)
    assert not missing, f"AWS services read by a fetcher but not discovered: {missing}"


def test_aws_regions_can_be_limited_in_config(tmp_path, monkeypatch):
    _, doc, _, fake, _ = run_aws(tmp_path, monkeypatch, regions="us-east-2")
    assert not [c for c in fake.calls if c[0] == "ec2 describe-regions"]
    assert {e["scope"]["region"] for e in _entries(doc, "vpc")} == {"us-east-2"}


def test_aws_each_target_writes_its_own_file(tmp_path, monkeypatch):
    """A fanout over profiles must not overwrite one account's document with the next."""
    _, _, _, _, outs = run_aws(tmp_path, monkeypatch, profile="prod/admin")
    assert [o.name for o in outs] == ["aws_discovery_beta_prod_admin.json"]


def test_aws_expired_credentials_fail_before_anything_is_listed(tmp_path, monkeypatch):
    code, doc, status, fake, _ = run_aws(tmp_path, monkeypatch, {
        ("sts get-caller-identity", "us-east-1"): ("stderr", "aws: [ERROR]: Your session has expired. "
                                                     "Please reauthenticate using 'aws login'."),
    })
    assert code == 1 and doc is None
    assert status["code"] == "auth_failed"
    assert len(fake.calls) == 1


def test_aws_runs_standalone_the_way_the_runner_execs_it(tmp_path):
    """Exec'd from its own dir with no PYTHONPATH, the _lib imports resolve, and
    a missing aws CLI is a reported failure rather than a traceback."""
    status_file = tmp_path / "status.json"
    proc = subprocess.run(
        [sys.executable, "fetcher.py"], cwd=AWS_DIR, capture_output=True, text=True, timeout=60,
        env={"PATH": str(tmp_path), "EVIDENCE_DIR": str(tmp_path), "FETCHER_STATUS_FILE": str(status_file)},
    )
    assert proc.returncode == 1, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "could not run the aws CLI" in json.loads(status_file.read_text())["error"]


# --------------------------------------------------------------------------- #
# Switched off is an answer, not a gap
# --------------------------------------------------------------------------- #

OFF = {"type": "securityhub_hub", "label": "Security Hub", "status": "not_enabled", "count": None,
       "truncated": False, "items": None, "reason": "InvalidAccessException: not subscribed",
       "source": "aws securityhub describe-hub"}


# --------------------------------------------------------------------------- #
# Reading names
# --------------------------------------------------------------------------- #

def test_boolean_breakdowns_read_yes_and_no(monkeypatch):
    sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
    from discovery import by

    assert by("encrypted")([{"encrypted": True}, {"encrypted": False}, {"encrypted": True}]) == {
        "by_encrypted": {"yes": 2, "no": 1}
    }


def test_a_fetcher_note_is_valid_on_any_status():
    """A fetcher can explain an entry (a region with no Resource Explorer index
    was not searched), whatever the entry's status."""
    note = "Regions without an index were not searched."
    entries = [
        {"type": "resource_explorer_type", "scope": {"region": "us-east-1"}, "status": "not_enabled",
         "count": None, "truncated": False, "items": None, "reason": "no index", "note": note, "source": "s"},
        {"type": "resource_explorer_type", "scope": {"region": "us-east-2"}, "status": "ok",
         "count": 0, "truncated": False, "items": [], "note": note, "source": "s"},
    ]
    assert validate(_doc(*entries)) == []
