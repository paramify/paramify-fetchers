"""
The splunk fetchers, end to end against a local double.

Same method as the crowdstrike suite: the mock binds an ephemeral port
in-process and each fetcher runs as a subprocess with nothing but environment
variables, which is exactly how the runner invokes it. No credentials, no
network, no manually started server.

What these tests are actually for. Splunk's value types are **inconsistent**,
per field and per rendering. Verified against a real Splunk Enterprise 10.4.2:
under `output_mode=json`, `disabled` and `enableDataIntegrityControl` come back
as native JSON booleans and `totalEventCount` as an int — but `currentDBSizeMB`
is a string in the same response, and the Atom rendering the SDK parses makes
every one of them a string. In Python `"0"` is truthy, so a fetcher that reads
these raw reports every index disabled and every integrity control enabled, and
does it silently with `status: success` on top. That is the same failure shape
the crowdstrike set hit five times.

*These tests originally asserted that everything is a string, which is what the
SDK's integration tests implied. Running against a real instance showed that is
true of Atom and only partly true of JSON. The coercion was right; the premise
was wrong. Both renderings are now fixtures.*

The mock's fault switches (`SPLUNK_MOCK_*`) are read by the mock, which runs in
the **test** process — putting them in the fetcher subprocess's environment sets
them on the wrong side of the socket, and the test then passes for the wrong
reason. They go through `monkeypatch.setenv` here.

What is still NOT covered: what a real Splunk does. These tests pin the
fetcher's behaviour against the contract as documented in Splunk's SDK. Unlike
the CrowdStrike work, closing that gap is cheap — Splunk Enterprise has a free
download that runs locally — and `fetchers/splunk/README.md` says how.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "splunk"
MOCK_PATH = REPO_ROOT / "tools" / "splunk_mock.py"
CLIENT_PATH = FETCHER_ROOT / "_shared" / "splunk_client.py"

FETCHERS = ["indexes", "saved_searches", "users_roles", "fired_alerts"]


def _load_module(path: Path, name: str) -> Any:
    """Import a fetcher entry script by path; they are scripts, not a package."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mock_server() -> Iterator[str]:
    """
    Serve the Splunk double on an ephemeral port for the whole module.

    ThreadingHTTPServer, not HTTPServer: anything that retries opens a second
    connection while HTTP/1.1 keep-alive holds the first one open, and a
    single-threaded accept loop then blocks on the idle socket. The symptom is
    a test that hangs rather than fails, which cost the crowdstrike suite an
    afternoon.
    """
    mock = _load_module(MOCK_PATH, "splunk_mock")

    server = ThreadingHTTPServer(("127.0.0.1", 0), mock.SplunkMockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run_fetcher(name: str, base_url: str, evidence_dir: Path, **extra: str) -> tuple:
    """Run one fetcher exactly as the runner does: a subprocess, env only."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "PYTHONUNBUFFERED": "1",
        "EVIDENCE_DIR": str(evidence_dir),
        "SPLUNK_BASE_URL": base_url,
        "SPLUNK_USERNAME": "admin",
        "SPLUNK_PASSWORD": "mock-password",
        **extra,
    }
    result = subprocess.run(
        [sys.executable, str(FETCHER_ROOT / name / "fetcher.py")],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = evidence_dir / f"splunk_{name}.json"
    payload = json.loads(output.read_text()) if output.exists() else None
    return result.returncode, payload


# --- end to end ---------------------------------------------------------------


@pytest.mark.parametrize("name", FETCHERS)
def test_fetcher_collects_successfully(name: str, mock_server: str, tmp_path: Path) -> None:
    code, payload = _run_fetcher(name, mock_server, tmp_path)

    assert code == 0, f"{name} exited {code}"
    assert payload is not None, f"{name} wrote no evidence file"
    assert payload["status"] == "success"
    assert payload["api_failures"] == []
    assert payload["retrieved_at"].endswith("Z")


# How to reach each fetcher's allowlist. The keys are not written out here:
# calling describe() with an empty record returns the dict it always builds, so
# the expected set comes from the code rather than from a list beside it. The
# check is still real — `data` is read back from a subprocess run of the whole
# fetcher, so a fetcher that stopped routing through describe() fails even
# though both halves name the same function.
DESCRIBERS = {
    "indexes": lambda m: m.describe({}),
    "saved_searches": lambda m: m.describe({}),
    "fired_alerts": lambda m: m.describe_firing({}),
    "users_roles": lambda m: m.describe_user({}, 90),
}


def _allowed_keys(name: str) -> set:
    module = _load_module(FETCHER_ROOT / name / "fetcher.py", f"allowlist_{name}")
    return set(DESCRIBERS[name](module))


@pytest.mark.parametrize("name", FETCHERS)
def test_data_carries_only_the_allowlisted_fields(
    name: str, mock_server: str, tmp_path: Path
) -> None:
    """
    `data` is what describe() keeps, not Splunk's whole `content` block.

    Passing the collected records straight to evidence() shipped every setting
    Splunk returns — on an account that means the masked password and ~20 UI
    preferences, none of which this evidence set asks for. Upstream review
    caught it; this pins the routing so it cannot come back.
    """
    code, payload = _run_fetcher(name, mock_server, tmp_path)

    assert code == 0
    assert payload["data"], f"{name} returned no records to check"

    allowed = _allowed_keys(name)
    assert len(allowed) >= 10, "describe() probe returned suspiciously few keys"

    for record in payload["data"]:
        assert set(record) <= allowed, (
            f"{name} leaked {sorted(set(record) - allowed)} into data"
        )


def test_roles_travel_through_the_allowlist_too(
    mock_server: str, tmp_path: Path
) -> None:
    """
    users_roles puts roles in their own top-level key, so `data` alone does not
    cover it. A role record carries no password, but it carries the same kind
    of raw settings, and the two halves should not diverge.
    """
    module = _load_module(FETCHER_ROOT / "users_roles" / "fetcher.py", "allowlist_roles")
    allowed = set(module.describe_role({}))

    code, payload = _run_fetcher("users_roles", mock_server, tmp_path)

    assert code == 0
    assert payload["roles"]
    for record in payload["roles"]:
        assert set(record) <= allowed, (
            f"roles leaked {sorted(set(record) - allowed)}"
        )


def test_no_account_secret_or_ui_preference_reaches_the_evidence(
    mock_server: str, tmp_path: Path
) -> None:
    """
    The specific fields that prompted the fix, checked against the whole file.

    Scanned over the serialised payload rather than the parsed records, so a
    new top-level key added later cannot reintroduce them unnoticed.
    """
    code, payload = _run_fetcher("users_roles", mock_server, tmp_path)

    assert code == 0
    # The mock serves these on the admin account, as a real Splunk does.
    assert any(u["name"] == "admin" for u in payload["data"])

    serialised = json.dumps(payload)
    for leaked in ("password", "search_assistant", "search_syntax_highlighting",
                   "theme", "defaultApp"):
        assert leaked not in serialised, f"{leaked} reached the evidence payload"


@pytest.mark.parametrize("name", FETCHERS)
def test_fetcher_writes_evidence_even_when_auth_fails(
    name: str, mock_server: str, tmp_path: Path
) -> None:
    """
    The failure contract: exit non-zero, but still leave a readable file. A
    missing file is indistinguishable from a fetcher that never ran, which is
    the difference between "we have no evidence" and "we collected nothing".
    """
    code, payload = _run_fetcher(name, mock_server, tmp_path, SPLUNK_PASSWORD="wrong")

    assert code != 0
    assert payload is not None
    assert payload["status"] == "error"


def test_a_bearer_token_authenticates_as_well_as_a_password(
    mock_server: str, tmp_path: Path
) -> None:
    """
    A Splunk authentication token is the credential this should normally use —
    it carries the creating user's roles, expires, and is revocable without
    changing anyone's password. The username/password path exists because a
    fresh install has no tokens enabled yet, which is exactly when someone
    first runs this.

    The two use different header schemes — `Bearer <jwt>` against
    `Splunk <sessionKey>` — so neither one working proves the other does.
    """
    env = {"SPLUNK_TOKEN": "mock-token", "SPLUNK_USERNAME": "", "SPLUNK_PASSWORD": ""}
    code, payload = _run_fetcher("indexes", mock_server, tmp_path, **env)

    assert code == 0
    assert payload["collection"]["auth_method"] == "bearer_token"


# --- the string-boolean trap --------------------------------------------------


def test_both_of_splunks_value_renderings_are_decoded(
    mock_server: str, tmp_path: Path
) -> None:
    """
    A native JSON boolean and the string `"0"` mean the same thing, and both
    arrive from Splunk depending on the field and the output mode.

    `"0"` is truthy in Python, so reading `content["disabled"]` raw marks every
    index disabled; reading `content["enableDataIntegrityControl"]` raw marks
    every index tamper-evident, which is a cryptographic integrity claim
    invented out of a string. Both are silent — the run still succeeds and the
    numbers still look plausible.

    `legacy_string_rendering` carries `disabled: "0"` and
    `enableDataIntegrityControl: "1"`, so it must come back **enabled** and
    **integrity-on** — the exact inversion a raw read produces. Every other
    fixture uses the native types a live 10.4.2 sends.
    """
    _, payload = _run_fetcher("indexes", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["total_indexes"] == 9
    assert analysis["enabled_indexes"] == 7
    assert analysis["disabled_indexes"] == ["splunklogger"]

    # "0" -> enabled, not disabled. The inversion a truthiness read would give.
    assert "legacy_string_rendering" not in analysis["disabled_indexes"]
    # "1" -> integrity on, alongside the one carrying a native True.
    assert analysis["data_integrity_control_enabled"] == [
        "compliance_integrity",
        "legacy_string_rendering",
    ]
    assert analysis["data_integrity_control_disabled"] == [
        "_audit",
        "_internal",
        "main",
        "archived_by_script",
        "short_retention",
        "splunklogger",
    ]
    # "7776000" (a string) and 94608000 (an int) both parse.
    assert analysis["retention_days_by_index"]["legacy_string_rendering"] == 90
    assert analysis["retention_days_by_index"]["compliance_integrity"] == 1095


def test_a_value_that_cannot_be_read_is_reported_not_defaulted(
    mock_server: str, tmp_path: Path
) -> None:
    """
    An unreadable setting and a disabled control are different findings, and
    only one of them is the customer's.

    `metrics_pipeline` spells its values in ways this does not recognize. It
    must appear in neither the enabled nor the disabled list, and neither in
    integrity-on nor integrity-off — folding it into "off" would report a
    control failure the deployment did not have, and into "on" would claim
    tamper-evidence that is not there.
    """
    _, payload = _run_fetcher("indexes", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["indexes_with_unreadable_enabled_state"] == ["metrics_pipeline"]
    assert "metrics_pipeline" not in analysis["disabled_indexes"]

    assert analysis["data_integrity_control_unreadable"] == ["metrics_pipeline"]
    assert "metrics_pipeline" not in analysis["data_integrity_control_disabled"]
    assert "metrics_pipeline" not in analysis["data_integrity_control_enabled"]

    assert analysis["indexes_with_unreadable_retention"] == ["metrics_pipeline"]
    assert "metrics_pipeline" not in analysis["retention_days_by_index"]


def test_zero_retention_is_a_setting_not_a_missing_value(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `frozenTimePeriodInSecs: "0"` means freeze immediately. It is a real and
    very aggressive setting, and the most interesting one in a retention
    review — so it must survive as 0 rather than being folded in with the
    values that could not be read. Those are the two things `None` and `0`
    would otherwise both mean.
    """
    _, payload = _run_fetcher("indexes", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["retention_days_by_index"]["short_retention"] == 0
    assert analysis["shortest_retention_days"] == 0
    assert "short_retention" not in analysis["indexes_with_unreadable_retention"]


def test_archival_on_freeze_is_read_from_either_setting(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk deletes frozen buckets unless `coldToFrozenDir` OR
    `coldToFrozenScript` says otherwise. Reading only the first misses every
    deployment that archives with a script — `archived_by_script` here — and for
    a log store under a retention obligation that is the whole question.

    Both are real configurations: Splunk refuses to accept a
    `coldToFrozenScript` whose file does not exist, so a deployment holding one
    genuinely has that script on disk.
    """
    _, payload = _run_fetcher("indexes", mock_server, tmp_path)

    assert payload["analysis"]["indexes_archiving_on_freeze"] == [
        "compliance_integrity",
        "archived_by_script",
    ]


def test_the_audit_index_is_surfaced_on_its_own(mock_server: str, tmp_path: Path) -> None:
    """
    `_audit` is Splunk's own audit trail, so its retention and integrity
    settings are evidence in their own right rather than one row of six. A
    deployment that has shortened or disabled it has weakened the record of its
    own changes, which is what KSI-CMT-LMC is about.
    """
    _, payload = _run_fetcher("indexes", mock_server, tmp_path)
    audit = payload["analysis"]["audit_index"]

    assert audit["name"] == "_audit"
    assert audit["disabled"] is False
    assert audit["retention_days"] == 2184          # Splunk's stock ~6 years
    # A stock install ships data integrity control OFF everywhere, `_audit`
    # included. Asserting the opposite here would be asserting a deployment
    # nobody has by default.
    assert audit["data_integrity_control"] is False


# --- collection integrity -----------------------------------------------------


def test_pagination_walks_past_splunks_default_page_size(
    mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Splunk's `count` defaults to **30**, not to "all". A collection read without
    an explicit count returns the first 30 entries and looks complete.

    Here the mock is capped at two entries per page regardless of what is asked
    for, so a paginator that treats a short page as the last page collects two
    of six and reports success. `len(page) < count` is the obvious termination
    test and it is wrong.
    """
    monkeypatch.setenv("SPLUNK_MOCK_PAGE_SIZE", "2")

    _, payload = _run_fetcher("indexes", mock_server, tmp_path)

    assert payload["record_count"] == 9
    assert payload["analysis"]["total_indexes"] == 9
    assert payload["api_failures"] == []


def test_a_warning_in_messages_is_not_success(
    mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Splunk reports partial failures as HTTP 200 with the reason in `messages[]`
    — a search peer that did not answer, a knowledge object it could not read.
    `raise_for_status()` sees nothing wrong, so without this the run reports
    success over evidence that is quietly incomplete.
    """
    monkeypatch.setenv("SPLUNK_MOCK_MESSAGES", "1")

    code, payload = _run_fetcher("indexes", mock_server, tmp_path)

    assert code != 0
    assert payload["api_failures"]
    assert any(f.get("partial") for f in payload["api_failures"])


def test_a_missing_capability_is_recorded_with_splunks_own_reason(
    mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The most likely real failure is not a bad password — it is a role without
    the `list_indexes` capability. Splunk names the missing capability in the
    body, and that message is the difference between "wrong credentials" and
    "right credentials, wrong role", so it has to survive into the evidence.
    """
    monkeypatch.setenv("SPLUNK_MOCK_FORBID", "/services/data/indexes")

    code, payload = _run_fetcher("indexes", mock_server, tmp_path)

    assert code != 0
    failures = payload["api_failures"]
    assert failures
    assert any(f.get("status_code") == 403 for f in failures)
    assert any("list_indexes" in json.dumps(f.get("api_messages", "")) for f in failures)


def test_transient_errors_are_retried(
    mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A 503 with a Retry-After is what a busy or restarting Splunk answers.
    Failing the whole collection on the first one would make this unusable
    against anything under load.
    """
    monkeypatch.setenv("SPLUNK_MOCK_RATE_LIMIT", "2")

    code, payload = _run_fetcher("indexes", mock_server, tmp_path)

    assert code == 0
    assert payload["api_failures"] == []
    assert payload["record_count"] == 9


# --- provenance ---------------------------------------------------------------


def test_tls_verification_state_travels_with_the_evidence(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk's stock certificate on 8089 is self-signed, so running with
    verification off is common and not by itself a finding. It is still
    something an assessor should not have to guess about: evidence collected
    over an unauthenticated channel cannot rule out an interposed host.
    """
    _, verified = _run_fetcher("indexes", mock_server, tmp_path)
    assert verified["collection"]["tls_verified"] is True

    _, unverified = _run_fetcher(
        "indexes", mock_server, tmp_path, SPLUNK_VERIFY_SSL="false"
    )
    assert unverified["collection"]["tls_verified"] is False


def test_server_role_travels_with_the_evidence(mock_server: str, tmp_path: Path) -> None:
    """
    The same index list means different things on a single instance, a search
    head and one indexer of a cluster. `server_roles` is what says which, so it
    is collected before the indexes — that way the version and role survive even
    when the index call is the one that fails.
    """
    _, payload = _run_fetcher("indexes", mock_server, tmp_path)
    server = payload["collection"]["server"]

    assert server["version"] == "10.4.2"
    assert "indexer" in server["server_roles"]


def test_the_client_cannot_express_a_write() -> None:
    """
    Least privilege, enforced by construction rather than by review.

    Nothing in this category has any business writing to a customer's Splunk,
    and `request()` takes no method — it is GET or nothing. A client that cannot
    express a write cannot be talked into one by a later change, which is a
    stronger guarantee than a test that checks the verbs currently in use.
    """
    import inspect  # noqa: PLC0415

    client = _load_module(CLIENT_PATH, "splunk_client_verbs")
    source = inspect.getsource(client)

    assert "method" not in inspect.signature(client.SplunkClient.request).parameters
    for verb in ("requests.post", "requests.put", "requests.delete", "requests.patch"):
        # The one POST is the session login, which is how Splunk's own auth
        # endpoint works and is not a write to any customer data.
        occurrences = source.count(verb)
        if verb == "requests.post":
            assert occurrences == 1, "the only POST should be /services/auth/login"
        else:
            assert occurrences == 0, f"{verb} has no business in a read-only client"


# --- real recorded responses --------------------------------------------------
#
# `fetchers/splunk/tests/splunk_real_responses.json` was captured from a real Splunk
# Enterprise 10.4.2 (a local free-trial install), sanitized of hostnames, paths
# and the instance GUID. Unlike the crowdstrike corpus these are our own
# instance's responses, so they are committed rather than downloaded, and they
# are whole API responses rather than records unwrapped from one.
#
# A mock cannot catch a wrong assumption about types, because it is written from
# the same assumption as the fetcher. These can, and did: the first version of
# this client was built believing every Splunk value is a string.

REAL_RESPONSES = FETCHER_ROOT / "tests" / "splunk_real_responses.json"


@pytest.fixture(scope="module")
def real() -> dict:
    return json.loads(REAL_RESPONSES.read_text())


def test_the_real_response_types_are_mixed_and_all_of_them_decode(real: dict) -> None:
    """
    The correction that motivated this whole file.

    Under `output_mode=json` a live 10.4.2 sends `disabled` and
    `enableDataIntegrityControl` as native JSON **booleans**, `totalEventCount`
    and `frozenTimePeriodInSecs` as native **ints**, and `currentDBSizeMB` as a
    **string** — in one response. There is no single rule, which is exactly why
    every read goes through `as_bool` / `as_int`.

    This test asserts the mixture itself, so if CrowdStrike-style consistency
    ever arrives in a later Splunk the assumption is re-examined deliberately
    rather than discovered in production.
    """
    client = _load_module(CLIENT_PATH, "splunk_client_real")
    entries = real["indexes"]["entry"]

    def types(field: str) -> set:
        return {type(e["content"][field]).__name__ for e in entries if field in e["content"]}

    assert types("disabled") == {"bool"}
    assert types("enableDataIntegrityControl") == {"bool"}
    assert types("totalEventCount") == {"int"}
    assert types("frozenTimePeriodInSecs") == {"int"}
    assert types("currentDBSizeMB") == {"str"}, "the one string among the numbers"

    # And every one of them resolves rather than coming back unreadable.
    for entry in entries:
        content = entry["content"]
        assert client.as_bool(content["disabled"]) is not None
        assert client.as_bool(content["enableDataIntegrityControl"]) is not None
        assert client.as_int(content["totalEventCount"]) is not None
        assert client.as_int(content["currentDBSizeMB"]) is not None


# Keys the fetcher reads off something other than a raw index record — the
# runner's environment, the flattened record's own identity fields, and the
# result dict it builds itself. Everything else it asks a record for has to
# exist on a real one.
NON_RECORD_KEYS = {
    "name",                                    # added by flatten(), not from content
    "acl_app", "acl_owner", "acl_sharing",     # ditto
    "EVIDENCE_DIR", "LOG_LEVEL",               # os.environ
    "status", "api_failures", "analysis",      # the fetcher's own output dict
    "entry", "content", "acl", "paging", "messages",  # response envelope
}


def test_every_field_the_fetcher_reads_exists_on_a_real_index(real: dict) -> None:
    """
    The field names were taken from Splunk's SDK, which carries paths and
    parameters but no response models — so unlike gofalcon it could not confirm
    what an index record actually contains. This does.

    The list is pulled out of the fetcher's own AST rather than written out
    here. An earlier version restated the field names in the test, which meant
    the test agreed with a hand-written list instead of with the code: renaming
    a field in the fetcher left it passing. Same failure as a mock agreeing with
    the fetcher it was written from, one level up.
    """
    import ast  # noqa: PLC0415

    source = (FETCHER_ROOT / "indexes" / "fetcher.py").read_text()
    read_fields = {
        node.args[0].value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and len(node.args) >= 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    } - NON_RECORD_KEYS

    assert len(read_fields) >= 10, "AST extraction found suspiciously few fields"

    for entry in real["indexes"]["entry"]:
        missing = sorted(f for f in read_fields if f not in entry["content"])
        assert not missing, f"{entry['name']} has no {missing}"


def test_the_whole_summary_runs_over_real_records_without_an_unreadable(
    real: dict,
) -> None:
    """
    Every value on a real instance resolves. An unreadable one here would mean
    a rendering this client does not know about, which is the thing most likely
    to be silently wrong.
    """
    fetcher = _load_module(FETCHER_ROOT / "indexes" / "fetcher.py", "cs_splunk_real")
    client = _load_module(CLIENT_PATH, "splunk_client_real_fields")

    records = [client.flatten(e) for e in real["indexes"]["entry"]]
    analysis = fetcher.summarize(records)

    assert analysis["total_indexes"] == len(records)
    assert analysis["indexes_with_unreadable_enabled_state"] == []
    assert analysis["data_integrity_control_unreadable"] == []
    assert analysis["indexes_with_unreadable_retention"] == []


def test_a_real_instance_confirms_count_defaults_to_30(real: dict) -> None:
    """
    The claim the client's pagination is built on, measured rather than assumed.

    Captured with 46 indexes present: a request with no `count` returned 30 of
    them and said so in `paging.perPage`. A fetcher that does not set `count`
    collects the first 30 and reports success — and on a deployment with fewer
    than 30 indexes, which is most fresh installs, that bug is invisible.
    """
    meta = real["default_page_meta"]

    assert meta["entry_count"] == 30
    assert meta["paging"]["perPage"] == 30
    assert meta["paging"]["total"] == 46, "more indexes than one page, or this proves nothing"


def test_the_real_forbidden_response_names_the_capability(real: dict) -> None:
    """
    `_record_failure` keeps `messages` off a failed response because Splunk
    names the missing capability there — the difference between "wrong
    credentials" and "right credentials, wrong role".

    Captured from a user whose role lacks the capability. The wording was
    guessed when this was written and turns out to be exact.
    """
    for case in ("forbidden_read", "forbidden_write"):
        body = real[case]["body"]
        assert real[case]["status"] == 403
        text = body["messages"][0]["text"]
        assert "do not have permission" in text
        assert "requires capability:" in text

    assert "list_inputs" in real["forbidden_read"]["body"]["messages"][0]["text"]
    assert "indexes_edit" in real["forbidden_write"]["body"]["messages"][0]["text"]


def test_a_real_stock_install_has_data_integrity_control_off_everywhere(real: dict) -> None:
    """
    Worth pinning because it is the opposite of what a reviewer might assume,
    and it is the substance of the KSI-MLA-OSM / KSI-SVC-VRI claim.

    Splunk does not enable per-index data integrity control by default — not
    even on `_audit`, its own audit trail. Every index on a stock 10.4.2 has it
    off, so a deployment that wants the tamper-evidence has to have turned it
    on deliberately, and this fetcher reporting an empty
    `data_integrity_control_enabled` is the expected result rather than a
    collection failure.
    """
    client = _load_module(CLIENT_PATH, "splunk_client_real_dic")
    fetcher = _load_module(FETCHER_ROOT / "indexes" / "fetcher.py", "cs_splunk_real_dic")

    records = [client.flatten(e) for e in real["indexes"]["entry"]]
    analysis = fetcher.summarize(records)

    stock = [r for r in records if not str(r.get("name", "")).startswith(("compliance_", "archived_"))]
    assert all(client.as_bool(r["enableDataIntegrityControl"]) is False for r in stock)

    audit = analysis["audit_index"]
    assert audit["name"] == "_audit"
    assert audit["data_integrity_control"] is False


# --- saved searches ------------------------------------------------------------


def test_saved_searches_use_the_wildcard_namespace(
    mock_server: str, tmp_path: Path
) -> None:
    """
    The namespace decides how much of the deployment you see.

    `/services/saved/searches` is scoped to the calling user's app context. On
    the instance this was built against it returned **11 of 177** saved
    searches — a 94% undercount, with `status: success` and a plausible-looking
    number on top. `/servicesNS/-/-/saved/searches` wildcards user and app and
    returns all of them.

    This is measured, not assumed, and it is specific to knowledge objects:
    `data/indexes`, `authentication/users`, `authorization/roles` and
    `data/inputs/monitor` return identical counts either way, which is why the
    index fetcher does not need this and this one does.

    The mock serves the scoped path deliberately short, so a fetcher that used
    it would fail here rather than quietly collect a fraction.
    """
    fetcher = _load_module(
        FETCHER_ROOT / "saved_searches" / "fetcher.py", "cs_splunk_ss_path"
    )
    assert fetcher.SEARCHES_PATH.startswith("/servicesNS/-/-/"), (
        "saved searches must be read from the wildcard namespace"
    )

    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    assert payload["record_count"] == 10

    # And the scoped path really would have returned less, so the assertion
    # above is load-bearing rather than decorative.
    import urllib.request  # noqa: PLC0415

    req = urllib.request.Request(
        f"{mock_server}/services/saved/searches?output_mode=json&count=0",
        headers={"Authorization": "Bearer mock-token"},
    )
    with urllib.request.urlopen(req) as r:  # noqa: S310 - local mock
        scoped = json.loads(r.read())
    assert len(scoped["entry"]) < 10, "the scoped namespace should return fewer"


def test_actions_is_a_comma_separated_string_not_a_list(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `actions` arrives as `""`, `"outputtelemetry"`, `"email, summary_index"` —
    one string. Iterating it yields characters, and `"email" in actions` matches
    a substring of an unrelated action name.

    `Weekly access review digest` carries two, so a fetcher that failed to split
    would report one action named `"email, summary_index"` and count it once.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["by_action"] == {"email": 3, "summary_index": 2}

    weekly = next(
        s for s in payload["data"] if s["name"] == "Weekly access review digest"
    )
    assert weekly["actions"] == ["email", "summary_index"]


def test_a_scheduled_report_is_not_counted_as_an_alert(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `alert_type` is the literal string `"always"` for a scheduled report, which
    means it has no alerting condition at all. It is *truthy*, so testing the
    field for truth counts every scheduled report as an alert — on a stock
    install that is 159 of 174 searches misfiled.

    `Daily index growth report` is a report; `Failed authentication review` is
    an alert. Both are scheduled and enabled.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    by_name = {s["name"]: s for s in payload["data"]}
    assert by_name["Daily index growth report"]["is_alert"] is False
    assert by_name["Failed authentication review - hourly"]["is_alert"] is True
    assert analysis["total_alerts"] == 6


def test_scheduled_but_disabled_is_review_that_is_not_happening(
    mock_server: str, tmp_path: Path
) -> None:
    """
    A search can be scheduled and switched off, and a stock Splunk ships nine of
    them — every DMC alert is scheduled and disabled out of the box. Counting
    `is_scheduled` alone reports a deployment reviewing its logs when nothing is
    running.

    The KSI-MLA-RVL claim rests on `running_scheduled_searches`, which requires
    both, and the difference is named rather than dropped.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["scheduled_but_disabled"] == [
        "DMC Alert - Abnormal State of Indexer Processor"
    ]
    assert "DMC Alert - Abnormal State of Indexer Processor" not in (
        analysis["running_scheduled_search_names"]
    )
    assert analysis["running_scheduled_searches"] == 6


def test_an_alert_that_notifies_nobody_is_named(
    mock_server: str, tmp_path: Path
) -> None:
    """
    An alert with `alert.track` false and no actions runs, matches, and leaves
    no trace. From the outside it is indistinguishable from one that works —
    the schedule is live, the condition is set, and nothing reaches a human.

    Two independent things can save it: tracking puts it in Splunk's triggered
    -alerts list, an action sends it somewhere. Only when neither is present is
    it unrouted.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["running_alerts_that_notify_nobody"] == [
        "Privileged role change - unrouted"
    ]
    # Tracked but action-less still counts as notifying — it is reviewable in
    # Splunk's own alert list.
    by_name = {s["name"]: s for s in payload["data"]}
    # Tracked with an action.
    assert by_name["Failed authentication review - hourly"]["notifies"] is True
    # Tracked with NO action — still reviewable, in Splunk's own alert list.
    # Without this case the assertion cannot tell `track or actions` from
    # `actions` alone, which a mutation proved.
    tracked_only = by_name["Index growth anomaly - tracked only"]
    assert tracked_only["actions"] == []
    assert tracked_only["alert_tracked"] is True
    assert tracked_only["notifies"] is True


def test_an_unscheduled_search_is_not_evidence_of_review(
    mock_server: str, tmp_path: Path
) -> None:
    """
    A saved search with no schedule is somebody's bookmark. Folding it into the
    total would let a library of well-written detection queries stand in for
    review that never runs — which on a stock install would turn 152 ad-hoc
    searches into a very healthy-looking number.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["ad_hoc_searches"] == 1
    assert "Errors in the last 24 hours" not in analysis["running_scheduled_search_names"]


def test_saved_search_state_that_cannot_be_read_is_reported_not_defaulted(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Same rule as the index fetcher: an unreadable setting and a disabled one are
    different findings, and only one of them is the customer's.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["searches_with_unreadable_state"] == [
        "Half unreadable search",
        "Unreadable state search",
    ]
    assert "Unreadable state search" not in analysis["scheduled_but_disabled"]
    assert "Unreadable state search" not in analysis["running_scheduled_search_names"]


def test_saved_searches_decode_both_value_renderings(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `is_scheduled: "1"` and `disabled: "0"` must come back as a running search,
    the same as the native booleans elsewhere. `"0"` is truthy, so a raw read
    inverts it into a disabled one.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    by_name = {s["name"]: s for s in payload["data"]}
    legacy = by_name["Legacy string rendered search"]

    assert legacy["scheduled"] is True
    assert legacy["disabled"] is False
    assert legacy["running"] is True
    assert legacy["alert_tracked"] is True
    assert legacy["alert_severity"] == 5      # "5" -> 5


# --- saved searches, against the real capture ---------------------------------


def test_the_real_instance_confirms_the_namespace_undercount(real: dict) -> None:
    """
    The measurement the fetcher's endpoint choice rests on.

    Captured from a real 10.4.2: the app-scoped path returns a small fraction of
    what the wildcard namespace does. If a future Splunk makes them equal, this
    fails and the endpoint choice gets re-examined deliberately rather than
    being carried forever as folklore.
    """
    counts = real["saved_searches_namespace_counts"]

    assert counts["servicesNS_wildcard"] > counts["services_saved_searches"] * 5, (
        f"expected a large undercount, got {counts}"
    )
    assert counts["servicesNS_wildcard"] == 177


def test_every_saved_search_field_the_fetcher_reads_exists_on_a_real_record(
    real: dict,
) -> None:
    """
    Splunk's SDK carries paths and parameters but no response models, so the
    field names could not be confirmed from it. This confirms them.

    As with the index fetcher, the list comes out of the fetcher's AST rather
    than being restated here — a test that restates the code agrees with a
    hand-written list instead of with the code.
    """
    import ast  # noqa: PLC0415

    source = (FETCHER_ROOT / "saved_searches" / "fetcher.py").read_text()
    read_fields = {
        node.args[0].value
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and len(node.args) >= 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    } - NON_RECORD_KEYS - {"description"}   # description is genuinely optional

    assert len(read_fields) >= 8, "AST extraction found suspiciously few fields"

    for entry in real["saved_searches"]["entry"]:
        missing = sorted(f for f in read_fields if f not in entry["content"])
        assert not missing, f"{entry['name']} has no {missing}"


def test_the_real_stock_dmc_alerts_are_scheduled_and_disabled(real: dict) -> None:
    """
    The finding this fetcher exists to surface, present on a stock install.

    Splunk's Monitoring Console ships its alerts scheduled and switched off. A
    deployment that has not touched them has nine configured reviews running
    zero of them, and `is_scheduled` alone would report all nine as active.
    """
    client = _load_module(CLIENT_PATH, "splunk_client_real_ss")
    fetcher = _load_module(FETCHER_ROOT / "saved_searches" / "fetcher.py", "cs_ss_real")

    records = [client.flatten(e) for e in real["saved_searches"]["entry"]]
    analysis = fetcher.summarize(records)

    dmc = [n for n in analysis["scheduled_but_disabled"] if n.startswith("DMC Alert")]
    assert dmc, "the captured DMC alerts should be scheduled and disabled"
    for name in dmc:
        assert name not in analysis["running_scheduled_search_names"]


def test_the_real_actions_values_are_comma_separated_strings(real: dict) -> None:
    """
    `actions` is typed as a string on every real record, and the values seen on
    a stock install are `""`, `"outputtelemetry"` and `"summary_index"`.
    """
    entries = real["saved_searches"]["entry"]
    types = {type(e["content"]["actions"]).__name__ for e in entries if "actions" in e["content"]}

    assert types == {"str"}, f"actions should be a string, got {types}"


# --- pagination integrity ------------------------------------------------------
#
# These come from aiming the crowdstrike client's nine rounds of hard-won failure
# modes at this one. It is newer, and "it works against the happy path" is what
# that client also looked like before each of those rounds.


class OffsetHandler(BaseHTTPRequestHandler):
    """A server that pages badly in a specific, documented way."""

    mode = "healthy"
    total = 250

    def log_message(self, *args: Any) -> None:  # silence
        pass

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self._send({"sessionKey": "mock-session-key"})

    def do_GET(self) -> None:  # noqa: N802
        query = parse_qs(urlparse(self.path).query)
        count = int((query.get("count") or ["30"])[0])
        offset = int((query.get("offset") or ["0"])[0])

        start, end = offset, offset + count

        if OffsetHandler.mode == "ignores_offset":
            start, end = 0, count          # hand back page one, every time
        elif OffsetHandler.mode == "overlapping":
            # Repeat the previous page's last row, as an offset walk over a
            # collection being written to does. Still reaches the end — the
            # point is the duplicate, not a short tail.
            start = max(0, offset - 1)
        elif OffsetHandler.mode == "same_name_two_apps":
            # Two apps, each holding a saved search of the same name. Distinct
            # namespaced ids, identical `name`.
            self._send({
                "entry": [
                    {"name": "Errors", "content": {},
                     "id": "https://s:8089/servicesNS/nobody/search/saved/searches/Errors"},
                    {"name": "Errors", "content": {},
                     "id": "https://s:8089/servicesNS/nobody/audit/saved/searches/Errors"},
                ],
                "paging": {"total": 2, "perPage": count, "offset": offset},
                "messages": [],
            })
            return

        rows = [
            {"name": f"n{i}", "id": f"https://s:8089/x/n{i}", "content": {}}
            for i in range(start, min(end, OffsetHandler.total))
        ]
        self._send({
            "entry": rows,
            "paging": {"total": OffsetHandler.total, "perPage": count, "offset": offset},
            "messages": [],
        })


@pytest.fixture
def offset_client() -> Iterator[Any]:
    client_module = _load_module(CLIENT_PATH, "splunk_client_offset")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), OffsetHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        instance = client_module.SplunkClient(
            base_url=f"http://127.0.0.1:{httpd.server_address[1]}",
            username="admin",
            password="mock-password",
            timeout=30,
        )
        instance.authenticate()
        yield instance
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_a_server_that_ignores_offset_is_caught_not_believed(offset_client: Any) -> None:
    """
    Offset paging assumes the server honours `offset`. One that does not hands
    back page one every time — and the client's own counter still advances, so
    the walk terminates against `paging.total` looking perfectly healthy.

    Before the fix this returned **250 records of which only 50 were distinct**,
    with no failure recorded: the first page repeated five times, presented as a
    complete collection, while 200 real records were never seen. Duplicated
    evidence is bad; the missing 200 is worse.

    Same failure the crowdstrike client hit as a repeating cursor, arriving
    through integer offsets instead.
    """
    OffsetHandler.mode = "ignores_offset"
    OffsetHandler.total = 250

    collected = offset_client.collect("/x", page_size=50)
    names = [e["name"] for e in collected]

    assert len(names) == len(set(names)), "duplicates reached the evidence"
    assert len(collected) == 50, "should stop once the walk stops advancing"
    assert any(
        f.get("type") == "PaginationNotAdvancing" for f in offset_client.api_failures
    ), "a stalled walk must be recorded, so the run exits non-zero"


def test_overlapping_pages_are_deduplicated(offset_client: Any) -> None:
    """
    An offset walk over a collection being written to re-sees rows; Splunk
    offers no snapshot, so this is normal rather than a fault. Left alone it
    inflates every count in the analysis — `total_indexes`,
    `total_saved_searches` — by however many rows shifted under the walk.

    Deduplicated and logged, not recorded as a failure: failing a run for a
    condition a busy deployment produces routinely would make this unusable.
    """
    OffsetHandler.mode = "overlapping"
    OffsetHandler.total = 250

    collected = offset_client.collect("/x", page_size=50)
    names = [e["name"] for e in collected]

    assert len(names) == len(set(names))
    assert len(collected) == 250
    assert offset_client.api_failures == []


def test_the_healthy_case_still_collects_everything(offset_client: Any) -> None:
    """The dedupe must not cost a single legitimate record."""
    OffsetHandler.mode = "healthy"
    OffsetHandler.total = 250

    collected = offset_client.collect("/x", page_size=50)

    assert [e["name"] for e in collected] == [f"n{i}" for i in range(250)]
    assert offset_client.api_failures == []


def test_identity_is_the_namespaced_id_not_the_name(offset_client: Any) -> None:
    """
    `name` is not unique across a wildcard-namespace collection: two apps may
    each hold a saved search called the same thing. Deduplicating on name would
    silently drop one of them — turning a correctness fix into a new way to lose
    records, which is a bad trade.

    The entry `id` is a fully namespaced URL and is the only field that
    identifies a row across the whole collection.

    This drives the real client rather than restating its logic here; an earlier
    version of this test reimplemented the dedupe and would have passed no
    matter what the client did.
    """
    OffsetHandler.mode = "same_name_two_apps"
    OffsetHandler.total = 2

    collected = offset_client.collect("/x", page_size=50)

    assert len(collected) == 2, "same name in two apps must not collapse to one"
    assert {e["id"] for e in collected} == {
        "https://s:8089/servicesNS/nobody/search/saved/searches/Errors",
        "https://s:8089/servicesNS/nobody/audit/saved/searches/Errors",
    }
    assert offset_client.api_failures == []


# --- outputs nothing was asserting --------------------------------------------
#
# A mutation run over the judgement functions scored 62%: fifteen mutants
# survived. Most were not subtle logic — they were fields in the analysis that
# *no test looked at*, so any value passed. A summary field nobody asserts is a
# field that can silently become wrong, and these are the numbers an assessor
# reads first.


def test_index_totals_and_split_are_asserted(mock_server: str, tmp_path: Path) -> None:
    """
    `internal_indexes` / `customer_indexes` / `total_events` / `populated_indexes`
    all survived mutation because nothing checked them.

    The internal split matters for reading the evidence: Splunk creates `_audit`
    and `_internal` itself, so a deployment with nine indexes of which two are
    the product's own has seven of its own — and a reviewer comparing "indexes"
    against an inventory needs that distinction.
    """
    _, payload = _run_fetcher("indexes", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["total_indexes"] == 9
    # `_audit` and `_internal` are Splunk's own; the other seven are the
    # deployment's. Reading the `_` prefix wrongly collapses this to 0 or 9.
    assert analysis["internal_indexes"] == 2
    assert analysis["customer_indexes"] == 7
    assert analysis["internal_indexes"] + analysis["customer_indexes"] == analysis["total_indexes"]

    # Volume: four indexes hold events, five are configured and empty.
    assert analysis["populated_indexes"] == 4
    assert analysis["total_events"] == 107128
    assert analysis["total_size_mb"] == 264
    assert analysis["indexes_with_no_events"] == [
        "main",
        "compliance_integrity",
        "archived_by_script",
        "short_retention",
        "splunklogger",
    ]
    assert (
        analysis["populated_indexes"] + len(analysis["indexes_with_no_events"])
        == analysis["total_indexes"]
    )


def test_saved_search_grouping_is_asserted(mock_server: str, tmp_path: Path) -> None:
    """
    `by_app` and `by_owner` survived mutation for the same reason: nothing read
    them. They are how a reviewer tells the deployment's own detection content
    from what Splunk shipped — on a real stock install, 117 of 174 saved
    searches belong to `splunk_instrumentation` and are the vendor's, not the
    customer's.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["by_app"] == {
        "search": 8,
        "splunk_monitoring_console": 1,
        "audit_trail": 1,
    }
    assert analysis["by_owner"] == {"nobody": 9, "admin": 1}
    assert sum(analysis["by_app"].values()) == analysis["total_saved_searches"]
    assert sum(analysis["by_owner"].values()) == analysis["total_saved_searches"]


def test_one_unreadable_field_is_enough_to_flag_a_search(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `scheduled is None or disabled is None` — either alone is enough.

    A mutation flipping that `or` to `and` survived, because every fixture had
    *both* fields unreadable and the two operators gave the same answer.
    `Half unreadable search` has a schedule that parses and an enabled flag that
    does not, so only the `or` reports it.

    It matters: a search whose enabled state cannot be read must not be counted
    as running, and must not be silently dropped either.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert "Half unreadable search" in analysis["searches_with_unreadable_state"]
    assert "Half unreadable search" not in analysis["running_scheduled_search_names"]
    assert "Half unreadable search" not in analysis["scheduled_but_disabled"]


def test_the_schedule_of_each_running_search_is_recorded(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `cron_schedule` is the "persistently" in KSI-MLA-RVL — a search that runs on
    a defined cadence is the whole evidence claim, so the cadence itself has to
    survive into the output rather than being collapsed to a count.

    It survived mutation before this: `record.get("cron_schedule") or None`
    could be broken to always-None and every test still passed, which would have
    emptied `schedules` while `running_scheduled_searches` stayed 6.

    Only *running* searches appear — a cron on a disabled search is a cadence
    nothing is following.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["schedules"] == {
        "Failed authentication review - hourly": "0 * * * *",
        "Privileged role change - unrouted": "*/15 * * * *",
        "Daily index growth report": "30 2 * * *",
        "Weekly access review digest": "0 6 * * 1",
        "Index growth anomaly - tracked only": "0 */6 * * *",
        "Legacy string rendered search": "0 4 * * *",
    }
    assert len(analysis["schedules"]) == analysis["running_scheduled_searches"]
    assert "DMC Alert - Abnormal State of Indexer Processor" not in analysis["schedules"]


def test_a_running_search_with_no_next_run_time_is_reported_not_failed(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk leaves `next_scheduled_time` blank until it has dispatched a search
    once — the state right after creation, or after a restart. On the real
    instance four of sixteen running searches were in it.

    So it is reported, not counted against the deployment: it is the strongest
    single signal that a schedule is *live* rather than merely written down, but
    its absence has innocent explanations and treating it as a finding would
    flag every freshly-created alert.
    """
    _, payload = _run_fetcher("saved_searches", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["running_searches_with_no_next_run_time"] == [
        "Index growth anomaly - tracked only"
    ]
    # Still counted as running — a blank next-run is not a fault.
    assert "Index growth anomaly - tracked only" in analysis["running_scheduled_search_names"]
    assert payload["api_failures"] == []


# --- users and roles ----------------------------------------------------------


def test_a_roles_power_includes_what_it_inherits(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk splits a role's capabilities into `capabilities` (granted directly)
    and `imported_capabilities` (inherited via `imported_roles`).

    On a stock install `splunk-system-role` has **zero** direct capabilities and
    194 imported ones, including `admin_all_objects`. Reading the direct list
    alone reports a full-administrator role as holding nothing at all — the
    opposite of the truth, and silent.

    It is reported in its own bucket as well as the general one, because a
    reviewer scanning capability counts would otherwise skip straight past it.
    """
    _, payload = _run_fetcher("users_roles", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert "splunk-system-role" in analysis["administrative_roles"]
    assert analysis["roles_administrative_only_by_inheritance"] == ["splunk-system-role"]

    role = next(r for r in payload["roles"] if r["name"] == "splunk-system-role")
    assert role["direct_capability_count"] == 0
    assert role["capability_count"] > 0
    assert "admin_all_objects" in role["administrative_capabilities"]


def test_a_star_index_grant_does_not_reach_the_audit_trail(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk's `*` matches **non-internal** indexes only. Reaching `_audit`
    requires `_*` or the index named explicitly.

    The stock config proves it rather than the docs: `admin` is granted
    `["*", "_*"]` and `data_management_admin` names `_audit` alongside `*` —
    both redundant if `*` already covered them.

    Treating `*` as "everything" reports every role as able to read the audit
    trail, which inverts the finding this fetcher exists to produce: who can
    read the record of what everyone else did.
    """
    _, payload = _run_fetcher("users_roles", mock_server, tmp_path)
    analysis = payload["analysis"]

    # Reaches it: `_*` on admin and splunk-system-role, `_audit` named directly
    # on data_management_admin.
    assert sorted(analysis["roles_that_can_search_the_audit_trail"]) == [
        "admin",
        "data_management_admin",
        "splunk-system-role",
    ]
    # Granted `*` and nothing else — must NOT appear.
    for role in ("power", "user"):
        assert role not in analysis["roles_that_can_search_the_audit_trail"]
        entry = next(r for r in payload["roles"] if r["name"] == role)
        assert entry["can_search_all_non_internal"] is True
        assert entry["can_search_internal"] is False


def test_never_logged_in_is_not_the_same_as_dormant(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk omits `last_successful_login` entirely on an account that has never
    been used — not zero, not null. A provisioned account nobody ever touched
    and an account that went quiet are different findings, and collapsing them
    loses the one that matters more.
    """
    _, payload = _run_fetcher("users_roles", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["users_never_logged_in"] == ["contractor.temp"]
    assert [d["name"] for d in analysis["dormant_users"]] == ["former.admin"]
    # The never-used account must not also be counted as dormant.
    assert "contractor.temp" not in [d["name"] for d in analysis["dormant_users"]]
    assert analysis["dormant_threshold_days"] == 90


def test_local_accounts_are_separated_from_federated_ones(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `type` is "Splunk" for an account defined in Splunk itself, LDAP/SAML for a
    federated one. Local accounts bypass whatever SSO the deployment configured,
    so counting them together with federated ones hides exactly the accounts
    that are outside the identity provider's controls.
    """
    _, payload = _run_fetcher("users_roles", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["by_auth_type"] == {"Splunk": 4, "SAML": 1}
    assert analysis["federated_users"] == 1
    assert "soc.analyst" not in analysis["locally_defined_users"]
    assert len(analysis["locally_defined_users"]) == 4


def test_accounts_that_can_reach_nothing_are_named(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Two shapes of dead account, both worth a reviewer's attention: a user with
    no role at all, and a role with no index access. Neither is an error — a
    deployment may have reasons — but neither should be invisible.
    """
    _, payload = _run_fetcher("users_roles", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["users_with_no_role"] == ["orphaned.account"]
    assert analysis["roles_with_no_index_access"] == ["can_delete"]
    # A locked-out account still holding an administrative role.
    assert analysis["locked_out_users"] == ["former.admin"]
    assert "former.admin" in analysis["administrative_users"]


def test_the_real_roles_confirm_both_inheritance_traps(real: dict) -> None:
    """
    Both traps this fetcher handles, measured on a stock Splunk 10.4.2 rather
    than reasoned about.

    A mock cannot establish either: it would be written from the same
    assumptions as the fetcher and agree with it. These are the vendor's own
    default roles, shipped that way.
    """
    fetcher = _load_module(FETCHER_ROOT / "users_roles" / "fetcher.py", "cs_ur_real")
    client = _load_module(CLIENT_PATH, "splunk_client_ur")

    roles = {r["name"]: client.flatten(r) for r in real["roles"]["entry"]}

    # 1. splunk-system-role is a full administrator with an EMPTY direct list.
    system = roles["splunk-system-role"]
    assert system.get("capabilities") == [], "expected zero direct capabilities"
    assert "admin_all_objects" in (system.get("imported_capabilities") or [])
    assert "admin_all_objects" in fetcher.effective_capabilities(system)

    # 2. `*` and `_*` are granted separately, which they would not be if `*`
    #    already covered the internal indexes.
    admin = roles["admin"]
    assert set(admin.get("srchIndexesAllowed") or []) == {"*", "_*"}
    assert fetcher.can_read_audit(["*"]) is False
    assert fetcher.can_read_audit(["*", "_*"]) is True

    # And a stock role granted only `*` genuinely cannot reach the audit trail.
    assert fetcher.can_read_audit(
        fetcher.searchable_indexes(roles["user"])
    ) is False


# --- fired alerts -------------------------------------------------------------


def test_the_rollup_entry_is_not_counted_as_a_saved_search(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `/alerts/fired_alerts` returns a rollup entry named `-` carrying the total
    across every alert, alongside the per-search entries.

    Counting it as a saved search double-counts every firing and invents an
    alert named `-` in the evidence. It is excluded from the per-search
    breakdown and used as a cross-check instead — `counts_agree` is the
    assertion that the two views of the same number match.
    """
    _, payload = _run_fetcher("fired_alerts", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert "-" not in analysis["firings_by_search"]
    assert analysis["searches_that_fired"] == 2
    assert analysis["firings_by_search"] == {
        "Failed authentication review - hourly": 3,
        "Weekly access review digest": 1,
    }
    # The rollup said 4; the per-search counts sum to 4.
    assert analysis["total_reported_by_splunk"] == 4
    assert analysis["counts_agree"] is True


def test_summarize_excludes_the_rollup_even_if_it_is_handed_one(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `collect()` filters the rollup out before summarizing, so the end-to-end
    test above passes whether or not `summarize()` guards against it too.

    A mutation proved that: removing the guard inside `summarize()` changed
    nothing observable, because nothing ever handed it a rollup. This calls the
    function directly with one present, which is the only way to test the
    contract rather than the pipeline.
    """
    fetcher = _load_module(FETCHER_ROOT / "fired_alerts" / "fetcher.py", "cs_fa_direct")

    per_search = [
        {"name": "-", "triggered_alert_count": 4},
        {"name": "Real search", "triggered_alert_count": 4},
    ]
    analysis = fetcher.summarize(per_search, [], reported_total=4, truncated=False)

    assert "-" not in analysis["firings_by_search"]
    assert analysis["firings_by_search"] == {"Real search": 4}
    assert analysis["searches_that_fired"] == 1


def test_disagreeing_counts_are_reported_as_disagreeing(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `counts_agree` compares Splunk's own rollup against the per-search counts —
    if they differ, the collection missed something and a reviewer needs to see
    that rather than a confident single number.

    Asserting only the agreeing case is unfalsifiable: a mutation hardcoding
    `counts_agree: True` passed it. The field means nothing unless something
    proves it can come back False.
    """
    fetcher = _load_module(FETCHER_ROOT / "fired_alerts" / "fetcher.py", "cs_fa_disagree")

    per_search = [{"name": "Real search", "triggered_alert_count": 3}]

    agreeing = fetcher.summarize(per_search, [], reported_total=3, truncated=False)
    assert agreeing["counts_agree"] is True

    # Splunk says 7, the per-search counts sum to 3 — the collection is short.
    disagreeing = fetcher.summarize(per_search, [], reported_total=7, truncated=False)
    assert disagreeing["counts_agree"] is False
    assert disagreeing["total_reported_by_splunk"] == 7

    # No rollup at all is not a disagreement, just an absence.
    unknown = fetcher.summarize(per_search, [], reported_total=None, truncated=False)
    assert unknown["counts_agree"] is True


def test_an_unrecognized_severity_is_not_folded_into_a_known_band(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk's documented severity scale is 1-6. A value outside it is reported as
    `unknown-<n>` rather than clamped or bucketed — inventing a severity is
    worse than admitting the scale moved, and a compliance reviewer reading
    "high" for a value the vendor never defined has been misled.
    """
    _, payload = _run_fetcher("fired_alerts", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["firings_by_severity"] == {
        "critical": 2,   # severity 5
        "high": 1,       # severity 4
        "unknown-9": 1,  # off the documented scale
    }


def test_the_retention_window_caveat_travels_with_the_evidence(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Splunk deletes a triggered alert after `alert.expires` — 24 hours by
    default. So a small number here means "few in the window", not "few ever",
    and a quiet window is indistinguishable from a deployment with no alerting.

    The caveat is in the evidence body, not only in the fetcher's docstring,
    because whoever reads the JSON is the person who can be misled by the
    number. Each firing also carries its own expiry.
    """
    _, payload = _run_fetcher("fired_alerts", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert "retention_note" in analysis
    note = analysis["retention_note"].lower()
    assert "rolling window" in note or "not a complete history" in note
    assert "splunk_saved_searches" in analysis["retention_note"]

    for firing in payload["data"]:
        assert firing["expires"], "each firing should carry its own expiry"


def test_firing_recency_is_reported(mock_server: str, tmp_path: Path) -> None:
    """
    How recent the newest firing is, and how old the oldest retained one is.
    Together they describe the window the evidence actually covers, which is
    the only honest way to read a count that expires.
    """
    _, payload = _run_fetcher("fired_alerts", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["firings_collected"] == 4
    assert analysis["most_recent_firing_hours_ago"] is not None
    assert analysis["oldest_retained_firing_hours_ago"] is not None
    assert (
        analysis["most_recent_firing_hours_ago"]
        <= analysis["oldest_retained_firing_hours_ago"]
    )


# --- the failure paths, for every fetcher -------------------------------------
#
# These were only ever exercised against `splunk_indexes`. The other three have
# structurally different call patterns — `users_roles` collects two endpoints,
# `fired_alerts` makes one call per saved search that has fired — so "the client
# handles a 403" does not establish that each fetcher does the right thing with
# one.

# The first endpoint each fetcher reads, for aiming the fault injector.
FIRST_ENDPOINT = {
    "indexes": "/services/data/indexes",
    "saved_searches": "/servicesNS/-/-/saved/searches",
    "users_roles": "/servicesNS/-/-/authentication/users",
    "fired_alerts": "/servicesNS/-/-/alerts/fired_alerts",
}


@pytest.mark.parametrize("name", FETCHERS)
def test_every_fetcher_records_a_missing_capability(
    name: str, mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A 403 must exit non-zero, still write evidence, and keep Splunk's own
    "requires capability: X" text so the file says what to grant.
    """
    monkeypatch.setenv("SPLUNK_MOCK_FORBID", FIRST_ENDPOINT[name])

    code, payload = _run_fetcher(name, mock_server, tmp_path)

    assert code != 0, f"{name} should exit non-zero on a 403"
    assert payload is not None, f"{name} must still write evidence"
    failures = payload["api_failures"]
    assert any(f.get("status_code") == 403 for f in failures)
    assert any("list_indexes" in json.dumps(f.get("api_messages", "")) for f in failures)


@pytest.mark.parametrize("name", FETCHERS)
def test_every_fetcher_retries_transient_errors(
    name: str, mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    A 503 with Retry-After is what a busy or restarting Splunk answers. Failing
    the whole collection on the first one would make any of these unusable
    against a deployment under load.

    Note this bites harder on the multi-call fetchers: the rate limiter is
    per-path, and `fired_alerts` walks one path per saved search.
    """
    monkeypatch.setenv("SPLUNK_MOCK_RATE_LIMIT", "2")

    code, payload = _run_fetcher(name, mock_server, tmp_path)

    assert code == 0, f"{name} should ride out a transient 503"
    assert payload["api_failures"] == []


@pytest.mark.parametrize("name", FETCHERS)
def test_every_fetcher_treats_a_warning_as_incomplete(
    name: str, mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Splunk reports partial failure as HTTP 200 with the reason in `messages[]`
    — a search peer that did not answer. `raise_for_status()` sees nothing
    wrong, so without handling it every fetcher would report success over
    quietly incomplete evidence.
    """
    monkeypatch.setenv("SPLUNK_MOCK_MESSAGES", "1")

    code, payload = _run_fetcher(name, mock_server, tmp_path)

    assert code != 0, f"{name} should not call a partial response success"
    assert any(f.get("partial") for f in payload["api_failures"])


@pytest.mark.parametrize("name", FETCHERS)
def test_every_fetcher_pages_past_splunks_default(
    name: str, mock_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Splunk's `count` defaults to 30. With the mock capped at two entries per
    page regardless of what is asked for, a fetcher that treats a short page as
    the last page collects two of everything and reports success.

    Run for all four because each walks a different collection, and
    `fired_alerts` pages a nested one.
    """
    monkeypatch.setenv("SPLUNK_MOCK_PAGE_SIZE", "2")

    code, capped = _run_fetcher(name, mock_server, tmp_path)
    monkeypatch.delenv("SPLUNK_MOCK_PAGE_SIZE")
    _, uncapped = _run_fetcher(name, mock_server, tmp_path / "full")

    assert code == 0
    assert capped["api_failures"] == []
    assert capped["record_count"] == uncapped["record_count"], (
        f"{name} lost records when the server returned short pages"
    )
    assert _stable(capped["analysis"]) == _stable(uncapped["analysis"])


# Analysis fields derived from the wall clock. Two runs of the same fetcher
# seconds apart legitimately differ here, so comparing them across runs is a
# flaky assertion rather than a meaningful one.
#
# This is not hypothetical: the pagination test above compared whole analyses
# and failed once in a full-suite run and never again in isolation, because
# `fired_alerts` rounds "hours ago" to 0.01h — 36 seconds — and the two runs
# straddled a boundary. An intermittent test is worse than a failing one.
CLOCK_DERIVED = {
    "hours_ago",
    "most_recent_firing_hours_ago",
    "oldest_retained_firing_hours_ago",
    "days_since_login",
    "dormant_users",
    "retrieved_at",
}


def _stable(value: Any) -> Any:
    """Strip clock-derived fields so two runs are comparable."""
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in value.items() if k not in CLOCK_DERIVED}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value


def test_the_real_fired_alerts_shape_holds(real: dict) -> None:
    """
    Captured from a real Splunk 10.4.2 after triggering an alert deliberately —
    a stock install has nothing here, which is itself the point.

    Pins the two things the fetcher's correctness rests on: the rollup entry
    really is named `-` and really does carry the total across every alert, and
    each firing really does carry an expiry.
    """
    entries = real["fired_alerts"]["entry"]
    names = [e["name"] for e in entries]

    assert "-" in names, "the rollup entry is real, not defensive coding"
    rollup = next(e for e in entries if e["name"] == "-")
    per_search = [e for e in entries if e["name"] != "-"]

    total = rollup["content"]["triggered_alert_count"]
    assert total == sum(e["content"]["triggered_alert_count"] for e in per_search), (
        "the rollup is the sum of the per-search counts — which is why counting "
        "it as a search would double every figure"
    )

    for detail in real["fired_alert_detail"].values():
        for firing in detail["entry"]:
            content = firing["content"]
            assert content["expiration_time_rendered"], "every firing carries an expiry"
            assert isinstance(content["severity"], int), "severity is an int on the wire"
            assert content["savedsearch_name"]


def test_the_real_capture_confirms_firings_are_transient(real: dict) -> None:
    """
    The reason `retention_note` exists, measured rather than argued.

    Every captured firing expires exactly 24 hours after it triggered — Splunk's
    `alert.expires` default. So a collection run a day later sees none of them,
    and "0 alerts fired" means "none in the last 24 hours", never "none ever".

    Observed during this work: the same deployment reported 10 firings, then 0,
    then 17 within a few hours. The zero was a Splunk restart — the list is
    **also** eventually consistent while the instance comes up, which is a
    second way a run at the wrong moment reads as "nothing is alerting".
    """
    from datetime import datetime  # noqa: PLC0415

    fmt = "%Y-%m-%d %H:%M:%S"
    for detail in real["fired_alert_detail"].values():
        for firing in detail["entry"]:
            content = firing["content"]
            fired = datetime.strptime(content["trigger_time_rendered"][:19], fmt)
            expires = datetime.strptime(content["expiration_time_rendered"][:19], fmt)
            assert (expires - fired).total_seconds() == 24 * 3600, (
                "Splunk's default alert.expires is 24h; if this ever changes, "
                "the retention caveat needs rewording"
            )


def test_the_dormancy_threshold_includes_the_boundary_day() -> None:
    """
    An account idle for *exactly* the threshold is dormant.

    `idle >= dormant_days` could be flipped to `>` and survive: no fixture sat
    on the boundary. It matters because the threshold is the whole control — a
    reviewer setting 90 days means "90 days is too long", not "91".

    Unlike the CrowdStrike stale-host cutoff, this one is genuinely testable:
    `days_since` truncates to whole days, so a login exactly N days ago yields
    exactly N and lands on the boundary deterministically.
    """
    ur = _load_module(FETCHER_ROOT / "users_roles" / "fetcher.py", "cs_ur_dormant")
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415

    now = datetime.now(timezone.utc)

    def user_idle(days: float) -> dict:
        # A few seconds' margin so truncation lands on the intended whole day.
        login = now - timedelta(days=days, seconds=30)
        return ur.describe_user(
            {"name": "u", "roles": ["user"], "type": "Splunk",
             "last_successful_login": int(login.timestamp())},
            dormant_days=90,
        )

    assert user_idle(89)["dormant"] is False
    assert user_idle(90)["dormant"] is True, "the threshold day itself counts as dormant"
    assert user_idle(91)["dormant"] is True

    # And an account that has never logged in is never *dormant* — it is a
    # different finding, tracked separately.
    never = ur.describe_user(
        {"name": "n", "roles": ["user"], "type": "Splunk"}, dormant_days=90
    )
    assert never["never_logged_in"] is True
    assert never["dormant"] is False
    assert never["days_since_login"] is None


def test_index_home_path_prefers_the_expanded_form() -> None:
    """
    Splunk returns both `homePath` (`$SPLUNK_DB/audit/db`) and
    `homePath_expanded` (`/opt/splunk/var/lib/splunk/audit/db`). The expanded
    one is what tells a reviewer where the data physically is — which disk,
    which mount — so it is preferred, with the variable form as a fallback
    rather than nothing.

    A fallback chain, not a passthrough: mutating the `or` breaks the
    preference silently, and both fields being present in every fixture meant
    nothing noticed.
    """
    idx = _load_module(FETCHER_ROOT / "indexes" / "fetcher.py", "cs_idx_home")

    both = idx.describe({
        "name": "i", "homePath": "$SPLUNK_DB/audit/db",
        "homePath_expanded": "/opt/splunk/var/lib/splunk/audit/db",
    })
    assert both["home_path"] == "/opt/splunk/var/lib/splunk/audit/db"

    # Only the variable form available — better than reporting nothing.
    raw_only = idx.describe({"name": "i", "homePath": "$SPLUNK_DB/audit/db"})
    assert raw_only["home_path"] == "$SPLUNK_DB/audit/db"

    assert idx.describe({"name": "i"})["home_path"] is None


# --- manifest completeness ----------------------------------------------------


@pytest.mark.parametrize("name", FETCHERS)
def test_the_manifest_declares_everything_the_runner_needs(name: str) -> None:
    """
    A structural guard, added after a bad edit silently deleted `config_schema`,
    `evidence_set` and `ksis` from two of these manifests.

    Nothing caught it. The JSON schema does not require those sections, so
    validation passed; and the whole suite passed too, because every test
    invokes fetchers **directly with environment variables** rather than through
    the runner's config injection. The only thing that noticed was a manual
    `paramify run`, where both fetchers ignored the manifest's `base_url`, fell
    back to `https://localhost:8089`, and burned 30 and 45 seconds retrying a
    refused connection.

    So: assert the sections exist, because "the schema allows it to be missing"
    and "this fetcher works without it" are different questions.
    """
    import yaml  # noqa: PLC0415

    manifest = yaml.safe_load((FETCHER_ROOT / name / "fetcher.yaml").read_text())

    assert manifest["name"] == f"splunk_{name}"
    assert manifest["category"] == "splunk"

    # Every knob the fetcher reads from the environment must be declared, or the
    # runner strips it and the fetcher silently uses its default.
    config = manifest.get("config_schema") or {}
    assert "base_url" in config, "without this the runner cannot point it at a deployment"
    assert config["base_url"]["env"] == "SPLUNK_BASE_URL"
    for key in ("ca_bundle", "verify_ssl"):
        assert key in config, f"{key} must be declarable"

    # Auth: all three optional, so a manifest supplies whichever it has.
    secrets = {s["name"]: s for s in manifest.get("secrets") or []}
    assert set(secrets) == {"token", "username", "password"}
    for s in secrets.values():
        assert s["required"] is False, "one mechanism or the other, never both mandatory"
        assert s.get("description"), "shown in `paramify describe` and the TUI"

    evidence_set = manifest.get("evidence_set") or {}
    assert evidence_set.get("reference_id", "").startswith("EVD-SPLK-")
    assert evidence_set.get("instructions")
    assert evidence_set.get("description")

    # KSIs must be 2026 mnemonics, not the pre-CR26 numbered scheme the repo
    # migrated off in commit ad2b2a5.
    ksis = manifest.get("ksis") or []
    assert ksis, "every fetcher here claims at least one indicator"
    for k in ksis:
        assert re.fullmatch(r"KSI-[A-Z]{3}-[A-Z]{3}", k), f"{k} is not a 2026 mnemonic"


# --- through the runner --------------------------------------------------------
#
# Everything above invokes fetcher.py directly. That is the right shape for
# testing collection logic, and it is blind to an entire class of breakage: the
# manifest is only read by the *runner*, so a fetcher can be perfect and the
# shipped manifest still unusable.
#
# This is not hypothetical. A careless `re.S` regex once ate `config_schema`,
# `evidence_set` and `ksis` out of two manifests. The schema did not require
# them, every test in this file passed, and the damage only surfaced on a manual
# `paramify run`. The test below is that manual run, automated: it drives
# `framework.api.run` over the manifest we actually ship, against the mock.


@pytest.fixture
def mock_manifest(mock_server: str, tmp_path: Path) -> dict:
    """The shipped example manifest, repointed at the ephemeral mock.

    Loading `examples/splunk_mock_run.yaml` rather than building a dict inline
    is deliberate — it puts the example under test, so it cannot rot unnoticed.
    Only the two environment-specific values are rewritten.
    """
    import yaml

    manifest = yaml.safe_load((REPO_ROOT / "examples" / "splunk_mock_run.yaml").read_text())
    manifest["run"]["output_dir"] = str(tmp_path / "evidence")
    for entry in manifest["run"]["fetchers"]:
        entry["config"]["base_url"] = mock_server
    return manifest


def test_the_shipped_manifest_runs_all_four_through_the_runner(
    mock_manifest: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from framework import api

    monkeypatch.setenv("SPLUNK_TOKEN", "mock-token")

    summary = api.run(mock_manifest, REPO_ROOT)

    assert summary["ok"] is True, summary
    invocations = summary["invocations"]
    assert [r["fetcher_name"] for r in invocations] == [
        "splunk_indexes",
        "splunk_saved_searches",
        "splunk_users_roles",
        "splunk_fired_alerts",
    ]
    for r in invocations:
        assert r["exit_code"] == 0, r
        assert r["outputs"], f"{r['fetcher_name']} produced no evidence file"


def test_the_runner_writes_a_complete_envelope_for_every_fetcher(
    mock_manifest: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The envelope is assembled by the runner from the manifest, so this is
    what catches a manifest that lost its `evidence_set` or its `ksis`."""
    from framework import api

    monkeypatch.setenv("SPLUNK_TOKEN", "mock-token")

    summary = api.run(mock_manifest, REPO_ROOT)
    run_dir = Path(summary["run_dir"])

    written = sorted(p.name for p in run_dir.glob("splunk_*.json"))
    assert written == [
        "splunk_fired_alerts.json",
        "splunk_indexes.json",
        "splunk_saved_searches.json",
        "splunk_users_roles.json",
    ]

    for path in run_dir.glob("splunk_*.json"):
        envelope = json.loads(path.read_text())
        assert envelope["schema_version"], path.name
        meta = envelope["metadata"]
        assert meta["category"] == "splunk"
        assert meta["status"] == "success"
        assert meta["fetcher_version"], path.name

        # The block the regex destroyed. Present, and carrying real text —
        # an empty string would satisfy a mere key check.
        evidence_set = meta["evidence_set"]
        assert evidence_set["reference_id"].startswith("EVD-SPLK-")
        assert len(evidence_set["instructions"]) > 100, "instructions were truncated"
        assert evidence_set["description"]

        assert envelope["payload"]["status"] == "success"
        assert envelope["payload"]["record_count"] > 0


def test_a_manifest_missing_its_evidence_set_is_caught_here(
    mock_manifest: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard above only earns its place if it fails when the block is gone.

    Simulates the regex damage by discovering the fetcher, stripping
    `evidence_set` from the loaded manifest, and confirming the envelope comes
    out incomplete — i.e. that the assertion above is falsifiable rather than
    asserting something the runner guarantees anyway.
    """
    from framework import api

    monkeypatch.setenv("SPLUNK_TOKEN", "mock-token")

    fetchers = api.discover(REPO_ROOT)["fetchers"]
    assert "splunk_indexes" in fetchers, "precondition"

    original = (FETCHER_ROOT / "indexes" / "fetcher.yaml").read_text()
    damaged = re.sub(r"\nevidence_set:.*?\nksis:", "\nksis:", original, flags=re.S)
    assert "evidence_set" not in damaged, "the simulated damage must actually land"

    try:
        (FETCHER_ROOT / "indexes" / "fetcher.yaml").write_text(damaged)
        summary = api.run(mock_manifest, REPO_ROOT)
        envelope = json.loads(
            (Path(summary["run_dir"]) / "splunk_indexes.json").read_text()
        )
        assert not envelope["metadata"].get("evidence_set"), (
            "a manifest with no evidence_set still produced one — this test "
            "cannot detect the damage it exists to detect"
        )
    finally:
        (FETCHER_ROOT / "indexes" / "fetcher.yaml").write_text(original)
