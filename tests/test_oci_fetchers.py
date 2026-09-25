"""Every OCI fetcher, run as a subprocess against recorded responses.

No credentials, no network, no tenancy. Each fetcher is started the way the
runner starts it, with `tests/oci_replay_bootstrap` on PYTHONPATH so
Python's own `sitecustomize` hook patches the SDK's HTTP layer before the
fetcher imports anything. Nothing in `fetchers/oci/` knows the test exists.

WHAT THIS PROVES that the unit tests do not: the whole path runs — credential
resolution, client construction, request signing, the SDK's deserialization into
its generated models, pagination, the collector's guard/record behaviour, the
evidence file, and the exit code.

WHAT IT DOES NOT PROVE: the tenancy's real numbers. Cassette bodies are trimmed
to three items per list (`tools/oci_cassette.MAX_LIST_ITEMS`), so these assert
wiring, shape and field presence — never a count that came off the live
tenancy. The live runs are recorded in the commit messages; this suite is what
survives the trial lapsing.

Re-record with `python tools/oci_capture.py` after changing which calls a
fetcher makes. An unmatched request raises rather than returning an empty body,
so drift fails here instead of quietly collecting nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "oci"
CASSETTE_DIR = FETCHER_ROOT / "tests" / "cassettes"
BOOTSTRAP = REPO_ROOT / "tests" / "oci_replay_bootstrap"

sys.path.insert(0, str(REPO_ROOT / "tests"))
from oci_test_key import throwaway_signing_key  # noqa: E402

pytest.importorskip("oci", reason="the OCI SDK deserializes the recorded responses")

FETCHERS = sorted(
    d.name for d in FETCHER_ROOT.iterdir()
    if d.is_dir() and not d.name.startswith("_") and (d / "fetcher.py").exists()
) if FETCHER_ROOT.is_dir() else []

# The summary key each fetcher must produce, as a shape check on the evidence.
REQUIRED_SUMMARY_KEY = {
    "audit_logging_events": "change_category_coverage_percentage",
    "bastion_sessions": "total_bastions",
    "block_volume_encryption": "total_volumes",
    "certificates": "total_certificates",
    "cloud_guard_posture": "cloud_guard_status",
    "compute_instances": "total_instances",
    "data_service_exposure": "total_autonomous_databases",
    "dependency_vulnerabilities": "adm_service_readable",
    "dr_plan_executions": "total_executions",
    "iam_password_policy": "identity_domains",
    "iam_policies": "total_policies",
    "iam_users_credentials": "total_users",
    "network_exposure": "internet_ingress_rules",
    "object_storage_buckets": "total_buckets",
    "operator_access_control": "provider_access_requests",
    "vault_keys": "total_keys",
    "zpr_policies": "zpr_enabled",
}


@pytest.fixture(scope="session")
def signing_key(tmp_path_factory) -> str:
    """A throwaway RSA key, so request signing runs for real under replay."""
    return throwaway_signing_key()


def run_fetcher(name: str, signing_key: str, evidence_dir: Path, **extra_env):
    """Start one fetcher as the runner would, with replay bootstrapped."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(evidence_dir),
        "PYTHONPATH": str(BOOTSTRAP),
        "EVIDENCE_DIR": str(evidence_dir),
        # Cassette replay.
        "OCI_CASSETTE": str(CASSETTE_DIR / f"{name}.json"),
        "OCI_CASSETTE_MODE": "replay",
        # The API-key auth path, so no ~/.oci/config is read.
        "OCI_TENANCY_OCID": "ocid1.tenancy.oc1..aaaaaaaatenancy",
        "OCI_USER_OCID": "ocid1.user.oc1..aaaaaaaauser",
        "OCI_FINGERPRINT": "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
        "OCI_PRIVATE_KEY": signing_key,
        "OCI_REGION": "us-phoenix-1",
        **extra_env,
    }
    return subprocess.run(
        [sys.executable, str(FETCHER_ROOT / name / "fetcher.py")],
        env=env, capture_output=True, text=True, timeout=300,
    )


def evidence_of(evidence_dir: Path) -> dict:
    files = list(evidence_dir.glob("oci_*.json"))
    assert len(files) == 1, f"expected one evidence file, got {[f.name for f in files]}"
    return json.loads(files[0].read_text())


@pytest.mark.parametrize("name", FETCHERS)
def test_fetcher_runs_end_to_end_against_recorded_responses(name, signing_key, tmp_path):
    """Exit 0, one evidence file, no API failures, and the summary shape."""
    assert (CASSETTE_DIR / f"{name}.json").exists(), (
        f"no cassette for {name} — run `python tools/oci_capture.py {name}`"
    )
    result = run_fetcher(name, signing_key, tmp_path)
    assert result.returncode == 0, f"{name} exited {result.returncode}\n{result.stderr[-2000:]}"

    evidence = evidence_of(tmp_path)
    assert set(evidence) == {"metadata", "results", "summary"}
    assert evidence["metadata"]["api_failures"] == []
    assert evidence["metadata"]["partial_failure"] is False
    assert evidence["metadata"]["auth_method"] == "api_key"
    assert REQUIRED_SUMMARY_KEY[name] in evidence["summary"]


@pytest.mark.parametrize("name", FETCHERS)
def test_no_secret_material_reaches_the_evidence(name, signing_key, tmp_path):
    """The signing key is in the environment of every run; none may copy it."""
    run_fetcher(name, signing_key, tmp_path)
    text = (tmp_path / next(p.name for p in tmp_path.glob("oci_*.json"))).read_text()
    assert "BEGIN RSA PRIVATE KEY" not in text
    assert "PRIVATE KEY" not in text
    # A few lines of the key itself, in case it were copied re-encoded.
    for chunk in signing_key.splitlines()[1:4]:
        assert chunk not in text


def test_an_unmatched_request_fails_the_run_rather_than_collecting_nothing(signing_key, tmp_path):
    """The failure mode this whole design exists to avoid.

    Pointed at an empty cassette, a fetcher must not exit 0 with empty results:
    replay raises, the collector records it, and the run exits non-zero.
    """
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"interactions": []}))
    result = run_fetcher("iam_users_credentials", signing_key, tmp_path,
                         OCI_CASSETTE=str(empty))
    assert result.returncode != 0
    evidence = evidence_of(tmp_path)
    assert evidence["metadata"]["partial_failure"] is True
    assert evidence["metadata"]["api_failures"], "an unmatched request must be recorded"


def test_every_fetcher_has_a_cassette_and_the_fixture_stays_small():
    """A new fetcher without a cassette would silently skip this whole suite."""
    missing = [n for n in FETCHERS if not (CASSETTE_DIR / f"{n}.json").exists()]
    assert missing == [], f"no cassette recorded for: {missing}"

    total_kb = sum(p.stat().st_size for p in CASSETTE_DIR.glob("*.json")) / 1024
    # PR #42's review cut a 7,936-line fixture as 59% of the diff. Trimming lists
    # to three items keeps every shape at a fraction of that; this is the guard
    # that keeps it true as the tenancy grows.
    assert total_kb < 400, f"cassettes have grown to {total_kb:.0f} KB — re-trim"


def test_cassettes_carry_no_tenancy_identifiers():
    """Recording redacts; this is what proves the redaction actually ran."""
    import re

    for path in sorted(CASSETTE_DIR.glob("*.json")):
        text = path.read_text()
        # Stand-ins are user<6 hex>@example.com — distinct per original, so two
        # users never collide on one cassette key.
        emails = {e for e in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
                  if not re.fullmatch(r"user[0-9a-f]{6}@example\.com", e)}
        assert not emails, f"{path.name} carries {emails}"
        real_tenancy = [t for t in re.findall(r"ocid1\.tenancy\.oc1\.\.[a-z0-9]+", text)
                        if t != "ocid1.tenancy.oc1..aaaaaaaatenancy"]
        assert not real_tenancy, f"{path.name} carries a real tenancy OCID"
        hosts = {h for h in re.findall(r"idcs-[0-9a-f]{32}", text) if not h.startswith("idcs-" + "0" * 26)}
        assert not hosts, f"{path.name} carries a real identity domain host: {hosts}"
        for body in (i["body"] for i in json.loads(text)["interactions"]):
            try:
                parsed = json.loads(body)
            except ValueError:
                continue
            items = parsed.get("items", []) if isinstance(parsed, dict) else []
            people = {p.get("resourceName") for p in items
                      if isinstance(p, dict) and p.get("detectorId") == "IAAS_ACTIVITY_DETECTOR"
                      and p.get("resourceType") == "User"} - {"Example User"}
            assert not people, f"{path.name} names the person behind an activity problem: {people}"


def test_redaction_covers_every_identifier_it_claims_to():
    """The cassette test above guards the committed FILES; this guards the CODE.

    Making `redact` a no-op leaves the recorded cassettes untouched and is only
    caught the next time someone re-records — which is far too late. Found by
    mutation.
    """
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    from oci_cassette import redact

    raw = json.dumps({
        "tenancy": "ocid1.tenancy.oc1..aaaaaaaareal0000000000000000000000000",
        "user": "ocid1.user.oc1..aaaaaaaareal1111111111111111111111111",
        "name": "someone@example.org",
        "fingerprint": "f3:57:06:12:a8:46:1c:37:f4:67:fe:64:b7:c7:77:68",
        "domain": "https://idcs-0123456789abcdef0123456789abcdef.identity.oraclecloud.com:443",
        "compartment": "ocid1.compartment.oc1..keptbecauseitnamesnoperson",
    })
    cleaned = redact(raw)
    assert "aaaaaaaareal0000000000000000000000000" not in cleaned
    assert "aaaaaaaareal1111111111111111111111111" not in cleaned
    assert "someone@example.org" not in cleaned and "@example.com" in cleaned
    assert "f3:57:06" not in cleaned
    assert "0123456789abcdef0123" not in cleaned and redact(cleaned) == cleaned
    # Compartment OCIDs are kept on purpose: they name no person and the
    # evidence is unreadable without them.
    assert "ocid1.compartment.oc1..keptbecauseitnamesnoperson" in cleaned


# --- the permission paths, which running as tenancy admin never exercises -----
#
# A live run as a restricted collector showed OCI's denial shape — a missing
# grant is 404 NotAuthorizedOrNotFound, as staging had also shown. What is worth
# testing on every run is the handling, so the recorded response is replaced
# with that exact shape.

NOT_AUTHORIZED = json.dumps({
    "code": "NotAuthorizedOrNotFound",
    "message": "Authorization failed or requested resource not found.",
})
FORBIDDEN = json.dumps({"code": "NotAuthorized", "message": "The required permissions are missing."})


def _cassette_with(name, tmp_path, match, status, body):
    """A copy of a fetcher's cassette with one interaction replaced by an error."""
    data = json.loads((CASSETTE_DIR / f"{name}.json").read_text())
    hits = 0
    for interaction in data["interactions"]:
        if match in interaction["key"]:
            interaction["status"], interaction["body"] = status, body
            interaction["headers"] = {"content-type": "application/json"}
            hits += 1
    assert hits, f"no interaction in {name}'s cassette matches {match!r} — re-record?"
    path = tmp_path / f"{name}-denied.json"
    path.write_text(json.dumps(data))
    return path


def _status_file(tmp_path):
    path = tmp_path / "status.json"
    return path, {"FETCHER_STATUS_FILE": str(path)}


def test_a_denied_call_fails_the_run_and_names_the_operation(signing_key, tmp_path):
    """404 NotAuthorizedOrNotFound on the central call: exit 1, and say which call."""
    cassette = _cassette_with("iam_users_credentials", tmp_path, "/users?", 404, NOT_AUTHORIZED)
    status_path, status_env = _status_file(tmp_path)
    result = run_fetcher("iam_users_credentials", signing_key, tmp_path,
                         OCI_CASSETTE=str(cassette), **status_env)

    assert result.returncode == 1
    evidence = evidence_of(tmp_path)
    assert evidence["metadata"]["partial_failure"] is True
    failures = evidence["metadata"]["api_failures"]
    assert any(f["operation"] == "identity.list_users" for f in failures), failures
    assert any(f.get("status") == "404" for f in failures), failures
    # And the runner is told why, rather than reading the tail of stderr.
    reported = json.loads(status_path.read_text())
    assert reported["code"] in {"bad_config", "not_authorized", "partial_failure"}
    assert "list_users" in reported["error"]


def test_a_denied_call_never_reads_as_a_clean_empty_result(signing_key, tmp_path):
    """The failure this category exists to avoid: zero findings from zero reads."""
    cassette = _cassette_with("object_storage_buckets", tmp_path, "/b?compartmentId", 403, FORBIDDEN)
    result = run_fetcher("object_storage_buckets", signing_key, tmp_path,
                         OCI_CASSETTE=str(cassette))

    assert result.returncode != 0, "a forbidden listing must not exit 0"
    summary = evidence_of(tmp_path)["summary"]
    # Reporting `object_storage_readable: false` is the point — a reader must be
    # able to tell "no public buckets" from "no buckets could be read".
    assert summary["object_storage_readable"] is False
    assert summary["total_buckets"] == 0


def test_a_service_that_was_never_enabled_is_evidence_not_a_failure(signing_key, tmp_path):
    """ZPR answers 404 until it is switched on, and that answer IS the evidence.

    A denied call returns the same 404, so the two are told apart by shape rather
    than by code: the configuration is unreadable AND no policies came back, which
    is what "never enabled" looks like. Exit 0, reporting zpr_enabled false.
    """
    data = json.loads((CASSETTE_DIR / "zpr_policies.json").read_text())
    for interaction in data["interactions"]:
        if "zpr/20240301/configuration" in interaction["key"]:
            interaction["status"], interaction["body"] = 404, NOT_AUTHORIZED
            interaction["headers"] = {"content-type": "application/json"}
        elif "zprPolicies" in interaction["key"]:
            interaction["body"] = json.dumps({"items": []})
    cassette = tmp_path / "zpr-off.json"
    cassette.write_text(json.dumps(data))

    result = run_fetcher("zpr_policies", signing_key, tmp_path, OCI_CASSETTE=str(cassette))

    assert result.returncode == 0, f"a disabled service must not fail the run\n{result.stderr[-800:]}"
    evidence = evidence_of(tmp_path)
    assert evidence["summary"]["zpr_enabled"] is False
    assert evidence["metadata"]["api_failures"] == []
    assert evidence["metadata"]["skipped_calls"], "the tolerated call must still be recorded"


def test_a_denied_configuration_with_readable_policies_is_a_permission_gap(signing_key, tmp_path):
    """The distinction the fetcher draws, and the reason the test above is shaped as it is.

    ZPR's configuration 404s both when the service was never enabled and when the
    caller lacks `read zpr-configuration`. Policies coming back anyway settles it:
    the service is plainly on, so the 404 is a missing policy statement and must
    fail the run rather than reporting ZPR as disabled.
    """
    cassette = _cassette_with("zpr_policies", tmp_path, "zpr/20240301/configuration",
                              404, NOT_AUTHORIZED)
    result = run_fetcher("zpr_policies", signing_key, tmp_path, OCI_CASSETTE=str(cassette))

    assert result.returncode == 1
    evidence = evidence_of(tmp_path)
    assert evidence["summary"]["zpr_enabled"] is None, "unknown, not disabled"
    assert any("permission" in f["message"] for f in evidence["metadata"]["api_failures"])


def test_one_denied_compartment_of_several_is_a_partial_failure(signing_key, tmp_path):
    """A per-resource denial must not take down the whole collection.

    The detail call for one bastion is denied; the bastion still appears, marked
    as unread rather than as compliant, and the run reports partial failure.
    """
    cassette = _cassette_with("bastion_sessions", tmp_path, "/bastions/", 404, NOT_AUTHORIZED)
    result = run_fetcher("bastion_sessions", signing_key, tmp_path, OCI_CASSETTE=str(cassette))

    evidence = evidence_of(tmp_path)
    summary = evidence["summary"]
    if summary["total_bastions"] == 0:
        pytest.skip("this recording holds no bastion to deny")
    assert result.returncode == 1
    assert summary["bastions_with_unreadable_detail"] >= 1
    # The finding must not be fabricated from the missing read.
    assert summary["bastions_open_to_any_client_ip"] == 0


def test_skipping_audit_retention_is_a_decision_not_a_failure(signing_key, tmp_path):
    """Reading retention needs {AUDIT_CONFIGURATION}, which also allows changing it,
    so a strictly read-only collector opts out. That must not fail the run, and
    must not read as retention being short."""
    result = run_fetcher("audit_logging_events", signing_key, tmp_path, OCI_SKIP_AUDIT_RETENTION="true")

    assert result.returncode == 0
    evidence = evidence_of(tmp_path)
    assert evidence["summary"]["audit_retention_skipped_by_configuration"] is True
    assert evidence["summary"]["audit_retention_period_days"] is None
    assert evidence["summary"]["audit_meets_365_day_retention"] is None
    assert [c["operation"] for c in evidence["metadata"]["skipped_calls"]] == ["audit.get_configuration"]
    assert not evidence["metadata"].get("api_failures")


def test_a_target_compartment_that_does_not_exist_fails_the_run(signing_key, tmp_path):
    """Live: a manifest still carrying `replace-me` ran green with zero bastions —
    the walk tolerated the denied target, and the bastion 404 read as "Bastion not
    subscribed". The target itself must be readable; only its children may not be."""
    bogus = "ocid1.compartment.oc1..doesnotexist"
    data = json.loads((CASSETTE_DIR / "bastion_sessions.json").read_text())
    data["interactions"].append({
        "key": f"GET identity/20160918/compartments/{bogus}",
        "status": 404, "headers": {"content-type": "application/json"}, "body": NOT_AUTHORIZED,
    })
    cassette = tmp_path / "bastion-bogus-target.json"
    cassette.write_text(json.dumps(data))

    result = run_fetcher("bastion_sessions", signing_key, tmp_path,
                         OCI_CASSETTE=str(cassette), OCI_COMPARTMENT_ID=bogus)

    assert result.returncode == 1
    failures = evidence_of(tmp_path)["metadata"]["api_failures"]
    assert any(f["operation"].startswith("identity.get_compartment") for f in failures)


def test_a_denied_service_listing_is_a_failure_not_an_unsubscribed_service(signing_key, tmp_path):
    """A bare 404 NotAuthorizedOrNotFound is what a missing grant returns. It was
    read as "service not subscribed" and skipped, so a collector without the
    Bastion grant exited 0."""
    cassette = _cassette_with("bastion_sessions", tmp_path, "/bastions?", 404, NOT_AUTHORIZED)
    result = run_fetcher("bastion_sessions", signing_key, tmp_path, OCI_CASSETTE=str(cassette))

    assert result.returncode == 1
    evidence = evidence_of(tmp_path)
    assert any(f["operation"].startswith("bastion.list_bastions") for f in evidence["metadata"]["api_failures"])
    assert evidence["summary"]["bastion_service_readable"] is False


def test_denied_zpr_policies_with_zpr_on_is_a_failure_not_zero_policies(signing_key, tmp_path):
    """The listings' 404 must not be tolerated like the configuration's, or a
    collector missing `read zpr-policies` on a tenancy with ZPR enabled exits 0
    reporting no policies. Covered by tools/oci_fault_sweep.py as well."""
    cassette = _cassette_with("zpr_policies", tmp_path, "zpr/20240301/zprPolicies?", 404, NOT_AUTHORIZED)
    result = run_fetcher("zpr_policies", signing_key, tmp_path, OCI_CASSETTE=str(cassette))

    assert result.returncode == 1
    evidence = evidence_of(tmp_path)
    assert evidence["summary"]["zpr_enabled"] is True
    assert any(f["operation"].startswith("zpr.list_zpr_policies") for f in evidence["metadata"]["api_failures"])


def test_zpr_listings_that_404_alongside_the_configuration_read_as_not_enabled(signing_key, tmp_path):
    """The other side of the gate: everything ZPR 404s, which is "never enabled"."""
    data = json.loads((CASSETTE_DIR / "zpr_policies.json").read_text())
    for interaction in data["interactions"]:
        if interaction["key"].startswith(("GET zpr/", "GET security-attribute/")):
            interaction["status"], interaction["body"] = 404, NOT_AUTHORIZED
            interaction["headers"] = {"content-type": "application/json"}
    cassette = tmp_path / "zpr-all-404.json"
    cassette.write_text(json.dumps(data))

    result = run_fetcher("zpr_policies", signing_key, tmp_path, OCI_CASSETTE=str(cassette))

    assert result.returncode == 0, result.stderr[-800:]
    evidence = evidence_of(tmp_path)
    assert evidence["summary"]["zpr_enabled"] is False
    assert evidence["metadata"]["api_failures"] == []


def test_the_fault_sweep_bootstrap_fails_the_named_call(signing_key, tmp_path):
    """tools/oci_fault_sweep.py drives replay through these variables; if they
    stop reaching the bootstrap, every sweep run would read as a pass."""
    key = next(i["key"] for i in json.loads((CASSETTE_DIR / "iam_policies.json").read_text())["interactions"]
               if "/policies?" in i["key"])
    hits = tmp_path / "hits"
    result = run_fetcher("iam_policies", signing_key, tmp_path, OCI_FAULT_KEY=key,
                         OCI_FAULT_KIND="500", OCI_FAULT_HITS=str(hits))

    assert result.returncode == 1
    assert hits.read_text().count("x") > 1, "a 500 must be retried, and with backoff disabled"
    failures = evidence_of(tmp_path)["metadata"]["api_failures"]
    # Ten failures on one client open the SDK's default circuit breaker, so the
    # 500 surfaces as CircuitBreakerError with the status inside its message.
    assert any(f.get("status") == "500" or "'status': 500" in f["message"] for f in failures), failures
