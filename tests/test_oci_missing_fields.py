"""A field Oracle may leave out must never make the evidence look better.

Each case blanks one field that the SDK's own models mark optional, in the real
recorded responses, and runs the fetcher end to end. Found by nulling every
field of every cassette in turn and keeping the changes that read as an
improvement: before these fixes, a missing console-capability block dropped a
user out of the MFA finding, a missing `isEnabled` made an internet gateway
disabled and its SSH exposure vanish, and a certificate with no validity window
left the expiry count. Missing now reads as the conservative answer, or is
counted as unknown beside the finding it would have skewed.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("oci", reason="the OCI SDK deserializes the recorded responses")

_spec = importlib.util.spec_from_file_location(
    "oci_fetcher_subprocess_helpers", Path(__file__).parent / "test_oci_fetchers.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)

signing_key = _helpers.signing_key  # re-exported so the fixture resolves here

SCIM_CAPABILITIES = "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User"


def _null_at(node, path):
    head, rest = path[0], path[1:]
    if head == "*":
        for item in node if isinstance(node, list) else []:
            _null_at(item, rest)
    elif isinstance(node, dict) and head in node:
        if rest:
            _null_at(node[head], rest)
        else:
            node[head] = None


def _run(name, signing_key, tmp_path, match=None, path=None):
    """Summary of `name`, with `path` nulled in every interaction whose key contains `match`."""
    cassette = _helpers.CASSETTE_DIR / f"{name}.json"
    if match:
        data = json.loads(cassette.read_text())
        hits = 0
        for interaction in data["interactions"]:
            if match in interaction["key"] and interaction["status"] == 200:
                body = json.loads(interaction["body"])
                _null_at(body, path)
                interaction["body"] = json.dumps(body)
                hits += 1
        assert hits, f"no interaction in {name}'s cassette matches {match!r} — re-record?"
        cassette = tmp_path / f"{name}-nulled.json"
        cassette.write_text(json.dumps(data))
    out = tmp_path / ("nulled" if match else "baseline")
    out.mkdir()
    result = _helpers.run_fetcher(name, signing_key, out, OCI_CASSETTE=str(cassette))
    assert result.returncode == 0, f"{name} exited {result.returncode}\n{result.stderr[-1500:]}"
    return _helpers.evidence_of(out)["summary"]


def _unchanged(name, signing_key, tmp_path, match, path, keys):
    baseline = _run(name, signing_key, tmp_path)
    nulled = _run(name, signing_key, tmp_path, match, path)
    for key in keys:
        assert nulled[key] == baseline[key], f"{key}: {baseline[key]!r} -> {nulled[key]!r}"
    return baseline, nulled


def test_no_console_capability_on_a_legacy_user_keeps_them_in_the_mfa_finding(signing_key, tmp_path):
    _unchanged("iam_users_credentials", signing_key, tmp_path, "/users?",
               ("*", "capabilities"), ["console_capable_users_without_mfa", "users_without_mfa"])


def test_no_capabilities_extension_on_a_domain_user_keeps_them_in_the_mfa_finding(signing_key, tmp_path):
    _unchanged("iam_users_credentials", signing_key, tmp_path, "admin/v1/Users?",
               ("Resources", "*", SCIM_CAPABILITIES), ["users_without_mfa"])


def test_a_domain_user_with_unknown_state_is_still_judged(signing_key, tmp_path):
    _, nulled = _unchanged("iam_users_credentials", signing_key, tmp_path, "admin/v1/Users?",
                           ("Resources", "*", "active"), ["users_without_mfa", "secondary_domain_admins"])
    assert nulled["users_with_unknown_state"] == 1


def test_an_identity_domain_without_a_display_name_does_not_crash_the_run(signing_key, tmp_path):
    _run("iam_users_credentials", signing_key, tmp_path, "identity/20160918/domains?", ("*", "displayName"))


def test_an_internet_gateway_with_no_enabled_flag_still_carries_its_exposure(signing_key, tmp_path):
    _unchanged("network_exposure", signing_key, tmp_path, "internetGateways?", ("*", "isEnabled"),
               ["reachable_internet_ingress_rules", "sensitive_ports_reachable_from_internet",
                "enabled_internet_gateways_routed_to"])


def test_a_certificate_with_no_validity_window_is_counted_as_unknown_expiry(signing_key, tmp_path):
    nulled = _run("certificates", signing_key, tmp_path, "certificates?",
                  ("items", "*", "currentVersionSummary"))
    assert nulled["certificates_with_unknown_expiry"] == nulled["total_certificates"] >= 1


def test_a_problem_listed_as_open_stays_open_without_its_lifecycle_detail(signing_key, tmp_path):
    _unchanged("cloud_guard_posture", signing_key, tmp_path, "/problems?",
               ("items", "*", "lifecycleDetail"), ["open_problems"])


def test_a_problem_with_no_risk_level_is_counted_as_unknown_risk(signing_key, tmp_path):
    baseline, nulled = _unchanged("cloud_guard_posture", signing_key, tmp_path, "/problems?",
                                  ("items", "*", "riskLevel"), ["open_problems"])
    assert nulled["open_problems_with_unknown_risk"] == baseline["open_problems"] >= 1


def test_an_instance_with_no_launch_options_has_unknown_in_transit_encryption(signing_key, tmp_path):
    nulled = _run("compute_instances", signing_key, tmp_path, "/instances?", ("*", "launchOptions"))
    assert nulled["in_transit_encryption_unknown"] == nulled["total_instances"] >= 1


def test_a_finished_audit_with_no_severity_is_counted_as_unknown(signing_key, tmp_path):
    nulled = _run("dependency_vulnerabilities", signing_key, tmp_path, "vulnerabilityAudits?",
                  ("items", "*", "maxObservedSeverity"))
    assert nulled["completed_audits_with_unknown_severity"] == nulled["audits_completed"] >= 1


def test_a_bucket_with_no_public_access_type_is_counted_as_unknown(signing_key, tmp_path):
    nulled = _run("object_storage_buckets", signing_key, tmp_path, "b/fetcher-test-public",
                  ("publicAccessType",))
    assert nulled["buckets_with_unknown_public_access"] == 1
