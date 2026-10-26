"""Our findings, checked against Cloud Guard's own findings on the same tenancy.

Every other category in this repo can only check itself: the fetcher reads an
API and nothing independent says whether the reading is right. Oracle is the
exception. Cloud Guard is a detector running inside the same tenancy, raising
its own problems from its own rules, and those problems overlap what seven of our
fetchers report. So the vendor grades the homework.

This runs entirely on the recorded cassettes, so it needs no tenancy — but the
recordings are of one moment on one real tenancy, and Cloud Guard's problems
there were raised by Oracle, not by us. A disagreement means one of:

  * our fetcher missed something Oracle found — the serious case, and the reason
    this test exists;
  * Oracle found something we deliberately do not report, which belongs in the
    mapping below with a comment rather than being silently tolerated;
  * the cassettes were re-recorded at different moments and have drifted apart,
    which is a re-record problem and says so in the failure message.

The cassette bodies are trimmed to three items per list, so this asserts the
DIRECTION "every Cloud Guard problem we claim to cover is also reported by us",
never a count.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

pytest.importorskip("oci", reason="the OCI SDK deserializes the recorded responses")

_spec = importlib.util.spec_from_file_location(
    "oci_fetcher_subprocess_helpers", Path(__file__).parent / "test_oci_fetchers.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)

run_fetcher = _helpers.run_fetcher
evidence_of = _helpers.evidence_of
signing_key = _helpers.signing_key  # re-exported so the fixture resolves here


def _evidence(name, key, tmp_path):
    directory = tmp_path / name
    directory.mkdir()
    result = run_fetcher(name, key, directory)
    assert result.returncode == 0, f"{name} exited {result.returncode}\n{result.stderr[-1500:]}"
    return evidence_of(directory)


@pytest.fixture(scope="module")
def findings(signing_key, tmp_path_factory):
    """Cloud Guard's problems plus the evidence from the fetchers they touch."""
    tmp_path = tmp_path_factory.mktemp("crosscheck")
    names = ["cloud_guard_posture", "iam_users_credentials", "iam_password_policy",
             "object_storage_buckets", "block_volume_encryption", "compute_instances",
             "network_exposure"]
    evidence = {name: _evidence(name, signing_key, tmp_path) for name in names}
    problems = evidence["cloud_guard_posture"]["results"]["problems"]
    assert problems, "the Cloud Guard cassette holds no problems — re-record"
    return evidence, problems


def _problem(problems, rule):
    return [p for p in problems if p["detector_rule_id"] == rule]


def test_cloud_guard_and_our_fetcher_name_the_same_user_without_mfa(findings):
    evidence, problems = findings
    for problem in _problem(problems, "NO_MFA_ENABLED_FOR_USER"):
        ours = evidence["iam_users_credentials"]["summary"]["users_without_mfa"]
        assert problem["resource_name"] in ours, (
            f"Cloud Guard says {problem['resource_name']} has no MFA; we report {ours}")


def test_cloud_guard_and_our_fetcher_agree_the_admin_holds_api_keys(findings):
    evidence, problems = findings
    for problem in _problem(problems, "USER_HAS_API_KEYS"):
        users = evidence["iam_users_credentials"]["results"]["users"]
        named = next((u for u in users if u["name"] == problem["resource_name"]), None)
        assert named is not None, f"Cloud Guard names a user we did not collect: {problem['resource_name']}"
        assert named["credentials"]["api_keys"], "Cloud Guard found API keys on a user we report as holding none"


def test_cloud_guard_and_our_fetcher_agree_the_password_policy_is_weak(findings):
    evidence, problems = findings
    for problem in _problem(problems, "PASSWORD_POLICY_NOT_COMPLEX"):
        summary = evidence["iam_password_policy"]["summary"]
        failing = summary["policies_below_cis_min_length"] + summary["policies_below_cis_history"]
        assert any(problem["resource_name"] in entry for entry in failing), (
            f"Cloud Guard faults policy {problem['resource_name']}; our failing set is {failing}")


def test_cloud_guard_and_our_fetcher_name_the_same_public_bucket(findings):
    evidence, problems = findings
    for problem in _problem(problems, "BUCKET_IS_PUBLIC"):
        ours = evidence["object_storage_buckets"]["summary"]["public_bucket_names"]
        assert problem["resource_name"] in ours, (
            f"Cloud Guard says {problem['resource_name']} is public; we report {ours}")


def test_cloud_guard_and_our_fetcher_agree_a_volume_is_unattached(findings):
    evidence, problems = findings
    unattached = _problem(problems, "BLOCK_VOLUME_NOT_ATTACHED")
    if not unattached:
        pytest.skip("no unattached-volume problem in this recording")
    volumes = evidence["block_volume_encryption"]["results"]["volumes"]
    for problem in unattached:
        named = next((v for v in volumes if v["display_name"] == problem["resource_name"]), None)
        assert named is not None, f"Cloud Guard names a volume we did not collect: {problem['resource_name']}"
        assert named["is_attached"] is False, "Cloud Guard says unattached; we report attached"
    assert evidence["block_volume_encryption"]["summary"]["unattached_volumes"] >= len(unattached)


def test_cloud_guard_and_our_fetcher_agree_a_vnic_has_no_nsg(findings):
    """Prowler never reads VNICs at all; this is the check that proves ours does."""
    evidence, problems = findings
    for problem in _problem(problems, "VNIC_WITHOUT_NETWORK_SECURITY_GROUP"):
        instances = evidence["compute_instances"]["results"]["instances"]
        named = next((i for i in instances if i["display_name"] == problem["resource_name"]), None)
        assert named is not None, f"Cloud Guard names an instance we did not collect: {problem['resource_name']}"
        assert named["vnics"], "we collected no VNICs for an instance Cloud Guard faults on its VNIC"
        assert any(not v["is_protected_by_nsg"] for v in named["vnics"]), (
            "Cloud Guard found a VNIC with no NSG; we report every VNIC as protected")


def test_cloud_guard_saw_a_gateway_created_and_we_report_one_enabled(findings):
    """An ACTIVITY problem: its resource is the user who created the gateway, not
    the gateway, so it cannot be matched name for name. The direction still
    holds: Oracle saw an internet gateway appear, so we must report one."""
    evidence, problems = findings
    if not _problem(problems, "INTERNET_GATEWAY_CREATED"):
        pytest.skip("no internet-gateway problem in this recording")
    assert evidence["network_exposure"]["summary"]["enabled_internet_gateways"], (
        "Cloud Guard saw an internet gateway created; we report none enabled")


def test_cloud_guard_and_our_fetcher_agree_which_vcn_has_an_internet_gateway(findings):
    """A configuration problem on the VCN — matched by name, then by the gateway
    records' vcn_id."""
    evidence, problems = findings
    attached = _problem(problems, "VCN_HAS_INTERNET_GATEWAY_ATTACHED")
    if not attached:
        pytest.skip("no attached-gateway problem in this recording")
    results = evidence["network_exposure"]["results"]
    for problem in attached:
        vcn = next((v for v in results["vcns"] if v["display_name"] == problem["resource_name"]), None)
        assert vcn is not None, f"Cloud Guard names a VCN we did not collect: {problem['resource_name']}"
        assert any(g["vcn_id"] == vcn["id"] and g["is_enabled"] for g in results["internet_gateways"]), (
            f"Cloud Guard says {problem['resource_name']} has an internet gateway; we record none enabled on it")


def test_every_problem_type_in_the_recording_is_either_mapped_or_explained(findings):
    """A new Cloud Guard problem type must be a decision, not an oversight.

    Without this, Oracle raising something we do not cover would go unnoticed —
    the same shape as a check whose input is derived from the thing it checks.
    """
    _, problems = findings
    mapped = {
        "NO_MFA_ENABLED_FOR_USER", "USER_HAS_API_KEYS", "PASSWORD_POLICY_NOT_COMPLEX",
        "BUCKET_IS_PUBLIC", "BLOCK_VOLUME_NOT_ATTACHED", "VNIC_WITHOUT_NETWORK_SECURITY_GROUP",
        "INTERNET_GATEWAY_CREATED", "VCN_HAS_INTERNET_GATEWAY_ATTACHED",
    }
    # Deliberately not cross-checked, with the reason:
    unmapped_by_design = {
        # Data Safe registration is a separate paid service; no fetcher covers it
        # and none claims to.
        "DATA_SAFE_DB_NOT_REGISTERED",
        # Reported by oci_block_volume_encryption as the key in use, but Cloud
        # Guard raises it per volume and we summarise per tenancy, so the
        # name-for-name assertion above is the wrong shape for it.
        "BLOCK_VOLUME_ENCRYPTED_WITH_ORACLE_MANAGED_KEY",
        "BOOT_VOLUME_ENCRYPTED_WITH_ORACLE_MANAGED_KEY",
        # Activity problems: Cloud Guard saw a change happen. These fetchers
        # report state, not change events, so there is nothing to agree with;
        # the resulting state (the policy, the membership) is in
        # oci_iam_policies and oci_iam_users_credentials.
        "SECURITY_POLICY_MODIFIED",
        "USER_ADDED_TO_GROUP",
    }
    seen = {p["detector_rule_id"] for p in problems}
    unknown = seen - mapped - unmapped_by_design
    assert not unknown, (
        f"Cloud Guard raised problem types nothing here accounts for: {sorted(unknown)}. "
        "Map them to a fetcher assertion or record why not.")
