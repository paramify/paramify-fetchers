"""What the recorded tenancy was staged to contain, asserted through the real fetchers.

The other cassette tests prove wiring. These pin findings that were staged on
purpose, each a real layout that a naive reading gets wrong:

  * an internet-reachable subnet whose route table, gateway, security list and
    flow-log group sit in three different compartments, three levels deep —
    joined per compartment, it read as unreachable, unattached and unlogged;
  * a bucket logged into a log group one compartment away — read as unlogged;
  * a block volume in one compartment attached to an instance in another — the
    attachment lives with the instance, so joined per compartment it read as
    unattached;
  * three finished ADM audits that all report `is_success: false` — read as
    "the scan ran", they would count as never completed.

Counts here are safe despite trimming: every list involved is three items or
fewer, and the compartment listing is recorded whole.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("oci", reason="the OCI SDK deserializes the recorded responses")

_spec = importlib.util.spec_from_file_location(
    "oci_fetcher_subprocess_helpers", Path(__file__).parent / "test_oci_fetchers.py")
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)

signing_key = _helpers.signing_key  # re-exported so the fixture resolves here


def _evidence(name, key, tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    result = _helpers.run_fetcher(name, key, tmp_path)
    assert result.returncode == 0, f"{name} exited {result.returncode}\n{result.stderr[-1500:]}"
    return _helpers.evidence_of(tmp_path)


def test_a_subnet_split_across_compartments_is_joined_and_reachable(signing_key, tmp_path):
    evidence = _evidence("network_exposure", signing_key, tmp_path)
    summary = evidence["summary"]
    assert summary["reachable_internet_ingress_rules"] >= 1
    assert "SSH" in summary["sensitive_ports_reachable_from_internet"]
    assert summary["unattached_security_lists"] == 0
    assert summary["subnets_with_unreadable_route_table"] == 0
    assert summary["enabled_internet_gateways_routed_to"] >= 1
    assert summary["flow_logging_percentage"] == 100
    # fetcher-test / fetcher-test-apps / fetcher-test-web: the walk reached level three.
    assert evidence["metadata"]["compartments_scanned"] >= 4


def test_a_bucket_logged_from_another_compartment_counts_as_logged(signing_key, tmp_path):
    summary = _evidence("object_storage_buckets", signing_key, tmp_path)["summary"]
    assert summary["buckets_with_read_logging"] >= 1


def test_a_volume_attached_from_another_compartment_counts_as_attached(signing_key, tmp_path):
    results = _evidence("block_volume_encryption", signing_key, tmp_path)["results"]
    volume = next(v for v in results["volumes"] if v["display_name"] == "fetcher-test-vol-apps")
    assert volume["is_attached"] is True
    assert volume["in_transit_encryption_enabled"] is False
    assert all(a["instance_id"] and a["is_attached"] for a in volume["attachments"])


def test_finished_audits_that_found_vulnerabilities_are_completed(signing_key, tmp_path):
    summary = _evidence("dependency_vulnerabilities", signing_key, tmp_path)["summary"]
    assert summary["total_audits"] >= 3
    assert summary["audits_completed"] == summary["total_audits"]
    assert summary["audits_passing_own_thresholds"] == 0
    assert summary["audits_where_suppression_lowered_severity"] >= 1
    assert summary["worst_severity_including_suppressed"] == "CRITICAL"


def test_a_regional_fetcher_says_which_subscribed_regions_it_did_not_collect(signing_key, tmp_path):
    metadata = _evidence("vault_keys", signing_key, tmp_path / "v")["metadata"]
    assert metadata["regions_subscribed"] == ["us-phoenix-1"]
    assert metadata["regions_not_collected"] == []


def test_an_iam_fetcher_is_tenancy_wide_and_makes_no_region_claim(signing_key, tmp_path):
    metadata = _evidence("iam_policies", signing_key, tmp_path / "i")["metadata"]
    assert "regions_not_collected" not in metadata


def test_a_user_in_a_second_identity_domain_is_collected_and_judged(signing_key, tmp_path):
    """The legacy IAM API sees the Default domain only; this user was invisible."""
    summary = _evidence("iam_users_credentials", signing_key, tmp_path / "u")["summary"]
    assert summary["users_by_identity_domain"].get("fetcher-test-domain") == 1
    assert "fetcher-test-domain-admin" in summary["users_without_mfa"]
    assert summary["secondary_domain_admins"] == ["fetcher-test-domain/fetcher-test-domain-admin"]
    assert summary["users_with_unknown_state"] == 0
