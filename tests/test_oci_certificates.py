"""Renewal-automation and expiry judgements in `oci_certificates`."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "certificates" / "fetcher.py"
NOW = datetime(2026, 9, 21, tzinfo=timezone.utc)
RENEWAL = [{"rule_type": "CERTIFICATE_RENEWAL_RULE", "renewal_interval": "P60D", "advance_renewal_period": "P15D"}]


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_certificates", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


certs = _load()


def _cert(name="c", *, config="ISSUED_BY_INTERNAL_CA", rules=None, expires_in=200, state="ACTIVE", revoked=False):
    version = {"version_number": 1, "validity": {"time_of_validity_not_after": NOW + timedelta(days=expires_in)}}
    if revoked:
        version["revocation_status"] = {"time_of_revocation": NOW, "revocation_reason": "KEY_COMPROMISE"}
    return certs.certificate_record({
        "id": f"ocid1.certificate.oc1..{name}", "name": name, "config_type": config,
        "lifecycle_state": state, "certificate_rules": rules, "key_algorithm": "RSA2048",
        "signature_algorithm": "SHA256_WITH_RSA", "current_version_summary": version,
    }, now=NOW)


def test_iso_durations_become_days():
    assert certs.duration_days("P30D") == 30
    assert certs.duration_days("P1Y") == 365
    assert certs.duration_days("PT48H") == 2
    assert certs.duration_days("P") is None
    assert certs.duration_days("30 days") is None


def test_only_a_renewal_rule_counts_as_automation():
    auto, manual = _cert("auto", rules=RENEWAL), _cert("manual")
    assert auto["auto_renews"] and auto["renewal_interval_days"] == 60
    assert manual["renewal_is_manual"]
    other = certs.renewal_rule([{"rule_type": "SOMETHING_NEW", "renewal_interval": "P1D"}])
    assert other["auto_renews"] is False
    out = certs.summarize([auto, manual], [])
    assert out["automatic_renewal_percentage"] == 50
    assert out["certificates_requiring_manual_renewal"] == 1


def test_certificates_oci_cannot_renew_are_not_manual_renewal_gaps():
    """Imported material and customer-held keys have no renewal rule to turn on."""
    records = [_cert("imp", config="IMPORTED"),
               _cert("csr", config="MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA"),
               _cert("auto", rules=RENEWAL)]
    out = certs.summarize(records, [])
    assert out["certificates_requiring_manual_renewal"] == 0
    assert out["imported_certificates"] == 1
    assert out["certificates_with_externally_managed_keys"] == 1
    assert out["automatic_renewal_percentage"] == 100


def test_a_certificate_being_deleted_is_not_posture():
    gone = _cert("gone", expires_in=-10, state="PENDING_DELETION")
    out = certs.summarize([gone, _cert("live", rules=RENEWAL)], [])
    assert out["total_certificates"] == 2
    assert out["certificates_pending_deletion"] == 1
    assert out["expired_certificates"] == 0
    assert out["certificates_requiring_manual_renewal"] == 0


def test_expiry_windows_are_nested_and_expired_is_apart():
    records = [_cert("soon", expires_in=10), _cert("later", expires_in=60),
               _cert("gone", expires_in=-1), _cert("fine", expires_in=400)]
    assert records[0]["days_until_expiry"] == 10
    out = certs.summarize(records, [])
    assert out["certificates_expiring_within_30_days"] == 1
    assert out["certificates_expiring_within_90_days"] == 2
    assert out["expired_certificates"] == 1
    assert out["soonest_certificate_expiry_days"] == 10


def test_a_revoked_certificate_is_counted_even_while_active():
    out = certs.summarize([_cert("r", revoked=True)], [])
    assert out["revoked_certificates"] == 1


def test_a_missing_version_summary_leaves_expiry_unknown_not_expired():
    record = certs.certificate_record({"id": "c", "config_type": "ISSUED_BY_INTERNAL_CA",
                                       "lifecycle_state": "ACTIVE"}, now=NOW)
    assert record["days_until_expiry"] is None
    assert record["is_expired"] is None
    assert certs.summarize([record], [])["expired_certificates"] == 0
