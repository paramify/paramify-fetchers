"""Access judgements in `oci_object_storage_buckets` — chiefly the PAR hole Prowler misses."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "object_storage_buckets" / "fetcher.py"
NOW = datetime(2026, 9, 17, tzinfo=timezone.utc)


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_object_storage_buckets", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ob = _load()


def _bucket(name, *, access="NoPublicAccess", key=None, versioning="Disabled"):
    return {"name": name, "id": f"ocid1.bucket.oc1..{name}", "public_access_type": access,
            "kms_key_id": key, "versioning": versioning, "object_events_enabled": False}


def _par(access="AnyObjectRead", *, days_to_expiry=21, listing="ListObjects"):
    return ob.par_record({"name": "p", "access_type": access, "bucket_listing_action": listing,
                          "time_expires": NOW + timedelta(days=days_to_expiry)}, now=NOW)


def _log(category, *, enabled=True, service="objectstorage", resource="b"):
    return {"id": "l", "display_name": f"{category}-log", "is_enabled": enabled,
            "configuration": {"source": {"service": service, "category": category, "resource": resource}}}


def test_a_private_bucket_with_a_par_is_reachable():
    """Prowler reads public_access_type and stops, so this bucket passes its check."""
    bucket = ob.bucket_record(_bucket("private"), pars=[_par()])
    assert bucket["is_public"] is False
    assert bucket["reachable_by_par"] is True and bucket["pars_granting_whole_bucket"] == 1

    out = ob.summarize([bucket])
    assert out["public_buckets"] == 0
    assert out["buckets_private_but_reachable_by_par"] == 1
    assert [n.split(" (")[0] for n in out["bucket_names_public_or_par_reachable"]] == ["private"]


def test_an_expired_par_grants_nothing():
    bucket = ob.bucket_record(_bucket("b"), pars=[_par(days_to_expiry=-3)])
    assert bucket["preauthenticated_requests"][0]["expired"] is True
    assert bucket["reachable_by_par"] is False and bucket["active_par_count"] == 0
    assert ob.summarize([bucket])["buckets_reachable_by_par"] == 0


def test_par_scope_and_write_access_are_distinguished():
    single_object = ob.bucket_record(_bucket("b"), pars=[_par("ObjectRead", listing="Deny")])
    assert single_object["pars_granting_whole_bucket"] == 0
    assert single_object["reachable_by_par"] is True

    writable = ob.bucket_record(_bucket("w"), pars=[_par("AnyObjectReadWrite")])
    out = ob.summarize([single_object, writable])
    assert out["pars_granting_write"] == 1
    assert out["pars_granting_whole_bucket"] == 1
    assert out["total_active_pars"] == 2


def test_unreadable_pars_are_not_no_pars():
    bucket = ob.bucket_record(_bucket("b"), pars=None)
    assert bucket["pars_read"] is False and bucket["reachable_by_par"] is None
    out = ob.summarize([bucket])
    assert out["buckets_with_unreadable_pars"] == 1
    assert out["buckets_reachable_by_par"] == 0


def test_read_and_write_logging_are_reported_separately():
    """Prowler computes has_read_logging and then never uses it."""
    write_only = ob.bucket_record(_bucket("w"), logs=[_log("write")], pars=[])
    both = ob.bucket_record(_bucket("b"), logs=[_log("write"), _log("read")], pars=[])
    neither = ob.bucket_record(_bucket("n"), logs=[], pars=[])
    out = ob.summarize([write_only, both, neither])
    assert out["buckets_with_write_logging"] == 2
    assert out["buckets_with_read_logging"] == 1
    assert out["buckets_with_no_data_logging"] == 1


def test_a_disabled_or_foreign_log_does_not_count():
    disabled = ob.bucket_record(_bucket("d"), logs=[_log("write", enabled=False)], pars=[])
    flowlog = ob.bucket_record(_bucket("f"), logs=[_log("all", service="flowlogs")], pars=[])
    assert disabled["write_logging_enabled"] is False
    assert flowlog["write_logging_enabled"] is False


def test_public_access_types_and_key_and_versioning_counts():
    public = ob.bucket_record(_bucket("p", access="ObjectRead"), pars=[])
    private = ob.bucket_record(_bucket("q", key="ocid1.key.oc1..k", versioning="Enabled"), pars=[])
    out = ob.summarize([public, private])
    assert out["public_bucket_names"] == ["p"] and out["public_access_types_in_use"] == ["ObjectRead"]
    assert out["customer_managed_key_percentage"] == 50
    assert out["versioning_percentage"] == 50


def test_locked_retention_and_replication_destinations_are_surfaced():
    rule = ob.retention_rule_record({"id": "r", "display_name": "hold",
                                     "duration": {"time_amount": 30, "time_unit": "DAYS"},
                                     "time_rule_locked": NOW - timedelta(days=1)}, now=NOW)
    policy = ob.replication_record({"id": "x", "name": "dr", "destination_region_name": "us-ashburn-1",
                                    "status": "ACTIVE"})
    bucket = ob.bucket_record(_bucket("b"), pars=[], retention=[rule], replication=[policy])
    out = ob.summarize([bucket])
    assert out["buckets_with_locked_retention_rules"] == 1
    assert out["replication_destination_regions"] == ["us-ashburn-1"]
