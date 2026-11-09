"""Just-in-time access judgements in `oci_bastion_sessions`."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "bastion_sessions" / "fetcher.py"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_bastion_sessions", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bastion = _load()


def _bastion(name="b", *, cidrs=("10.0.0.0/16",), ttl=1800, jump=None, state="ACTIVE"):
    return bastion.bastion_record({
        "id": f"ocid1.bastion.oc1..{name}", "name": name, "lifecycle_state": state,
        "client_cidr_block_allow_list": list(cidrs) if cidrs is not None else None,
        "max_session_ttl_in_seconds": ttl, "static_jump_host_ip_addresses": jump,
    })


def test_an_empty_allow_list_is_unrestricted_not_locked_down():
    assert bastion.allows_internet([]) is True
    assert bastion.allows_internet(None) is True


def test_the_whole_internet_is_recognised_however_it_is_spelled():
    assert bastion.allows_internet(["0.0.0.0/0"])
    assert bastion.allows_internet(["0::/0"])
    assert bastion.allows_internet([" ::/0 "])
    # Two halves are the whole: an exact-string check reads this as restricted.
    assert bastion.allows_internet(["0.0.0.0/1", "128.0.0.0/1"])


def test_a_real_allow_list_is_restricted():
    assert not bastion.allows_internet(["10.0.0.0/16"])
    assert not bastion.allows_internet(["203.0.113.0/24", "2001:db8::/32"])
    # Half the IPv4 internet is broad, but it is not all of it.
    assert not bastion.allows_internet(["0.0.0.0/1"])


def test_an_unparseable_entry_never_reads_as_restrictive_by_being_skipped():
    assert bastion.allows_internet(["not-a-cidr", "0.0.0.0/0"])
    assert not bastion.allows_internet(["not-a-cidr", "10.0.0.0/8"])


def test_a_failed_detail_read_never_reads_as_a_clean_bastion():
    """TTL and allow-list are detail-only; a list-only read must not count."""
    unread = _bastion("unread", cidrs=None, ttl=None)
    out = bastion.summarize([unread, _bastion("ok")], [])
    assert unread["detail_read"] is False
    assert out["bastions_with_unreadable_detail"] == 1
    assert out["bastions_open_to_any_client_ip"] == 0
    assert out["cidr_restriction_percentage"] == 100


def test_ttl_thresholds_and_static_jump_hosts_are_counted():
    records = [_bastion("max", ttl=10800), _bastion("two-hours", ttl=7200),
               _bastion("jump", jump=["10.0.0.5"])]
    out = bastion.summarize(records, [])
    assert out["bastions_at_maximum_session_ttl"] == 1
    assert out["bastions_with_session_ttl_over_one_hour"] == 2
    assert out["bastions_with_static_jump_hosts"] == 1
    assert out["shortest_max_session_ttl_seconds"] == 1800


def test_a_creating_session_can_already_carry_access():
    sessions = [bastion.session_record({"lifecycle_state": s, "session_ttl_in_seconds": 3600,
                                        "target_resource_details": {"session_type": "MANAGED_SSH",
                                                                    "target_resource_id": "i1",
                                                                    "target_resource_operating_system_user_name": "opc"}})
                for s in ("ACTIVE", "CREATING", "DELETED")]
    out = bastion.summarize([], sessions)
    assert out["active_sessions"] == 2
    assert out["os_usernames_assumed"] == ["opc"]
    assert out["distinct_session_targets"] == 1
