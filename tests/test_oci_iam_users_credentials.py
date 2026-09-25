"""Judgments in `oci_iam_users_credentials`, including where it departs from Prowler."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "iam_users_credentials" / "fetcher.py"
NOW = datetime(2026, 9, 15, tzinfo=timezone.utc)


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_iam_users_credentials", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


iam = _load()


def _user(name, *, mfa=False, console=True, last_login=None):
    return {"id": f"ocid1.user.oc1..{name}", "name": name, "lifecycle_state": "ACTIVE",
            "is_mfa_activated": mfa, "last_successful_login_time": last_login,
            "capabilities": {"can_use_console_password": console, "can_use_api_keys": True}}


def _cred(days_old, state="ACTIVE", **extra):
    return iam.credential_record({"time_created": NOW - timedelta(days=days_old),
                                  "lifecycle_state": state, **extra}, now=NOW)


def test_only_the_exact_administrators_group_is_tenancy_admin():
    """Prowler's substring match would make both of these admins."""
    network = iam.user_record(_user("n"), group_names=["NetworkAdministrators"], now=NOW)
    real = iam.user_record(_user("a"), group_names=["Administrators"], now=NOW)
    assert network["is_tenancy_admin"] is False
    assert real["is_tenancy_admin"] is True


def test_never_activated_users_without_mfa_are_separated_from_live_ones():
    ghost = iam.user_record(_user("ghost"), now=NOW)
    live = iam.user_record(_user("live", last_login=NOW - timedelta(days=1)), now=NOW)
    out = iam.summarize([ghost, live])
    assert out["console_capable_users_without_mfa"] == 2
    assert out["console_users_without_mfa_who_have_logged_in"] == 1


def test_rotation_window_counts_only_active_credentials_of_every_type():
    creds = {
        "api_keys": [_cred(120, key_id="k1", fingerprint="aa"), _cred(10, key_id="k2")],
        "smtp_credentials": [_cred(200)],
        "oauth2_client_credentials": [_cred(400, state="INACTIVE", expires_on=NOW)],
    }
    user = iam.user_record(_user("u"), group_names=["Administrators"], credentials=creds, now=NOW)
    assert user["credentials"]["api_keys"][0]["id"] == "k1"
    assert user["active_credentials_older_than_rotation_window"] == 2
    out = iam.summarize([user])
    assert out["credentials_by_type"]["smtp_credentials"]["older_than_90_days"] == 1
    assert out["credentials_by_type"]["oauth2_client_credentials"]["active"] == 0
    assert out["tenancy_admins_with_api_keys"] == 1


def test_a_failed_credential_read_is_not_none_held():
    user = iam.user_record(_user("u"), credentials={"api_keys": None, "auth_tokens": []}, now=NOW)
    assert user["unreadable_credential_types"] == ["api_keys"]
    assert iam.summarize([user])["users_with_unreadable_credentials"] == 1


def test_secret_material_is_never_copied():
    record = iam.credential_record({"key_id": "k", "key_value": "-----BEGIN PUBLIC KEY-----",
                                    "token": "s3cr3t", "time_created": NOW}, now=NOW)
    assert "s3cr3t" not in str(record) and "BEGIN" not in str(record)


# --- secondary identity domains, read through SCIM ---

def _scim(name, *, active=True, mfa=None, groups=("All Domain Users",)):
    user = {"id": f"scim-{name}", "ocid": f"ocid1.user.oc1..{name}", "user_name": name,
            "meta": {"created": "2026-09-01T00:00:00.000Z"},
            "groups": [{"display": g} for g in groups],
            iam.EXT_CAPABILITIES: {"can_use_console_password": True, "can_use_api_keys": True}}
    if active is not None:
        user["active"] = active
    if mfa:
        user[iam.EXT_MFA] = {"mfa_status": mfa}
    return user


def _scim_record(raw, **kwargs):
    names = [g["display"] for g in raw["groups"]]
    return iam.user_record(iam.scim_user(raw), group_names=names, credentials={}, now=NOW,
                           domain="second", domain_admin_group=iam.DOMAIN_ADMIN_GROUP, **kwargs)


def test_a_secondary_domain_user_without_mfa_is_a_finding():
    out = iam.summarize([_scim_record(_scim("nomfa")), _scim_record(_scim("ok", mfa="ENROLLED"))])
    assert out["users_without_mfa"] == ["nomfa"]
    assert out["users_by_identity_domain"] == {"second": 2}


def test_a_missing_active_flag_is_unknown_never_inactive():
    """Live: an attribute request that dropped `active` made a no-MFA user read
    as inactive and vanish from the finding."""
    record = _scim_record(_scim("blind", active=None))
    assert record["lifecycle_state"] == "UNKNOWN"
    assert iam.summarize([record])["users_with_unknown_state"] == 1
    assert _scim_record(_scim("off", active=False))["lifecycle_state"] == "INACTIVE"


def test_a_domain_administrator_is_not_a_tenancy_administrator():
    record = _scim_record(_scim("dadmin", groups=("Domain_Administrators", "Administrators")))
    assert record["is_domain_admin"] is True
    assert record["is_tenancy_admin"] is False
    out = iam.summarize([record])
    assert out["secondary_domain_admins"] == ["second/dadmin"]
    assert out["tenancy_admins"] == 0
    default = iam.user_record(_user("root"), group_names=["Administrators"], credentials={}, now=NOW)
    assert default["is_tenancy_admin"] is True and default["is_domain_admin"] is False


def test_a_scim_api_key_has_no_status_and_counts_as_active():
    key = iam.credential_record(iam.scim_credential(
        {"ocid": "k", "fingerprint": "aa:bb", "meta": {"created": "2026-01-01T00:00:00Z"}}), now=NOW)
    token = iam.credential_record(iam.scim_credential(
        {"ocid": "t", "status": "inactive", "meta": {"created": "2026-09-10T00:00:00Z"}}), now=NOW)
    record = iam.user_record(iam.scim_user(_scim("keys")), group_names=[], now=NOW,
                             credentials={"api_keys": [key], "auth_tokens": [token]})
    assert record["active_credential_count"] == 1
    assert record["active_credentials_older_than_rotation_window"] == 1
