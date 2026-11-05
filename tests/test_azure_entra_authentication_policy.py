"""azure_entra_authentication_policy: trusted certificate authorities, and the users the X.509 method targets."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))

spec = importlib.util.spec_from_file_location("azure_entra_auth_policy_cba_under_test",
                                              AZURE / "entra_authentication_policy" / "fetcher.py")
ap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ap)

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
DENIED = Exception("Insufficient privileges to complete the operation. (403)")


class Mode(Enum):
    MULTI = "x509CertificateMultiFactor"


class Affinity(Enum):
    LOW = "low"
    HIGH = "high"


class Kind(Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"


def _cert(days_left: int) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Example CA {days_left}")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=400))
            .not_valid_after(now + timedelta(days=days_left)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def _authority(days_left, root=True, crl="http://crl.example/ca.crl", cert=None):
    return ns(issuer=f"CN=Example CA {days_left}", issuer_ski="ab", is_root_authority=root,
              certificate_revocation_list_url=crl, delta_certificate_revocation_list_url=None,
              certificate=cert if cert is not None else _cert(days_left))


def _pki_authority(days_left, kind=Kind.ROOT, crl="http://crl.example/pki.crl", cert=None, expires=None,
                   thumbprint=None):
    return ns(display_name=f"PKI CA {days_left}", issuer=f"CN=PKI CA {days_left}", issuer_subject_key_identifier="cd",
              certificate_authority_type=kind, certificate_revocation_list_url=crl,
              delta_certificate_revocation_list_url=None, certificate=cert if cert is not None else _cert(days_left),
              expiration_date_time=expires, thumbprint=thumbprint)


def _target(tid, kind="group"):
    return ns(id=tid, target_type=kind, is_registration_required=False)


def _x509(state="enabled", include=("g1",), exclude=("g2",), bindings=True):
    return ns(
        id="X509Certificate", state=state,
        include_targets=[_target(t) for t in include], exclude_targets=[_target(t) for t in exclude],
        authentication_mode_configuration=ns(x509_certificate_authentication_default_mode=Mode.MULTI),
        certificate_user_bindings=[
            ns(x509_certificate_field="SubjectKeyIdentifier", user_property="certificateUserIds", priority=2,
               trust_affinity_level=Affinity.HIGH),
            ns(x509_certificate_field="PrincipalName", user_property="onPremisesUserPrincipalName", priority=1,
               trust_affinity_level=Affinity.LOW),
        ] if bindings else [],
    )


def _method(mid, include=("all_users",), state="enabled"):
    return ns(id=mid, state=state, include_targets=[_target(t) for t in include], exclude_targets=[])


def _user(uid, cert_ids=0, on_prem=None, user_type="Member", enabled=True):
    return ns(id=uid, user_principal_name=f"{uid}@example.com", user_type=user_type, account_enabled=enabled,
              on_premises_user_principal_name=on_prem,
              authorization_info=ns(certificate_user_ids=[f"X509:<SKI>{i}" for i in range(cert_ids)]))


USERS = [_user("u1", cert_ids=1), _user("u2", on_prem="u2@corp.example"), _user("u3", cert_ids=1),
         _user("u4", cert_ids=1, user_type="Guest"), _user("u5", enabled=False), _user("u6", cert_ids=1),
         _user("u7")]
GROUPS = {"g1": ["u1", "u2", "u3", "u4", "u5", "u7"], "g2": ["u3"], "g3": ["u2"]}


class Pages:
    """A paged Graph collection: one page, or the exception its read raises."""

    def __init__(self, items, calls=None, name=None):
        self.items, self.calls, self.name = items, calls, name

    async def get(self, request_configuration=None):
        if self.calls is not None:
            self.calls.append((self.name, request_configuration))
        if isinstance(self.items, Exception):
            raise self.items
        return ns(value=list(self.items), odata_next_link=None)

    def with_url(self, url):
        return self


class PkiStore(Pages):
    """The PKI-based trust store: its configurations, and each one's certificate authorities."""

    def __init__(self, pkis, calls, error=None, ca_error=None):
        super().__init__(error or [ns(id=pid) for pid in pkis], calls, "pki")
        self.pkis, self.ca_error = pkis, ca_error

    def by_certificate_based_auth_pki_id(self, pid):
        return ns(certificate_authorities=Pages(self.ca_error or self.pkis[pid], self.calls, f"pki {pid}"))


def _async(value):
    async def get(*a, **k):
        if isinstance(value, Exception):
            raise value
        return value
    return get


def _client(calls, configs, authorities, fail=(), pki=None):
    policy = ns(id="authenticationMethodsPolicy", policy_migration_state="migrationComplete",
                authentication_method_configurations=configs)
    organization = ns(
        get=_async(ns(value=[ns(id="t1", display_name="Example", verified_domains=[])])),
        by_organization_id=lambda oid: ns(certificate_based_auth_configuration=Pages(
            DENIED if "authorities" in fail else [ns(certificate_authorities=authorities)], calls, "authorities")),
    )

    def group(gid):
        members = DENIED if gid in fail else [ns(id=u) for u in GROUPS.get(gid, [])]
        return ns(transitive_members=ns(graph_user=Pages(members, calls, f"group {gid}")))

    return ns(
        organization=organization,
        policies=ns(authentication_methods_policy=ns(get=_async(policy)),
                    identity_security_defaults_enforcement_policy=ns(get=_async(ns(is_enabled=False)))),
        group_settings=Pages([]),
        group_setting_templates=ns(by_group_setting_template_id=lambda tid: ns(get=_async(ns(values=[])))),
        subscribed_skus=Pages([]),
        users=Pages(DENIED if "users" in fail else USERS, calls, "users"),
        groups=ns(by_group_id=group),
        directory=ns(public_key_infrastructure=ns(certificate_based_auth_configurations=PkiStore(
            pki or {}, calls, error=DENIED if "pki" in fail else RuntimeError("timed out") if "pki_error" in fail
            else None, ca_error=DENIED if "pki_authorities" in fail else None))),
    )


def run(monkeypatch, tmp_path, configs, authorities=(), fail=(), pki=None):
    calls: list = []
    client = _client(calls, list(configs), list(authorities), fail, pki)

    async def with_client(collector, cred, work, default=None):
        return await work(client)

    monkeypatch.setattr(ap, "load_dotenv", lambda: None)
    monkeypatch.setattr(ap, "credential", lambda: object())
    monkeypatch.setattr(ap, "with_graph_client", with_client)
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    code = ap.main()
    evidence = json.loads(next(tmp_path.glob("azure_entra_authentication_policy_*.json")).read_text())
    return code, evidence, calls


CONFIGS = (_x509(), _method("Sms"), _method("MicrosoftAuthenticator", include=("g3",)), _method("Fido2"),
           _method("Email"), _method("Voice", state="disabled"))


def test_targeted_users_are_matched_to_certificates_and_their_weaker_methods_listed(monkeypatch, tmp_path):
    code, evidence, calls = run(monkeypatch, tmp_path, CONFIGS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    # Guests, disabled accounts, excluded members and users outside the target groups are not targeted.
    users = {u["id"]: u for u in results["x509_certificate_users"]}
    assert sorted(users) == ["u1", "u2", "u7"]
    assert (users["u1"]["mapped"], users["u1"]["mapped_high_affinity"], users["u1"]["mapping_user_properties"]) == (
        True, True, ["certificateUserIds"])
    assert (users["u2"]["mapped"], users["u2"]["mapped_high_affinity"], users["u2"]["mapping_user_properties"]) == (
        True, False, ["onPremisesUserPrincipalName"])
    assert (users["u7"]["mapped"], users["u7"]["mapping_user_properties"]) == (False, [])
    # Email signs in guests only, FIDO2 is phishing-resistant and Voice is off.
    assert users["u2"]["weaker_methods_enabled"] == ["MicrosoftAuthenticator", "Sms"]
    assert users["u7"]["weaker_methods_enabled"] == ["Sms"]
    assert (summary["x509_targeted_users"], summary["x509_targeted_users_unmapped"],
            summary["x509_targeted_users_without_certificate_user_ids"],
            summary["x509_targeted_users_with_weaker_methods"], summary["x509_targeted_users_with_weak_methods"]) == (
        3, 1, 2, 3, 3)
    # The users are read with their certificate user ids, and only the groups the enabled methods name.
    (users_call,) = [c for c in calls if c[0] == "users"]
    assert "authorizationInfo" in users_call[1].query_parameters.select
    assert sorted(c[0] for c in calls if c[0].startswith("group")) == ["group g1", "group g2", "group g3"]
    bindings = next(m for m in results["authentication_methods"] if m["id"] == "X509Certificate")["settings"][
        "certificate_user_bindings"]
    assert [(b["priority"], b["user_property"], b["trust_affinity_level"]) for b in bindings] == [
        (1, "onPremisesUserPrincipalName", "low"), (2, "certificateUserIds", "high")]


def test_trusted_authorities_flag_expired_and_crl_less_ones(monkeypatch, tmp_path):
    authorities = [_authority(300), _authority(-5, root=False, crl=""), _authority(10, cert=b"not a certificate")]
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, authorities)
    summary = evidence["summary"]
    records = evidence["results"]["trusted_certificate_authorities"]
    assert code == 0
    by_issuer = {r["issuer"]: r for r in records}
    valid, expired, unreadable = by_issuer["CN=Example CA 300"], by_issuer["CN=Example CA -5"], by_issuer[
        "CN=Example CA 10"]
    assert (valid["authority_type"], valid["has_crl"], valid["expired"], valid["subject"]) == (
        "root", True, False, "CN=Example CA 300")
    assert 298 <= valid["days_until_expiry"] <= 300
    assert (expired["authority_type"], expired["has_crl"], expired["expired"],
            expired["certificate_revocation_list_url"]) == ("intermediate", False, True, None)
    assert (unreadable["expired"], unreadable["not_after"], unreadable["days_until_expiry"]) == (None, None, None)
    assert "certificate" not in valid
    assert (summary["trusted_certificate_authorities"], summary["expired_certificate_authorities"],
            summary["certificate_authorities_expiry_unknown"], summary["certificate_authorities_without_crl"]) == (
        3, 1, 1, 1)


def test_failed_reads_are_null_never_zero(monkeypatch, tmp_path):
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=("authorities", "g3"))
    summary, results = evidence["summary"], evidence["results"]
    assert code == 1
    # Only the PKI store was read, so the list holds its CAs (none) and every count is null.
    assert results["trusted_certificate_authorities"] == []
    assert results["certificate_authority_stores"]["certificate_based_auth_configuration"] == {
        "status": "failed", "certificate_authorities": None}
    for key in ("trusted_certificate_authorities", "expired_certificate_authorities",
                "certificate_authorities_expiry_unknown", "certificate_authorities_without_crl"):
        assert summary[key] is None, key
    # The Authenticator group is unread: whether weaker methods reach u2 is unknown, but SMS reaches everyone.
    users = {u["id"]: u for u in results["x509_certificate_users"]}
    assert (users["u2"]["weaker_method_enabled"], users["u2"]["weaker_methods_unknown"]) == (
        True, ["MicrosoftAuthenticator"])
    assert users["u1"]["weaker_method_enabled"] is True
    assert (summary["x509_targeted_users"], summary["x509_targeted_users_with_weak_methods"]) == (3, 3)

    _, evidence, _ = run(monkeypatch, tmp_path, (_x509(include=("g1",)), _method("MicrosoftAuthenticator",
                                                                                   include=("g3",))),
                         fail=("g3",))
    # Without SMS, whether Authenticator reaches anyone depends on the unread group.
    users = {u["id"]: u for u in evidence["results"]["x509_certificate_users"]}
    assert {u["weaker_method_enabled"] for u in users.values()} == {None}
    assert (evidence["summary"]["x509_targeted_users_with_weaker_methods"],
            evidence["summary"]["x509_targeted_users_with_weak_methods"]) == (None, 0)

    for fail in ("users", "g1"):
        code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, fail=(fail,))
        assert code == 1 and evidence["results"]["x509_certificate_users"] is None, fail
        for key in ("x509_targeted_users", "x509_targeted_users_unmapped",
                    "x509_targeted_users_without_certificate_user_ids", "x509_targeted_users_with_weaker_methods",
                    "x509_targeted_users_with_weak_methods"):
            assert evidence["summary"][key] is None, (fail, key)


def test_x509_off_reads_no_users_and_counts_none_targeted(monkeypatch, tmp_path):
    code, evidence, calls = run(monkeypatch, tmp_path, (_x509(state="disabled"), _method("Sms")))
    assert code == 0 and evidence["results"]["x509_certificate_users"] == []
    assert (evidence["summary"]["x509_targeted_users"], evidence["summary"]["x509_targeted_users_unmapped"]) == (0, 0)
    assert [c for c in calls if c[0] not in ("authorities", "pki")] == []


def test_an_unreadable_policy_leaves_the_targets_unknown(monkeypatch, tmp_path):
    monkeypatch.setattr(ap, "project_methods_policy", lambda model: None)
    _, evidence, calls = run(monkeypatch, tmp_path, CONFIGS)
    assert evidence["summary"]["x509_targeted_users"] is None
    assert [c for c in calls if c[0] == "users"] == []


def test_pki_store_cas_are_read_with_the_classic_ones_and_counted_once(monkeypatch, tmp_path):
    shared = _cert(300)
    past = datetime(2026, 1, 1, tzinfo=timezone.utc)
    pki = {"p1": [_pki_authority(300, cert=shared, crl=""),
                  _pki_authority(0, kind=Kind.INTERMEDIATE, cert=b"unreadable", expires=past, thumbprint="ab12")]}
    code, evidence, calls = run(monkeypatch, tmp_path, CONFIGS, [_authority(300, cert=shared)], pki=pki)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert [c[0] for c in calls if c[0].startswith("pki")] == ["pki", "pki p1"]
    records = results["trusted_certificate_authorities"]
    assert [(r["trust_store"], r["authority_type"], r["has_crl"], r["expired"]) for r in records] == [
        ("certificate_based_auth_configuration", "root", True, False),
        ("public_key_infrastructure", "root", False, False),
        ("public_key_infrastructure", "intermediate", True, True)]
    # The unreadable certificate takes the service's expiry and thumbprint.
    assert (records[2]["not_after"], records[2]["thumbprint"]) == ("2026-01-01T00:00:00Z", "AB12")
    assert records[0]["thumbprint"] == records[1]["thumbprint"]
    assert results["certificate_authority_stores"]["public_key_infrastructure"] == {
        "status": "read", "certificate_authorities": 2, "missing_permission": None}
    # The CA in both stores counts once, and without a CRL because its PKI entry has none.
    assert (summary["trusted_certificate_authorities"], summary["expired_certificate_authorities"],
            summary["certificate_authorities_expiry_unknown"], summary["certificate_authorities_without_crl"]) == (
        2, 1, 0, 1)
    assert (summary["classic_store_certificate_authorities"], summary["pki_store_certificate_authorities"],
            summary["pki_store_status"], summary["pki_store_missing_permission"]) == (1, 2, "read", None)


@pytest.mark.parametrize("fail", ["pki", "pki_authorities"])
def test_a_refused_pki_store_reads_null_and_names_the_grant(monkeypatch, tmp_path, fail):
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=(fail,),
                            pki={"p1": [_pki_authority(30)]})
    summary, results = evidence["summary"], evidence["results"]
    # The grant is optional: the run succeeds, and the store is unknown rather than empty.
    assert code == 0 and evidence["metadata"].get("partial_failure") is not True
    assert results["certificate_authority_stores"]["public_key_infrastructure"] == {
        "status": "not_authorized", "certificate_authorities": None,
        "missing_permission": "PublicKeyInfrastructure.Read.All"}
    assert (summary["pki_store_status"], summary["pki_store_missing_permission"],
            summary["pki_store_certificate_authorities"], summary["classic_store_certificate_authorities"]) == (
        "not_authorized", "PublicKeyInfrastructure.Read.All", None, 1)
    for key in ("trusted_certificate_authorities", "expired_certificate_authorities",
                "certificate_authorities_expiry_unknown", "certificate_authorities_without_crl"):
        assert summary[key] is None, key
    assert [r["trust_store"] for r in results["trusted_certificate_authorities"]] == [
        "certificate_based_auth_configuration"]


def test_a_failed_pki_read_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=("pki_error",))
    summary = evidence["summary"]
    assert code == 1
    assert (summary["pki_store_status"], summary["pki_store_missing_permission"],
            summary["trusted_certificate_authorities"]) == ("failed", None, None)


def test_mapping_is_unknown_without_reported_bindings():
    methods = ap.method_records(ap.project_methods_policy(ns(authentication_method_configurations=[
        _x509(include=("all_users",), exclude=(), bindings=False)])))
    users = ap.certificate_users({"policy": True}, methods, [ap.project_user(_user("u1", cert_ids=1))], {})
    assert (users[0]["mapped"], users[0]["mapped_high_affinity"]) == (None, None)
    assert ap.summarize_certificates([], users)["x509_targeted_users_unmapped"] is None


@pytest.mark.parametrize("include,exclude,members,expected", [
    (["all_users"], [], {}, True),
    (["g1"], [], {"g1": {"u1"}}, True),
    (["g1"], ["g2"], {"g1": {"u1"}, "g2": {"u1"}}, False),
    (["g1"], [], {"g1": None}, None),
    (["g1"], ["g2"], {"g1": {"u1"}, "g2": None}, None),
    (["g1"], ["g2"], {"g1": None, "g2": {"u1"}}, False),
    (["u1"], [], {}, True),
])
def test_method_applies(include, exclude, members, expected):
    method = {"enabled": True,
              "include_targets": [{"id": t, "target_type": "user" if t.startswith("u") else "group"} for t in include],
              "exclude_targets": [{"id": t, "target_type": "group"} for t in exclude]}
    assert ap.method_applies(method, "U1", members) is expected
