"""azure_entra_authentication_policy: trusted certificate authorities, and the users the X.509 method targets."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from types import ModuleType
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


def _status_error(status):
    error = Exception(f"Resource not found for the segment 'publicKeyInfrastructure'. ({status})")
    error.response_status_code = status
    return error


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
    return ns(issuer=f"CN=Example CA {days_left}", issuer_ski=f"ab{days_left}", is_root_authority=root,
              certificate_revocation_list_url=crl, delta_certificate_revocation_list_url=None,
              certificate=cert if cert is not None else _cert(days_left))


def _pki_authority(days_left, kind=Kind.ROOT, crl="http://crl.example/pki.crl", cert=None, expires=None,
                   thumbprint=None):
    return ns(display_name=f"PKI CA {days_left}", issuer=f"CN=PKI CA {days_left}", issuer_subject_key_identifier=f"cd{days_left}",
              certificate_authority_type=kind, certificate_revocation_list_url=crl,
              delta_certificate_revocation_list_url=None, certificate=cert if cert is not None else _cert(days_left),
              expiration_date_time=expires, thumbprint=thumbprint)


def _target(tid, kind="group"):
    return ns(id=tid, target_type=kind, is_registration_required=False)


def _binding(field, prop, priority, affinity=Affinity.LOW):
    return ns(x509_certificate_field=field, user_property=prop, priority=priority, trust_affinity_level=affinity)


# Entra's default bindings: the certificate's names against the UPN, its SKI against the certificate user ids.
DEFAULT_BINDINGS = [_binding("PrincipalName", "userPrincipalName", 1), _binding("RFC822Name", "userPrincipalName", 2),
                    _binding("SubjectKeyIdentifier", "certificateUserIds", 3, Affinity.HIGH)]


def _x509(state="enabled", include=("g1",), exclude=("g2",), bindings=True):
    return ns(
        id="X509Certificate", state=state,
        include_targets=[_target(t) for t in include], exclude_targets=[_target(t) for t in exclude],
        authentication_mode_configuration=ns(x509_certificate_authentication_default_mode=Mode.MULTI),
        certificate_user_bindings=bindings if isinstance(bindings, list) else [
            _binding("SubjectKeyIdentifier", "certificateUserIds", 2, Affinity.HIGH),
            _binding("PrincipalName", "onPremisesUserPrincipalName", 1),
        ] if bindings else [],
    )


def _method(mid, include=("all_users",), state="enabled"):
    return ns(id=mid, state=state, include_targets=[_target(t) for t in include], exclude_targets=[])


def _user(uid, cert_ids=0, on_prem=None, user_type="Member", enabled=True, ids=()):
    return ns(id=uid, user_principal_name=f"{uid}@example.com", user_type=user_type, account_enabled=enabled,
              on_premises_user_principal_name=on_prem,
              authorization_info=ns(certificate_user_ids=[f"X509:<SKI>{i}" for i in range(cert_ids)] + list(ids)))


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


def _client(calls, configs, authorities, fail=(), pki=None, pki_error=None):
    policy = ns(id="authenticationMethodsPolicy", policy_migration_state="migrationComplete",
                authentication_method_configurations=configs)
    organization = ns(
        get=_async(ns(value=[ns(id="t1", display_name="Example", verified_domains=[])])),
        by_organization_id=lambda oid: ns(certificate_based_auth_configuration=Pages(
            DENIED if "authorities" in fail else RuntimeError("timed out") if "authorities_error" in fail
            else [ns(certificate_authorities=authorities)], calls, "authorities")),
    )

    def group(gid):
        members = DENIED if gid in fail else [next(u for u in USERS if u.id == uid) for uid in GROUPS.get(gid, [])]
        return ns(transitive_members=ns(graph_user=Pages(members, calls, f"group {gid}")))

    return ns(
        organization=organization,
        policies=ns(authentication_methods_policy=ns(get=_async(policy)),
                    identity_security_defaults_enforcement_policy=ns(get=_async(ns(is_enabled=False)))),
        group_settings=Pages(DENIED if "group_settings" in fail else []),
        group_setting_templates=ns(by_group_setting_template_id=lambda tid: ns(get=_async(ns(values=[
            ns(name="LockoutThreshold", default_value="10")])))),
        subscribed_skus=Pages([]),
        users=Pages(DENIED if "users" in fail else USERS, calls, "users"),
        groups=ns(by_group_id=group),
        directory=ns(public_key_infrastructure=ns(certificate_based_auth_configurations=PkiStore(
            pki or {}, calls, error=DENIED if "pki" in fail else RuntimeError("timed out") if "pki_error" in fail
            else pki_error, ca_error=DENIED if "pki_authorities" in fail else None))),
    )


class Query:
    def __init__(self, select=None, top=None):
        self.select, self.top = select, top


def _stub_msgraph(monkeypatch):
    """Stand in for the msgraph and kiota imports the X.509 user reads make, so these tests run without the
    azure extra (the CI `test` job doesn't install it)."""
    for module_name, cls in {
        "msgraph.generated.users.users_request_builder": "UsersRequestBuilder",
        "msgraph.generated.groups.item.transitive_members.graph_user.graph_user_request_builder":
            "GraphUserRequestBuilder",
    }.items():
        module = ModuleType(module_name)
        setattr(module, cls, type(cls, (), {f"{cls}GetQueryParameters": Query}))
        monkeypatch.setitem(sys.modules, module_name, module)
    config = ModuleType("kiota_abstractions.base_request_configuration")
    config.RequestConfiguration = lambda query_parameters=None: ns(query_parameters=query_parameters)
    monkeypatch.setitem(sys.modules, "kiota_abstractions.base_request_configuration", config)


def run(monkeypatch, tmp_path, configs, authorities=(), fail=(), pki=None, pki_error=None):
    calls: list = []
    client = _client(calls, list(configs), list(authorities), fail, pki, pki_error)

    async def with_client(collector, cred, work, default=None):
        return await work(client)

    _stub_msgraph(monkeypatch)
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


def test_targeted_users_are_matched_to_certificates_and_their_weaker_methods_listed(
        monkeypatch, tmp_path, assert_summary_documented):
    code, evidence, calls = run(monkeypatch, tmp_path, CONFIGS)
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0
    assert_summary_documented("azure/entra_authentication_policy", summary)
    # Guests, disabled accounts, excluded members and users outside the target groups are not targeted.
    users = {u["id"]: u for u in results["x509_certificate_users"]}
    assert sorted(users) == ["u1", "u2", "u7"]
    def mapping(uid):
        u = users[uid]
        return u["mapping"], u["mapped"], u["mapped_high_affinity"], u["certificate_user_id_types"]
    assert mapping("u1") == ("certificate_user_id", True, True, ["SubjectKeyIdentifier"])
    # Only the certificate shows whether it carries u2's on-premises name.
    assert mapping("u2") == ("unverified", None, False, [])
    assert mapping("u7") == ("none", False, False, [])
    # Email signs in guests only, FIDO2 is phishing-resistant and Voice is off.
    assert users["u2"]["weaker_methods_enabled"] == ["MicrosoftAuthenticator", "Sms"]
    assert users["u7"]["weaker_methods_enabled"] == ["Sms"]
    assert (summary["x509_targeted_users"], summary["x509_targeted_users_unmapped"],
            summary["x509_targeted_users_mapping_unverified"],
            summary["x509_targeted_users_without_certificate_user_ids"],
            summary["x509_targeted_users_with_weaker_methods"], summary["x509_targeted_users_with_weak_methods"]) == (
        3, 1, 1, 2, 3, 3)
    # X.509 targets a group, so its users come from the groups the enabled methods name, with their certificate
    # user ids, and the directory isn't read.
    assert [c for c in calls if c[0] == "users"] == []
    groups = [c for c in calls if c[0].startswith("group")]
    assert sorted(c[0] for c in groups) == ["group g1", "group g2", "group g3"]
    assert all("authorizationInfo" in c[1].query_parameters.select for c in groups)
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
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=("authorities_error", "g3"))
    summary, results = evidence["summary"], evidence["results"]
    assert code == 1
    # The classic store failed, so the list and every count are null even though the PKI store read empty.
    assert results["trusted_certificate_authorities"] is None
    assert results["certificate_authority_stores"]["certificate_based_auth_configuration"] == {
        "status": "failed", "certificate_authorities": None, "missing_permission": None, "authorities": None}
    assert (summary["classic_store_status"], summary["classic_store_missing_permission"]) == ("failed", None)
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

    for fail, x509 in (("users", _x509(include=("all_users",))), ("g1", _x509())):
        code, evidence, _ = run(monkeypatch, tmp_path, (x509, *CONFIGS[1:]), fail=(fail,))
        assert code == 1 and evidence["results"]["x509_certificate_users"] is None, fail
        for key in ("x509_targeted_users", "x509_targeted_users_unmapped",
                    "x509_targeted_users_without_certificate_user_ids", "x509_targeted_users_with_weaker_methods",
                    "x509_targeted_users_with_weak_methods"):
            assert evidence["summary"][key] is None, (fail, key)


def test_all_users_targeting_reads_the_directory(monkeypatch, tmp_path):
    code, evidence, calls = run(monkeypatch, tmp_path, (_x509(include=("all_users",), exclude=("g2",)), _method("Fido2")))
    (users_call,) = [c for c in calls if c[0] == "users"]
    assert "authorizationInfo" in users_call[1].query_parameters.select
    # u4 is a guest, u5 is disabled and u3 is excluded.
    assert (code, evidence["summary"]["x509_targeted_users"]) == (0, 4)


def test_only_users_failing_a_check_are_listed_and_the_list_is_capped(monkeypatch, tmp_path):
    configs = (_x509(), _method("Fido2"))
    _, evidence, _ = run(monkeypatch, tmp_path, configs)
    # u1 is matched by its certificate user id and reached by no weaker method, so only the counts include it.
    assert [u["id"] for u in evidence["results"]["x509_certificate_users"]] == ["u2", "u7"]
    assert (evidence["summary"]["x509_targeted_users"], evidence["summary"]["x509_certificate_users_truncated"]) == (
        3, False)
    monkeypatch.setattr(ap, "MAX_LISTED_USERS", 1)
    _, evidence, _ = run(monkeypatch, tmp_path, configs)
    assert [u["id"] for u in evidence["results"]["x509_certificate_users"]] == ["u2"]
    assert (evidence["summary"]["x509_targeted_users_unmapped"], evidence["summary"]["x509_certificate_users_truncated"]) == (
        1, True)


def test_x509_off_reads_no_users_and_counts_none_targeted(monkeypatch, tmp_path):
    code, evidence, calls = run(monkeypatch, tmp_path, (_x509(state="disabled"), _method("Sms")))
    assert code == 0 and evidence["results"]["x509_certificate_users"] == []
    assert (evidence["summary"]["x509_targeted_users"], evidence["summary"]["x509_targeted_users_unmapped"]) == (0, 0)
    assert [c for c in calls if c[0] not in ("authorities", "pki")] == []


def test_an_unreadable_policy_leaves_the_methods_and_targets_unknown(monkeypatch, tmp_path):
    monkeypatch.setattr(ap, "project_methods_policy", lambda model: None)
    _, evidence, calls = run(monkeypatch, tmp_path, CONFIGS)
    assert evidence["results"]["authentication_methods"] is None
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
    pki_store = results["certificate_authority_stores"]["public_key_infrastructure"]
    assert {k: v for k, v in pki_store.items() if k != "authorities"} == {
        "status": "read", "certificate_authorities": 2, "missing_permission": None}
    assert pki_store["authorities"] == records[1:]
    # The CA in both stores counts once, and without a CRL because its PKI entry has none.
    assert (summary["trusted_certificate_authorities"], summary["expired_certificate_authorities"],
            summary["certificate_authorities_expiry_unknown"], summary["certificate_authorities_without_crl"]) == (
        2, 1, 0, 1)
    assert (summary["classic_store_certificate_authorities"], summary["pki_store_certificate_authorities"],
            summary["pki_store_status"], summary["pki_store_missing_permission"]) == (1, 2, "read", None)
    assert (summary["classic_store_status"], summary["classic_store_missing_permission"]) == ("read", None)


@pytest.mark.parametrize("fail", ["pki", "pki_authorities"])
def test_a_refused_pki_store_reads_null_and_names_the_grant(monkeypatch, tmp_path, fail):
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=(fail,),
                            pki={"p1": [_pki_authority(30)]})
    summary, results = evidence["summary"], evidence["results"]
    # The grant is optional: the run succeeds, and the store is unknown rather than empty.
    assert code == 0 and evidence["metadata"].get("partial_failure") is not True
    assert results["certificate_authority_stores"]["public_key_infrastructure"] == {
        "status": "not_authorized", "certificate_authorities": None,
        "missing_permission": "PublicKeyInfrastructure.Read.All", "authorities": None}
    assert (summary["pki_store_status"], summary["pki_store_missing_permission"],
            summary["pki_store_certificate_authorities"], summary["classic_store_certificate_authorities"]) == (
        "not_authorized", "PublicKeyInfrastructure.Read.All", None, 1)
    for key in ("trusted_certificate_authorities", "expired_certificate_authorities",
                "certificate_authorities_expiry_unknown", "certificate_authorities_without_crl"):
        assert summary[key] is None, key
    # The combined list needs both stores; the classic store's own CAs are still listed under it.
    assert results["trusted_certificate_authorities"] is None
    assert [r["trust_store"] for r in results["certificate_authority_stores"][
        "certificate_based_auth_configuration"]["authorities"]] == ["certificate_based_auth_configuration"]


def test_a_refused_classic_store_reads_null_and_names_the_grant(monkeypatch, tmp_path):
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=("authorities",),
                            pki={"p1": [_pki_authority(30)]})
    summary, results = evidence["summary"], evidence["results"]
    # The grant is optional: the run succeeds, and the store is unknown rather than empty.
    assert code == 0 and evidence["metadata"].get("partial_failure") is not True
    assert results["certificate_authority_stores"]["certificate_based_auth_configuration"] == {
        "status": "not_authorized", "certificate_authorities": None, "missing_permission": "Organization.Read.All",
        "authorities": None}
    assert (summary["classic_store_status"], summary["classic_store_missing_permission"],
            summary["classic_store_certificate_authorities"], summary["pki_store_certificate_authorities"]) == (
        "not_authorized", "Organization.Read.All", None, 1)
    for key in ("trusted_certificate_authorities", "expired_certificate_authorities",
                "certificate_authorities_expiry_unknown", "certificate_authorities_without_crl"):
        assert summary[key] is None, key
    assert results["trusted_certificate_authorities"] is None
    assert len(results["certificate_authority_stores"]["public_key_infrastructure"]["authorities"]) == 1

    # The likely shape without the grant: the other store reads empty, which is still no proof of "no CAs".
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, fail=("authorities",))
    assert code == 0 and evidence["results"]["trusted_certificate_authorities"] is None
    assert evidence["results"]["certificate_authority_stores"]["public_key_infrastructure"]["authorities"] == []

    # With neither store read, there is no list at all.
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=("authorities", "pki"))
    assert code == 0 and evidence["results"]["trusted_certificate_authorities"] is None


def test_a_failed_classic_read_fails_the_run(monkeypatch, tmp_path):
    code, evidence, _ = run(monkeypatch, tmp_path, (_x509(state="disabled"),), [_authority(300)],
                            fail=("authorities_error",))
    summary = evidence["summary"]
    assert code == 1 and evidence["results"]["trusted_certificate_authorities"] is None
    assert (summary["classic_store_status"], summary["classic_store_missing_permission"],
            summary["classic_store_certificate_authorities"], summary["trusted_certificate_authorities"]) == (
        "failed", None, None, None)


@pytest.mark.parametrize("error", ["timeout", 503])
def test_a_failed_pki_read_fails_the_run(monkeypatch, tmp_path, error):
    fail, pki_error = (("pki_error",), None) if error == "timeout" else ((), _status_error(error))
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], fail=fail, pki_error=pki_error)
    summary = evidence["summary"]
    assert code == 1 and evidence["results"]["trusted_certificate_authorities"] is None
    assert (summary["pki_store_status"], summary["pki_store_missing_permission"],
            summary["trusted_certificate_authorities"]) == ("failed", None, None)


@pytest.mark.parametrize("status", [400, 404])
def test_a_cloud_without_the_pki_store_reads_not_available_and_still_succeeds(monkeypatch, tmp_path, status):
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [_authority(300)], pki_error=_status_error(status))
    summary, results = evidence["summary"], evidence["results"]
    assert code == 0 and evidence["metadata"].get("partial_failure") is not True
    assert (summary["pki_store_status"], summary["pki_store_missing_permission"],
            summary["pki_store_certificate_authorities"], summary["classic_store_certificate_authorities"],
            summary["trusted_certificate_authorities"]) == ("not_available", None, None, 1, None)
    assert results["trusted_certificate_authorities"] is None
    assert len(results["certificate_authority_stores"]["certificate_based_auth_configuration"]["authorities"]) == 1


def test_an_unreadable_classic_certificate_matches_its_pki_entry_by_key_identifier(monkeypatch, tmp_path):
    classic = _authority(300, cert=b"unreadable")
    classic.issuer_ski = "AB:12:CD"
    pki = _pki_authority(300)
    pki.issuer_subject_key_identifier = "ab12cd"
    _, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, [classic], pki={"p1": [pki]})
    summary = evidence["summary"]
    # Counted once, with the expiry its PKI entry could read.
    assert (summary["trusted_certificate_authorities"], summary["certificate_authorities_expiry_unknown"],
            summary["expired_certificate_authorities"]) == (1, 0, 0)


def test_failed_settings_read_leaves_the_password_values_null_not_the_defaults(monkeypatch, tmp_path):
    summary = run(monkeypatch, tmp_path, CONFIGS)[1]["summary"]
    assert (summary["password_settings_source"], summary["lockout_threshold"]) == ("template_defaults", 10)
    code, evidence, _ = run(monkeypatch, tmp_path, CONFIGS, fail=("group_settings",))
    summary = evidence["summary"]
    assert code == 1
    assert [summary[k] for k in ("password_settings_source", "custom_banned_password_check_enabled",
                                 "custom_banned_password_count", "custom_banned_password_list_enforced",
                                 "lockout_threshold", "lockout_duration_in_seconds")] == [None] * 6


def test_a_missing_cryptography_package_raises_rather_than_reading_as_an_unreadable_certificate(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography", None)
    with pytest.raises(ImportError):
        ap.certificate_details(b"not a certificate")


def test_mapping_is_unknown_without_reported_bindings():
    methods = ap.method_records(ap.project_methods_policy(ns(authentication_method_configurations=[
        _x509(include=("all_users",), exclude=(), bindings=False)])))
    users = ap.certificate_users({"policy": True}, methods, [ap.project_user(_user("u1", cert_ids=1))], {})
    assert (users[0]["mapping"], users[0]["mapped"], users[0]["mapped_high_affinity"]) == (None, None, None)
    summary = ap.summarize_certificates([], users)
    assert (summary["x509_targeted_users_unmapped"], summary["x509_targeted_users_mapping_unverified"]) == (None, None)


def _mapped(bindings, *users):
    methods = ap.method_records(ap.project_methods_policy(ns(authentication_method_configurations=[
        _x509(include=("all_users",), exclude=(), bindings=bindings)])))
    records = ap.certificate_users({"policy": True}, methods, [ap.project_user(u) for u in users], {})
    return {r["id"]: (r["mapping"], r["mapped"], r["mapped_high_affinity"]) for r in records}


def test_each_binding_matches_only_its_own_certificate_user_id_type():
    # A PrincipalName id doesn't satisfy the SKI binding, and the UPN bindings depend on the certificate.
    assert _mapped(DEFAULT_BINDINGS, _user("pn", ids=["X509:<PN>pn@example.com"]), _user("ski", cert_ids=1)) == {
        "pn": ("unverified", None, False), "ski": ("certificate_user_id", True, True)}
    bindings = [_binding("PrincipalName", "certificateUserIds", 1),
                _binding("IssuerAndSerialNumber", "certificateUserIds", 2, Affinity.HIGH)]
    assert _mapped(bindings, _user("pn", ids=["X509:<PN>pn@example.com"]),
                   _user("sr", ids=["X509:<I>DC=example,CN=CA<SR>0a1b"]), _user("ski", cert_ids=1)) == {
        "pn": ("certificate_user_id", True, False), "sr": ("certificate_user_id", True, True),
        "ski": ("none", False, False)}
    # A field this fetcher doesn't know is never counted as a match or a miss.
    assert _mapped([_binding("SHA256PublicKey", "certificateUserIds", 1, Affinity.HIGH)], _user("ski", cert_ids=1)) == {
        "ski": ("unverified", None, None)}


@pytest.mark.parametrize("value,field", [
    ("X509:<PN>bob@example.com", "PrincipalName"), ("X509:<RFC822>bob@example.com", "RFC822Name"),
    ("X509:<SKI>aB1c", "SubjectKeyIdentifier"), ("x509:<SHA1-PUKEY>cD2e", "SHA1PublicKey"),
    ("X509:<S>DC=example,CN=bob", "Subject"), ("X509:<I>DC=example,CN=CA<S>DC=example,CN=bob", "IssuerAndSubject"),
    ("X509:<I>DC=example,CN=CA<SR>0a1b", "IssuerAndSerialNumber"), ("X509:<OTHER>x", None), ("bob", None),
])
def test_certificate_id_field(value, field):
    assert ap.certificate_id_field(value) == field


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
