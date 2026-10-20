"""Azure Key Vault certificate lifecycle: Key Vault and App Service certificates. Synthetic fixtures, no SDK or network."""

from __future__ import annotations

import enum
import importlib.util
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kv = _load("key_vault_key_rotation")
Collector = sys.modules["azure_common"].Collector

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-kv"
VAULT_ID = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-one"
VAULT_URI = "https://kv-one.vault.azure.net/"


class Action(str, enum.Enum):
    AUTO_RENEW = "AutoRenew"
    EMAIL_CONTACTS = "EmailContacts"


class HttpResponseError(Exception):
    def __init__(self, status_code, message="refused"):
        super().__init__(f"({status_code}) {message}")
        self.status_code = status_code


class ClientAuthenticationError(HttpResponseError):
    def __init__(self, message="DefaultAzureCredential failed to retrieve a token"):
        Exception.__init__(self, message)
        self.status_code = None


class ServiceRequestError(Exception):
    pass


def collector():
    return Collector(logging.getLogger("test_kv"))


def cert_props(name, expires=datetime(2027, 1, 1, tzinfo=timezone.utc), thumbprint=b"\x0a\xbc"):
    return ns(id=f"{VAULT_URI}certificates/{name}", name=name, enabled=True, created_on=NOW, updated_on=NOW,
              expires_on=expires, not_before=None, recovery_level="Recoverable+Purgeable", x509_thumbprint=thumbprint)


def policy(*actions, issuer="Self"):
    return ns(issuer_name=issuer, subject="CN=app.example.com", validity_in_months=12, key_type="RSA", key_size=2048,
              key_curve_name=None, reuse_key=False, exportable=True, content_type="application/x-pkcs12",
              lifetime_actions=[ns(action=a, lifetime_percentage=80, days_before_expiry=None) for a in actions])


def fake_certificates(monkeypatch, listed=(), list_error=None, policies=None, page_error=None):
    policies = policies or {}

    def pages():
        yield from listed
        raise page_error

    class CertificateClient:
        def __init__(self, vault_url, credential):
            self.vault_url = vault_url

        def list_properties_of_certificates(self):
            if list_error:
                raise list_error
            return pages() if page_error else iter(listed)

        def get_certificate_policy(self, name):
            result = policies.get(name)
            if isinstance(result, Exception):
                raise result
            return result

    monkeypatch.setitem(sys.modules, "azure.keyvault.certificates", ns(CertificateClient=CertificateClient))


def vault(**overrides):
    return {"id": VAULT_ID, "name": "kv-one", "vault_uri": VAULT_URI, **overrides}


# --- Key Vault certificates: the data-plane read ---

@pytest.mark.parametrize("status_code", [401, 403])
def test_refused_certificate_list_is_not_authorized_not_zero_certificates(monkeypatch, status_code):
    fake_certificates(monkeypatch, list_error=HttpResponseError(status_code, "Caller is not authorized"))
    v, c = vault(), collector()
    kv.collect_certificates(v, object(), c, NOW)
    record = kv.vault_record(v)
    assert (record["certificates_status"], record["certificates"], c.ok) == ("not_authorized", [], True)
    assert "not authorized" in record["certificates_message"]
    summary = kv.summarize_certificates([record], [])
    assert (summary["certificate_not_authorized_vaults"], summary["certificate_accessible_vaults"]) == (1, 0)


def test_refusal_on_a_later_page_is_not_authorized_with_no_partial_list(monkeypatch):
    fake_certificates(monkeypatch, listed=[cert_props("first")], page_error=HttpResponseError(403, "Forbidden"))
    v, c = vault(), collector()
    kv.collect_certificates(v, object(), c, NOW)
    assert (v["certificates_status"], v["certificates"], c.ok) == ("not_authorized", [], True)


@pytest.mark.parametrize("error", [
    HttpResponseError(500, "boom"), HttpResponseError(404, "vault gone"), ClientAuthenticationError(),
    ServiceRequestError("connection reset"),
])
def test_other_certificate_list_failures_fail_the_run(monkeypatch, error):
    fake_certificates(monkeypatch, list_error=error)
    v, c = vault(), collector()
    kv.collect_certificates(v, object(), c, NOW)
    assert (v["certificates_status"], c.ok) == ("failed", False)
    assert c.failures[0]["operation"] == "keyvault.certificates.list_properties_of_certificates (kv-one)"


def test_vault_without_uri_or_name_is_not_attempted(monkeypatch):
    fake_certificates(monkeypatch)
    v = {"id": VAULT_ID, "name": None, "vault_uri": None}
    kv.collect_certificates(v, object(), collector(), NOW)
    assert kv.vault_record(v)["certificates_status"] == "not_attempted"


@pytest.mark.parametrize("policy_status", [401, 403, 404])
def test_readable_vault_lists_certificates_with_auto_renew(monkeypatch, policy_status):
    fake_certificates(
        monkeypatch,
        listed=[cert_props("web"), cert_props("api"), cert_props("old")],
        policies={
            "web": policy(Action.AUTO_RENEW),
            "api": policy(Action.EMAIL_CONTACTS, issuer="Unknown"),
            "old": HttpResponseError(policy_status, "no get permission or no policy"),
        },
    )
    v, c = vault(), collector()
    kv.collect_certificates(v, object(), c, NOW)
    assert (v["certificates_status"], c.ok) == ("accessible", True)
    by_name = {cert["name"]: cert for cert in v["certificates"]}
    assert [cert["name"] for cert in v["certificates"]] == ["api", "old", "web"]
    assert (by_name["web"]["auto_renew_enabled"], by_name["web"]["policy_readable"]) == (True, True)
    assert by_name["web"]["policy"]["lifetime_actions"] == [
        {"action": "AutoRenew", "lifetime_percentage": 80, "days_before_expiry": None}]
    assert (by_name["api"]["auto_renew_enabled"], by_name["api"]["policy"]["issuer_name"]) == (False, "Unknown")
    assert (by_name["old"]["auto_renew_enabled"], by_name["old"]["policy"]) == (None, None)
    assert by_name["web"]["x509_thumbprint"] == "0ABC"

    summary = kv.summarize_certificates([kv.vault_record(v)], [])
    assert (summary["total_certificates"], summary["certificates_with_readable_policy"],
            summary["certificates_with_auto_renew"], summary["certificate_auto_renew_percentage"]) == (3, 2, 1, 50)


@pytest.mark.parametrize("error", [HttpResponseError(500), ClientAuthenticationError()])
def test_policy_read_failure_other_than_refusal_is_recorded(monkeypatch, error):
    fake_certificates(monkeypatch, listed=[cert_props("web")], policies={"web": error})
    v, c = vault(), collector()
    kv.collect_certificates(v, object(), c, NOW)
    assert (v["certificates_status"], v["certificates"][0]["policy_readable"], c.ok) == ("accessible", False, False)


# --- expiry ---

@pytest.mark.parametrize("expires, expired, days", [
    (datetime(2026, 10, 19, 11, 0, tzinfo=timezone.utc), True, -1),
    (datetime(2026, 10, 19, 13, 0, tzinfo=timezone.utc), False, 0),
    (datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc), False, 30),
    (None, None, None),
])
def test_certificate_expiry(expires, expired, days):
    record = kv.certificate_record(kv.project_certificate_properties(cert_props("c", expires)), None, False, NOW)
    assert (record["expired"], record["days_until_expiry"]) == (expired, days)


def test_expiry_summary_counts_only_unexpired_within_thirty_days():
    records = [kv.certificate_record({"name": n, "expires": e}, None, False, NOW) for n, e in [
        ("expired", "2026-10-01T00:00:00Z"), ("soon", "2026-11-01T00:00:00Z"), ("later", "2027-06-01T00:00:00Z")]]
    summary = kv.summarize_certificates([{"certificates_status": "accessible", "certificates": records}], [])
    assert (summary["expired_certificates"], summary["certificates_expiring_within_30_days"]) == (1, 1)


def test_offset_timestamps_are_brought_to_utc():
    assert kv._utc_timestamp("2027-03-01T05:00:00+05:00") == "2027-03-01T00:00:00Z"
    assert kv._utc_timestamp(datetime(2027, 3, 1)) == "2027-03-01T00:00:00Z"


# --- App Service certificates ---

class SecretAttrs:
    """An App Service certificate whose secret-bearing fields fail the test if read."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    @property
    def pfx_blob(self):
        raise AssertionError("pfx_blob must never be read")

    @property
    def password(self):
        raise AssertionError("password must never be read")

    @property
    def cer_blob(self):
        raise AssertionError("cer_blob must never be read")


def web_cert(name, **props):
    fields = {"subject_name": "app.example.com", "host_names": ["www.example.com", "app.example.com"],
              "issuer": "Example CA", "issue_date": datetime(2026, 1, 1, tzinfo=timezone.utc),
              "expiration_date": datetime(2027, 1, 1, tzinfo=timezone.utc), "thumbprint": "0ABC",
              "canonical_name": None, "key_vault_id": None, "key_vault_secret_name": None,
              "key_vault_secret_status": None, "server_farm_id": None, **props}
    return ns(id=f"{RG}/providers/Microsoft.Web/certificates/{name}", name=name, location="eastus",
              properties=SecretAttrs(**fields))


def test_app_service_projection_never_reads_secret_fields():
    record = kv.project_app_service_certificate(web_cert("c"))
    assert record["expiration_date"] == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert not {"pfx_blob", "password", "cer_blob"} & set(record)


@pytest.mark.parametrize("props, source", [
    ({"key_vault_id": VAULT_ID, "key_vault_secret_name": "web", "key_vault_secret_status": "Succeeded"}, "key_vault"),
    ({"canonical_name": "www.example.com"}, "managed"),
    ({"domain_validation_method": "http-token"}, "managed"),
    ({}, "uploaded"),
])
def test_app_service_certificate_source(props, source):
    record = kv.app_service_certificate_record(kv.project_app_service_certificate(web_cert("c", **props)), NOW)
    assert record["source"] == source
    assert record["host_names"] == ["app.example.com", "www.example.com"]
    assert (record["expiration_date"], record["expired"], record["days_until_expiry"]) == (
        "2027-01-01T00:00:00Z", False, 73)


def test_key_vault_sync_status_and_auto_renew_link():
    vaults = [{"id": VAULT_ID.upper(), "certificates_status": "accessible",
               "certificates": [{"name": "Web", "auto_renew_enabled": True}]}]
    index = kv.key_vault_auto_renew_index(vaults)
    linked = kv.app_service_certificate_record(kv.project_app_service_certificate(web_cert(
        "a", key_vault_id=VAULT_ID, key_vault_secret_name="web", key_vault_secret_status="Succeeded")), NOW, index)
    broken = kv.app_service_certificate_record(kv.project_app_service_certificate(web_cert(
        "b", key_vault_id=VAULT_ID, key_vault_secret_name="gone", key_vault_secret_status="KeyVaultSecretDoesNotExist")),
        NOW, index)
    uploaded = kv.app_service_certificate_record(kv.project_app_service_certificate(web_cert("c")), NOW, index)
    assert (linked["key_vault_sync_succeeded"], linked["key_vault_certificate_auto_renew"]) == (True, True)
    assert (broken["key_vault_sync_succeeded"], broken["key_vault_certificate_auto_renew"]) == (False, None)
    assert (uploaded["key_vault_sync_succeeded"], uploaded["key_vault_certificate_auto_renew"]) == (None, None)

    summary = kv.summarize_certificates([], [linked, broken, uploaded])
    assert summary["app_service_certificates_by_source"] == {"key_vault": 2, "managed": 0, "uploaded": 1}
    assert kv.summarize_certificates([], [])["app_service_certificates_by_source"] == {
        "key_vault": 0, "managed": 0, "uploaded": 0}
    assert summary["app_service_certificates_key_vault_sync_failing"] == 1


@pytest.mark.parametrize("status, succeeded", [
    ("Succeeded", True),
    (None, None), ("Unknown", None), ("Initialized", None), ("WaitingOnCertificateOrder", None),
    ("CertificateOrderFailed", False), ("OperationNotPermittedOnKeyVault", False),
    ("AzureServiceUnauthorizedToAccessKeyVault", False), ("KeyVaultDoesNotExist", False),
    ("KeyVaultSecretDoesNotExist", False), ("UnknownError", False),
])
def test_key_vault_sync_status(status, succeeded):
    record = kv.app_service_certificate_record(kv.project_app_service_certificate(web_cert(
        "a", key_vault_id=VAULT_ID, key_vault_secret_name="web", key_vault_secret_status=status)), NOW)
    assert record["key_vault_sync_succeeded"] is succeeded
    assert kv.summarize_certificates([], [record])["app_service_certificates_key_vault_sync_failing"] == (
        1 if succeeded is False else 0)


def test_unreadable_vault_gives_no_auto_renew_answer():
    vaults = [{"id": VAULT_ID, "certificates_status": "not_authorized", "certificates": []}]
    record = kv.app_service_certificate_record(kv.project_app_service_certificate(web_cert(
        "a", key_vault_id=VAULT_ID, key_vault_secret_name="web", key_vault_secret_status="Succeeded")), NOW,
        kv.key_vault_auto_renew_index(vaults))
    assert record["key_vault_certificate_auto_renew"] is None


def test_app_service_list_uses_reader_arm_call(monkeypatch):
    def client(**_):
        return ns(certificates=ns(list=lambda: [web_cert("b"), web_cert("a", canonical_name="x")]))

    monkeypatch.setitem(sys.modules, "azure.mgmt.web", ns(WebSiteManagementClient=client))
    c = collector()
    records = kv.collect_app_service_certificates("sub", object(), c, [], NOW)
    assert ([r["name"] for r in records], [r["source"] for r in records], c.ok) == (
        ["a", "b"], ["managed", "uploaded"], True)


@pytest.mark.parametrize("failing", ["init", "list"])
def test_app_service_certificate_list_failure_fails_the_run(monkeypatch, failing):
    def listing():
        raise HttpResponseError(403, "does not have authorization to perform action Microsoft.Web/certificates/read")

    def client(**_):
        if failing == "init":
            raise RuntimeError("client init failed")
        return ns(certificates=ns(list=listing))

    monkeypatch.setitem(sys.modules, "azure.mgmt.web", ns(WebSiteManagementClient=client))
    c = collector()
    assert kv.collect_app_service_certificates("sub", object(), c, [], NOW) == []
    assert c.ok is False
    assert c.failures[0]["operation"] == (
        "web.WebSiteManagementClient (init)" if failing == "init" else "web.certificates.list")


# --- the existing evidence is unchanged ---

def test_existing_vault_and_summary_keys_are_kept():
    record = kv.vault_record(vault())
    assert {"id", "name", "location", "resource_group", "vault_uri", "rbac_authorization_enabled",
            "data_plane_status", "data_plane_message", "keys", "secrets"} <= set(record)
    assert set(kv.summarize([record])) == {
        "total_key_vaults", "data_plane_accessible_vaults", "data_plane_inaccessible_vaults",
        "rbac_authorization_vaults", "total_keys", "enabled_keys", "keys_with_readable_rotation_policy",
        "keys_with_rotation_policy", "keys_with_rotation_enabled", "rotation_enabled_percentage",
        "keys_with_expiration", "key_expiration_percentage", "total_secrets", "enabled_secrets",
        "secrets_with_expiration", "secret_expiration_percentage"}


def test_new_summary_keys_overwrite_nothing_and_results_keep_their_keys():
    assert not set(kv.summarize([])) & set(kv.summarize_certificates([], []))
    record = kv.vault_record(vault())
    results, summary = kv.evidence_sections([record], "registered", [], "not_registered")
    assert (results["key_vaults"], results["provider_registration_status"]) == ([record], "registered")
    assert set(results) == {"key_vaults", "provider_registration_status", "app_service_certificates",
                            "web_provider_registration_status"}
    assert set(summary) == set(kv.summarize([record])) | set(kv.summarize_certificates([record], [])) | {
        "provider_registration_status", "web_provider_registration_status"}
    assert (summary["provider_registration_status"], summary["web_provider_registration_status"]) == (
        "registered", "not_registered")
