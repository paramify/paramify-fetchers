"""azure_app_service_configuration: cipher suites, basic-auth publishing, Key Vault references and
runtime end of support, driven by a fake WebSiteManagementClient. No SDK, no credentials, no network."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_under_test", AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


appsvc = _load("app_service_configuration")

SUB = "00000000-0000-0000-0000-000000000001"
SITES = f"/subscriptions/{SUB}/resourceGroups/rg-web/providers/Microsoft.Web/sites"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
DENIED = Exception("(AuthorizationFailed) The client does not have authorization to perform action")


class RawSettings(dict):
    """A container-settings model: attributes for the named fields, mapping access for raw keys."""

    def __getattr__(self, name):
        return self.get(name)


def eol(year, month, day):
    return datetime(year, month, day, tzinfo=timezone.utc)


def runtime(version, end_of_life=None, deprecated=None):
    return ns(runtime_version=version, end_of_life_date=end_of_life, is_deprecated=deprecated)


def minor(value, **settings):
    keys = ("linux_runtime_settings", "windows_runtime_settings", "linux_container_settings",
            "windows_container_settings")
    return ns(value=value, stack_settings=ns(**{k: settings.get(k) for k in keys}))


def stack(name, *minors):
    return ns(name=name, value=name, major_versions=[ns(value=name, minor_versions=list(minors))])


STACKS = [
    stack(
        "dotnet",
        minor("8", windows_runtime_settings=runtime("v8.0", eol(2026, 11, 10)),
              linux_runtime_settings=runtime("DOTNETCORE|8.0", eol(2026, 11, 10))),
        minor("6", windows_runtime_settings=runtime("v6.0", eol(2024, 11, 12), True)),
        minor("v4.8", windows_runtime_settings=runtime("v4.0")),
    ),
    stack("node", minor("20-lts", linux_runtime_settings=runtime("NODE|20-lts", eol(2026, 4, 30)))),
    stack("php", minor("5.6", windows_runtime_settings=runtime("5.6", eol(2021, 2, 1), True))),
    stack("python", minor("3.12", linux_runtime_settings=runtime("PYTHON|3.12", eol(2028, 10, 31)))),
    stack(
        "javacontainers",
        minor("10.1",
              linux_container_settings=RawSettings(java11Runtime="TOMCAT|10.1-java11",
                                                   java17Runtime="TOMCAT|10.1-java17",
                                                   end_of_life_date=eol(2027, 12, 31), runtimes=[]),
              windows_container_settings=ns(java_container="TOMCAT", java_container_version="10.1",
                                            end_of_life_date=None, is_deprecated=None)),
        minor("8.5", windows_container_settings=ns(java_container="TOMCAT", java_container_version="8.5",
                                                   end_of_life_date=eol(2024, 3, 31), is_deprecated=None)),
    ),
]


def index():
    return appsvc.runtime_index([e for s in STACKS for e in appsvc.project_web_app_stack(s)])


def support(kind, **config):
    return appsvc.runtime_support_record(kind, config, index(), NOW)


# --- TLS cipher suites ---

def test_no_cipher_suite_minimum_allows_every_suite():
    record = appsvc.cipher_suite_record("1.2", None)
    assert record["allowed_tls_cipher_suites"] == list(appsvc.TLS_CIPHER_SUITE_ORDER)
    assert record["allows_cbc_cipher_suites"] is True
    assert record["allows_non_forward_secret_cipher_suites"] is True


def test_minimum_at_last_ecdhe_gcm_suite_blocks_cbc_and_static_rsa():
    record = appsvc.cipher_suite_record("1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert len(record["allowed_tls_cipher_suites"]) == 6
    assert record["allows_cbc_cipher_suites"] is False
    assert record["allows_non_forward_secret_cipher_suites"] is False


def test_ecdsa_cbc_suite_sits_below_the_gcm_suites():
    record = appsvc.cipher_suite_record("1.2", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256")
    assert record["allows_cbc_cipher_suites"] is True
    assert record["allows_non_forward_secret_cipher_suites"] is False


def test_tls_1_3_minimum_leaves_only_tls_1_3_suites():
    record = appsvc.cipher_suite_record("1.3", "TLS_RSA_WITH_AES_128_CBC_SHA")
    assert record["allowed_tls_cipher_suites"] == ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]
    assert record["allows_cbc_cipher_suites"] is False


def test_unknown_cipher_suite_minimum_is_unknown_not_safe():
    record = appsvc.cipher_suite_record("1.2", "TLS_SOMETHING_NEW")
    assert record["allowed_tls_cipher_suites"] is None
    assert record["allows_cbc_cipher_suites"] is None
    assert record["allows_non_forward_secret_cipher_suites"] is None


# --- basic-auth publishing ---

@pytest.mark.parametrize(
    "scm, ftp, disabled",
    [(False, False, True), (True, False, False), (False, True, False), (None, False, None),
     (None, True, False), (None, None, None)],
)
def test_basic_auth_disabled_only_when_both_policies_are_off(scm, ftp, disabled):
    assert appsvc.basic_auth_record(scm, ftp)["disabled"] is disabled


# --- runtime end of support ---

def test_windows_dotnet_runtimes_join_to_stack_end_of_life():
    supported = support("app", net_framework_version="v8.0", php_version="")
    assert supported["past_end_of_support"] is False
    [dotnet] = supported["declared_runtimes"]
    assert (dotnet["stack"], dotnet["version"], dotnet["days_until_end_of_life"]) == ("dotnet", "8", 11)

    retired = support("app", net_framework_version="v6.0")
    assert retired["past_end_of_support"] is True
    assert retired["runtimes_past_end_of_support"] == ["v6.0"]
    assert retired["declared_runtimes"][0]["days_until_end_of_life"] < 0


def test_net_framework_4_has_no_end_of_life_date_and_is_supported():
    record = support("app", net_framework_version="v4.0", php_version="Off")
    assert record["past_end_of_support"] is False
    assert [r["setting"] for r in record["declared_runtimes"]] == ["net_framework_version"]


def test_legacy_php_alongside_dotnet_is_reported_past_end_of_support():
    record = support("app", net_framework_version="v8.0", php_version="5.6")
    assert record["past_end_of_support"] is True
    assert record["runtimes_past_end_of_support"] == ["5.6"]


def test_end_of_life_date_passed_counts_without_the_deprecated_flag():
    record = support("app,linux", linux_fx_version="NODE|20-lts", net_framework_version="v4.0")
    assert record["past_end_of_support"] is True
    assert [r["setting"] for r in record["declared_runtimes"]] == ["linux_fx_version"]


def test_linux_runtime_match_ignores_case():
    assert support("app,linux", linux_fx_version="python|3.12")["past_end_of_support"] is False


def test_linux_java_runtime_read_from_raw_container_keys():
    record = support("app,linux", linux_fx_version="TOMCAT|10.1-java17")
    assert record["past_end_of_support"] is False
    assert record["declared_runtimes"][0]["stack"] == "javacontainers"


def test_windows_java_container_joins_container_end_of_life():
    record = support("app", java_container="TOMCAT", java_container_version="8.5")
    assert record["past_end_of_support"] is True


def test_custom_container_and_unmatched_runtime_are_unknown():
    container = support("app,linux,container", linux_fx_version="DOCKER|registry.example/app:1")
    assert container["past_end_of_support"] is None
    assert container["declared_runtimes"][0]["custom_container"] is True
    assert support("app", net_framework_version="v99.0")["past_end_of_support"] is None
    assert support("app,linux", linux_fx_version="")["past_end_of_support"] is None


def test_unknown_runtime_does_not_hide_one_past_end_of_support():
    record = support("app", net_framework_version="v99.0", php_version="5.6")
    assert record["past_end_of_support"] is True


# --- collection through a fake client ---

def site(name, kind="app"):
    return ns(id=f"{SITES}/{name}", name=name, kind=kind, location="eastus", state="Running",
              default_host_name=f"{name}.example.net", https_only=True, identity=None)


def config(**overrides):
    base = dict(net_framework_version="v8.0", php_version="", min_tls_version="1.2", scm_min_tls_version="1.0",
                min_tls_cipher_suite=None, ftps_state="FtpsOnly", ip_security_restrictions=[],
                scm_ip_security_restrictions=[])
    return ns(**(base | overrides))


def kv_ref(name, status="Resolved", version=None):
    return ns(id=f"{SITES}/web-a/config/configreferences/appsettings/{name}", name=name, status=status,
              source="KeyVault", vault_name="kv-app", secret_name=name.lower(), secret_version=version,
              identity_type="SystemAssigned", details=None,
              reference="@Microsoft.KeyVault(SecretUri=https://kv-app.vault.azure.net/secrets/x/)")


def per_app(values, default=None):
    """A web_apps GET answering per app name; an Exception value is raised."""
    def fn(resource_group_name, name):
        assert resource_group_name == "rg-web"
        value = (values or {}).get(name, default)
        if isinstance(value, Exception):
            raise value
        return value
    return fn


def never_called(resource_group_name, name):
    raise AssertionError("config/list called with the scan off")


def web_client(scm=None, ftp=None, app_refs=None, conn_refs=None, stacks=None, settings=None, strings=None):
    return ns(
        web_apps=ns(
            list_application_settings=never_called if settings is None else per_app(settings, ns(properties={})),
            list_connection_strings=never_called if strings is None else per_app(strings, ns(properties={})),
            list=lambda: [site("web-a"), site("web-b"), site("func", kind="functionapp")],
            get_configuration=per_app({
                "web-a": config(min_tls_cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                "web-b": config(net_framework_version="v6.0", php_version="5.6"),
            }),
            get_auth_settings_v2_without_secrets=per_app({}, ns(platform=None, global_validation=None)),
            get_scm_allowed=per_app(scm, ns(allow=True)),
            get_ftp_allowed=per_app(ftp, ns(allow=False)),
            get_app_settings_key_vault_references=per_app(app_refs, []),
            get_site_connection_string_key_vault_references=per_app(conn_refs, []),
        ),
        provider=ns(get_web_app_stacks=lambda: STACKS if stacks is None else stacks()),
    )


def collect(monkeypatch, client, scan=False):
    fake_web = ns(WebSiteManagementClient=lambda **kwargs: client)
    monkeypatch.setitem(sys.modules, "azure.mgmt.web", fake_web)
    monkeypatch.setattr(appsvc, "_attach_diagnostic_settings", lambda *a: None)
    collector = appsvc.Collector(logging.getLogger("test"))
    apps = appsvc.collect_web_apps(SUB, object(), collector, scan)
    return {a["name"]: a for a in apps}, collector


def test_collects_new_fields_per_web_app(monkeypatch):
    client = web_client(scm={"web-a": ns(allow=False)},
                        app_refs={"web-a": [kv_ref("DB_PASSWORD"), kv_ref("API_KEY", "AccessToKeyVaultDenied", "abc")]},
                        conn_refs={"web-a": [kv_ref("Default")]})
    apps, collector = collect(monkeypatch, client)
    assert collector.ok and set(apps) == {"web-a", "web-b"}

    a, b = apps["web-a"], apps["web-b"]
    assert a["basic_auth_publishing"] == {"scm_allowed": False, "ftp_allowed": False, "disabled": True}
    assert b["basic_auth_publishing"]["disabled"] is False
    assert a["configuration"]["allows_cbc_cipher_suites"] is False
    assert b["configuration"]["allows_non_forward_secret_cipher_suites"] is True
    assert a["configuration"]["scm_min_tls_version"] == "1.0"

    refs = a["key_vault_references"]
    assert [r["name"] for r in refs["app_settings"]] == ["API_KEY", "DB_PASSWORD"]
    assert refs["app_settings"][0]["resolved"] is False and refs["app_settings"][0]["secret_version_pinned"] is True
    assert "reference" not in refs["app_settings"][0]
    assert b["key_vault_references"] == {"app_settings": [], "connection_strings": []}

    assert a["runtime_support"]["past_end_of_support"] is False
    assert b["runtime_support"]["runtimes_past_end_of_support"] == ["v6.0", "5.6"]

    summary = appsvc.summarize(list(apps.values()))
    assert summary["basic_auth_publishing_disabled_apps"] == 1
    assert summary["scm_basic_auth_allowed_apps"] == 1
    assert summary["ftp_basic_auth_allowed_apps"] == 0
    assert summary["min_tls_cipher_suite_set_apps"] == 1
    assert summary["cbc_cipher_suites_allowed_apps"] == 1
    assert summary["scm_minimum_tls_1_2_apps"] == 0
    assert summary["apps_with_key_vault_references"] == 1
    assert summary["key_vault_references"] == 3
    assert summary["unresolved_key_vault_references"] == 1
    assert summary["apps_with_unresolved_key_vault_references"] == 1
    assert summary["apps_with_runtime_past_end_of_support"] == 1
    assert summary["apps_with_runtime_support_unknown"] == 0


def test_denied_policy_read_is_recorded_and_unknown_not_disabled(monkeypatch):
    apps, collector = collect(monkeypatch, web_client(scm={"web-a": DENIED}))
    assert not collector.ok
    assert apps["web-a"]["basic_auth_publishing"] == {"scm_allowed": None, "ftp_allowed": False, "disabled": None}
    assert appsvc.classify_failure_code(collector.failures) == "not_authorized"
    assert appsvc.summarize(list(apps.values()))["basic_auth_publishing_unknown_apps"] == 1


def test_failed_reference_read_is_null_not_empty(monkeypatch):
    apps, collector = collect(monkeypatch, web_client(app_refs={"web-a": DENIED}))
    assert not collector.ok
    assert apps["web-a"]["key_vault_references"]["app_settings"] is None
    assert apps["web-a"]["key_vault_references"]["connection_strings"] == []


def test_failed_stack_read_leaves_runtime_support_uncollected(monkeypatch):
    def boom():
        raise DENIED

    apps, collector = collect(monkeypatch, web_client(stacks=boom))
    assert not collector.ok
    assert all(a["runtime_support"] is None for a in apps.values())
    assert appsvc.summarize(list(apps.values()))["apps_with_runtime_past_end_of_support"] == 0


def test_evidence_never_carries_a_setting_value(monkeypatch):
    apps, _ = collect(monkeypatch, web_client(app_refs={"web-a": [kv_ref("DB_PASSWORD")]}))
    assert "SecretUri" not in json.dumps(list(apps.values()), default=str)


# --- opt-in literal-secret scan (fake values are low-entropy on purpose) ---

KV_SETTING = "@Microsoft.KeyVault(SecretUri=https://kv-app.vault.azure.net/secrets/db/)"
PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"


@pytest.mark.parametrize("name, value, reason", [
    ("DB_PASSWORD", "xxxxxxxxxx", "secret_like_name"),
    ("SendGridKey", "xxxxxxxxxxxx", "secret_like_name"),
    ("MICROSOFT_PROVIDER_AUTHENTICATION_SECRET", "xxxxxxxxxx", "secret_like_name"),
    ("DB_PASSWORD", KV_SETTING, None),
    ("DB_PASSWORD", " @microsoft.appconfiguration(Endpoint=https://x.azconfig.io; Key=db)", None),
    ("AzureWebJobsStorage", "DefaultEndpointsProtocol=https;AccountName=st;AccountKey=xxxx", "credential_in_value"),
    ("WEBSITE_RUN_FROM_PACKAGE", "https://st.blob.core.windows.net/pkg/app.zip?sv=2022&sig=xxxx", "credential_in_value"),
    ("REDIS", "cache.example.net:6380,password=xxxx,ssl=True", "credential_in_value"),
    ("MONGO_URL", "mongodb://app:xxxxxxxx@db.example.net/app", "credential_in_value"),
    ("SIGNING", PEM_HEADER + "xxxx", "credential_in_value"),
    ("KEY_VAULT_URI", "https://kv-app.vault.azure.net/", None),
    ("ClientSecretName", "db-password-name", None),
    ("APPINSIGHTS_INSTRUMENTATIONKEY", "00000000-0000-0000-0000-000000000000", None),
    ("APPLICATIONINSIGHTS_CONNECTION_STRING", "InstrumentationKey=0000;IngestionEndpoint=https://x.example/", None),
    ("JWT_TOKEN", "short", None),
    ("API_TOKEN_ENABLED", "true", None),
    ("WEBSITE_TIME_ZONE", "Mountain Standard Time", None),
    ("DB_PASSWORD", "", None),
])
def test_literal_secret_reason(name, value, reason):
    assert appsvc.literal_secret_reason(name, value) == reason


def test_connection_strings_are_judged_by_their_value_only():
    managed = "Server=tcp:db.example.net;Database=app;Authentication=Active Directory Managed Identity"
    assert appsvc.literal_secret_reason("DbPassword", managed, by_name=False) is None
    assert appsvc.literal_secret_reason("Default", "Server=tcp:db;User ID=app;Password=xxxx", by_name=False) == (
        "credential_in_value"
    )


def scan_client(**kwargs):
    return web_client(
        settings={"web-a": ns(properties={"DB_PASSWORD": "xxxxxxxxxx", "API_KEY": KV_SETTING,
                                          "WEBSITE_TIME_ZONE": "Mountain Standard Time"}),
                  "web-b": DENIED},
        strings={"web-a": ns(properties={
            "Default": ns(value="Server=tcp:db;User ID=app;Password=xxxx", type="SQLAzure"),
            "Reports": ns(value=KV_SETTING, type="SQLAzure"),
        })},
        **kwargs,
    )


def test_scan_writes_names_and_reasons_never_values(monkeypatch):
    apps, collector = collect(monkeypatch, scan_client(), scan=True)
    assert collector.ok
    a, b = apps["web-a"]["literal_secret_scan"], apps["web-b"]["literal_secret_scan"]
    assert a == {
        "status": "scanned", "app_settings_read": 3, "connection_strings_read": 2, "has_literal_secrets": True,
        "literal_secrets": [{"name": "DB_PASSWORD", "kind": "app_setting", "reason": "secret_like_name"},
                            {"name": "Default", "kind": "connection_string", "reason": "credential_in_value"}],
    }
    assert b == {"status": "not_authorized", "app_settings_read": None, "connection_strings_read": None,
                 "literal_secrets": None, "has_literal_secrets": None}
    dumped = json.dumps(list(apps.values()), default=str)
    assert "xxxx" not in dumped and "SecretUri" not in dumped and "Mountain" not in dumped

    summary = appsvc.summarize(list(apps.values()), scan_enabled=True)
    assert summary["literal_secret_scan_enabled"] is True
    assert summary["apps_scanned_for_literal_secrets"] == 1
    assert summary["apps_literal_secret_scan_not_authorized"] == 1
    assert summary["apps_with_literal_secrets"] == 1
    assert summary["literal_secret_settings"] == 2


def test_scan_is_off_by_default_and_reads_no_values(monkeypatch):
    monkeypatch.delenv(appsvc.SCAN_ENV, raising=False)
    assert appsvc.scan_enabled() is False
    apps, collector = collect(monkeypatch, web_client())
    assert collector.ok
    assert all(a["literal_secret_scan"]["status"] == "off" for a in apps.values())
    summary = appsvc.summarize(list(apps.values()))
    assert summary["literal_secret_scan_enabled"] is False
    assert summary["apps_with_literal_secrets"] is None and summary["literal_secret_settings"] is None


def test_scan_failure_other_than_403_is_recorded(monkeypatch):
    client = web_client(settings={"web-a": RuntimeError("(InternalServerError) boom")}, strings={})
    apps, collector = collect(monkeypatch, client, scan=True)
    assert not collector.ok
    assert apps["web-a"]["literal_secret_scan"]["status"] == "error"
    assert apps["web-b"]["literal_secret_scan"]["status"] == "scanned"


@pytest.mark.parametrize("raw, enabled", [("true", True), ("1", True), ("false", False), ("", False)])
def test_scan_enabled_reads_the_env(monkeypatch, raw, enabled):
    monkeypatch.setenv(appsvc.SCAN_ENV, raw)
    assert appsvc.scan_enabled() is enabled


def test_main_writes_the_scan_block_and_limitations(monkeypatch, tmp_path):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv(appsvc.SCAN_ENV, "true")
    monkeypatch.setattr(appsvc, "resolve_subscription", lambda c: {"subscription_id": SUB, "subscription_source": "env"})
    monkeypatch.setattr(appsvc, "credential", lambda: object())
    monkeypatch.setattr(appsvc, "provider_registration_status", lambda *a: "registered")
    monkeypatch.setattr(appsvc, "web_client", lambda *a: scan_client())
    monkeypatch.setattr(appsvc, "_attach_diagnostic_settings", lambda *a: None)
    assert appsvc.main() == 0
    [path] = tmp_path.glob("azure_app_service_configuration_*.json")
    evidence = json.loads(path.read_text())
    assert evidence["results"]["literal_secret_scan"] == {
        "enabled": True, "permission": "Microsoft.Web/sites/config/list/action", "apps_not_authorized": 1,
    }
    assert evidence["results"]["limitations"] == appsvc.SCAN_LIMITATIONS
    assert evidence["summary"]["literal_secret_settings"] == 2
    assert "xxxx" not in path.read_text()
