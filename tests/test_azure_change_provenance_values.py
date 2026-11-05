"""azure_change_provenance property values: the allowlist, secret masking and the size caps. No SDK or network."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from framework import api
from framework.contract import ManifestEntry
from framework.runner.executor import _apply_config, merged_config

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

spec = importlib.util.spec_from_file_location("azure_change_provenance_values_under_test",
                                              AZURE / "change_provenance" / "fetcher.py")
cp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cp)

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-in"
SA = f"{RG}/providers/Microsoft.Storage/storageAccounts/sain"
VNET_SUBNET = f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"
OPERATOR = "operator@example.com"

# Low-entropy fakes shaped like each kind of secret.
FAKE_SECRETS = {
    "tags.connection": "AccountName=fake;AccountKey=xxxxxxxxxxxxxxxx",
    "tags.sas": "https://fake.blob.core.windows.net/c?sv=2022&sig=xxxxxxxx",
    "tags.webhook": "https://fn.example.net/api/x?code=xxxxxxxx",
    "tags.bearer": "eyJxxxxxxxx.yyyyyyyyyy.zzzz",
    "tags.pem": "-----BEGIN PRIVATE KEY-----xxxx",
    "tags.url": "https://admin:xxxxxxxx@example.net/db",
    "tags.base64": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx00==",
    "tags.hexkey": "0000000000000000000000000000abab",
    "tags.password": "hunter-two",
    "tags.apitoken": "plain-words",
}
# Secret-named paths stay withheld even when value_paths is path:*.
SECRET_PATHS = {
    "properties.siteConfig.appSettings[0].value": "fake-setting-one",
    "properties.containers[0].properties.environmentVariables[1].value": "fake-env-two",
    "properties.definition.actions.Http.inputs.headers.Authorization": "Basic fake-three",
    "properties.primaryKey": "fake-four",
    "properties.keys[0]": "fake-five",
    "properties.connectionStrings[0].connectionString": "fake-six",
    "properties.settings.commandToExecute": "fake-seven",
    "properties.configuration.secrets[0].value": "fake-eight",
    "properties.administratorLoginPassword": "fake-nine",
}
SHOWN = {
    "properties.minimumTlsVersion": ("TLS1_0", "TLS1_2"),
    "properties.publicNetworkAccess": ("Disabled", "Enabled"),
    "properties.networkAcls.ipRules[0].value": (None, "203.0.113.4"),
    "properties.networkAcls.virtualNetworkRules[0].id": (None, VNET_SUBNET),
    "properties.securityRules[2].properties.access": ("Deny", "Allow"),
    "properties.accessPolicies[0].objectId": (None, "00000000-0000-0000-0000-000000000001"),
    "properties.accessPolicies[0].permissions.secrets[0]": (None, "get"),
    "properties.accessPolicies[0].permissions.keys[1]": (None, "wrapKey"),
    "properties.defaultToOAuthAuthentication": ("false", "true"),
    "tags.owner": ("rg-shared-network-hub-east-01", "team-a"),
    "sku.name": ("Standard_LRS", "Standard_GRS"),
    "properties.securitySettings.multiUserAuthorization": ("Invalid", "Disabled"),
}


def raw(values: dict) -> dict:
    return {path: {"previousValue": v[0], "newValue": v[1]} if isinstance(v, tuple)
            else {"previousValue": None, "newValue": v} for path, v in values.items()}


def row(cid, when, changes, *, by=OPERATOR, by_type="User", client="Azure Portal", target=SA, corr=None):
    return {
        "changeId": cid, "targetResourceId": target, "targetResourceType": "microsoft.storage/storageaccounts",
        "changeType": "Update", "timestamp": when, "changedBy": by, "changedByType": by_type, "clientType": client,
        "operation": "Microsoft.Storage/storageAccounts/write", "correlationId": corr,
        "changesCount": None, "changedProperties": sorted(changes) if isinstance(changes, dict) else [],
        "changes": changes,
    }


def by_path(record):
    return {e["path"]: e for e in record["property_changes"]}


@pytest.mark.parametrize("path, value", sorted(FAKE_SECRETS.items()))
def test_secret_looking_values_and_names_are_withheld_on_allowlisted_paths(path, value):
    record = cp.change_record(row("c1", "2026-11-01T00:00:00Z", raw({path: value})), "resourcechanges")
    # The path and the reason only: no value, and nothing derived from one.
    assert by_path(record)[path] == {"path": path, "withheld": "secret"}
    assert record["property_value_counts"] == {"shown": 0, "not_allowlisted": 0, "secret": 1}


@pytest.mark.parametrize("path, value", sorted(SECRET_PATHS.items()))
def test_secret_named_paths_are_withheld_even_when_every_path_is_allowed(path, value):
    record = cp.change_record(row("c1", "2026-11-01T00:00:00Z", raw({path: value})), "resourcechanges",
                              cp.ValuePaths(["path:*"]))
    assert by_path(record)[path] == {"path": path, "withheld": "secret"}
    assert value not in json.dumps(record)


def test_allowlisted_settings_keep_both_values():
    record = cp.change_record(row("c1", "2026-11-01T00:00:00Z", raw(SHOWN)), "resourcechanges")
    entries = by_path(record)
    assert {p: (e["previous_value"], e["new_value"]) for p, e in entries.items()} == SHOWN
    assert all(e["withheld"] is None and e["truncated"] is False for e in entries.values())
    assert record["property_value_counts"] == {"shown": len(SHOWN), "not_allowlisted": 0, "secret": 0}


def test_paths_off_the_allowlist_are_named_but_their_values_withheld():
    path = "properties.definition.actions.Compose.inputs"
    entry = by_path(cp.change_record(row("c1", "t", raw({path: ("old text", "new text")})), "resourcechanges"))[path]
    assert entry == {"path": path, "withheld": "not_allowlisted"}


def test_value_paths_adds_globs_to_the_allowlist(monkeypatch):
    monkeypatch.setenv("AZURE_CHANGE_VALUE_PATHS", " path:properties.definition.actions.*.type , ")
    paths = cp.ValuePaths.from_env()
    assert (paths.extra, paths.invalid) == (["path:properties.definition.actions.*.type"], [])
    entries = by_path(cp.change_record(row("c1", "t", raw({
        "properties.definition.actions.Compose.type": ("Compose", "Terminate"),
        "properties.definition.actions.Compose.inputs": ("a", "b"),
    })), "resourcechanges", paths))
    assert entries["properties.definition.actions.Compose.type"]["new_value"] == "Terminate"
    assert entries["properties.definition.actions.Compose.inputs"]["withheld"] == "not_allowlisted"


def test_a_boolean_is_shown_under_a_secret_sounding_allowlisted_path():
    entries = by_path(cp.change_record(row("c1", "t", raw({"tags.tokenrequired": ("False", "True")})),
                                       "resourcechanges"))
    assert entries["tags.tokenrequired"]["new_value"] == "True"


def test_non_string_values_are_written_as_json_text():
    record = cp.change_record(row("c1", "t", {"sku.capacity": {"previousValue": 1, "newValue": {"a": 2}}}),
                              "resourcechanges")
    assert by_path(record)["sku.capacity"] == {"path": "sku.capacity", "previous_value": "1",
                                               "new_value": '{"a": 2}', "withheld": None, "truncated": False}


@pytest.mark.parametrize("value", [
    {"password": "plain"}, {"Key": "plain"}, [{"name": "a", "connectionString": "plain"}], '{"token": "plain"}',
])
def test_an_object_value_with_a_secret_named_key_is_withheld(value):
    changes = {"tags.blob": {"previousValue": None, "newValue": value}}
    assert by_path(cp.change_record(row("c1", "t", changes), "resourcechanges"))["tags.blob"]["withheld"] == "secret"


def test_an_object_value_without_secrets_is_shown_as_json_text():
    changes = {"tags.blob": {"previousValue": None, "newValue": ["203.0.113.4", "get"]}}
    assert by_path(cp.change_record(row("c1", "t", changes), "resourcechanges"))["tags.blob"]["new_value"] == \
        '["203.0.113.4", "get"]'


def test_changes_sent_as_json_text_are_read():
    text = json.dumps(raw({"tags.owner": ("a", "b")}))
    assert by_path(cp.change_record(row("c1", "t", text), "resourcechanges"))["tags.owner"]["new_value"] == "b"


def test_a_change_with_no_changed_properties_has_an_empty_list():
    record = cp.change_record(row("c1", "t", None), "resourcechanges")
    assert (record["property_changes"], record["property_changes_truncated"]) == ([], False)


@pytest.mark.parametrize("changes", [None, "not json", ["tags.a"], {"tags.a": "not a detail"}, {}])
def test_values_that_could_not_be_read_are_unknown_not_empty(changes):
    record = cp.change_record({**row("c1", "t", None), "changedProperties": ["tags.a"], "changes": changes},
                              "resourcechanges")
    assert [record[k] for k in ("property_changes", "property_changes_truncated", "property_value_counts")] == \
        [None, None, None]


# --- caps ---

def test_a_long_value_is_cut_and_flagged():
    long = "a" * (cp.MAX_VALUE_CHARS + 1)
    entry = by_path(cp.change_record(row("c1", "t", raw({"tags.note": ("short", long)})), "resourcechanges"))[
        "tags.note"]
    assert (entry["previous_value"], entry["new_value"], entry["truncated"]) == (
        "short", "a" * cp.MAX_VALUE_CHARS, True)


def test_resource_graph_truncation_is_flagged():
    changes = {"tags.note": {"previousValue": "x", "newValue": "y", "isTruncated": "true"}}
    assert by_path(cp.change_record(row("c1", "t", changes), "resourcechanges"))["tags.note"]["truncated"] is True


def test_the_secret_check_reads_the_whole_value_before_it_is_cut():
    value = "a " * cp.MAX_VALUE_CHARS + "password=xxxx"
    entry = by_path(cp.change_record(row("c1", "t", raw({"tags.note": value})), "resourcechanges"))["tags.note"]
    assert entry == {"path": "tags.note", "withheld": "secret"}


def test_entries_per_change_are_capped_with_shown_values_first():
    changes = raw({f"properties.definition.actions.a{i:02d}.type": "x" for i in range(cp.MAX_VALUES_PER_CHANGE)})
    changes.update(raw({"tags.owner": "team-a", "properties.minimumTlsVersion": "TLS1_2"}))
    record = cp.change_record(row("c1", "t", changes), "resourcechanges")
    assert len(record["property_changes"]) == cp.MAX_VALUES_PER_CHANGE
    assert record["property_changes_truncated"] is True
    assert [e["path"] for e in record["property_changes"][:2]] == ["properties.minimumTlsVersion", "tags.owner"]
    # The counts cover every changed property, including the ones the cap left out.
    assert record["property_value_counts"] == {"shown": 2, "not_allowlisted": cp.MAX_VALUES_PER_CHANGE, "secret": 0}
    assert cp.change_record(row("c2", "t", raw({"tags.a": "b"})), "resourcechanges")[
        "property_changes_truncated"] is False


def _attributed(rows, deployments=()):
    return cp.attribute([cp.change_record(r, "resourcechanges") for r in rows], list(deployments))


def test_only_direct_and_manual_deployment_changes_keep_values_newest_first():
    dep = {"id": f"{RG}/providers/Microsoft.Resources/deployments/pipe", "name": "pipe", "correlation_id": "corr-p",
           "started": None, "timestamp": None, "output_resource_ids": []}
    rows = [
        row("c1", "2026-11-01T01:00:00Z", raw({"tags.a": "1"})),
        row("c2", "2026-11-01T02:00:00Z", raw({"tags.a": "2"})),
        row("c3", "2026-11-01T03:00:00Z", raw({"tags.a": "3"})),
        row("c4", "2026-11-01T04:00:00Z", raw({"tags.a": "4"}), by="app-id", by_type="Application", client="CLI",
            corr="corr-p"),
    ]
    kept = {c["change_id"]: c for c in cp.keep_values(_attributed(rows, [dep]), 2)}
    assert kept["c4"]["origin"] == "deployment"
    assert [kept["c4"][k] for k in ("property_changes", "property_changes_truncated",
                                     "property_value_counts")] == [None, None, None]
    assert [kept["c1"][k] for k in ("property_changes", "property_changes_truncated",
                                     "property_value_counts")] == [None, True, None]
    assert [kept[c]["property_changes"][0]["new_value"] for c in ("c2", "c3")] == ["2", "3"]
    summary = cp.summarize(list(kept.values()), [dep], [], None)
    assert (summary["changes_with_property_values"], summary["changes_property_values_capped"]) == (2, 1)


def test_a_cap_of_zero_keeps_no_values():
    kept = cp.keep_values(_attributed([row("c1", "t", raw({"tags.a": "1"}))]), 0)
    assert kept[0]["property_changes"] is None and kept[0]["property_changes_truncated"] is True


@pytest.mark.parametrize("raw_value, expected, failed", [
    (None, cp.MAX_VALUE_CHANGES, False), ("0", 0, False), ("25", 25, False), ("-1", 0, True), ("lots", 0, True),
])
def test_max_value_changes_setting(monkeypatch, raw_value, expected, failed):
    if raw_value is None:
        monkeypatch.delenv("AZURE_CHANGE_MAX_VALUE_CHANGES", raising=False)
    else:
        monkeypatch.setenv("AZURE_CHANGE_MAX_VALUE_CHANGES", raw_value)
    collector = cp.Collector(cp.logger)
    assert cp.max_value_changes(collector) == expected
    assert (not collector.ok) is failed


# --- the whole run ---

def _run(monkeypatch, tmp_path, rows, *, refuse_containers=False, env=None):
    def query(client, sub, q):
        if q.startswith("resourcecontainerchanges"):
            if refuse_containers:
                raise PermissionError("(AuthorizationFailed) 403")
            return {"rows": [], "total_records": 0, "pages": 1}
        return {"rows": rows, "total_records": len(rows), "pages": 1}

    monkeypatch.setattr(cp, "load_dotenv", lambda: None)
    monkeypatch.setattr(cp, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(cp, "pinned_credential", lambda sub: object())
    monkeypatch.setattr(cp, "resource_graph_client", lambda cred: object())
    monkeypatch.setattr(cp, "query_all", query)
    monkeypatch.setattr(cp, "collect_deployments", lambda sub, cred, collector: ([], [], ["rg-in"]))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    monkeypatch.setenv("FETCHER_STATUS_FILE", str(tmp_path / "status.json"))
    for name in ("AZURE_PIPELINE_PRINCIPALS", "AZURE_CHANGE_LOOKBACK_DAYS", "AZURE_RESOURCE_EXCLUSIONS",
                 "AZURE_CHANGE_VALUE_PATHS", "AZURE_CHANGE_MAX_VALUE_CHANGES"):
        monkeypatch.delenv(name, raising=False)
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    code = cp.main()
    text = (tmp_path / "azure_change_provenance_s1.json").read_text()
    return code, text, json.loads(text)


def test_no_fake_secret_reaches_the_evidence_even_with_every_path_allowed(monkeypatch, tmp_path):
    secrets = {**FAKE_SECRETS, **SECRET_PATHS}
    rows = [row("c1", "2026-11-01T00:00:00Z", raw(secrets)), row("c2", "2026-11-01T00:01:00Z", raw(SHOWN))]
    code, text, evidence = _run(monkeypatch, tmp_path, rows, env={"AZURE_CHANGE_VALUE_PATHS": "path:*"})
    assert code == 0
    for value in secrets.values():
        assert value not in text and json.dumps(value)[1:-1] not in text
    assert "TLS1_2" in text and VNET_SUBNET in text
    assert evidence["summary"]["property_values_withheld_by_reason"] == {"not_allowlisted": 0, "secret": len(secrets)}
    assert evidence["summary"]["property_values_shown"] == len(SHOWN)
    assert evidence["results"]["property_value_paths_added"] == ["path:*"]


def test_run_counts_and_settings(monkeypatch, tmp_path):
    rows = [row(f"c{i}", f"2026-11-01T0{i}:00:00Z", raw({"tags.a": str(i)})) for i in range(1, 4)]
    code, _, evidence = _run(monkeypatch, tmp_path, rows, env={"AZURE_CHANGE_MAX_VALUE_CHANGES": "2"})
    assert code == 0
    summary = evidence["summary"]
    assert (summary["changes_with_property_values"], summary["changes_property_values_capped"],
            summary["property_values_shown"]) == (2, 1, 2)
    assert summary["property_values_withheld_by_reason"] == {"not_allowlisted": 0, "secret": 0}
    assert evidence["results"]["max_property_value_changes"] == 2
    assert evidence["results"]["property_value_paths_added"] == []


def test_an_invalid_cap_fails_the_run_as_bad_config_and_keeps_no_values(monkeypatch, tmp_path):
    rows = [row("c1", "2026-11-01T00:00:00Z", raw({"tags.a": "visible-if-kept"}))]
    code, text, evidence = _run(monkeypatch, tmp_path, rows, env={"AZURE_CHANGE_MAX_VALUE_CHANGES": "many"})
    assert code == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"
    assert "visible-if-kept" not in text
    assert evidence["results"]["changes"][0]["property_changes"] is None


def test_value_counts_are_null_when_a_change_table_was_refused(monkeypatch, tmp_path):
    rows = [row("c1", "2026-11-01T00:00:00Z", raw({"tags.a": "1"}))]
    code, _, evidence = _run(monkeypatch, tmp_path, rows, refuse_containers=True)
    assert code == 1
    assert [evidence["summary"][k] for k in ("changes_with_property_values", "changes_property_values_capped",
                                             "property_values_shown", "property_values_withheld_by_reason")] == \
        [None, None, None, None]


def test_excluded_changes_carry_no_values(monkeypatch, tmp_path):
    rows = [row("c1", "2026-11-01T00:00:00Z", raw({"tags.a": "kept-out-value"}))]
    code, text, evidence = _run(monkeypatch, tmp_path, rows, env={"AZURE_RESOURCE_EXCLUSIONS": "rg:rg-in"})
    assert code == 0 and evidence["results"]["changes"] == []
    assert "kept-out-value" not in text
    assert evidence["summary"]["changes_with_property_values"] == 0


def test_a_value_path_without_its_prefix_fails_the_run_and_widens_nothing(monkeypatch, tmp_path):
    rows = [row("c1", "2026-11-01T00:00:00Z", raw({"properties.definition.x": "hidden-unless-allowed"}))]
    code, text, evidence = _run(monkeypatch, tmp_path, rows, env={"AZURE_CHANGE_VALUE_PATHS": "*,rg:x"})
    assert code == 1
    assert json.loads((tmp_path / "status.json").read_text())["code"] == "bad_config"
    assert "hidden-unless-allowed" not in text
    assert evidence["results"]["property_value_paths_added"] == []
    # Like an invalid max_value_changes, a bad pattern keeps no values at all.
    assert evidence["results"]["max_property_value_changes"] == 0
    assert evidence["results"]["changes"][0]["property_changes"] is None


# --- the manifest setting ---

FETCHERS, PLATFORMS = api.discover_fetchers(REPO_ROOT), api.discover_platforms(REPO_ROOT)
PROVENANCE = FETCHERS["azure_change_provenance"]


def test_value_paths_is_a_manifest_pattern_list_that_reaches_the_fetcher():
    field = PROVENANCE.config_schema["value_paths"]
    assert (field.type, list(field.prefixes), field.bare) == ("patterns", ["path"], False)
    env: dict = {}
    entry = ManifestEntry(use="azure_change_provenance", config={
        "value_paths": [{"pattern": "path:properties.siteConfig.*", "reason": "App Service drift"}, "path:kind"]})
    _apply_config(env, PROVENANCE, None, None, entry)
    assert env["AZURE_CHANGE_VALUE_PATHS"] == "path:properties.siteConfig.*,path:kind"


def test_value_paths_refuses_an_env_reference():
    entry = ManifestEntry(use="azure_change_provenance", config={"value_paths": "${env:AZURE_CHANGE_VALUE_PATHS}"})
    assert "value_paths" in merged_config(PROVENANCE, None, None, entry).errors
    with pytest.raises(RuntimeError, match="aren't read for a pattern list"):
        _apply_config({}, PROVENANCE, None, None, entry)


@pytest.mark.parametrize("pattern", ["path:*", "path:tags.*", "*", "tags.*", "rg-out"])
def test_manifest_exclude_never_routes_to_value_paths(pattern):
    # value_paths is an allowlist (exclusion: false): an exclude must never widen what's shown.
    assert PROVENANCE.config_schema["value_paths"].exclusion is False
    _, fields, _ = api.pattern_fields("azure_change_provenance", FETCHERS, PLATFORMS)
    assert list(fields) == ["resource_exclusions"]
    with pytest.raises(ValueError):
        api.pick_pattern_field(fields, pattern)
    with pytest.raises(ValueError):
        api.pick_pattern_field(fields, pattern, "value_paths")
    _, category_fields, mixed = api.pattern_fields("azure", FETCHERS, PLATFORMS)
    assert "value_paths" not in category_fields and "value_paths" not in mixed
    assert api.pick_pattern_field(fields, "rg:rg-out") == "resource_exclusions"


def test_the_exclude_commands_leave_value_paths_untouched(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from framework.cli import app

    runner = CliRunner()
    monkeypatch.chdir(REPO_ROOT)
    path = str(tmp_path / "m.yaml")
    runner.invoke(app, ["manifest", "init", "-f", path])
    runner.invoke(app, ["manifest", "add", "azure_change_provenance", "-f", path])
    before = Path(path).read_text()
    for args in (["exclude", "azure_change_provenance", "path:*"], ["exclude", "azure", "path:*"],
                 ["exclude", "azure_change_provenance", "path:tags.*", "--field", "value_paths"],
                 ["exclude", "azure", "path:*", "--field", "value_paths"],
                 ["unexclude", "azure_change_provenance", "path:*", "--field", "value_paths"],
                 ["unexclude", "azure_change_provenance", "--all", "--field", "value_paths"]):
        assert runner.invoke(app, ["manifest", *args, "-f", path, "--json"]).exit_code == 1, args
    assert Path(path).read_text() == before and "value_paths" not in before
    # A real exclusion still lands in resource_exclusions, for the fetcher and for the category.
    for target in ("azure_change_provenance", "azure"):
        out = json.loads(runner.invoke(app, ["manifest", "exclude", target, "rg:rg-out", "-f", path, "--json"]).output)
        assert (out["ok"], out["field"]) == (True, "resource_exclusions"), target
    assert "value_paths" not in Path(path).read_text()


# --- the review's probe: every case must be withheld ---

def pem(kind):
    # Built at run time, so no PEM header sits in the source for secret scanners.
    return "-----BEGIN " + kind + "-----\nabc"


# (path, value, scope): "default" is the built-in allowlist, "star" is value_paths path:*. Low-entropy fakes.
PROBE = [
    ("tags.notes", "DB_PASSWORD=hunter2", "default"),
    ("tags.notes", "AZURE_CLIENT_SECRET=abc8Q", "default"),
    ("tags.notes", "spring.datasource.password=hunter2", "default"),
    ("tags.notes", "--password hunter2", "default"),
    ("tags.notes", "--client-secret=hunter2", "default"),
    ("tags.notes", "Basic xxxxxxxxxxxx", "default"),
    ("tags.notes", "Bearer abc123abc123", "default"),
    ("tags.notes", "user: admin\npassword: hunter2", "default"),
    ("tags.notes", "Server=x;User Id=a;Password=hunter2", "default"),
    ("tags.notes", "x.redis.cache.windows.net:6380,password=hunter2,ssl=True", "default"),
    ("tags.notes", "Aa1.Aa1.Aa1.Aa1.Aa1", "default"),
    ("tags.notes", "sv=2022-11-02&ss=b&srt=co&sp=rl&se=2026&sig=abc", "default"),
    ("tags.notes", "https://f.example.net/api/x?x-functions-key=abc", "default"),
    ("tags.notes", "https://apim.example.net/x?subscription-key=abc", "default"),
    ("tags.notes", "https://x.example.net/?api_key=abc", "default"),
    ("tags.notes", "https://x.example.net/?access_token=abc", "default"),
    ("tags.notes", pem("OPENSSH PRIVATE KEY"), "default"),
    ("tags.notes", pem("RSA PRIVATE KEY"), "default"),
    ("tags.notes", pem("ENCRYPTED PRIVATE KEY"), "default"),
    ("tags.notes", pem("PGP PRIVATE KEY BLOCK"), "default"),
    ("tags.notes", '{"clientSecret":"abc"}', "default"),
    ("tags.notes", '{"client_secret":"abc"}', "default"),
    ("tags.notes", 'cfg {"pwd":"abc"}', "default"),
    ("tags.notes", "https://ghp_xxxx@github.com/o/r", "default"),
    ("tags.notes", "Aa1Bb2Aa1Bb2", "default"),
    ("tags.api_key", "Aa1Bb2Aa1Bb2", "default"),
    ("tags.SharedKey", "Aa1Bb2Aa1Bb2", "default"),
    ("tags.access_key", "Aa1Bb2Aa1Bb2", "default"),
    ("tags.db_pass", "Aa1Bb2Aa1Bb2", "default"),
    ("properties.sharedKey", "hunter2psk", "star"),
    ("properties.key1", "abc", "star"),
    ("properties.template.containers[0].env[1].value", "hunter2", "star"),
    ("properties.template.containers[0].args[1]", "--password=hunter2", "star"),
    ("properties.typeProperties.servicePrincipalKey.value", "hunter2", "star"),
    ("properties.access_key", "hunter2", "star"),
    ("properties.primary_key", "hunter2", "star"),
    ("properties.value", "hunter2", "star"),
    ("properties.osProfile.customData", "xxxxxxxx", "star"),
    ("properties.definition.actions.Http.inputs.queries.code", "abc", "star"),
    ("properties.definition.actions.Http.inputs.body.pass", "hunter2", "star"),
    ("properties.definition.actions.Http.inputs.authentication.password", "fake-auth-pass", "star"),
    ("properties.passphrase", "hunter2", "star"),
    ("properties.adminPin", "1234", "star"),
    ("properties.authKey", "hunter2", "star"),
    ("properties.signingKey", "hunter2", "star"),
    ("properties.serviceUri", "https://x.example.net/hook/abc", "star"),
    ("properties.ADMIN_PASSWORD", "hunter2", "star"),
    ("properties.secretConfig.status", "hunter2", "star"),
    ("properties.siteConfig.appSettings[0].state", "hunter2", "star"),
    ("properties.DB_PASS", "hunter2", "star"),
    ("properties.MyDb.value", "Server=x;Password=y", "star"),
    ("properties.definition.actions.Http.inputs.headers.status", "plain", "star"),
    ("properties.definition.actions.Http.inputs.body.status", "hunter2", "star"),
    ("properties.password.enabled", "hunter2", "default"),
    ("properties.connectionString.state", "hunter2", "default"),
    ("properties.siteConfig.appSettings[0].status", "hunter2", "default"),
    ("properties.definition.actions.Http.inputs.headers.status", "Aa1Bb2Aa1Bb2", "default"),
]


@pytest.mark.parametrize("path, value, scope", PROBE)
def test_every_probe_value_is_withheld(path, value, scope):
    paths = cp.ValuePaths(["path:*"]) if scope == "star" else cp.ValuePaths()
    record = cp.change_record(row("c1", "t", raw({path: value})), "resourcechanges", paths)
    assert value not in json.dumps(record) and json.dumps(value)[1:-1] not in json.dumps(record)
    entry = by_path(record)[path]
    assert set(entry) == {"path", "withheld"}
    # Under path:* or on an allowlisted path, only the secret check can withhold it.
    if scope == "star" or paths.allows(path):
        assert entry["withheld"] == "secret"


# Settings, ids, addresses, tags and dates that must stay visible under the defaults or the paths they're under.
VISIBLE = [
    ("properties.networkAcls.bypass", "None", "AzureServices", None),
    ("properties.networkAcls.defaultAction", "Allow", "Deny", None),
    ("properties.securityRules[2].properties.sourceAddressPrefix", "10.0.0.0/8", "*", None),
    ("properties.securityRules[2].properties.destinationPortRange", "443", "3389", None),
    ("properties.accessPolicies[0].tenantId", None, "00000000-0000-0000-0000-000000000002", None),
    ("properties.provisioningState", "Provisioning", "Succeeded", None),
    ("properties.enableSoftDelete", "false", "true", None),
    ("properties.siteConfig.minTlsVersion", "1.0", "1.2", None),
    ("properties.siteConfig.ftpsState", "AllAllowed", "Disabled", None),
    ("properties.encryption.keySource", "Microsoft.Storage", "Microsoft.Keyvault", None),
    ("tags.Owner", "team-a", "jane.doe@example.com", None),
    ("tags.Owner", None, "Jane.Doe@example.com", None),
    ("tags.Environment", "prod", "Production", None),
    ("tags.CostCenter", None, "CC-1234", None),
    ("tags.CreatedOn", None, "2026-11-01T00:00:00Z", None),
    ("sku.tier", "Basic", "Standard", None),
    ("location", None, "eastus2", None),
    ("properties.definition.actions.Compose_noop.inputs", "fake no-op", None, "path:properties.definition.*"),
    ("properties.definition.actions.Compose_noop.type", "Compose", None, "path:properties.definition.*"),
    ("properties.definition.actions.Stop.inputs.runError.code", None, "FakeNoopFailure", "path:properties.definition.*"),
    ("properties.definition.actions.Stop.inputs.runError.message", None, "fake test failure",
     "path:properties.definition.*"),
    ("properties.definition.actions.Stop.inputs.runStatus", None, "Failed", "path:properties.definition.*"),
]


@pytest.mark.parametrize("path, before, after, pattern", VISIBLE)
def test_useful_values_stay_visible(path, before, after, pattern):
    paths = cp.ValuePaths([pattern] if pattern else [])
    entry = by_path(cp.change_record(row("c1", "t", raw({path: (before, after)})), "resourcechanges", paths))[path]
    assert (entry["withheld"], entry["previous_value"], entry["new_value"]) == (None, before, after)


def test_setting_names_are_shown_only_on_their_own_paths():
    assert cp.ValuePaths().allows("properties.status")
    assert not cp.ValuePaths().allows("properties.definition.actions.Http.inputs.headers.status")
    assert not cp.ValuePaths().allows("properties.template.containers[0].state")


def test_shown_and_withheld_counts_cover_every_changed_property():
    changes = raw({f"properties.definition.actions.a{i:02d}.type": "x" for i in range(cp.MAX_VALUES_PER_CHANGE)})
    changes.update(raw({"tags.a": "1", "tags.b": "2", "tags.password": "x"}))
    record = cp.change_record(row("c1", "t", changes), "resourcechanges")
    assert sum(record["property_value_counts"].values()) == len(changes)
    assert record["property_value_counts"] == {"shown": 2, "not_allowlisted": cp.MAX_VALUES_PER_CHANGE, "secret": 1}


def test_a_change_whose_values_could_not_be_read_is_unknown_not_kept(monkeypatch, tmp_path):
    rows = [row("c1", "2026-11-01T00:00:00Z", raw({"tags.a": "1"})),
            {**row("c2", "2026-11-01T01:00:00Z", None), "changedProperties": ["tags.a"], "changes": "not json"}]
    code, _, evidence = _run(monkeypatch, tmp_path, rows)
    assert code == 0
    summary = evidence["summary"]
    assert [summary[k] for k in ("changes_with_property_values", "changes_property_values_capped",
                                 "changes_property_values_unknown", "property_values_shown",
                                 "property_values_withheld_by_reason")] == [1, 0, 1, None, None]
    unread = next(c for c in evidence["results"]["changes"] if c["change_id"] == "c2")
    assert [unread[k] for k in ("property_changes", "property_changes_truncated", "property_value_counts")] == \
        [None, None, None]
