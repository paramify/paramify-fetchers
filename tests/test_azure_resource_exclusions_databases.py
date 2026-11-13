"""resource_exclusions in the Azure data-service fetchers: excluded resources leave every count and stay listed under
excluded, their children are never read, and a bare pattern fails the run."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace as ns

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AZURE = REPO_ROOT / "fetchers" / "azure"
sys.path.insert(0, str(REPO_ROOT / "fetchers" / "_lib"))
sys.path.insert(0, str(AZURE / "_shared"))

from resource_exclusions import ENV  # noqa: E402

SUB = "/subscriptions/s1"
PATTERNS = "rg:rg-out, location:regioneast, rg:rg-typo"
UNMATCHED = ["rg:rg-typo"]
KEYS = ("resource_exclusion_patterns", "resource_exclusion_patterns_unmatched")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"azure_{name}_exclusions_databases_under_test",
                                                  AZURE / name / "fetcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Group:
    def __init__(self, calls, group, lists):
        self._calls, self._group, self._lists = calls, group, lists

    def __getattr__(self, method):
        def call(*args, **kwargs):
            self._calls.append((self._group, method, args))
            if (self._group, method) in self._lists:
                return self._lists[(self._group, method)]
            return [] if method.startswith("list") else ns()
        return call


class _Client:
    """A fake SDK client: every call is recorded; the listed (group, method) pairs return their given list."""

    def __init__(self, lists):
        self.calls: list = []
        self._lists = lists

    def __getattr__(self, group):
        return _Group(self.calls, group, self._lists)

    def read(self, group):
        return [c for c in self.calls if c[0] == group]


def _res(kind, name, rg, location, **fields):
    return ns(id=f"{SUB}/resourceGroups/{rg}/providers/{kind}/{name}", name=name, location=location, **fields)


def _three(kind, make=_res, **fields):
    """An in-scope resource, one in rg-out and one in regioneast; `fields` may be a dict of per-name overrides."""
    return [make(kind, n, rg, loc, **fields.get(n, {}))
            for n, rg, loc in (("in", "rg-in", "regionwest"), ("out", "rg-out", "regionwest"),
                               ("east", "rg-in", "regioneast"))]


def _run(m, monkeypatch, tmp_path, patterns, filename, modules):
    monkeypatch.setattr(m, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(m, "resolve_subscription", lambda c: {"subscription_id": "s1", "subscription_source": "env"})
    monkeypatch.setattr(m, "credential", lambda: object())
    monkeypatch.setattr(m, "provider_registration_status", lambda *a: "registered")
    for module_name, attrs in modules.items():
        monkeypatch.setitem(sys.modules, module_name, ns(**attrs))
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path))
    if patterns is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, patterns)
    code = m.main()
    return code, json.loads((tmp_path / f"{filename}_s1.json").read_text())


def _excluded(evidence) -> list:
    return sorted((e["kind"], e["name"], e["pattern"], e["reason"]) for e in evidence["results"]["excluded"])


def _refuse(monkeypatch, m, operation):
    """Answers one guarded call with a 403, as Azure does for a list the identity may not read."""
    class Refusing(m.Collector):
        def guard(self, op, fn, default=None):
            if op == operation:
                self.record(op, PermissionError("(AuthorizationFailed) 403"))
                return default
            return super().guard(op, fn, default)

    monkeypatch.setattr(m, "Collector", Refusing)


def _names(records) -> list:
    return sorted(r["name"] for r in records)


def _added(kinds: dict) -> dict:
    """The fields a run without patterns adds: plural -> in-scope total, singular kind -> 0 excluded."""
    return {
        "resource_exclusion_patterns": [], "resource_exclusion_patterns_unmatched": [],
        **{f"excluded_{k}s": 0 for k in kinds}, **{f"in_scope_{k}s": total for k, total in kinds.items()},
    }


EXPECTED = [("{kind}", "east", "location:regioneast", "resource_matched"),
            ("{kind}", "out", "rg:rg-out", "resource_matched")]


def _expected(kind):
    return [(k.format(kind=kind), n, p, r) for k, n, p, r in EXPECTED]


# --- one case per fetcher: (module, evidence file, results key, kind, fake modules builder, verdict key/in-scope value) ---

cosmos = _load("cosmosdb_configuration")
databricks = _load("databricks_workspace_configuration")
managed_redis = _load("managed_redis_configuration")
redis_cache = _load("redis_cache_configuration")
mysql = _load("mysql_configuration")
postgres = _load("postgresql_configuration")
sql_enc = _load("sql_encryption_status")
sql_cfg = _load("sql_server_configuration")
data_services = _load("data_services_configuration")


def _cosmos_modules():
    accounts = _three("Microsoft.DocumentDB/databaseAccounts")
    for account, local_auth_disabled in zip(accounts, (True, True, False)):
        account.disable_local_auth = local_auth_disabled
    client = _Client({("database_accounts", "list"): accounts})
    return client, {"azure.mgmt.cosmosdb": {"CosmosDBManagementClient": lambda **k: client}}


def _databricks_modules():
    items = _three("Microsoft.Databricks/workspaces")
    client = _Client({("workspaces", "list_by_subscription"): items})
    return client, {"azure.mgmt.databricks": {"AzureDatabricksManagementClient": lambda **k: client}}


def _managed_redis_modules():
    items = _three("Microsoft.Cache/redisEnterprise")
    dbs = [ns(id="db1", name="default", client_protocol="Encrypted")]
    client = _Client({("redis_enterprise", "list"): items, ("databases", "list_by_cluster"): dbs})
    return client, {"azure.mgmt.redisenterprise": {"RedisEnterpriseManagementClient": lambda **k: client}}


def _redis_cache_modules():
    items = _three("Microsoft.Cache/redis")
    client = _Client({("redis", "list_by_subscription"): items})
    monitor = _Client({})
    return client, {"azure.mgmt.redis": {"RedisManagementClient": lambda **k: client},
                    "azure.mgmt.monitor": {"MonitorManagementClient": lambda **k: monitor},
                    "azure.core.exceptions": {"ResourceNotFoundError": type("ResourceNotFoundError", (Exception,), {})}}


def _mysql_modules():
    items = _three("Microsoft.DBforMySQL/flexibleServers")
    client = _Client({("servers", "list"): items})
    return client, {"azure.mgmt.rdbms.mysql_flexibleservers": {"MySQLManagementClient": lambda **k: client}}


def _postgres_modules():
    items = _three("Microsoft.DBforPostgreSQL/flexibleServers")
    client = _Client({("servers", "list"): items})
    return client, {"azure.mgmt.postgresqlflexibleservers": {"PostgreSQLManagementClient": lambda **k: client}}


def _sql_modules():
    items = _three("Microsoft.Sql/servers")
    client = _Client({("servers", "list"): items,
                      ("databases", "list_by_server"): [ns(id="d1", name="app", status="Online")]})
    return client, {"azure.mgmt.sql": {"SqlManagementClient": lambda **k: client}}


SIMPLE = [
    # module, file, results key, kind, plural, total key, modules, per-resource read groups
    (cosmos, "azure_cosmosdb_configuration", "cosmosdb_accounts", "cosmosdb_account", "cosmosdb_accounts",
     "total_cosmosdb_accounts", _cosmos_modules, ()),
    (databricks, "azure_databricks_workspace_configuration", "databricks_workspaces", "databricks_workspace",
     "databricks_workspaces", "total_workspaces", _databricks_modules, ()),
    (managed_redis, "azure_managed_redis_configuration", "redis_clusters", "redis_cluster", "redis_clusters",
     "total_clusters", _managed_redis_modules, ("databases",)),
    (mysql, "azure_mysql_configuration", "mysql_servers", "mysql_server", "mysql_servers", "total_mysql_servers",
     _mysql_modules, ("configurations",)),
    (postgres, "azure_postgresql_configuration", "postgresql_servers", "postgresql_server", "postgresql_servers",
     "total_postgresql_servers", _postgres_modules, ("configurations", "firewall_rules")),
    (sql_enc, "azure_sql_encryption_status", "sql_servers", "sql_server", "sql_servers", "total_sql_servers",
     _sql_modules, ("encryption_protectors", "databases")),
    (sql_cfg, "azure_sql_server_configuration", "sql_servers", "sql_server", "sql_servers", "total_sql_servers",
     _sql_modules, ("firewall_rules", "server_blob_auditing_policies")),
]
IDS = [case[0].__name__.split("_exclusions")[0].replace("azure_", "") for case in SIMPLE]


@pytest.mark.parametrize("case", SIMPLE, ids=IDS)
def test_no_patterns_adds_only_the_exclusion_fields(case, monkeypatch, tmp_path):
    m, filename, key, kind, plural, total_key, modules, _ = case
    _, modules_ = modules()
    code, evidence = _run(m, monkeypatch, tmp_path, None, filename, modules_)
    assert code == 0
    records = evidence["results"][key]
    assert _names(records) == ["east", "in", "out"]
    assert evidence["results"]["excluded"] == []
    old = {**m.summarize(records), "provider_registration_status": "registered"}
    assert evidence["summary"] == {**old, **_added({kind: 3}), f"in_scope_{plural}": 3}


@pytest.mark.parametrize("case", SIMPLE, ids=IDS)
def test_patterns_exclude_by_rg_and_location_and_skip_their_reads(case, monkeypatch, tmp_path):
    m, filename, key, kind, plural, total_key, modules, read_groups = case
    client, modules_ = modules()
    code, evidence = _run(m, monkeypatch, tmp_path, PATTERNS, filename, modules_)
    assert code == 0
    assert _names(evidence["results"][key]) == ["in"]
    assert _excluded(evidence) == _expected(kind)
    summary = evidence["summary"]
    assert summary[total_key] == 1
    assert summary[f"in_scope_{plural}"] == 1 and summary[f"excluded_{kind}s"] == 2
    assert summary["resource_exclusion_patterns"] == ["rg:rg-out", "location:regioneast", "rg:rg-typo"]
    assert summary["resource_exclusion_patterns_unmatched"] == UNMATCHED
    for group in read_groups:
        assert not any("out" in c[2] or "east" in c[2] for c in client.read(group)), group


def test_cosmos_verdicts_cover_only_in_scope_accounts(monkeypatch, tmp_path):
    _, modules = _cosmos_modules()
    _, everything = _run(cosmos, monkeypatch, tmp_path, None, "azure_cosmosdb_configuration", modules)
    _, scoped = _run(cosmos, monkeypatch, tmp_path, PATTERNS, "azure_cosmosdb_configuration", modules)
    assert everything["summary"]["local_auth_disabled_accounts"] == 2
    assert scoped["summary"]["local_auth_disabled_accounts"] == 1


def test_cosmos_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    accounts = _three("Microsoft.DocumentDB/databaseAccounts")
    for account, api in zip(accounts, ("GlobalDocumentDB", "MongoDB", "Parse")):
        account.kind = api
    accounts.append(_res("Microsoft.DocumentDB/databaseAccounts", "none", "rg-in", "regionwest"))
    client = _Client({("database_accounts", "list"): accounts})
    modules = {"azure.mgmt.cosmosdb": {"CosmosDBManagementClient": lambda **k: client}}
    _, evidence = _run(cosmos, monkeypatch, tmp_path, "rg:rg-typo", "azure_cosmosdb_configuration", modules)
    assert_summary_documented("azure/cosmosdb_configuration", evidence["summary"])


def test_databricks_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, modules = _databricks_modules()
    _, evidence = _run(databricks, monkeypatch, tmp_path, PATTERNS, "azure_databricks_workspace_configuration", modules)
    assert_summary_documented("azure/databricks_workspace_configuration", evidence["summary"])


def test_mysql_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, modules = _mysql_modules()
    _, evidence = _run(mysql, monkeypatch, tmp_path, PATTERNS, "azure_mysql_configuration", modules)
    assert_summary_documented("azure/mysql_configuration", evidence["summary"])


def test_postgresql_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, modules = _postgres_modules()
    _, evidence = _run(postgres, monkeypatch, tmp_path, PATTERNS, "azure_postgresql_configuration", modules)
    assert_summary_documented("azure/postgresql_configuration", evidence["summary"])


def test_sql_server_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, modules = _sql_modules()
    _, evidence = _run(sql_cfg, monkeypatch, tmp_path, PATTERNS, "azure_sql_server_configuration", modules)
    assert_summary_documented("azure/sql_server_configuration", evidence["summary"])


def test_sql_encryption_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, modules = _sql_modules()
    _, evidence = _run(sql_enc, monkeypatch, tmp_path, PATTERNS, "azure_sql_encryption_status", modules)
    assert_summary_documented("azure/sql_encryption_status", evidence["summary"])


def test_sql_encryption_keeps_the_verdict_when_its_key_vault_is_excluded(monkeypatch, tmp_path):
    vault = f"{SUB}/resourceGroups/rg-out/providers/Microsoft.KeyVault/vaults/kv-out"
    protector = ns(server_key_type="AzureKeyVault", uri="https://kv-out.example/keys/k1", auto_rotation_enabled=True)

    def verdict(patterns):
        client = _Client({("servers", "list"): _three("Microsoft.Sql/servers")[:1],
                          ("encryption_protectors", "get"): protector})
        modules = {"azure.mgmt.sql": {"SqlManagementClient": lambda **k: client}}
        _, evidence = _run(sql_enc, monkeypatch, tmp_path, patterns, "azure_sql_encryption_status", modules)
        return evidence["summary"]["customer_managed_key_servers"], evidence["results"]["sql_servers"][0]

    assert verdict(None)[0] == 1
    count, server = verdict(f"id:{vault}")
    assert count == 1 and server["customer_managed_key"] is True


def test_sql_server_keeps_its_audit_verdict_when_the_destination_is_excluded(monkeypatch, tmp_path):
    policy = ns(state="Enabled", retention_days=120)
    client = _Client({("servers", "list"): _three("Microsoft.Sql/servers")[:1],
                      ("server_blob_auditing_policies", "list_by_server"): [policy]})
    modules = {"azure.mgmt.sql": {"SqlManagementClient": lambda **k: client}}
    pattern = f"id:{SUB}/resourceGroups/rg-out/providers/Microsoft.Storage/storageAccounts/audit"
    _, evidence = _run(sql_cfg, monkeypatch, tmp_path, pattern, "azure_sql_server_configuration", modules)
    assert evidence["summary"]["auditing_enabled_servers"] == 1
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] == [pattern]


def test_redis_cache_reads_nothing_for_excluded_caches(monkeypatch, tmp_path):
    client, modules = _redis_cache_modules()
    _run(redis_cache, monkeypatch, tmp_path, PATTERNS, "azure_redis_cache_configuration", modules)
    read = {c[2][1] for c in client.calls if len(c[2]) > 1}
    assert read == {"in"}
    assert client.read("firewall_rules")


def test_redis_cache_no_patterns_and_patterns(monkeypatch, tmp_path):
    client, modules = _redis_cache_modules()
    code, evidence = _run(redis_cache, monkeypatch, tmp_path, None, "azure_redis_cache_configuration", modules)
    assert code == 0 and evidence["results"]["excluded"] == []
    old = {**redis_cache.summarize(evidence["results"]["redis_caches"]), "provider_registration_status": "registered"}
    assert evidence["summary"] == {**old, **_added({"redis_cache": 3}), "in_scope_redis_caches": 3}
    _, evidence = _run(redis_cache, monkeypatch, tmp_path, PATTERNS, "azure_redis_cache_configuration", modules)
    assert _names(evidence["results"]["redis_caches"]) == ["in"]
    assert _excluded(evidence) == _expected("redis_cache")
    assert evidence["summary"]["total_caches"] == 1
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] == UNMATCHED


def test_redis_cache_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, modules = _redis_cache_modules()
    _, evidence = _run(redis_cache, monkeypatch, tmp_path, PATTERNS, "azure_redis_cache_configuration", modules)
    assert_summary_documented("azure/redis_cache_configuration", evidence["summary"])


def test_managed_redis_summary_matches_the_instructions(monkeypatch, tmp_path, assert_summary_documented):
    _, modules = _managed_redis_modules()
    _, evidence = _run(managed_redis, monkeypatch, tmp_path, PATTERNS, "azure_managed_redis_configuration", modules)
    assert_summary_documented("azure/managed_redis_configuration", evidence["summary"])


def _mongo(name, rg, location):
    return ns(id=f"{SUB}/resourceGroups/{rg}/providers/Microsoft.DocumentDB/mongoClusters/{name}", name=name,
              location=location)


def _data_services(patterns, monkeypatch, tmp_path):
    mongo = _Client({("mongo_clusters", "list"): [_mongo(n, rg, loc) for n, rg, loc in
                                                  (("in", "rg-in", "regionwest"), ("out", "rg-out", "regionwest"))]})
    kusto = _Client({("clusters", "list"): _three("Microsoft.Kusto/clusters")[::2]})
    hubs = _Client({("namespaces", "list"): _three("Microsoft.EventHub/namespaces")[:2]})
    modules = {
        "azure.mgmt.mongocluster": {"MongoClusterMgmtClient": lambda **k: mongo},
        "azure.mgmt.kusto": {"KustoManagementClient": lambda **k: kusto},
        "azure.mgmt.eventhub": {"EventHubManagementClient": lambda **k: hubs},
    }
    monkeypatch.setattr(data_services, "monitor_client", lambda *a: _Client({}))
    code, evidence = _run(data_services, monkeypatch, tmp_path, patterns, "azure_data_services_configuration", modules)
    return code, evidence, (mongo, kusto, hubs)


def test_data_services_no_patterns(monkeypatch, tmp_path, assert_summary_documented):
    code, evidence, _ = _data_services(None, monkeypatch, tmp_path)
    assert_summary_documented("azure/data_services_configuration", evidence["summary"])
    assert code == 0 and evidence["results"]["excluded"] == []
    r = evidence["results"]
    registration = {k: v for k, v in r.items() if k.startswith("provider_registration_status_")}
    old = {**data_services.summarize(r["mongo_clusters"], r["data_explorer_clusters"], r["event_hub_namespaces"]),
           **registration}
    added = _added({"mongo_cluster": 2, "data_explorer_cluster": 2, "event_hub_namespace": 2})
    assert evidence["summary"] == {**old, **added}


def test_data_services_patterns_exclude_all_three_kinds_and_skip_their_reads(monkeypatch, tmp_path):
    code, evidence, (mongo, kusto, hubs) = _data_services("rg:rg-out, location:regioneast, rg:rg-typo", monkeypatch,
                                                         tmp_path)
    assert code == 0
    assert _names(evidence["results"]["mongo_clusters"]) == ["in"]
    assert _names(evidence["results"]["data_explorer_clusters"]) == ["in"]
    assert _names(evidence["results"]["event_hub_namespaces"]) == ["in"]
    assert _excluded(evidence) == sorted([
        ("mongo_cluster", "out", "rg:rg-out", "resource_matched"),
        ("data_explorer_cluster", "east", "location:regioneast", "resource_matched"),
        ("event_hub_namespace", "out", "rg:rg-out", "resource_matched"),
    ])
    s = evidence["summary"]
    assert (s["excluded_mongo_clusters"], s["excluded_data_explorer_clusters"], s["excluded_event_hub_namespaces"]) \
        == (1, 1, 1)
    assert (s["total_mongo_clusters"], s["total_data_explorer_clusters"], s["total_event_hub_namespaces"]) == (1, 1, 1)
    assert s["resource_exclusion_patterns_unmatched"] == UNMATCHED
    for client, group in ((mongo, "firewall_rules"), (kusto, "databases"), (hubs, "event_hubs")):
        calls = client.read(group)
        assert calls and all(c[2][1] == "in" for c in calls)


@pytest.mark.parametrize("case", SIMPLE, ids=IDS)
def test_a_bare_pattern_fails_the_run(case, monkeypatch, tmp_path, capsys):
    m, filename, _, _, _, _, modules, _ = case
    _, modules_ = modules()
    code, _evidence = _run(m, monkeypatch, tmp_path, "rg-out", filename, modules_)
    assert code == 1


def test_a_bare_pattern_fails_the_redis_cache_and_data_services_runs(monkeypatch, tmp_path):
    _, modules = _redis_cache_modules()
    code, _evidence = _run(redis_cache, monkeypatch, tmp_path, "rg-out", "azure_redis_cache_configuration", modules)
    assert code == 1
    code, _evidence, _ = _data_services("rg-out", monkeypatch, tmp_path)
    assert code == 1


LISTS = {cosmos: "cosmosdb.database_accounts.list", databricks: "databricks.workspaces.list_by_subscription",
         managed_redis: "redisenterprise.redis_enterprise.list", mysql: "mysql.servers.list",
         postgres: "postgresql.servers.list_by_subscription", sql_enc: "sql.servers.list", sql_cfg: "sql.servers.list"}


@pytest.mark.parametrize("case", SIMPLE, ids=IDS)
def test_a_refused_list_leaves_its_exclusion_counts_null(case, monkeypatch, tmp_path, caplog):
    m, filename, _, kind, plural, _, modules, _ = case
    _refuse(monkeypatch, m, LISTS[m])
    _, modules_ = modules()
    code, evidence = _run(m, monkeypatch, tmp_path, PATTERNS, filename, modules_)
    assert code == 1
    assert (evidence["summary"][f"in_scope_{plural}"], evidence["summary"][f"excluded_{kind}s"]) == (None, None)
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None
    assert "matched nothing" not in caplog.text


def test_a_refused_list_leaves_the_redis_cache_and_data_services_counts_null(monkeypatch, tmp_path):
    _refuse(monkeypatch, redis_cache, "redis.redis.list_by_subscription")
    _, modules = _redis_cache_modules()
    code, evidence = _run(redis_cache, monkeypatch, tmp_path, PATTERNS, "azure_redis_cache_configuration", modules)
    assert code == 1
    assert (evidence["summary"]["in_scope_redis_caches"], evidence["summary"]["excluded_redis_caches"]) == (None, None)
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None
    _refuse(monkeypatch, data_services, "eventhub.namespaces.list")
    code, evidence, _ = _data_services(PATTERNS, monkeypatch, tmp_path)
    s = evidence["summary"]
    assert code == 1
    assert (s["in_scope_event_hub_namespaces"], s["excluded_event_hub_namespaces"]) == (None, None)
    assert (s["in_scope_mongo_clusters"], s["excluded_mongo_clusters"]) == (1, 1)
    assert s["resource_exclusion_patterns_unmatched"] is None


@pytest.mark.parametrize("refused, unknown", [
    ("mongocluster.mongo_clusters.list", "mongo_clusters"),
    ("kusto.clusters.list", "data_explorer_clusters"),
], ids=["mongo", "kusto"])
def test_a_refused_data_services_list_leaves_only_its_counts_null(refused, unknown, monkeypatch, tmp_path):
    _refuse(monkeypatch, data_services, refused)
    code, evidence, _ = _data_services(PATTERNS, monkeypatch, tmp_path)
    counts = {k: v for k, v in evidence["summary"].items() if k.startswith(("in_scope_", "excluded_"))}
    assert code == 1
    assert {k for k, v in counts.items() if v is None} == {f"in_scope_{unknown}", f"excluded_{unknown}"}
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None


INITS = {cosmos: "cosmosdb.CosmosDBManagementClient (init)",
         databricks: "databricks.AzureDatabricksManagementClient (init)",
         managed_redis: "redisenterprise.RedisEnterpriseManagementClient (init)",
         mysql: "mysql.MySQLManagementClient (init)", postgres: "postgresql.PostgreSQLManagementClient (init)",
         sql_enc: "sql.SqlManagementClient (init)", sql_cfg: "sql.SqlManagementClient (init)"}


@pytest.mark.parametrize("case", SIMPLE, ids=IDS)
def test_a_client_that_couldnt_be_built_leaves_the_exclusion_counts_null(case, monkeypatch, tmp_path):
    m, filename, _, kind, plural, _, modules, _ = case
    _refuse(monkeypatch, m, INITS[m])
    _, modules_ = modules()
    code, evidence = _run(m, monkeypatch, tmp_path, PATTERNS, filename, modules_)
    assert code == 1
    assert (evidence["summary"][f"in_scope_{plural}"], evidence["summary"][f"excluded_{kind}s"]) == (None, None)
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None


def test_a_client_that_couldnt_be_built_leaves_the_redis_cache_and_data_services_counts_null(monkeypatch, tmp_path):
    _refuse(monkeypatch, redis_cache, "redis.RedisManagementClient (init)")
    _, modules = _redis_cache_modules()
    code, evidence = _run(redis_cache, monkeypatch, tmp_path, PATTERNS, "azure_redis_cache_configuration", modules)
    assert code == 1
    assert (evidence["summary"]["in_scope_redis_caches"], evidence["summary"]["excluded_redis_caches"]) == (None, None)
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None
    _refuse(monkeypatch, data_services, "data services clients (init)")
    code, evidence, _ = _data_services(PATTERNS, monkeypatch, tmp_path)
    counts = {k: v for k, v in evidence["summary"].items() if k.startswith(("in_scope_", "excluded_"))}
    assert code == 1 and len(counts) == 6 and set(counts.values()) == {None}
    assert evidence["summary"]["resource_exclusion_patterns_unmatched"] is None
