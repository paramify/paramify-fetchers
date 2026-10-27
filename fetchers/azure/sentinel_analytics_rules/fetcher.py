#!/usr/bin/env python3
"""Microsoft Sentinel analytics (detection) rules per workspace: enabled state, queries, the tables each reads, and whether those tables get data."""

import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import (  # noqa: E402
    LAW_API,
    SI_API,
    SI_PREVIEW_API,
    int_config,
    iso_duration_days,
    run_workspaces,
)
from sentinel_ingestion import (  # noqa: E402
    ALERT_PRODUCTS_QUERY,
    ALERTS_TABLE,
    DEFAULT_WINDOW_DAYS,
    INGESTION_QUERY,
    NON_SOURCE_TABLES,
    WINDOW_ENV,
)

NAME = "azure_sentinel_analytics_rules"
FUSION_TEMPLATE = "f71aba3d-28fb-450b-b192-4e76a83015c8"
INCIDENT_CREATION = "MicrosoftSecurityIncidentCreation"
# Kinds with no query of their own: their template's connectors are optional signals, not tables the rule needs.
NO_QUERY_KINDS = frozenset({"Fusion", "MLBehaviorAnalytics", "ThreatIntelligence"})

# Verbatim strings (@"…") escape only a doubled quote, so a trailing backslash still closes them.
_KQL_TOKEN = re.compile(
    r"//[^\n]*|```.*?```|@\"[^\"\n]*(?:\"\"[^\"\n]*)*\"|@'[^'\n]*(?:''[^'\n]*)*'|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|[A-Za-z_]\w*|\S",
    re.S,
)
_CUSTOM_TABLE = re.compile(r"\w+_CL$")
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*$")
_SOURCE_AFTER = {None, "|", ";", ")", ",", "}", "on"}
_SOURCE_BEFORE = {None, ";", "{", "union", "join", "lookup"}
_TABULAR_CALLS = {"materialize", "toscalar", "union", "join", "lookup", "in"}
_OPERATOR_PARAMS = {"kind", "isfuzzy", "withsource"}

logger = logging.getLogger(NAME)


def project_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    props = rule.get("properties") or {}
    incident = props.get("incidentConfiguration") or {}
    return {
        "name": rule.get("name"),
        "display_name": props.get("displayName"),
        "kind": rule.get("kind"),
        "enabled": props.get("enabled"),
        "severity": props.get("severity"),
        "tactics": props.get("tactics") or [],
        "techniques": props.get("techniques") or [],
        "alert_rule_template_name": props.get("alertRuleTemplateName"),
        "template_version": props.get("templateVersion"),
        "last_modified_utc": props.get("lastModifiedUtc"),
        "query_frequency": props.get("queryFrequency"),
        "query_period": props.get("queryPeriod"),
        "trigger_operator": props.get("triggerOperator"),
        "trigger_threshold": props.get("triggerThreshold"),
        "creates_incidents": incident.get("createIncident"),
        "product_filter": props.get("productFilter"),
        "query": props.get("query"),
        "suppression_enabled": props.get("suppressionEnabled"),
        "suppression_duration": props.get("suppressionDuration"),
    }


def merge_rules(stable: List[Dict[str, Any]], preview: List[Dict[str, Any]] | None) -> List[Dict[str, Any]]:
    """Union by rule id, preferring the stable shape; `seen_in` says which listing returned each."""
    merged: Dict[str, Dict[str, Any]] = {}
    for rule in stable:
        merged[(rule.get("id") or rule.get("name") or "").lower()] = {**project_rule(rule), "seen_in": ["stable"]}
    for rule in preview or []:
        key = (rule.get("id") or rule.get("name") or "").lower()
        if key in merged:
            merged[key]["seen_in"].append("preview")
        else:
            merged[key] = {**project_rule(rule), "seen_in": ["preview"]}
    return sorted(merged.values(), key=lambda r: ((r["kind"] or ""), (r["display_name"] or ""), (r["name"] or "")))


def _is_source(toks: List[str], i: int) -> bool:
    """Whether toks[i] stands where a tabular source goes rather than a column (`Operation` is both)."""
    at = lambda j: toks[j] if 0 <= j < len(toks) else None  # noqa: E731
    if at(i + 1) not in _SOURCE_AFTER:
        return False
    prev = at(i - 1)
    if prev in _SOURCE_BEFORE or (prev == "=" and at(i - 3) == "let") or (at(i - 2) == "=" and at(i - 3) in _OPERATOR_PARAMS):
        return True
    if prev == "(":
        before = at(i - 2)
        return before is None or not re.match(r"\w", before) or before in _TABULAR_CALLS or (at(i - 3) == "=" and at(i - 4) in _OPERATOR_PARAMS)
    if prev == ",":
        j = i - 1
        while j >= 0 and toks[j] not in {"|", ";", "(", ")", "union"}:
            j -= 1
        return at(j) == "union" or (at(j) == "(" and at(j - 1) == "in")
    return False


def _call_name(toks: List[str], i: int) -> Optional[str]:
    """The name called with toks[i] among its arguments, if any."""
    depth = 0
    for j in range(i - 1, -1, -1):
        if toks[j] == ")":
            depth += 1
        elif toks[j] == "(":
            if depth == 0:
                return toks[j - 1] if j > 0 else None
            depth -= 1
    return None


def _tokens(query: Optional[str]) -> Tuple[List[str], Set[int]]:
    """KQL tokens without comments, and the positions of bracket-quoted names (['T']) read as bare names."""
    raw = [t for t in _KQL_TOKEN.findall(query or "") if not t.startswith("//")]
    toks: List[str] = []
    quoted: Set[int] = set()
    i = 0
    while i < len(raw):
        name = raw[i + 1].strip("\"'") if raw[i] == "[" and i + 2 < len(raw) and raw[i + 2] == "]" else ""
        if raw[i + 1:i + 2] and raw[i + 1][0] in "\"'" and _IDENTIFIER.match(name):
            quoted.add(len(toks))
            toks.append(name)
            i += 3
            continue
        toks.append(raw[i])
        i += 1
    return toks, quoted


def _binding_positions(toks: List[str]) -> Set[int]:
    """Where the query names a column or result rather than reading one: mv-expand and mv-apply targets,
    `as` names and the withsource= column."""
    at: Set[int] = set()
    for k, tok in enumerate(toks):
        if (tok in {"expand", "apply"} and toks[k - 2:k] == ["mv", "-"]) or (tok == "as" and k > 0 and toks[k - 1] == "|"):
            j = k + 1
            while j < len(toks) and toks[j] not in {"|", ";", "on"}:
                at.add(j)
                j += 1
        if tok == "withsource" and toks[k + 1:k + 2] == ["="] and k + 2 < len(toks):
            at.add(k + 2)
    return at


def query_tables(query: Optional[str], tables: Set[str], columns: Set[str]) -> List[str]:
    """Local workspace tables a KQL query names, in code or as a string passed to table() or a function it defines."""
    toks, quoted = _tokens(query)
    functions = {toks[k + 1] for k in range(len(toks) - 3) if toks[k] == "let" and toks[k + 2] == "=" and toks[k + 3] == "("}
    binding = _binding_positions(toks)
    # Names the query assigns, declares or binds (`extend X =`, `let X =`, `datatable(X:string)`, `mv-expand X`) count
    # only where a table can stand; so does a bracket-quoted name, which can be an index.
    ambiguous = columns | {toks[k] for k in range(len(toks) - 1) if toks[k + 1] in {"=", ":"}} | {toks[k] for k in binding}
    found = set()
    for i, tok in enumerate(toks):
        if i in binding:
            continue
        if i in quoted:
            if (tok in tables or _CUSTOM_TABLE.match(tok)) and _is_source(toks, i):
                found.add(tok)
        elif tok[0] in "\"'@`":
            literal = tok.lstrip("@").strip("\"'`")
            argument = i > 0 and toks[i - 1] in {"(", ","} and i + 1 < len(toks) and toks[i + 1] in {")", ","}
            if argument and (literal in tables or _CUSTOM_TABLE.match(literal)) and _call_name(toks, i) in functions | {"table"}:
                found.add(literal)
        elif (tok in tables or _CUSTOM_TABLE.match(tok)) and (i == 0 or toks[i - 1] != "."):
            if tok not in ambiguous or _is_source(toks, i):
                found.add(tok)
    return sorted(found)


def template_tables(template: Optional[Dict[str, Any]], tables: Set[str]) -> List[str]:
    """The template's requiredDataConnectors dataTypes, `SecurityAlert (ASC)` read as SecurityAlert."""
    connectors = ((template or {}).get("properties") or {}).get("requiredDataConnectors") or []
    names = {dt.split(" (")[0].strip() for c in connectors for dt in c.get("dataTypes") or [] if isinstance(dt, str)}
    return sorted(n for n in names if n in tables or _CUSTOM_TABLE.match(n))


def rule_tables(
    rule: Dict[str, Any], tables: Set[str], columns: Set[str], templates: Dict[str, Dict[str, Any]]
) -> Tuple[Optional[List[str]], Optional[str]]:
    """(tables read, where that came from): the query, else the template, else unknown."""
    if rule.get("kind") == INCIDENT_CREATION:
        return [ALERTS_TABLE], "alert_product"
    found = query_tables(rule.get("query"), tables, columns)
    if found:
        return found, "query"
    if rule.get("kind") in NO_QUERY_KINDS:
        return None, None
    found = template_tables(templates.get(rule.get("alert_rule_template_name") or ""), tables)
    if found:
        return found, "template"
    return None, None


def tables_without_data(
    rule: Dict[str, Any], ingested: Optional[Dict[str, Any]], products: Optional[Dict[str, Any]]
) -> Optional[List[str]]:
    """Tables read that got nothing in the window; an incident-creation rule needs its product's alerts, a template rule any one source."""
    read = rule.get("tables_read")
    if read is None or ingested is None:
        return None
    if rule.get("kind") == INCIDENT_CREATION:
        if products is None:
            return None
        return [] if (rule.get("product_filter") or "").lower() in products else [ALERTS_TABLE]
    if rule.get("tables_from") == "template":
        return read if not any(t in ingested for t in read) else []
    return [t for t in read if t not in ingested]


def is_fusion(rule: Dict[str, Any]) -> bool:
    return rule.get("kind") == "Fusion" or rule.get("alert_rule_template_name") == FUSION_TEMPLATE


def rule_summary(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    enabled = [r for r in rules if r.get("enabled") is True]
    by_kind: Dict[str, int] = {}
    for r in enabled:
        by_kind[r.get("kind") or "unknown"] = by_kind.get(r.get("kind") or "unknown", 0) + 1
    fusion = [r for r in rules if is_fusion(r)]
    return {
        "rules_total": len(rules),
        "enabled_rules": len(enabled),
        "disabled_rules": len(rules) - len(enabled),
        "enabled_by_kind": dict(sorted(by_kind.items())),
        "fusion_present": bool(fusion),
        "fusion_enabled": any(r.get("enabled") is True for r in fusion) if fusion else None,
        "rules_only_in_preview": sum(1 for r in rules if r.get("seen_in") == ["preview"]),
        "enabled_rules_suppressed": sum(1 for r in enabled if r.get("suppression_enabled") is True),
    }


def coverage(rules: List[Dict[str, Any]], ingested: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Which ingesting tables enabled rules read, which they don't, and which enabled rules read tables with no data."""
    enabled = [r for r in rules if r.get("enabled") is True]
    readers: Dict[str, int] = {}
    for r in enabled:
        for t in r.get("tables_read") or []:
            readers[t] = readers.get(t, 0) + 1
    return {
        "enabled_rules_tables_unknown": sum(1 for r in enabled if r.get("tables_read") is None),
        "tables_read_by_enabled_rules": [
            {"table": t, "enabled_rules": n, "last_ingested": ingested.get(t) if ingested is not None else None}
            for t, n in sorted(readers.items(), key=lambda kv: kv[0].lower())
        ],
        "ingesting_tables_not_read": (
            sorted((t for t in ingested if t not in NON_SOURCE_TABLES | {ALERTS_TABLE} and t not in readers), key=str.lower)
            if ingested is not None else None
        ),
        "enabled_rules_missing_data": (
            [
                {"name": r["name"], "display_name": r["display_name"], "tables_without_data": r["tables_without_data"]}
                for r in enabled if r.get("tables_without_data")
            ]
            if ingested is not None else None
        ),
    }


def table_vocabulary(listed: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str]]:
    """Table names, and the names that are also some table's column."""
    names = {t.get("name") for t in listed if t.get("name")}
    columns = set()
    for t in listed:
        schema = (t.get("properties") or {}).get("schema") or {}
        columns.update(c.get("name") for c in (schema.get("standardColumns") or []) + (schema.get("columns") or []))
    return names, names & columns


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
    days = int_config(WINDOW_ENV, DEFAULT_WINDOW_DAYS)
    path = f"{ws['id']}/providers/Microsoft.SecurityInsights"
    stable = collector.guard(f"securityinsights.alertRules.list({ws['name']})", lambda: client.list(f"{path}/alertRules", SI_API))
    notes: List[str] = []
    preview = None
    try:
        preview = client.list(f"{path}/alertRules", SI_PREVIEW_API)
    except Exception as exc:  # noqa: BLE001 — the stable list is the evidence; preview only adds kinds it omits
        notes.append(f"preview listing at {SI_PREVIEW_API} failed, so NRT and other preview-only kinds may be missing: {exc}")
    templates = collector.guard(
        f"securityinsights.alertRuleTemplates.list({ws['name']})", lambda: client.list(f"{path}/alertRuleTemplates", SI_API)
    )
    try:
        preview_templates = client.list(f"{path}/alertRuleTemplates", SI_PREVIEW_API)
    except Exception as exc:  # noqa: BLE001 — as with rules, the preview listing only adds kinds the stable one omits
        preview_templates = []
        notes.append(f"preview template listing at {SI_PREVIEW_API} failed, so NRT rules may have no template to fall back on: {exc}")
    if templates is not None:
        stable_names = {t.get("name") for t in templates}
        templates = templates + [t for t in preview_templates if t.get("name") not in stable_names]
    listed_tables = collector.guard(
        f"operationalinsights.tables.list({ws['name']})", lambda: client.list(f"{ws['id']}/tables", LAW_API)
    )
    rows = None
    if ws.get("customer_id"):
        rows = collector.guard(
            f"loganalytics.query(table ingestion, {ws['name']})",
            lambda: client.query(ws["customer_id"], INGESTION_QUERY.format(days=days), iso_duration_days(days)),
        )
    else:
        collector.record(f"workspace customerId ({ws['name']})", LookupError("workspace has no customerId to query"))
    ingested = {r["ParamifySourceTable"]: r.get("LastIngested") for r in rows if r.get("ParamifySourceTable")} if rows is not None else None

    rules = merge_rules(stable, preview) if stable is not None else None
    if rules is not None:
        names, columns = table_vocabulary(listed_tables) if listed_tables is not None else (None, set())
        by_template = {t.get("name"): t for t in templates or []}
        for r in rules:
            r["tables_read"], r["tables_from"] = rule_tables(r, names, columns, by_template) if names is not None else (None, None)
        products: Optional[Dict[str, Any]] = {}
        if ingested and ALERTS_TABLE in ingested and any(r["kind"] == INCIDENT_CREATION for r in rules):
            alert_rows = collector.guard(
                f"loganalytics.query(SecurityAlert products, {ws['name']})",
                lambda: client.query(ws["customer_id"], ALERT_PRODUCTS_QUERY.format(days=days), iso_duration_days(days)),
            )
            products = {(p.get("ProductName") or "").lower(): p.get("LastIngested") for p in alert_rows} if alert_rows is not None else None
        for r in rules:
            r["tables_without_data"] = tables_without_data(r, ingested, products)

    used = {r.get("alert_rule_template_name") for r in rules or [] if r.get("alert_rule_template_name")}
    template_names = {t.get("name") for t in templates or []}
    return {
        "api_versions": {"stable": SI_API, "preview": SI_PREVIEW_API},
        "ingestion_window_days": days,
        "rules": rules,
        **(rule_summary(rules) if rules is not None else {}),
        **(coverage(rules, ingested) if rules is not None and listed_tables is not None else {}),
        "workspace_tables_listed": len(listed_tables) if listed_tables is not None else None,
        "templates_available": len(template_names) if templates is not None else None,
        "templates_in_use": len(used & template_names) if templates is not None else None,
        "notes": notes,
    }


def _total(workspaces: List[Dict[str, Any]], field: str) -> Optional[int]:
    """Sum over the workspaces that have the field; None when none does, so a failed query never reads as zero."""
    values = [w[field] for w in workspaces if w.get(field) is not None]
    return sum(len(v) if isinstance(v, list) else v for v in values) if values else None


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    collected = [w for w in workspaces if w.get("rules") is not None]
    enabled = [w.get("enabled_rules") or 0 for w in collected]
    return {
        "enabled_rules_total": sum(enabled),
        "min_enabled_rules": min(enabled) if enabled else None,
        "workspaces_with_no_enabled_rules": sum(1 for e in enabled if e == 0),
        "workspaces_with_fusion_enabled": sum(1 for w in collected if w.get("fusion_enabled") is True),
        "enabled_rules_missing_data": _total(collected, "enabled_rules_missing_data"),
        "ingesting_tables_not_read": _total(collected, "ingesting_tables_not_read"),
        "enabled_rules_tables_unknown": _total(collected, "enabled_rules_tables_unknown"),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
