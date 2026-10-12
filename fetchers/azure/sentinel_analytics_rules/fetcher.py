#!/usr/bin/env python3
"""Microsoft Sentinel analytics (detection) rules per workspace, with their enabled state and the templates in use."""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_rest import SI_API, SI_PREVIEW_API, run_workspaces  # noqa: E402

NAME = "azure_sentinel_analytics_rules"
FUSION_TEMPLATE = "f71aba3d-28fb-450b-b192-4e76a83015c8"

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
    }


def collect(client, ws: Dict[str, Any], collector) -> Dict[str, Any]:
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

    rules = merge_rules(stable, preview) if stable is not None else None
    used = {r.get("alert_rule_template_name") for r in rules or [] if r.get("alert_rule_template_name")}
    template_names = {t.get("name") for t in templates or []}
    return {
        "api_versions": {"stable": SI_API, "preview": SI_PREVIEW_API},
        "rules": rules,
        **(rule_summary(rules) if rules is not None else {}),
        "templates_available": len(template_names) if templates is not None else None,
        "templates_in_use": len(used & template_names) if templates is not None else None,
        "notes": notes,
    }


def summarize(workspaces: List[Dict[str, Any]]) -> Dict[str, Any]:
    collected = [w for w in workspaces if w.get("rules") is not None]
    enabled = [w.get("enabled_rules") or 0 for w in collected]
    return {
        "enabled_rules_total": sum(enabled),
        "min_enabled_rules": min(enabled) if enabled else None,
        "workspaces_with_no_enabled_rules": sum(1 for e in enabled if e == 0),
        "workspaces_with_fusion_enabled": sum(1 for w in collected if w.get("fusion_enabled") is True),
    }


def main() -> int:
    return run_workspaces(fetcher=NAME, logger=logger, collect=collect, summarize=summarize)


if __name__ == "__main__":
    sys.exit(main())
