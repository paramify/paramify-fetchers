#!/usr/bin/env python3
"""Every repository in the organization as one Inventory record, with its visibility, state and security features.

An inventory: all or nothing (docs/inventory_fetchers_guide.md). Records come from the repository listing the client
already pages and checks against the organization's own count, plus one paged call for custom property values.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_shared"))
from github_client import PLAN_UNAVAILABLE, run  # noqa: E402

NAME = "github_repository_inventory"
INVENTORY = True
CONFIG = {"include_custom_properties": ("GITHUB_INCLUDE_CUSTOM_PROPERTIES", True)}
SECURITY_FEATURES = ("advanced_security", "secret_scanning", "secret_scanning_push_protection",
                     "dependabot_security_updates")


def scalar(value):
    """A pipeline's field picker cannot select a list; a multi-select property is joined."""
    return ", ".join(str(v) for v in value) if isinstance(value, list) else value


def custom_properties(client, org):
    """({property name: {repository id: value}}, available). None when unreadable (already recorded)."""
    state, schema = client.paginate(f"orgs/{org}/properties/schema")
    if state == PLAN_UNAVAILABLE:
        return {}, False
    if state is not None:
        if state != "failed":
            client.fail(f"GET orgs/{org}/properties/schema", "UnexpectedState", f"{state}: {client.last_message}",
                        "not_authorized")
        return None, None
    values = client.paginate_required(f"orgs/{org}/properties/values") if schema else []
    if values is None:
        return None, None
    by_name = {p.get("property_name"): {} for p in schema if p.get("property_name")}
    for row in values:
        for prop in row.get("properties") or []:
            if prop.get("property_name") in by_name:
                by_name[prop["property_name"]][row.get("repository_id")] = scalar(prop.get("value"))
    return by_name, True


def record(client, repo, properties):
    security = repo.get("security_and_analysis")  # present only to an admin of the repository
    out = {
        # The repository's REST URL by numeric id: unique per host, stable across renames and transfers.
        "unique_asset_identifier": f"{client.api_url}/repositories/{repo['id']}",
        "name": repo.get("name"),
        "full_name": repo.get("full_name"),
        "url": repo.get("html_url"),
        "asset_type": "Source code repository",
        "visibility": repo.get("visibility"),
        "public": repo.get("visibility") == "public" if repo.get("visibility") else None,
        "archived": repo.get("archived"),
        "disabled": repo.get("disabled"),
        "fork": repo.get("fork"),
        "is_template": repo.get("is_template"),
        "default_branch": repo.get("default_branch"),
        "language": repo.get("language"),
        "topics": scalar(repo.get("topics") or []),
        "size_kb": repo.get("size"),
        "created_at": repo.get("created_at"),
        "pushed_at": repo.get("pushed_at"),
        "security_settings_readable": security is not None,
    }
    for feature in SECURITY_FEATURES:
        status = ((security or {}).get(feature) or {}).get("status")
        out[feature] = None if status is None else status == "enabled"
    for name, values in sorted(properties.items()):
        out[f"property_{name}"] = values.get(repo["id"])
    return out


def collect(client, org, repos, config):
    properties, available = ({}, None)
    if config["include_custom_properties"]:
        properties, available = custom_properties(client, org["login"])
        if properties is None:
            return {"summary": {"repositories_total": len(repos)}, "data": []}
    records = [record(client, repo, properties) for repo in repos]
    return {
        "metadata": {"custom_properties_available": available, "custom_properties": sorted(properties)},
        "summary": {
            "repositories_total": len(records),
            "by_visibility": {v: sum(1 for r in records if (r["visibility"] or "unknown") == v)
                              for v in sorted({r["visibility"] or "unknown" for r in records})},
            "archived": sum(1 for r in records if r["archived"]),
            "security_settings_unreadable": [r["name"] for r in records if not r["security_settings_readable"]],
        },
        "data": records,
    }


if __name__ == "__main__":
    sys.exit(run(NAME, collect, CONFIG, inventory=INVENTORY))
