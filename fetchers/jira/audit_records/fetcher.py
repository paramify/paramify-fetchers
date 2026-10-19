#!/usr/bin/env python3
"""Jira audit log: administrative changes recorded by the site over a lookback window."""

import logging
import os
import sys
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from jira_common import (  # noqa: E402
    Abort,
    JiraClient,
    collector_info,
    connection_settings,
    counts,
    int_env,
    report_failure,
    utc_now,
    write_and_finish,
)

logger = logging.getLogger("jira_audit_records")

OUTPUT_FILE = "jira_audit_records.json"
PAGE_LIMIT = 1000

# Atlassian does not publish the list of audit `category` values (the API
# reference shows only "group management"), so records are classified by key
# words in the category name rather than by an exact list. Categories that match
# nothing are reported in summary.unclassified_categories so a miss is visible
# and the list can be tuned against a real site.
SENSITIVE_KEYWORDS = (
    "permission",
    "user",
    "group",
    "workflow",
    "security",
    "scheme",
    "project",
    "field",
    "screen",
    "system",
    "global",
    "application",
    "role",
)
VALUE_LIMIT = 200


def is_sensitive(category) -> bool:
    cat = (category or "").lower()
    return any(k in cat for k in SENSITIVE_KEYWORDS)


def _clip(value):
    """Shorten a changed value and defuse markup: admin changes can carry HTML or script
    text (an announcement banner), which can be large and can trip request filters."""
    if value is None:
        return None
    text = str(value).replace("<", "&lt;").replace(">", "&gt;")
    return text if len(text) <= VALUE_LIMIT else text[:VALUE_LIMIT] + "..."


def _record(r: dict) -> dict:
    obj = r.get("objectItem") or {}
    sensitive = is_sensitive(r.get("category"))
    return {
        "id": r.get("id"),
        "created": r.get("created"),
        "category": r.get("category"),
        "sensitive": sensitive,
        "summary": _clip(r.get("summary")),
        "event_source": r.get("eventSource"),
        "author_account_id": r.get("authorAccountId") or r.get("authorKey"),
        "remote_address": r.get("remoteAddress"),
        "object": {
            "type": obj.get("typeName"),
            "name": _clip(obj.get("name")),
            "parent": _clip(obj.get("parentName")),
        },
        "associated_items": [
            {"type": a.get("typeName"), "name": _clip(a.get("name")), "parent": _clip(a.get("parentName"))}
            for a in r.get("associatedItems") or []
        ],
        # Values are evidence only for privileged changes; elsewhere the field name is enough.
        "changed_values": [
            {"field": c.get("fieldName"), "from": _clip(c.get("changedFrom")), "to": _clip(c.get("changedTo"))}
            if sensitive
            else {"field": c.get("fieldName")}
            for c in r.get("changedValues") or []
        ],
    }


def _summarize(records: list) -> dict:
    created = sorted(r["created"] for r in records if r["created"])
    sensitive = [r for r in records if r["sensitive"]]
    return {
        "total": len(records),
        "oldest_record": created[0] if created else None,
        "newest_record": created[-1] if created else None,
        "distinct_authors": len({r["author_account_id"] for r in records if r["author_account_id"]}),
        "by_category": counts(r["category"] for r in records),
        "by_object_type": counts(r["object"]["type"] for r in records),
        "by_author": counts(r["author_account_id"] for r in records),
        "sensitive_changes": {
            "total": len(sensitive),
            "by_category": counts(r["category"] for r in sensitive),
        },
        "unclassified_categories": counts(r["category"] for r in records if not r["sensitive"]),
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    settings = connection_settings()
    if isinstance(settings, str):
        report_failure(settings, "bad_config")
        return 1
    base_url, email, api_token = settings

    lookback_days = int_env("JIRA_AUDIT_LOOKBACK_DAYS", 90)
    max_records = int_env("JIRA_AUDIT_MAX_RECORDS", 20000)
    if lookback_days is None or max_records is None:
        report_failure(
            "JIRA_AUDIT_LOOKBACK_DAYS and JIRA_AUDIT_MAX_RECORDS must be positive integers",
            "bad_config",
        )
        return 1
    audit_filter = os.environ.get("JIRA_AUDIT_FILTER", "").strip()

    client = JiraClient(base_url, email, api_token)
    now = utc_now()
    window_from = (now - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    window_to = now.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    collector = None
    records: list = []
    reported_total = None
    truncated = False

    try:
        collector = collector_info(client)
        offset = 0
        while True:
            params = {"offset": offset, "limit": PAGE_LIMIT, "from": window_from, "to": window_to}
            if audit_filter:
                params["filter"] = audit_filter
            page = client.request(
                "GET", "/rest/api/3/auditing/record", "GET /rest/api/3/auditing/record", params=params
            )
            if page is None:
                break
            batch = page.get("records") or []
            reported_total = page.get("total", reported_total)
            records.extend(_record(r) for r in batch)
            offset += len(batch)
            if len(records) >= max_records:
                fetched = len(records)
                records = records[:max_records]
                truncated = fetched > max_records or (
                    reported_total is None or reported_total > max_records
                )
                break
            if not batch or (reported_total is not None and offset >= reported_total):
                break
    except Abort:
        pass

    evidence = {
        "metadata": {
            "collected_at": now.isoformat(),
            "base_url": base_url,
            "window_from": window_from,
            "window_to": window_to,
            "lookback_days": lookback_days,
            "filter": audit_filter or None,
            "reported_total": reported_total,
            "records_collected": len(records),
            "records_truncated": truncated,
            "partial_failure": bool(client.api_failures),
            "api_failures": client.api_failures,
        },
        "collector": collector,
        "summary": _summarize(records),
        "records": records,
    }
    incomplete = ""
    if truncated:
        incomplete = (
            f"audit records truncated at JIRA_AUDIT_MAX_RECORDS={max_records}"
            f" ({reported_total if reported_total is not None else 'unknown'} available)"
        )
    elif reported_total is not None and len(records) < reported_total:
        # The server stopped paging early (an empty page before `total`): not complete.
        incomplete = f"only {len(records)} of {reported_total} audit records were returned"
    return write_and_finish(logger, client, evidence, OUTPUT_FILE, incomplete)


if __name__ == "__main__":
    sys.exit(main())
