#!/usr/bin/env python3
"""
KnowBe4 — Discovery

Lists what this API key can see in the tenant: the account, groups, training
campaigns, purchased modules, policies, phishing campaigns and tests, plus user
and enrollment counts. Writes a discovery document, not evidence; nothing here
is uploaded.

Every list call is a Reporting API collection endpoint, paged by cursor.
KnowBe4 retires the `page` parameter in November 2026, so this never uses it.

Output: $EVIDENCE_DIR/knowbe4_discovery_beta.json
Required env: KNOWBE4_API_KEY, KNOWBE4_REGION
"""

import logging
import os
import sys
from pathlib import Path
from typing import Iterator, List, Optional

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from discovery import (  # noqa: E402
    CallFailed,
    HttpClient,
    Resource,
    by,
    failure_code,
    run,
    setup_logging,
)
from fetcher_status import report_failure  # noqa: E402

FETCHER = "knowbe4_discovery_beta"
PER_PAGE = 500
MAX_PAGES = 1000

logger = logging.getLogger(FETCHER)

# Users and enrollments are records about people: counted, with a breakdown by
# status, never listed.
RESOURCES = [
    Resource("user", "/v1/users", count_only=True, summary=by("status")),
    Resource(
        "group", "/v1/groups",
        fields=["group_type", "status", "member_count"],
        summary=by("status", "group_type"),
    ),
    # exclude_percentages=true: without it the API caps this endpoint at 10 a
    # page and computes a completion percentage per campaign, which is slow and
    # is not discovery's question.
    Resource(
        "training_campaign", "/v1/training/campaigns",
        params={"exclude_percentages": "true"},
        id="campaign_id",
        fields=["status", "start_date", "end_date"],
        extra=lambda r: {
            "groups": [g.get("name") for g in r.get("groups") or []],
            "modules": len(r.get("content") or []),
        },
        summary=by("status"),
    ),
    Resource(
        "training_module", "/v1/training/store_purchases",
        id="store_purchase_id",
        fields=["type", "content_type", "retired"],
        summary=by("type"),
    ),
    Resource(
        "training_policy", "/v1/training/policies",
        id="policy_id",
        fields=["status", "content_type"],
    ),
    Resource("training_enrollment", "/v1/training/enrollments", count_only=True, summary=by("status")),
    Resource(
        "phishing_campaign", "/v1/phishing/campaigns",
        id="campaign_id",
        fields=["status", "frequency", "last_run", "psts_count"],
        summary=by("status"),
    ),
    Resource(
        "phishing_test", "/v1/phishing/security_tests",
        id="pst_id",
        fields=["campaign_id", "status", "started_at"],
        summary=by("status"),
    ),
]


def cursor_pages(client: HttpClient):
    """The Reporting API's paging: {data: [...], pagination: {nextCursor}},
    started with cursor=0 and finished when nextCursor is null."""

    def pages(resource: Resource) -> Iterator[List[dict]]:
        cursor = "0"
        for _ in range(MAX_PAGES):
            body = client.get_json(resource.path, {**resource.params, "per_page": PER_PAGE, "cursor": cursor})
            if not isinstance(body, dict) or not isinstance(body.get("data"), list):
                raise CallFailed("error", "unexpected response shape (no data array)")
            yield body["data"]
            cursor = (body.get("pagination") or {}).get("nextCursor")
            if not cursor:
                return
        raise CallFailed("error", f"stopped at the {MAX_PAGES}-page cap")

    return pages


def account_entry(account: dict) -> dict:
    """The account as a resource. Admins are people: counted, never named."""
    return {
        "type": "account",
        "status": "ok",
        "count": 1,
        "truncated": False,
        "items": [{
            "id": str(account.get("name") or "account"),
            "name": account.get("name"),
            "type": account.get("type"),
            "subscription_level": account.get("subscription_level"),
            "subscription_end_date": account.get("subscription_end_date"),
            "number_of_seats": account.get("number_of_seats"),
            "domains": account.get("domains") or [],
            "admin_count": len(account.get("admins") or []),
        }],
        "source": "GET /v1/account",
    }


def main(session: Optional[requests.Session] = None) -> int:
    setup_logging(FETCHER)
    api_key = os.environ.get("KNOWBE4_API_KEY", "")
    region = os.environ.get("KNOWBE4_REGION", "")
    if not api_key:
        report_failure("KNOWBE4_API_KEY is not set", "bad_config")
        return 1
    if not region:
        report_failure("KNOWBE4_REGION is not set", "bad_config")
        return 1

    base_url = f"https://{region}.api.knowbe4.com"
    client = HttpClient(
        base_url,
        {"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        # Four requests a second, 50 a minute in a burst.
        pace=0.3,
        session=session,
    )

    # The account is identity, and the check that the key works at all. A key
    # that cannot read its own account is a failed run, not an empty tenant.
    logger.info("enumerating KnowBe4 (%s)", region)
    try:
        account = client.get_json("/v1/account")
    except CallFailed as e:
        where = f"cannot reach {base_url}" if e.http_status is None else "cannot read the account with this key"
        report_failure(f"{where}: {e.reason}", failure_code(e.http_status))
        return 1
    if not isinstance(account, dict):
        report_failure("cannot read the account: response was not an object")
        return 1

    return run(
        platform="knowbe4",
        output_name=f"{FETCHER}.json",
        identity=f"{account.get('name') or 'unknown account'} ({account.get('subscription_level') or 'unknown subscription'})",
        scope={"region": region},
        leading=[account_entry(account)],
        resources=RESOURCES,
        pages=cursor_pages(client),
    )


if __name__ == "__main__":
    sys.exit(main())
