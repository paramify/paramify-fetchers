#!/usr/bin/env python3
"""Zendesk ticket forms and their fields, read with an API token, plus an anonymous check of the request page."""

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from zendesk_client import (  # noqa: E402
    CollectionError,
    current_timestamp,
    env,
    get_json,
    http_session,
    parse_origin,
    public_page_status,
    require_env,
    run,
    verify_ssl_enabled,
)

NAME = "zendesk_request_form"
VERSION = "0.1.0"

MAX_PAGES = 100
USER_AGENT = f"paramify-fetchers {NAME}/{VERSION}"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}

# Field names are from Zendesk's Support API documentation, UNVERIFIED against a live response.
FORM_FIELDS = ["id", "name", "display_name", "active", "default", "end_user_visible", "in_all_brands",
               "restricted_brand_ids", "ticket_field_ids", "agent_conditions", "end_user_conditions"]
FIELD_FIELDS = ["id", "type", "title", "title_in_portal", "description", "active", "required", "required_in_portal",
                "visible_in_portal", "editable_in_portal", "custom_field_options"]
OPTION_FIELDS = ["name", "value", "default"]

# Paramify-specific keyword heuristic; see evidence_set.instructions.
SECURITY = re.compile(r"secur|vulnerab|disclos", re.IGNORECASE)

FAILURE_FIELDS: Dict[str, Any] = {
    "forms_end_user_visible": None, "security_report_option": None, "has_security_report_option": None,
    "required_portal_fields": None, "requests_new_public": None, "requests_new_status": None,
    "form_count": None, "field_count": None, "pagination": None, "forms": [],
}


def parse_form_ids(raw: str) -> Optional[List[int]]:
    if not raw:
        return None
    ids = [part.strip() for part in raw.split(",") if part.strip()]
    if not ids or not all(part.isdigit() for part in ids):
        raise CollectionError(f"ZENDESK_TICKET_FORM_IDS must be a comma list of form ids; got {raw!r}",
                              "bad_config", "bad_config")
    return [int(part) for part in ids]


def api_origin(base_url: str) -> str:
    """The origin to send the token to: https only, except a loopback stand-in."""
    origin = parse_origin(base_url, "ZENDESK_BASE_URL")
    scheme, host = origin.split("://", 1)
    if scheme != "https" and host.rsplit(":", 1)[0].strip("[]") not in LOOPBACK:
        raise CollectionError(f"ZENDESK_BASE_URL must be https, since an API token is sent to it; got {base_url!r}",
                              "bad_url", "bad_config")
    return origin


def list_all(http: requests.Session, url: str, key: str, origin: str, verify: bool,
             auth: Tuple[str, str]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Every page, offset (`next_page` + `count`) or cursor (`meta.has_more` + `links.next`).

    Offset fails unless the collected number equals `count`. Cursor has no total, so it ends on has_more false.
    """
    items: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    style: Optional[str] = None
    reported: Optional[int] = None
    next_url: Optional[str] = url
    while next_url:
        if next_url in seen or len(seen) >= MAX_PAGES:
            raise CollectionError(f"pagination did not end after {len(seen)} page(s) at {next_url}", "pagination")
        if not next_url.startswith(origin + "/"):
            raise CollectionError(f"next page of {key} points off {origin}: {next_url!r}", "pagination")
        seen.add(next_url)
        page = get_json(http, next_url, verify, auth)
        if not isinstance(page.get(key), list):
            raise CollectionError(f"GET {next_url} has no `{key}` list", "unexpected_shape")
        items += page[key]
        meta, links = page.get("meta"), page.get("links")
        if isinstance(meta, dict) and isinstance(meta.get("has_more"), bool):
            style = "cursor"
            following = links.get("next") if isinstance(links, dict) else None
            if meta["has_more"] and not isinstance(following, str):
                raise CollectionError(f"GET {next_url} says has_more but gives no links.next", "pagination")
            next_url = following if meta["has_more"] else None
        elif isinstance(page.get("count"), int):
            style, reported = "offset", page["count"]
            next_url = page.get("next_page")
        else:
            raise CollectionError(
                f"GET {next_url} has neither `count` (offset) nor `meta.has_more` (cursor) pagination",
                "unexpected_shape")
    if style == "offset" and len(items) != reported:
        raise CollectionError(f"collected {len(items)} {key} but the API reported count={reported}",
                              "count_mismatch")
    return items, {"style": style, "pages": len(seen), "collected": len(items), "reported_count": reported}


def field_record(field: Dict[str, Any]) -> Dict[str, Any]:
    record = {name: field.get(name) for name in FIELD_FIELDS}
    options = field.get("custom_field_options")
    if isinstance(options, list):
        record["custom_field_options"] = [{name: o.get(name) for name in OPTION_FIELDS}
                                          for o in options if isinstance(o, dict)]
    return record


def form_record(form: Dict[str, Any], fields_by_id: Dict[Any, Dict[str, Any]]) -> Dict[str, Any]:
    raw_ids = form.get("ticket_field_ids")
    ids: List[Any] = raw_ids if isinstance(raw_ids, list) else []
    return {
        **{name: form.get(name) for name in FORM_FIELDS},
        "fields": [fields_by_id[i] for i in ids if i in fields_by_id],
        "missing_field_ids": [i for i in ids if i not in fields_by_id],
    }


def _portal_title(field: Dict[str, Any]) -> Any:
    return field.get("title_in_portal") or field.get("title")


def security_matches(forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Form names and portal-visible options on active, end-user-visible forms that read as security reporting."""
    matches: List[Dict[str, Any]] = []
    for form in forms:
        for key in ("display_name", "name"):
            if isinstance(form[key], str) and SECURITY.search(form[key]):
                matches.append({"form_id": form["id"], "source": f"form.{key}", "text": form[key]})
                break
        for field in form["fields"]:
            if field["active"] is not True or field["visible_in_portal"] is not True:
                continue
            for option in field["custom_field_options"] or []:
                if isinstance(option["name"], str) and SECURITY.search(option["name"]):
                    matches.append({"form_id": form["id"], "source": "field_option", "field_id": field["id"],
                                    "field": _portal_title(field), "text": option["name"], "value": option["value"]})
    return matches


def required_portal_fields(forms: List[Dict[str, Any]]) -> List[Any]:
    titles: List[Any] = []
    for form in forms:
        for field in form["fields"]:
            required = all(field[k] is True for k in ("active", "visible_in_portal", "required_in_portal"))
            if required and _portal_title(field) not in titles:
                titles.append(_portal_title(field))
    return titles


def requests_new_public(status: Dict[str, Any]) -> Optional[bool]:
    """False on a sign-in redirect or a plain error; None when a bot challenge or network error left it unverified."""
    if status["error"] or status["bot_challenge"]:
        return None
    return status["http_status"] == 200 and not status["redirected_to_signin"]


def collect(record: Dict[str, Any], origin: str, locale: str, form_ids: Optional[List[int]], verify: bool,
            auth: Tuple[str, str]) -> Dict[str, Any]:
    http = http_session(USER_AGENT)
    raw_forms, form_pages = list_all(http, f"{origin}/api/v2/ticket_forms.json", "ticket_forms", origin, verify,
                                     auth)
    raw_fields, field_pages = list_all(http, f"{origin}/api/v2/ticket_fields.json", "ticket_fields", origin, verify,
                                       auth)
    if form_ids is not None:
        missing = sorted(set(form_ids) - {f.get("id") for f in raw_forms})
        if missing:
            raise CollectionError(f"ZENDESK_TICKET_FORM_IDS names form(s) the API did not return: {missing}",
                                  "form_not_found", "bad_config")
        raw_forms = [f for f in raw_forms if f.get("id") in form_ids]
    fields_by_id = {f.get("id"): field_record(f) for f in raw_fields}
    forms = [form_record(f, fields_by_id) for f in raw_forms]
    shown = [f for f in forms if f["active"] is True and f["end_user_visible"] is True]
    security = security_matches(shown)

    # A fresh session with no auth, so no credential or API session cookie reaches the public page.
    status = public_page_status(http_session(USER_AGENT), f"{origin}/hc/{locale}/requests/new", verify)
    return {
        **record,
        "forms_end_user_visible": len(shown),
        "security_report_option": security,
        "has_security_report_option": bool(security),
        "required_portal_fields": required_portal_fields(shown),
        "requests_new_public": requests_new_public(status),
        "requests_new_status": {"url": f"{origin}/hc/{locale}/requests/new", **status},
        "form_count": len(forms),
        "field_count": len(raw_fields),
        "pagination": {"ticket_forms": form_pages, "ticket_fields": field_pages},
        "forms": forms,
    }


def main() -> int:
    load_dotenv()
    target_name = env("ZENDESK_TARGET_NAME") or "request_form"
    record: Dict[str, Any] = {
        "collected_at": current_timestamp(),
        "target_name": target_name,
        "base_url": env("ZENDESK_BASE_URL"),
        "help_center": None,
        "locale": None,
        "ticket_form_ids": None,
        "authenticated": True,
    }

    def work() -> Dict[str, Any]:
        require_env("ZENDESK_TARGET_NAME", "ZENDESK_BASE_URL", "ZENDESK_EMAIL", "ZENDESK_API_TOKEN")
        origin = api_origin(env("ZENDESK_BASE_URL"))
        locale = env("ZENDESK_LOCALE") or "en-us"
        form_ids = parse_form_ids(env("ZENDESK_TICKET_FORM_IDS"))
        record.update(help_center=origin, locale=locale, ticket_form_ids=form_ids)
        # Zendesk's documented API-token scheme: HTTP Basic with "{email}/token" as the user name.
        auth = (f"{env('ZENDESK_EMAIL')}/token", env("ZENDESK_API_TOKEN"))
        return collect(record, origin, locale, form_ids, verify_ssl_enabled(), auth)

    return run(NAME, target_name, record, work, FAILURE_FIELDS, f"read ticket forms {record['base_url']}",
               redact=[env("ZENDESK_API_TOKEN")])


if __name__ == "__main__":
    sys.exit(main())
