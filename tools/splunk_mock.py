#!/usr/bin/env python3
"""
A local stand-in for the Splunk management REST API, for developing and testing
the splunk fetchers without a Splunk deployment.

It implements only the endpoints the fetchers call, with response shapes,
auth headers and `count`/`offset` paging taken from Splunk's own SDK
(github.com/splunk/splunk-sdk-python — `splunklib/client.py` for the paths and
paging, `splunklib/binding.py` for the auth headers, and the integration tests
for how values are actually rendered on the wire).

Implements: `POST /services/auth/login`, `GET /services/server/info`,
`GET /services/data/indexes`, and both namespace forms of
`GET /saved/searches`.

    python tools/splunk_mock.py --port 8089

    export SPLUNK_BASE_URL=http://127.0.0.1:8089
    export SPLUNK_USERNAME=admin
    export SPLUNK_PASSWORD=mock-password
    # or: export SPLUNK_TOKEN=mock-token

**These fixtures were checked against a real Splunk Enterprise 10.4.2** and the
capture is committed at `tests/fixtures/splunk_real_responses.json`. Names,
value types and stock settings come from that instance.

The fixtures are deliberately awkward, and every awkwardness is a real Splunk
behaviour rather than an invented one:

  - **Value types are mixed within a single response.** Under
    `output_mode=json` a live 10.4.2 sends `disabled` and
    `enableDataIntegrityControl` as native JSON booleans, `totalEventCount` and
    `frozenTimePeriodInSecs` as native ints, and `currentDBSizeMB` as a
    **string**. The Atom rendering the SDK parses makes all of them strings.
    One fixture keeps that all-strings rendering so both are exercised — `"0"`
    is truthy in Python, and a fetcher that reads it raw calls every index
    disabled.
  - `_audit` and `_internal` are present with their real stock retention,
    because Splunk creates them and they are themselves evidence.
  - **A stock install has data integrity control OFF on every index**, which is
    the opposite of what an evidence reviewer might assume. One index has it on,
    created by hand, so the True branch is exercised at all.
  - One index archives to a directory, one to a *script* — reading only
    `coldToFrozenDir` misses the second entirely.
  - One has `frozenTimePeriodInSecs: 0`, which means freeze immediately.
  - One index has never received an event; one is disabled and still holds data.
  - One spells its values in a way neither rendering uses, so the "unreadable"
    path is exercised rather than being a shipped-but-never-run branch.

Fault injection, matching tools/crowdstrike_mock.py:

    SPLUNK_MOCK_RATE_LIMIT=n   first n calls per path answer 503
    SPLUNK_MOCK_FORBID=/path   that path answers 403 (the role-lacks-capability
                               case, which is the most likely real failure)
    SPLUNK_MOCK_MESSAGES=1     200 with a WARN in messages[] (partial success)
    SPLUNK_MOCK_PAGE_SIZE=n    cap every page at n entries regardless of `count`,
                               so a short page that is not the last page is
                               exercised

This is a test double, not a simulator: it does not enforce search filters, and
its record counts are small enough to read by eye.
"""

import argparse
import json
import os
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

VALID_USERNAME = "admin"
VALID_PASSWORD = "mock-password"
VALID_TOKEN = "mock-token"
SESSION_KEY = "mock-session-key"

_CALLS: Dict[str, int] = defaultdict(int)


def _env_int(name: str) -> int:
    try:
        return int(os.environ.get(name, "0") or "0")
    except ValueError:
        return 0


def _server_info() -> Dict[str, Any]:
    return {
        "version": "10.4.2",
        "build": "33c3bf42cd73",
        "serverName": "mock-splunk",
        "guid": "3B8E4A2C-1F5D-4C7A-9E2B-6D0F8A1C4B93",
        "server_roles": ["indexer", "license_master", "license_manager", "kv_store"],
        "product_type": "enterprise",
        "licenseState": "OK",
        "isFree": "0",
        "isTrial": "1",
    }


def _indexes() -> List[Dict[str, Any]]:
    """
    Shaped like a real Splunk Enterprise 10.4.2, because it was checked against
    one. `tests/fixtures/splunk_real_responses.json` is the capture.

    **The types are mixed, and that is the real behaviour, not a quirk of this
    fixture.** Under `output_mode=json` a live 10.4.2 sends `disabled` and
    `enableDataIntegrityControl` as native JSON booleans, `totalEventCount` and
    `frozenTimePeriodInSecs` as native integers, and `currentDBSizeMB` as a
    **string** — in the same response. The Atom rendering the SDK parses by
    default makes every one of them a string instead.

    This file originally sent everything as `"0"`/`"1"` strings, on the strength
    of the SDK's integration tests. That was half right, and a mock that is half
    right about types is exactly the trap this project keeps hitting, so the
    last fixture below deliberately keeps the all-strings rendering to prove
    `as_bool`/`as_int` still handle it.

    `frozenTimePeriodInSecs`: 188697600 is Splunk's stock ~6 years, 2592000 is
    30 days, 7776000 is 90 days. `coldToFrozen*` are empty strings when unset,
    not absent — a real install has them present and empty on every index.
    """
    return [
        {
            # Splunk's audit trail, with its real stock retention. Data
            # integrity control is OFF here, which is what a fresh install
            # actually ships — the opposite of what an evidence reviewer might
            # assume, and worth showing.
            "name": "_audit",
            "datatype": "event",
            "disabled": False,
            "enableDataIntegrityControl": False,
            "frozenTimePeriodInSecs": 188697600,
            "coldToFrozenDir": "",
            "coldToFrozenScript": "",
            "totalEventCount": 623,
            "currentDBSizeMB": "1",
            "maxTotalDataSizeMB": 500000,
            "minTime": "2026-08-24T21:16:26-0600",
            "maxTime": "2026-08-24T21:19:09-0600",
            "homePath": "$SPLUNK_DB/audit/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/audit/db",
        },
        {
            "name": "_internal",
            "datatype": "event",
            "disabled": False,
            "enableDataIntegrityControl": False,
            "frozenTimePeriodInSecs": 2592000,
            "coldToFrozenDir": "",
            "coldToFrozenScript": "",
            "totalEventCount": 4461,
            "currentDBSizeMB": "2",
            "maxTotalDataSizeMB": 500000,
            "minTime": "2026-08-24T21:16:26-0600",
            "maxTime": "2026-08-24T21:19:11-0600",
            "homePath": "$SPLUNK_DB/_internaldb/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/_internaldb/db",
        },
        {
            "name": "main",
            "datatype": "event",
            "disabled": False,
            "enableDataIntegrityControl": False,
            "frozenTimePeriodInSecs": 188697600,
            "coldToFrozenDir": "",
            "coldToFrozenScript": "",
            "totalEventCount": 0,
            "currentDBSizeMB": "1",
            "maxTotalDataSizeMB": 500000,
            "minTime": "",
            "maxTime": "",
            "homePath": "$SPLUNK_DB/defaultdb/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/defaultdb/db",
        },
        {
            # The shape a deployment claiming tamper-resistant logging should
            # have: integrity control on, long retention, archived on freeze.
            # Created by hand on the test instance — a stock install has no
            # index with enableDataIntegrityControl set, so without this the
            # True branch would never be exercised.
            "name": "compliance_integrity",
            "datatype": "event",
            "disabled": False,
            "enableDataIntegrityControl": True,
            "frozenTimePeriodInSecs": 94608000,
            "coldToFrozenDir": "/opt/frozen/compliance",
            "coldToFrozenScript": "",
            "totalEventCount": 0,
            "currentDBSizeMB": "1",
            "maxTotalDataSizeMB": 500000,
            "minTime": "",
            "maxTime": "",
            "homePath": "$SPLUNK_DB/compliance_integrity/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/compliance_integrity/db",
        },
        {
            # Archives via a script rather than a directory. Splunk validates
            # that the script exists before it will accept the setting, so this
            # is a configuration a real deployment can actually hold — and
            # reading only coldToFrozenDir misses it entirely.
            "name": "archived_by_script",
            "datatype": "event",
            "disabled": False,
            "enableDataIntegrityControl": False,
            "frozenTimePeriodInSecs": 31536000,
            "coldToFrozenDir": "",
            "coldToFrozenScript": "/opt/frozen/archive.sh",
            "totalEventCount": 0,
            "currentDBSizeMB": "1",
            "maxTotalDataSizeMB": 500000,
            "minTime": "",
            "maxTime": "",
            "homePath": "$SPLUNK_DB/archived_by_script/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/archived_by_script/db",
        },
        {
            # frozenTimePeriodInSecs 0 means freeze immediately. A real and very
            # aggressive setting, and the most interesting one in a retention
            # review, so it must not be folded in with the unreadable values.
            "name": "short_retention",
            "datatype": "event",
            "disabled": False,
            "enableDataIntegrityControl": False,
            "frozenTimePeriodInSecs": 0,
            "coldToFrozenDir": "",
            "coldToFrozenScript": "",
            "totalEventCount": 0,
            "currentDBSizeMB": "1",
            "maxTotalDataSizeMB": 500000,
            "minTime": "",
            "maxTime": "",
            "homePath": "$SPLUNK_DB/short_retention/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/short_retention/db",
        },
        {
            # Disabled, and still holding data — Splunk keeps a disabled index's
            # buckets, it just stops routing to it. `splunklogger` really does
            # ship disabled on a stock install.
            "name": "splunklogger",
            "datatype": "event",
            "disabled": True,
            "enableDataIntegrityControl": False,
            "frozenTimePeriodInSecs": 188697600,
            "coldToFrozenDir": "",
            "coldToFrozenScript": "",
            "totalEventCount": 0,
            "currentDBSizeMB": "1",
            "maxTotalDataSizeMB": 500000,
            "minTime": "",
            "maxTime": "",
            "homePath": "$SPLUNK_DB/splunklogger/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/splunklogger/db",
        },
        {
            # The Atom rendering, where every value is a string — what the SDK
            # parses by default, and what several JSON fields still use. Kept as
            # its own fixture so `as_bool`/`as_int` are proven against both
            # renderings rather than only the one this instance happened to send.
            "name": "legacy_string_rendering",
            "datatype": "event",
            "disabled": "0",
            "enableDataIntegrityControl": "1",
            "frozenTimePeriodInSecs": "7776000",
            "coldToFrozenDir": "",
            "coldToFrozenScript": "",
            "totalEventCount": "51022",
            "currentDBSizeMB": "128",
            "maxTotalDataSizeMB": "500000",
            "minTime": "2026-06-01T00:00:00-0600",
            "maxTime": "2026-08-24T17:59:31-0600",
            "homePath": "$SPLUNK_DB/legacy_string_rendering/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/legacy_string_rendering/db",
        },
        {
            # Values in a spelling neither rendering uses. Both the enabled
            # state and the retention must come back unreadable rather than
            # defaulted — an unknown is not a finding.
            "name": "metrics_pipeline",
            "datatype": "metric",
            "disabled": "maybe",
            "enableDataIntegrityControl": "inherit",
            "frozenTimePeriodInSecs": "default",
            "coldToFrozenDir": "",
            "coldToFrozenScript": "",
            "totalEventCount": 51022,
            "currentDBSizeMB": "128",
            "maxTotalDataSizeMB": 500000,
            "minTime": "2026-06-01T00:00:00-0600",
            "maxTime": "2026-08-24T17:59:31-0600",
            "homePath": "$SPLUNK_DB/metrics_pipeline/db",
            "homePath_expanded": "/opt/splunk/var/lib/splunk/metrics_pipeline/db",
        },
    ]


def _saved_searches() -> List[Dict[str, Any]]:
    """
    Shaped like a real Splunk Enterprise 10.4.2. Field names, value types and
    the stock DMC alerts come from that instance.

    Two things here are traps rather than decoration:

    - **`actions` is a comma-separated STRING**, not a list. The real values on
      a stock install are `""`, `"outputtelemetry"` and `"summary_index"`.
      Iterating it yields characters; `in` matches substrings.
    - **`alert_type` is the literal `"always"` for a scheduled report**, which
      means "not really an alert". Anything else is a real alerting condition,
      so testing `alert_type` for truthiness counts every report as an alert.

    `acl` carries the app and owner, which is where `by_app`/`by_owner` come
    from — a stock install has 174 of these across six apps, nearly all owned by
    `nobody`.
    """
    return [
        {
            # The shape a deployment claiming persistent log review should have:
            # scheduled, enabled, alerting, and it actually notifies someone.
            "name": "Failed authentication review - hourly",
            "_app": "search",
            "_owner": "nobody",
            "search": "index=_audit action=login attempt failure | stats count by user",
            "description": "Hourly review of failed authentications",
            "is_scheduled": True,
            "disabled": False,
            "cron_schedule": "0 * * * *",
            "next_scheduled_time": "2026-08-25 22:00:00 MDT",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "5",
            "alert.severity": 4,
            "alert.track": True,
            "actions": "email",
            "action.email": True,
            "realtime_schedule": True,
        },
        {
            # Runs, matches, and leaves no trace: tracks nothing, notifies
            # nobody. Indistinguishable from working unless something looks.
            "name": "Privileged role change - unrouted",
            "_app": "search",
            "_owner": "nobody",
            "search": "index=_audit action=edit_roles | stats count by user",
            "description": "",
            "is_scheduled": True,
            "disabled": False,
            "cron_schedule": "*/15 * * * *",
            "next_scheduled_time": "2026-08-25 21:15:00 MDT",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.severity": 3,
            "alert.track": False,
            "actions": "",
            "action.email": False,
            "realtime_schedule": True,
        },
        {
            # A stock Splunk ships nine of these: scheduled, and disabled out of
            # the box. Review that was configured and then switched off.
            "name": "DMC Alert - Abnormal State of Indexer Processor",
            "_app": "splunk_monitoring_console",
            "_owner": "nobody",
            "search": "| rest splunk_server_group=dmc_group_indexer /services/server/info",
            "description": "One or more of your indexers is reporting an abnormal state.",
            "is_scheduled": True,
            "disabled": True,
            "cron_schedule": "3,8,13,18,23,28,33,38,43,48,53,58 * * * *",
            "next_scheduled_time": "",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.severity": 3,
            "alert.track": True,
            "actions": "",
            "action.email": False,
            "realtime_schedule": True,
        },
        {
            # A scheduled *report*, not an alert: alert_type "always" means it
            # has no condition. Real review activity, writing to a summary index.
            "name": "Daily index growth report",
            "_app": "search",
            "_owner": "admin",
            "search": "| rest /services/data/indexes | stats sum(currentDBSizeMB)",
            "description": "",
            "is_scheduled": True,
            "disabled": False,
            "cron_schedule": "30 2 * * *",
            "next_scheduled_time": "2026-08-26 02:30:00 MDT",
            "alert_type": "always",
            "alert.severity": 3,
            "alert.track": False,
            "actions": "summary_index",
            "action.summary_index": True,
            "realtime_schedule": True,
        },
        {
            # Two actions at once, which is what makes `actions` a string worth
            # splitting rather than comparing.
            "name": "Weekly access review digest",
            "_app": "audit_trail",
            "_owner": "nobody",
            "search": "index=_audit | stats count by user, action",
            "description": "Weekly digest for the access review",
            "is_scheduled": True,
            "disabled": False,
            "cron_schedule": "0 6 * * 1",
            "next_scheduled_time": "2026-08-31 06:00:00 MDT",
            "alert_type": "number of results",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.severity": 2,
            "alert.track": True,
            "actions": "email, summary_index",
            "action.email": True,
            "action.summary_index": True,
            "realtime_schedule": True,
        },
        {
            # Tracked, but with no action: it appears in Splunk's own triggered
            # -alerts list and sends nothing. That IS a reviewable record, so it
            # must not be reported as unrouted.
            #
            # This fixture exists because a mutation proved the test could not
            # tell `track or actions` from `actions` alone — every other alert
            # here has both. An OR needs a case that isolates each branch, the
            # same way a distinction needs two unequal values.
            "name": "Index growth anomaly - tracked only",
            "_app": "search",
            "_owner": "nobody",
            "search": "| rest /services/data/indexes | where currentDBSizeMB > 1000",
            "description": "",
            "is_scheduled": True,
            "disabled": False,
            "cron_schedule": "0 */6 * * *",
            # Blank until Splunk has dispatched it once — the real state right
            # after creation or a restart. Reported, but not a finding.
            "next_scheduled_time": "",
            "alert_type": "number of results",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.severity": 2,
            "alert.track": True,
            "actions": "",
            "action.email": False,
            "realtime_schedule": True,
        },
        {
            # Not scheduled: somebody's saved query. Evidence that a search
            # exists, not that review happens.
            "name": "Errors in the last 24 hours",
            "_app": "search",
            "_owner": "nobody",
            "search": 'index=_internal " error " NOT debug source=*splunkd.log*',
            "description": "",
            "is_scheduled": False,
            "disabled": False,
            "cron_schedule": "",
            "next_scheduled_time": "",
            "alert_type": "always",
            "alert.severity": 3,
            "alert.track": False,
            "actions": "",
            "realtime_schedule": True,
        },
        {
            # The Atom / string rendering: "1" and "0" rather than booleans.
            "name": "Legacy string rendered search",
            "_app": "search",
            "_owner": "nobody",
            "search": "index=main | head 1",
            "description": "",
            "is_scheduled": "1",
            "disabled": "0",
            "cron_schedule": "0 4 * * *",
            "next_scheduled_time": "2026-08-25 04:00:00 MDT",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.severity": "5",
            "alert.track": "1",
            "actions": "email",
            "action.email": "1",
            "realtime_schedule": "1",
        },
        {
            # Only ONE of the two state fields is unreadable: the schedule
            # parses, the enabled flag does not.
            #
            # This exists because a mutation proved the test could not tell
            # `scheduled is None or disabled is None` from `and` — every other
            # fixture had both fields unreadable, so either operator gave the
            # same answer. An OR needs a case that isolates each branch.
            "name": "Half unreadable search",
            "_app": "search",
            "_owner": "nobody",
            "search": "index=main | head 1",
            "description": "",
            "is_scheduled": True,
            "disabled": "perhaps",
            "cron_schedule": "0 7 * * *",
            "next_scheduled_time": "",
            "alert_type": "always",
            "alert.severity": 3,
            "alert.track": False,
            "actions": "",
            "realtime_schedule": True,
        },
        {
            # A spelling neither rendering uses, so the unreadable path is
            # exercised rather than being a shipped-but-never-run branch.
            "name": "Unreadable state search",
            "_app": "search",
            "_owner": "nobody",
            "search": "index=main | head 1",
            "description": "",
            "is_scheduled": "inherit",
            "disabled": "maybe",
            "cron_schedule": "0 5 * * *",
            "next_scheduled_time": "",
            "alert_type": "always",
            "alert.severity": 3,
            "alert.track": False,
            "actions": "",
            "realtime_schedule": True,
        },
    ]


def _roles() -> List[Dict[str, Any]]:
    """
    Shaped like a real Splunk Enterprise 10.4.2, including the two shapes that
    make a naive reading wrong:

    - **`splunk-system-role` holds `admin_all_objects` with ZERO direct
      capabilities** — all 194 of them arrive through `imported_roles: [admin]`.
      A fetcher reading `capabilities` alone reports a full-administrator role as
      holding nothing. This is stock configuration, not a contrived case.
    - **`srchIndexesAllowed: ["*"]` does not reach `_audit`.** Splunk's `*`
      matches non-internal indexes only. `admin` is granted `["*", "_*"]` and
      `data_management_admin` names `_audit` explicitly — both redundant if `*`
      already covered them.
    """
    return [
        {
            "name": "admin",
            "capabilities": ["admin_all_objects", "edit_user", "edit_roles",
                             "edit_indexes", "list_indexes", "search"],
            "imported_capabilities": ["accelerate_search", "change_own_password"],
            "imported_roles": ["power", "user"],
            "srchIndexesAllowed": ["*", "_*"],
            "imported_srchIndexesAllowed": ["*"],
            "srchFilter": "*",
        },
        {
            # Administrative purely by inheritance: its own list is empty.
            "name": "splunk-system-role",
            "capabilities": [],
            "imported_capabilities": ["admin_all_objects", "edit_user", "search"],
            "imported_roles": ["admin"],
            "srchIndexesAllowed": [],
            "imported_srchIndexesAllowed": ["*", "_*"],
            "srchFilter": "",
        },
        {
            # Names the audit index explicitly — can read it without `_*`.
            "name": "data_management_admin",
            "capabilities": ["list_indexes", "search"],
            "imported_capabilities": ["change_own_password"],
            "imported_roles": ["user"],
            "srchIndexesAllowed": ["*", "_audit", "_internal"],
            "imported_srchIndexesAllowed": ["*"],
            "srchFilter": "",
        },
        {
            # `*` only. Cannot reach _audit — the case a naive check inverts.
            "name": "power",
            "capabilities": ["accelerate_search", "schedule_search", "search"],
            "imported_capabilities": ["change_own_password"],
            "imported_roles": ["user"],
            "srchIndexesAllowed": ["*"],
            "imported_srchIndexesAllowed": ["*"],
            "srchFilter": "",
        },
        {
            "name": "user",
            "capabilities": ["change_own_password", "search"],
            "imported_capabilities": [],
            "imported_roles": [],
            "srchIndexesAllowed": ["*"],
            "imported_srchIndexesAllowed": [],
            "srchFilter": "",
        },
        {
            # No index access at all — a role that can log in and see nothing.
            "name": "can_delete",
            "capabilities": ["delete_by_keyword"],
            "imported_capabilities": [],
            "imported_roles": [],
            "srchIndexesAllowed": [],
            "imported_srchIndexesAllowed": [],
            "srchFilter": "",
        },
    ]


def _users() -> List[Dict[str, Any]]:
    """
    `type` is "Splunk" for an account defined in Splunk itself and LDAP/SAML for
    a federated one. Local accounts bypass whatever SSO is configured, which is
    why they are counted separately.

    `last_successful_login` is an epoch int, and **absent entirely** on an
    account that has never logged in — not zero, not null. That distinction is
    the difference between "went quiet" and "was never used".
    """
    return [
        {
            "name": "admin",
            "realname": "Administrator",
            "email": "admin@example.com",
            "roles": ["admin"],
            "type": "Splunk",
            "capabilities": ["admin_all_objects", "edit_user", "search"],
            "locked-out": False,
            "last_successful_login": 1787703902,
            # A real /authentication/users record carries the account's masked
            # password and the owner's UI preferences alongside the fields this
            # category actually reads. Reproduced on one account so the suite
            # can prove they never reach the evidence payload.
            "password": "********",
            "tz": "",
            "lang": "",
            "theme": "default_system_theme",
            "search_assistant": "compact",
            "search_syntax_highlighting": "default-system-theme",
            "defaultApp": "launcher",
        },
        {
            # Federated through SAML, and recently active.
            "name": "soc.analyst",
            "realname": "SOC Analyst",
            "email": "soc@example.com",
            "roles": ["power"],
            "type": "SAML",
            "capabilities": ["search", "schedule_search"],
            "locked-out": False,
            "last_successful_login": 1787600000,
        },
        {
            # Provisioned and never used. Different finding from dormant.
            "name": "contractor.temp",
            "realname": "Temporary Contractor",
            "email": "temp@example.com",
            "roles": ["user"],
            "type": "Splunk",
            "capabilities": ["search"],
            "locked-out": False,
        },
        {
            # Locked out, and holding an administrative role.
            "name": "former.admin",
            "realname": "Former Administrator",
            "email": "former@example.com",
            "roles": ["admin"],
            "type": "Splunk",
            "capabilities": ["admin_all_objects", "search"],
            "locked-out": True,
            "last_successful_login": 1700000000,
        },
        {
            # No role at all: can authenticate, can reach nothing.
            "name": "orphaned.account",
            "realname": "",
            "email": "",
            "roles": [],
            "type": "Splunk",
            "capabilities": [],
            "locked-out": False,
            "last_successful_login": 1787700000,
        },
    ]


def _fired_alerts() -> List[Dict[str, Any]]:
    """
    The per-saved-search view, shaped like a real Splunk 10.4.2.

    **Includes the rollup entry named `-`**, which carries the total across
    every alert. It is not a saved search — counting it as one double-counts
    every firing and invents an alert called `-`. It is here precisely so a
    fetcher that fails to exclude it fails a test.
    """
    return [
        {"name": "-", "triggered_alert_count": 4},
        {"name": "Failed authentication review - hourly",
         "triggered_alert_count": 3, "is_streaming_alert": False},
        {"name": "Weekly access review digest",
         "triggered_alert_count": 1, "is_streaming_alert": False},
    ]


def _firings(saved_search: str) -> List[Dict[str, Any]]:
    """
    Individual triggered-alert instances for one saved search.

    `severity` is an int on the wire. `expiration_time_rendered` is why this
    whole evidence set is a rolling window: Splunk deletes the record at that
    time, 24 hours after firing by default.
    """
    catalog = {
        "Failed authentication review - hourly": [
            (5, "2026-08-25 18:33:01 MDT", "2026-08-26 18:33:01 MDT"),
            (5, "2026-08-25 17:33:01 MDT", "2026-08-26 17:33:01 MDT"),
            (4, "2026-08-25 12:33:01 MDT", "2026-08-26 12:33:01 MDT"),
        ],
        "Weekly access review digest": [
            # A severity outside Splunk's documented 1-6 scale, so the
            # unknown-<n> path is exercised rather than being folded into a
            # band it does not belong to.
            (9, "2026-08-25 06:00:00 MDT", "2026-08-26 06:00:00 MDT"),
        ],
    }
    out = []
    for i, (sev, fired, expires) in enumerate(catalog.get(saved_search, [])):
        out.append({
            "name": f"admin__admin__search__RMD5{saved_search[:6]}_{i}",
            "savedsearch_name": saved_search,
            "severity": sev,
            "trigger_time": 1787704381 - i * 3600,
            "trigger_time_rendered": fired,
            "expiration_time_rendered": expires,
            "alert_type": "historical",
            "digest_mode": True,
            "triggered_alerts": 1,
            "sid": f"scheduler__admin__search__RMD5_{i}",
        })
    return out


def _entry(record: Dict[str, Any], collection: str = "data/indexes") -> Dict[str, Any]:
    """
    Wrap a flat record in Splunk's Atom-derived JSON entry shape.

    `_app` / `_owner` are the mock's own convention for setting the acl on a
    per-record basis — saved searches spread across six apps on a real install
    and `by_app` / `by_owner` are read straight off that.
    """
    name = record.get("name")
    content = {k: v for k, v in record.items() if k not in ("name", "_app", "_owner")}
    return {
        "name": name,
        "id": f"https://mock-splunk:8089/services/{collection}/{name}",
        "updated": "2026-08-24T18:23:00+00:00",
        "links": {"alternate": f"/services/{collection}/{name}"},
        "author": record.get("_owner", "nobody"),
        "acl": {
            "app": record.get("_app", "search"),
            "can_list": True,
            "can_write": True,
            "modifiable": False,
            "owner": record.get("_owner", "nobody"),
            "perms": {"read": ["*"], "write": ["admin"]},
            "removable": False,
            "sharing": "app",
        },
        "content": content,
    }


def collection(entries: List[Dict[str, Any]], offset: int, total: int) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "links": {},
        "origin": "https://mock-splunk:8089/services",
        "updated": "2026-08-24T18:23:00+00:00",
        "generator": {"build": "33c3bf42cd73", "version": "10.4.2"},
        "entry": entries,
        "paging": {"total": total, "perPage": len(entries), "offset": offset},
        "messages": [],
    }
    if os.environ.get("SPLUNK_MOCK_MESSAGES", "").strip() == "1":
        body["messages"] = [
            {
                "type": "WARN",
                "text": "Search peer idx-02 did not respond; results may be incomplete",
            }
        ]
    return body


class SplunkMockHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # keep test output readable
        pass

    # --- plumbing ---------------------------------------------------------

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, text: str) -> None:
        self._send(status, {"messages": [{"type": "ERROR", "text": text}]})

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        return header in (f"Bearer {VALID_TOKEN}", f"Splunk {SESSION_KEY}")

    def _fault(self, path: str) -> bool:
        """Apply the injected faults. True when a response was already sent."""
        forbid = os.environ.get("SPLUNK_MOCK_FORBID", "").strip()
        if forbid and path == forbid:
            self._error(
                403,
                "You (user=admin) do not have permission to perform this "
                "operation (requires capability: list_indexes)",
            )
            return True

        limit = _env_int("SPLUNK_MOCK_RATE_LIMIT")
        if limit:
            _CALLS[path] += 1
            if _CALLS[path] <= limit:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
                return True
        return False

    # --- routes -----------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/services/auth/login":
            self._error(404, f"no mock route for POST {parsed.path}")
            return

        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode() if length else "")
        username = (form.get("username") or [""])[0]
        password = (form.get("password") or [""])[0]

        if username != VALID_USERNAME or password != VALID_PASSWORD:
            self._error(401, "Login failed")
            return
        self._send(200, {"sessionKey": SESSION_KEY, "message": "", "code": ""})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not self._authorized():
            self._error(401, "Unauthorized")
            return
        if self._fault(path):
            return

        if path == "/services/server/info":
            self._send(200, collection([_entry({"name": "mock-splunk", **_server_info()})], 0, 1))
            return

        # The namespace matters, and only here. `/services/saved/searches` is
        # scoped to the caller's app context and returns a fraction of the
        # deployment's searches — 11 of 177 on the instance this was built
        # against. The wildcard namespace returns all of them. The mock serves
        # both, and serves the scoped one *short*, so a fetcher using the wrong
        # path fails a test rather than silently under-collecting.
        if path in ("/servicesNS/-/-/saved/searches", "/services/saved/searches"):
            records = _saved_searches()
            if path == "/services/saved/searches":
                records = [r for r in records if r.get("_app") == "search"]
            count = int((query.get("count") or ["30"])[0])
            offset = int((query.get("offset") or ["0"])[0])
            cap = _env_int("SPLUNK_MOCK_PAGE_SIZE")
            if cap:
                count = min(count, cap)
            page = records[offset : offset + count] if count else records[offset:]
            self._send(200, collection(
                [_entry(r, "saved/searches") for r in page], offset, len(records)))
            return

        if path.startswith("/servicesNS/-/-/alerts/fired_alerts"):
            from urllib.parse import unquote  # noqa: PLC0415
            tail = path[len("/servicesNS/-/-/alerts/fired_alerts"):].strip("/")
            records = _firings(unquote(tail)) if tail else _fired_alerts()
        elif path in ("/servicesNS/-/-/authentication/users",
                    "/services/authentication/users"):
            records = _users()
        elif path in ("/servicesNS/-/-/authorization/roles",
                      "/services/authorization/roles"):
            records = _roles()
        else:
            records = None

        if records is not None:
            count = int((query.get("count") or ["30"])[0])
            offset = int((query.get("offset") or ["0"])[0])
            cap = _env_int("SPLUNK_MOCK_PAGE_SIZE")
            if cap:
                count = min(count, cap)
            page = records[offset : offset + count] if count else records[offset:]
            coll = path.rsplit("/", 2)
            self._send(200, collection(
                [_entry(r, "/".join(coll[-2:])) for r in page], offset, len(records)))
            return

        if path == "/services/data/indexes":
            records = _indexes()
            count = int((query.get("count") or ["30"])[0])
            offset = int((query.get("offset") or ["0"])[0])

            cap = _env_int("SPLUNK_MOCK_PAGE_SIZE")
            if cap:
                count = min(count, cap)

            page = records[offset : offset + count] if count else records[offset:]
            self._send(200, collection([_entry(r) for r in page], offset, len(records)))
            return

        self._error(404, f"no mock route for GET {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Splunk management API for fetcher development")
    parser.add_argument("--port", type=int, default=8089)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    # ThreadingHTTPServer, not HTTPServer.
    #
    # HTTP/1.1 keep-alive holds a client's connection open after its response.
    # A single-threaded accept loop is then still blocked on that idle socket
    # when the next client arrives, so the second connection waits until
    # something times out. The test suite has always bound a threading server
    # for this reason; the standalone one did not, and running several fetchers
    # in sequence through `paramify run` hung two of them for 30 and 45 seconds
    # before failing with no evidence file at all.
    #
    # The symptom is indistinguishable from a broken fetcher, which is what
    # makes it worth a comment rather than a one-word change.
    server = ThreadingHTTPServer((args.host, args.port), SplunkMockHandler)
    print(f"Mock Splunk management API listening on http://{args.host}:{args.port}")
    print(f"  SPLUNK_BASE_URL=http://{args.host}:{args.port}")
    print(f"  SPLUNK_USERNAME={VALID_USERNAME}")
    print(f"  SPLUNK_PASSWORD={VALID_PASSWORD}")
    print(f"  SPLUNK_TOKEN={VALID_TOKEN}   (either works)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping mock Splunk API")
        server.server_close()


if __name__ == "__main__":
    main()
