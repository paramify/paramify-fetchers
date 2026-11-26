#!/usr/bin/env python3
"""Microsoft Defender for Cloud security assessment results for one subscription.

One record per (resource, check) pair — the per-resource pass/fail detail behind
the secure score. A subscription that never registered Microsoft.Security reports
`provider_registration_status: not_registered` and still exits 0 — "not enabled" is
a finding, not a broken run, matching azure_defender_plans.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

# Every azure/* fetcher shares one helper module instead of each reimplementing
# auth, retries, and output formatting. It isn't a normal importable package (no
# azure/_shared/__init__.py entry on the path by default), so we manually add
# fetchers/azure/_shared/ to sys.path before importing from it below.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,           # accumulates API failures without crashing the run
    build_payload,       # assembles the final evidence dict (metadata + results + summary)
    classify_failure_code,  # maps a failure onto a stable error "code" for the status file
    coverage_percentage,  # integer percentage helper, 0-safe on an empty denominator
    credential,            # returns azure.identity.DefaultAzureCredential()
    failure_reason,        # renders the Collector's failures into one status-file message
    resolve_subscription,  # figures out which subscription_id to collect from
    sanitize_for_filename,  # makes a subscription id safe to use in a filename
    write_evidence,        # writes the evidence dict to disk as JSON
    report_failure,        # logs the reason AND writes $FETCHER_STATUS_FILE
)
# The projection and collection live in _shared/defender.py, shared with azure_defender_sql_vulnerability_report.
from defender import (  # noqa: E402,F401 - project_assessment, _id_key, SEVERITY_QUERY, NOT_REGISTERED: tests
    FROM_CATALOGUE,
    NOT_REGISTERED,
    REGISTERED,
    SEVERITY_OPERATION,
    SEVERITY_QUERY,
    UNKNOWN,
    _id_key,
    collect_assessments,
    project_assessment,
)
from resource_exclusions import ResourceExclusions  # noqa: E402

logger = logging.getLogger("azure_defender_assessments")


# --- SLA age: days an Unhealthy assessment has been open, and whether that is past its severity's SLA ---

SEVERITIES = ("High", "Medium", "Low")
DEFAULT_SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}
SLA_ENV = {s: f"AZURE_DEFENDER_SLA_DAYS_{s.upper()}" for s in SEVERITIES}


def sla_days_from_env(collector: Optional[Collector] = None) -> dict:
    """SLA days per severity; a bad value is recorded and that severity's days are None (no default)."""
    days: dict = dict(DEFAULT_SLA_DAYS)
    for severity, env in SLA_ENV.items():
        raw = (os.environ.get(env) or "").strip()
        if not raw:
            continue
        if raw.isdecimal() and int(raw) > 0:
            days[severity] = int(raw)
            continue
        days[severity] = None
        if collector is not None:
            collector.record(f"config {env}", ValueError(f"invalid SLA days {raw!r}: needs a whole number above 0"))
    return days


def _parse_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment.astimezone(timezone.utc) if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def apply_sla(assessments: list[dict], sla_days: dict, now: datetime) -> None:
    """Set days_open, sla_days and past_sla on each record; only Unhealthy ones are aged, the rest are null."""
    for a in assessments:
        a["days_open"] = a["sla_days"] = a["past_sla"] = None
        if a.get("status_code") != "Unhealthy":
            continue
        changed = _parse_iso(a.get("status_change_date"))
        if changed is not None:
            a["days_open"] = max(0, (now - changed).days)
        a["sla_days"] = sla_days.get(a.get("severity"))
        if a["days_open"] is not None and a["sla_days"] is not None:
            a["past_sla"] = a["days_open"] > a["sla_days"]


def sla_summary(assessments: list[dict], sla_days: dict, list_read: bool, severity_read: bool = True) -> dict:
    """Unhealthy findings past SLA per severity and in total; a count is null when it can't be known.

    Every count is null when the list or the Resource Graph severity read failed, or any Unhealthy finding took
    its severity from the catalogue, which can rate a check lower than its assessment, so the finding may belong
    to any severity. A severity's count is also null when its SLA days are invalid or one of its Unhealthy
    findings has no date. The total is also null when an Unhealthy finding has no severity.
    """
    unhealthy = [a for a in assessments if a.get("status_code") == "Unhealthy"]
    readable = list_read and severity_read and not any(a.get("severity_source") == FROM_CATALOGUE for a in unhealthy)
    by_severity: dict = {}
    for severity in SEVERITIES:
        mine = [a for a in unhealthy if a.get("severity") == severity]
        known = readable and sla_days.get(severity) is not None and all(a.get("days_open") is not None for a in mine)
        by_severity[severity] = sum(1 for a in mine if a.get("past_sla")) if known else None
    total_known = (
        readable
        and all(v is not None for v in by_severity.values())
        and all(a.get("severity") in SEVERITIES for a in unhealthy)
    )
    return {
        "sla_days_by_severity": dict(sla_days),
        "unhealthy_past_sla_by_severity": by_severity,
        "unhealthy_past_sla_count": sum(by_severity.values()) if total_known else None,
        "unhealthy_days_open_unknown_count": (
            sum(1 for a in unhealthy if a.get("days_open") is None) if list_read else None
        ),
    }


# --- pure transform: flat dicts in, summary out ---
# No SDK objects touched here — just counting over the plain dicts project_assessment
# already produced. This is what makes `summarize` easy to unit-test on its own.

def summarize(assessments: list[dict], registration_status: str) -> dict:
    """Healthy/Unhealthy/NotApplicable counts are the headline — unhealthy is what needs fixing."""
    total = len(assessments)
    # Counter tallies how many records have each status_code value in one pass,
    # e.g. Counter({"Healthy": 40, "Unhealthy": 12, "NotApplicable": 3}).
    by_status = Counter(a["status_code"] for a in assessments)
    # Same idea, but scoped to only the failing checks, bucketed by severity —
    # this is what tells someone "how many High-severity things are broken".
    unhealthy_severities = Counter(
        a["severity"] for a in assessments if a["status_code"] == "Unhealthy" and a["severity"]
    )
    by_source = Counter(a.get("severity_source") for a in assessments)
    unhealthy_by_source = Counter(a.get("severity_source") for a in assessments if a["status_code"] == "Unhealthy")
    return {
        "provider_registration_status": registration_status,
        "total_assessments": total,
        "healthy_count": by_status.get("Healthy", 0),
        "unhealthy_count": by_status.get("Unhealthy", 0),
        "not_applicable_count": by_status.get("NotApplicable", 0),
        "healthy_percentage": coverage_percentage(by_status.get("Healthy", 0), total),
        "unhealthy_by_severity": dict(unhealthy_severities),
        # Records whose own severity was not found, so the catalogue's (possibly lower) one or none is used.
        "severity_from_catalogue_count": by_source.get(FROM_CATALOGUE, 0),
        "severity_unknown_count": by_source.get(None, 0),
        # The same for Unhealthy records only: an unknown one is missing from unhealthy_by_severity.
        "unhealthy_severity_from_catalogue_count": unhealthy_by_source.get(FROM_CATALOGUE, 0),
        "unhealthy_severity_unknown_count": unhealthy_by_source.get(None, 0),
    }


def main() -> int:
    # Standard logging setup — LOG_LEVEL is an env var the runner can override.
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # The azure-* SDKs log every HTTP request and response header at INFO, which would
    # bury this fetcher's own lines and dominate the runner's stderr tail.
    logging.getLogger("azure").setLevel(logging.WARNING)
    # Interim v0.x: the fetcher loads its own .env for local/manual runs. In
    # production the runner resolves secrets and injects them as real env vars
    # directly, so this is a no-op there.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    # One Collector instance tracks every API failure across this whole run —
    # it's threaded through resolve_subscription, credential(), and
    # collect_assessments below so failures from any of those three steps all
    # land in the same place.
    collector = Collector(logger)

    # Step 1: which subscription are we collecting from? Either an explicit
    # AZURE_SUBSCRIPTION_ID (set by the runner from a manifest target) or,
    # failing that, the first enabled subscription the ambient credential can see.
    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    # Step 2: get an Azure credential (DefaultAzureCredential — tries env vars,
    # managed identity, `az login` cache, etc., in order). collector.guard means
    # a bad/missing credential is recorded as a failure, not a crash.
    cred = collector.guard("azure.identity.DefaultAzureCredential", credential)
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)
    sla_days = sla_days_from_env(collector)

    assessments: list[dict] = []
    registration_status = UNKNOWN
    read = False
    if subscription_id and cred is not None:
        # Step 3: the actual API call + projection + sort, described above.
        assessments, registration_status = collect_assessments(subscription_id, cred, collector)
        read = registration_status == REGISTERED
    elif not subscription_id:
        # We never even got a subscription to try — record that explicitly so
        # the status file says WHY nothing was collected, instead of silently
        # writing an empty evidence file. Deliberately avoids the phrase "no
        # subscription": classify_failure_code (azure_common.py) ORs its message
        # markers across ALL accumulated failures, and "no subscription" is one
        # of its bad_config markers — if that phrase were present here, it would
        # win the classification even when the real, more specific cause is a
        # different recorded failure (e.g. a missing dependency, which has its
        # own internal_error classification that this text must not shadow).
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "could not resolve which Azure subscription to use (set "
                "AZURE_SUBSCRIPTION_ID or configure an ambient Azure credential "
                "that can list subscriptions)"
            ),
        )

    apply_sla(assessments, sla_days, datetime.now(timezone.utc))

    # An assessment follows the resource it is about; it carries no region, so location: patterns never match one.
    assessments, excluded = exclusions.split(
        assessments, "assessment", resource_id=lambda a: a["resource_id"],
        name=lambda a: a["display_name"] or a["name"])
    if not read:
        exclusions.mark_unread()
    exclusions.warn_unmatched(logger)

    # Step 4: assemble the raw evidence dict. build_payload wraps our
    # results/summary with the standard metadata block (subscription id, when
    # this ran, whether anything failed) — the runner then wraps THIS whole
    # dict again in its own envelope before it reaches Paramify.
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "assessments": assessments,
            # Also in results so a validator can assert the service is in use at all.
            "provider_registration_status": registration_status,
            "excluded": excluded,
        },
        summary={
            **summarize(assessments, registration_status),
            **sla_summary(
                assessments, sla_days, registration_status != UNKNOWN,
                not any(f["operation"] == SEVERITY_OPERATION for f in collector.failures),
            ),
            **exclusions.summary(excluded, ("assessment",), {"assessments": len(assessments) if registration_status != UNKNOWN else None}),
        },
    )

    # Step 5: write the evidence file. The subscription id is baked into the
    # filename because this fetcher fans out per-subscription (supports_targets:
    # true) — every target's run shares one output directory, so a fixed
    # filename would let each subscription's file overwrite the last.
    filename = f"azure_defender_assessments_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    # Step 6: decide the exit code. `collector.ok` is False if ANY step above
    # (resolve_subscription, credential(), or collect_assessments) recorded a
    # failure. On failure we still keep the evidence file we already wrote
    # (partial data can still be useful) but additionally report the failure and
    # exit 1, which is what the runner reads to mark this run as failed.
    #
    # report_failure is the WHOLE failure path: it logs the reason at error
    # level and writes $FETCHER_STATUS_FILE. Do not add a logger.error before
    # it — the reason would appear twice, and failure_reason() already opens
    # with the failure count.
    if not collector.ok:
        report_failure(
            failure_reason(collector.failures), classify_failure_code(collector.failures)
        )
        return 1
    # This INFO line must be the LAST thing logged on the success path: the
    # runner's fallback error reporting reads the TAIL of stderr, so if a
    # failure line were logged after this one, this "saved" message would win
    # and mask the real error.
    logger.info("Evidence saved to %s", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
