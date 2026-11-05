#!/usr/bin/env python3
"""Control-plane changes in one subscription, each attributed to a pipeline or ARM deployment, a manual deployment, or a direct edit."""

import json
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from azure_common import (  # noqa: E402
    Collector,
    arm_client_kwargs,
    basename,
    build_payload,
    classify_failure_code,
    coverage_percentage,
    failure_reason,
    model_attr,
    report_failure,
    resolve_subscription,
    resource_group_from_id,
    sanitize_for_filename,
    sorted_counts,
    write_evidence,
)
from azure_rest import parse_time, pinned_credential  # noqa: E402
from resource_exclusions import ResourceExclusions  # noqa: E402
from resource_graph import query_all, resource_graph_client  # noqa: E402
from scope_exclusions import excluded_item, parse_patterns  # noqa: E402

logger = logging.getLogger("azure_change_provenance")

MAX_LOOKBACK_DAYS = 14
DEPLOYMENT_HISTORY_CAP = 800
# Measured: Resource Graph keeps restamping a change for hours (10 minutes after the operation within 12 hours).
WINDOW_SLACK = timedelta(minutes=10)
CHANGE_TABLES = ("resourcechanges", "resourcecontainerchanges")
# The Portal's create wizards name their deployments Microsoft.Web-WebApp-Portal-…, Microsoft.Template-…, CreateVm-….
PORTAL_DEPLOYMENT = re.compile(r"^(microsoft\.|createvm-)|-portal-", re.IGNORECASE)

CHANGE_COLUMNS = (
    " | where todatetime(properties.changeAttributes.timestamp) > ago({days}d)"
    " | project changeId = tostring(id),"
    " targetResourceId = tostring(properties.targetResourceId),"
    " targetResourceType = tostring(properties.targetResourceType),"
    " changeType = tostring(properties.changeType),"
    " timestamp = tostring(properties.changeAttributes.timestamp),"
    " changedBy = tostring(properties.changeAttributes.changedBy),"
    " changedByType = tostring(properties.changeAttributes.changedByType),"
    " clientType = tostring(properties.changeAttributes.clientType),"
    " operation = tostring(properties.changeAttributes.operation),"
    " correlationId = tostring(properties.changeAttributes.correlationId),"
    " changesCount = toint(properties.changeAttributes.changesCount),"
    " changedProperties = bag_keys(properties.changes),"
    " changes = properties.changes"
    " | order by changeId asc"
)

# Values are kept for these origins only, on at most MAX_VALUE_CHANGES of them a run (newest first).
VALUE_ORIGINS = ("direct", "manual_deployment")
MAX_VALUE_CHANGES = 500
MAX_VALUES_PER_CHANGE = 25
MAX_VALUE_CHARS = 200
WITHHELD_REASONS = ("not_allowlisted", "secret")
# Paths (lower case, array indexes as [*]) whose values are shown; value_paths adds path:<glob> patterns.
VALUE_PATHS = (
    "location", "kind", "sku.*", "identity.type", "zones[*]", "tags.*",
    "properties.provisioningstate", "properties.state", "properties.status", "properties.enabled",
    "properties.publicnetworkaccess", "properties.minimumtlsversion", "properties.mintlsversion",
    "properties.minimaltlsversion", "properties.httpsonly", "properties.supportshttpstrafficonly",
    "properties.enablehttpstrafficonly", "properties.allowblobpublicaccess", "properties.allowsharedkeyaccess",
    "properties.allowcrosstenantreplication", "properties.defaulttooauthauthentication", "properties.disablelocalauth",
    "properties.enablesoftdelete", "properties.softdeleteretentionindays", "properties.enablepurgeprotection",
    "properties.enablerbacauthorization", "properties.enabledfordeployment", "properties.enabledfortemplatedeployment",
    "properties.enabledfordiskencryption", "properties.clientcertenabled", "properties.clientcertmode",
    "properties.restrictoutboundnetworkaccess", "properties.enforcementmode", "properties.retentionindays",
    "properties.retentiondays", "properties.startipaddress", "properties.endipaddress",
    "properties.siteconfig.mintlsversion", "properties.siteconfig.scmmintlsversion", "properties.siteconfig.ftpsstate",
    "properties.siteconfig.http20enabled", "properties.siteconfig.remotedebuggingenabled",
    "properties.siteconfig.ipsecurityrestrictions[*].*", "properties.siteconfig.scmipsecurityrestrictions[*].*",
    "properties.networkacls.*", "properties.securityrules[*].properties.*",
    "properties.accesspolicies[*].objectid", "properties.accesspolicies[*].tenantid",
    "properties.accesspolicies[*].permissions.*", "properties.encryption.*", "properties.securitysettings.*",
    "properties.retentionpolicy.*", "properties.deleteretentionpolicy.*", "properties.containerdeleteretentionpolicy.*",
)
# Path segments, lower case without _ - $ @, that name a secret or hold free-form content that can carry one.
SECRET_WORD = re.compile(
    r"password|passwd|passphrase|secret|token|apikey|credential|privatekey|connectionstring|sharedaccess|signature"
    r"|cookie|certificatedata|certificateblob|securevalue|securestring|protectedsettings|commandtoexecute"
    r"|customdata|environmentvariables|environmentsettings|appsettings|pfx|psk|passcode|keydata|keyvalue"
)
SECRET_SEGMENT = re.compile(
    r".*(key|keys|key\d+|pwd|pw|pin|uri|url)|(?!bypass$).*pass|sas.*|authorization|authentication|headers|queries"
    r"|body|env|secrets|args|command"
)
# Key Vault access-policy permission lists (permissions.keys[n], permissions.secrets[n]) hold permission names.
PERMISSION_LIST = re.compile(r"\.permissions\.\w+\[\*\]$")
_SECRET_NAME = (
    r"password|passwd|passphrase|pwd|pass|secret|token|api[_-]?key|access[_-]?key|account[_-]?key"
    r"|sharedaccesskey|sharedaccesssignature|instrumentationkey|subscription[_-]key|functions[_-]key"
    r"|credential|sig|code|key|auth"
)
SECRET_VALUE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)"
    r"|\beyJ[\w-]{8,}\.[\w-]{8,}"
    r"|://[^/\s@]+@"
    rf"|({_SECRET_NAME}|pin|pw)[\"']?\s*[=:]"
    rf"|--?[\w-]*({_SECRET_NAME})[\w-]*(\s+|=)\S"
    r"|\b(basic|bearer|digest|negotiate)\s+[\w.~+/=-]{6,}",
    re.IGNORECASE,
)
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_KEBAB = re.compile(r"[a-z0-9]+(-[a-z0-9]+)+")
_ARM_PATH = re.compile(r"/(subscriptions|resourcegroups|providers)/", re.IGNORECASE)
_ARM_ID = re.compile(r"/(subscriptions|providers)/[^?#=&\s]*", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}([T ][\d:.]+)?(Z|[+-]\d{2}:?\d{2})?")
_INDEX = re.compile(r"\[\d+\]")

_DURATION = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?)?$")


def parse_duration(value):
    match = _DURATION.match(str(value or ""))
    if not match or not any(match.groups()):
        return None
    days, hours, minutes, seconds = match.groups()
    return timedelta(
        days=int(days or 0), hours=int(hours or 0), minutes=int(minutes or 0), seconds=float(seconds or 0)
    )


def iso(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def deployment_record(deployment, scope: str) -> dict:
    props = model_attr(deployment, "properties")
    finished = parse_time(model_attr(props, "timestamp"))
    duration = parse_duration(model_attr(props, "duration"))
    link = model_attr(props, "template_link")
    outputs = model_attr(props, "output_resources") or []
    return {
        "id": model_attr(deployment, "id"),
        "name": model_attr(deployment, "name"),
        "scope": scope,
        "resource_group": resource_group_from_id(model_attr(deployment, "id")),
        "provisioning_state": model_attr(props, "provisioning_state"),
        "started": iso(finished - duration) if finished and duration is not None else None,
        "timestamp": iso(finished),
        "duration": model_attr(props, "duration"),
        "correlation_id": model_attr(props, "correlation_id") or None,
        "mode": model_attr(props, "mode"),
        "template_hash": model_attr(props, "template_hash"),
        "template_link": model_attr(link, "uri") if link else None,
        "output_resource_ids": sorted({model_attr(r, "id") for r in outputs if model_attr(r, "id")}),
    }


def normalize_path(path) -> str:
    return _INDEX.sub("[*]", str(path).strip().lower())


class ValuePaths:
    """The built-in allowlist plus the value_paths path:<glob> patterns (* any run, ? one character)."""

    ENV = "AZURE_CHANGE_VALUE_PATHS"

    def __init__(self, patterns=()):
        self.extra, self.invalid = [], []
        for p in patterns:
            kind, sep, glob = p.partition(":")
            ok = sep and kind.strip().lower() == "path" and glob.strip()
            (self.extra if ok else self.invalid).append(p)
        globs = [*VALUE_PATHS, *(normalize_path(p.partition(":")[2]) for p in self.extra)]
        self._globs = re.compile("|".join(re.escape(g).replace(r"\*", ".*").replace(r"\?", ".") for g in globs))

    @classmethod
    def from_env(cls) -> "ValuePaths":
        return cls(parse_patterns(os.environ.get(cls.ENV)))

    def record_invalid(self, collector) -> None:
        for pattern in self.invalid:
            collector.record(f"config {self.ENV}", ValueError(
                f"invalid setting value_paths pattern {pattern!r}: write path: and a property path glob after it"))

    def allows(self, path: str) -> bool:
        return bool(self._globs.fullmatch(normalize_path(path)))


def secret_name(path: str) -> bool:
    """Whether any segment of the path names a secret or free-form content, such as api_key, env or headers."""
    norm = normalize_path(path)
    if norm == "properties.value":
        return True
    segments = norm.split(".")
    if PERMISSION_LIST.search(norm):
        segments = segments[:-1]
    for segment in segments:
        word = re.sub(r"\[\*\]|[_\-$@]", "", segment)
        if SECRET_WORD.search(word) or SECRET_SEGMENT.fullmatch(word):
            return True
    return False


def random_token(token: str) -> bool:
    """A short secret: three or more character classes that keep switching, unlike names, ids and dates."""
    if len(token) < 12 or any(p.fullmatch(token) for p in (_GUID, _EMAIL, _ISO_TIME)) or _ARM_ID.fullmatch(token):
        return False
    kinds = [0 if c.isupper() else 1 if c.islower() else 2 if c.isdigit() else 3 for c in token]
    if len(set(kinds)) < 3:
        return False
    return sum(a != b for a, b in zip(kinds, kinds[1:])) / (len(kinds) - 1) >= 0.4


def looks_secret(value: str) -> bool:
    # Read URL-decoded too, so password%3D… is caught like password=….
    return any(_looks_secret(v) for v in {value, unquote(value)})


def _looks_secret(value: str) -> bool:
    # A secret named anywhere in the text, such as "name: DB_PASSWORD" or "Password123!", withholds it.
    if SECRET_VALUE.search(value) or SECRET_WORD.search(re.sub(r"[_\-$@]", "", value.lower())):
        return True
    # An object or array value is read as paths too, so {"password": …} is caught by its key.
    if (value.lstrip()[:1] in ("{", "[") or "{" in value) and secret_name(re.sub(r"[^a-z0-9_\-]+", ".", value.lower())):
        return True
    if _ARM_ID.fullmatch(value):
        return False
    if any(random_token(t) for t in value.split()):
        return True
    for run in LONG_TOKEN.findall(value):
        if _GUID.fullmatch(run) or _KEBAB.fullmatch(run) or run.isdigit() or _ARM_PATH.search(run):
            continue
        if any(c.isalpha() for c in run) and any(c.isdigit() or c in "+/=" for c in run):
            return True
    return False


def withheld_reason(path: str, before, after, paths: ValuePaths):
    """The secret check runs first on every path, whatever the allowlist says; a boolean is never a secret."""
    values = [v for v in (before, after) if v is not None]
    boolean = all(v.lower() in ("true", "false") for v in values)
    if (secret_name(path) and not boolean) or any(looks_secret(v) for v in values):
        return "secret"
    return None if paths.allows(path) else "not_allowlisted"


def _text(value):
    return value if value is None or isinstance(value, str) else json.dumps(value, sort_keys=True)


def property_changes(raw, changed, paths: ValuePaths):
    """(entries, truncated, counts): each changed property's values, or its path and why they were withheld, shown
    values first; counts cover every changed property. All three are None when properties changed but the values
    couldn't be read."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = False
    if raw is None or raw == {}:
        return (None, None, None) if changed else ([], False, {"shown": 0, **dict.fromkeys(WITHHELD_REASONS, 0)})
    if not isinstance(raw, dict) or not all(isinstance(d, dict) for d in raw.values()):
        return None, None, None
    counts = {"shown": 0, **dict.fromkeys(WITHHELD_REASONS, 0)}
    entries = []
    for path, detail in raw.items():
        before, after = _text(detail.get("previousValue")), _text(detail.get("newValue"))
        reason = withheld_reason(str(path), before, after, paths)
        counts[reason or "shown"] += 1
        if reason:
            entries.append({"path": str(path), "withheld": reason})
            continue
        cut = str(detail.get("isTruncated") or "").lower() == "true" or any(
            v is not None and len(v) > MAX_VALUE_CHARS for v in (before, after))
        before, after = (v if v is None else v[:MAX_VALUE_CHARS] for v in (before, after))
        entries.append({"path": str(path), "previous_value": before, "new_value": after, "truncated": cut,
                        "withheld": None})
    entries.sort(key=lambda e: (e["withheld"] is not None, e["path"]))
    return entries[:MAX_VALUES_PER_CHANGE], len(entries) > MAX_VALUES_PER_CHANGE, counts


def change_record(row: dict, table: str, paths: ValuePaths = None) -> dict:
    props = row.get("changedProperties")
    values, values_cut, counts = property_changes(row.get("changes"), props, paths or ValuePaths())
    return {
        "change_id": row.get("changeId") or None,
        "table": table,
        "target_resource_id": row.get("targetResourceId") or None,
        "target_resource_type": row.get("targetResourceType") or None,
        "resource_group": resource_group_from_id(row.get("targetResourceId")),
        "change_type": row.get("changeType") or None,
        "timestamp": row.get("timestamp") or None,
        "changed_by": row.get("changedBy") or None,
        "changed_by_type": row.get("changedByType") or None,
        "client_type": row.get("clientType") or None,
        "operation": row.get("operation") or None,
        "correlation_id": row.get("correlationId") or None,
        "changes_count": row.get("changesCount"),
        "changed_properties": sorted(props) if isinstance(props, list) else [],
        "property_changes": values,
        "property_changes_truncated": values_cut,
        "property_value_counts": counts,
    }


def keep_values(changes: list, limit: int) -> list:
    """Values stay on the newest `limit` direct and manual-deployment changes; every other change carries none."""
    eligible = sorted((c for c in changes if c["origin"] in VALUE_ORIGINS),
                      key=lambda c: (c["timestamp"] or "", c["change_id"] or ""), reverse=True)
    kept = {id(c) for c in eligible[:limit]}
    capped = {id(c) for c in eligible[limit:]}
    out = []
    for c in changes:
        if id(c) in kept:
            # As read: null, not empty, when the values couldn't be read.
            out.append({**c, "property_changes": c.get("property_changes"),
                        "property_changes_truncated": c.get("property_changes_truncated"),
                        "property_value_counts": c.get("property_value_counts")})
        else:
            out.append({**c, "property_changes": None, "property_value_counts": None,
                        "property_changes_truncated": True if id(c) in capped else None})
    return out


def pipeline_principals() -> set:
    raw = os.environ.get("AZURE_PIPELINE_PRINCIPALS") or ""
    return {p.strip().lower() for p in raw.split(",") if p.strip()}


def anonymous(change: dict) -> bool:
    who = {(change["changed_by"] or "").lower(), (change["changed_by_type"] or "").lower()}
    return not change["changed_by"] or bool(who & {"system", "unspecified"})


def deployment_origin(change: dict, deployment: dict, pipelines: frozenset) -> str:
    """A deployment run by a pipeline identity or an application, or a manual one run by a person or the Portal."""
    if (change["changed_by"] or "").lower() in pipelines:
        return "deployment"
    by_person = (change["changed_by_type"] or "").lower() == "user"
    from_portal = (change["client_type"] or "").lower() == "azure portal" or bool(
        PORTAL_DEPLOYMENT.search(deployment["name"] or "")
    )
    return "manual_deployment" if by_person or from_portal else "deployment"


def attribute(changes: list, deployments: list, pipelines: frozenset = frozenset()) -> list:
    """Mark each change as made by a deployment, a manual deployment, a pipeline identity, the platform, or directly."""
    by_correlation = {d["correlation_id"].lower(): d for d in deployments if d["correlation_id"]}
    by_output: dict = {}
    for d in deployments:
        for rid in d["output_resource_ids"]:
            by_output.setdefault(rid.lower(), []).append(d)

    def own(change):
        deployment = by_correlation.get((change["correlation_id"] or "").lower())
        if deployment:
            return deployment_origin(change, deployment, pipelines), "correlation_id", deployment
        if (change["changed_by"] or "").lower() in pipelines:
            return "pipeline", None, None
        return "direct", None, None

    named = [c for c in changes if not anonymous(c)]
    verdicts = {c["change_id"]: own(c) for c in named}
    named_by_target: dict = {}
    run_as: dict = {}
    for c in named:
        named_by_target.setdefault((c["target_resource_id"] or "").lower(), []).append(c)
        origin, _, d = verdicts[c["change_id"]]
        if d:
            run_as.setdefault(d["id"], set()).add(origin)

    def window_origin(d):
        seen = run_as.get(d["id"])
        if seen:
            return "manual_deployment" if "manual_deployment" in seen else "deployment"
        return "manual_deployment" if PORTAL_DEPLOYMENT.search(d["name"] or "") else "deployment"

    # Measured: callerless rows reuse unrelated correlationIds, so they take the nearest named change to the resource.
    def inherited(change):
        target = (change["target_resource_id"] or "").lower()
        when = parse_time(change["timestamp"])
        near = [
            (abs(parse_time(c["timestamp"]) - when), c)
            for c in named_by_target.get(target, [])
            if when and parse_time(c["timestamp"])
        ]
        near = [n for n in near if n[0] <= WINDOW_SLACK]
        if near:
            origin, _, d = verdicts[min(near, key=lambda n: n[0])[1]["change_id"]]
            return origin, "same_resource", d
        for d in by_output.get(target, []):
            start, end = parse_time(d["started"]), parse_time(d["timestamp"])
            if when and start and end and start - WINDOW_SLACK <= when <= end + WINDOW_SLACK:
                return window_origin(d), "deployment_window", d
        if "system" in ((change["changed_by_type"] or "").lower(), (change["changed_by"] or "").lower()):
            return "platform", None, None
        return "unattributed", None, None

    attributed = []
    for change in changes:
        origin, how, found = inherited(change) if anonymous(change) else verdicts[change["change_id"]]
        attributed.append({
            **change,
            "origin": origin,
            "via_deployment": found is not None,
            "attribution": how,
            "deployment_id": found["id"] if found else None,
        })
    return sorted(attributed, key=lambda c: (c["timestamp"] or "", c["change_id"] or ""))


def deployment_runs(deployments: list, changes: list) -> list:
    """Each deployment with who ran it and its origin, read from the changes it matched by correlationId."""
    matched: dict = {}
    for c in changes:
        if c["attribution"] == "correlation_id":
            matched.setdefault(c["deployment_id"], []).append(c)
    runs = []
    for d in deployments:
        mine = matched.get(d["id"], [])
        origins = {c["origin"] for c in mine}
        runs.append({
            **d,
            "run_by": sorted({c["changed_by"] for c in mine if c["changed_by"]}),
            "origin": ("manual_deployment" if "manual_deployment" in origins else "deployment") if origins else None,
        })
    return runs


def split_changes(changes: list, exclusions: ResourceExclusions) -> tuple[list, list]:
    """A change follows its target resource or resource group; a change to the subscription itself never matches."""
    kept, excluded = [], []
    for change in changes:
        target = change["target_resource_id"]
        pattern = exclusions.match(target) if exclusions and target else None
        if pattern is None:
            kept.append(change)
        else:
            # Caller fields kept so azure_change_work_items can still lend an in-scope change this change's caller.
            excluded.append(excluded_item(
                "change", basename(change["change_id"]), pattern, "target_matched", id=change["change_id"],
                target_id=target, timestamp=change.get("timestamp"), changed_by=change.get("changed_by"),
                changed_by_type=change.get("changed_by_type"), deployment_id=change.get("deployment_id")))
    return kept, excluded


def value_summary(changes: list) -> dict:
    """Value counts over the direct and manual-deployment changes; shown and withheld are null when any of their
    values couldn't be read."""
    eligible = [c for c in changes if c["origin"] in VALUE_ORIGINS]
    read = [c for c in eligible if c.get("property_changes") is not None]
    capped = [c for c in eligible if c.get("property_changes") is None and c.get("property_changes_truncated")]
    unknown = len(eligible) - len(read) - len(capped)
    total = Counter()
    for c in read:
        total.update(c.get("property_value_counts") or {})
    return {
        "changes_with_property_values": len(read),
        "changes_property_values_capped": len(capped),
        "changes_property_values_unknown": unknown,
        "property_values_shown": None if unknown else total["shown"],
        "property_values_withheld_by_reason": None if unknown else {r: total[r] for r in WITHHELD_REASONS},
    }


def summarize(changes: list, deployments: list, at_cap: list, groups=None) -> dict:
    """`groups` is the lower-cased resource groups that still exist, or None when they could not be listed."""
    origins = Counter(c["origin"] for c in changes)
    direct = [c for c in changes if c["origin"] == "direct"]
    redeployed = origins["deployment"] + origins["pipeline"]
    outside = origins["direct"] + origins["manual_deployment"]
    return {
        "total_changes": len(changes),
        "changes_via_deployment": origins["deployment"],
        "changes_via_pipeline": origins["pipeline"],
        "manual_deployment_changes": origins["manual_deployment"],
        "direct_changes": origins["direct"],
        "platform_changes": origins["platform"],
        "unattributed_changes": origins["unattributed"],
        "percent_redeployed": coverage_percentage(redeployed, redeployed + outside),
        "percent_redeployed_conservative": coverage_percentage(
            redeployed, redeployed + outside + origins["unattributed"]
        ),
        "manual_deployment_changes_by_changed_by": sorted_counts(
            Counter(c["changed_by"] or "none" for c in changes if c["origin"] == "manual_deployment")
        ),
        "direct_changes_by_changed_by_type": sorted_counts(Counter(c["changed_by_type"] or "none" for c in direct)),
        "attribution_by_method": sorted_counts(Counter(c["attribution"] for c in changes if c["attribution"])),
        "direct_changes_by_client_type": sorted_counts(Counter(c["client_type"] or "none" for c in direct)),
        "direct_changes_by_changed_by": sorted_counts(Counter(c["changed_by"] or "none" for c in direct)),
        "direct_changes_by_resource_type": sorted_counts(
            Counter(c["target_resource_type"] or "unknown" for c in direct)
        ),
        "direct_changes_in_deleted_resource_groups": None if groups is None else sum(
            1 for c in direct if c["resource_group"] and c["resource_group"].lower() not in groups
        ),
        **value_summary(changes),
        "deployments_in_history": len(deployments),
        "deployments_matched_to_changes": len({c["deployment_id"] for c in changes if c["deployment_id"]}),
        "resource_groups_at_deployment_history_cap": at_cap,
    }


def lookback_days(collector: Collector) -> int:
    raw = os.environ.get("AZURE_CHANGE_LOOKBACK_DAYS") or str(MAX_LOOKBACK_DAYS)
    try:
        days = int(raw)
    except ValueError:
        collector.record(
            "config AZURE_CHANGE_LOOKBACK_DAYS",
            ValueError(f"invalid lookback {raw!r}: expected an integer from 1 to {MAX_LOOKBACK_DAYS}"),
        )
        return MAX_LOOKBACK_DAYS
    clamped = min(max(days, 1), MAX_LOOKBACK_DAYS)
    if clamped != days:
        logger.warning("AZURE_CHANGE_LOOKBACK_DAYS=%d is outside 1-%d; using %d", days, MAX_LOOKBACK_DAYS, clamped)
    return clamped


def max_value_changes(collector: Collector) -> int:
    """An invalid setting fails the run and keeps no values, rather than more than were asked for."""
    raw = (os.environ.get("AZURE_CHANGE_MAX_VALUE_CHANGES") or "").strip()
    if not raw:
        return MAX_VALUE_CHANGES
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value < 0:
        collector.record("config AZURE_CHANGE_MAX_VALUE_CHANGES", ValueError(
            f"invalid setting AZURE_CHANGE_MAX_VALUE_CHANGES={raw!r}: expected a whole number from 0; kept no values"))
        return 0
    return value


def collect_changes(subscription_id, cred, days: int, collector: Collector, paths: ValuePaths = None):
    paths = paths or ValuePaths.from_env()
    client = collector.guard("resourcegraph.ResourceGraphClient (init)", lambda: resource_graph_client(cred))
    if client is None:
        return [], {}
    changes, sources = [], {}
    for table in CHANGE_TABLES:
        query = table + CHANGE_COLUMNS.format(days=days)
        result = collector.guard(
            f"resourcegraph.resources ({table})", lambda q=query: query_all(client, subscription_id, q)
        )
        if result is None:
            continue
        sources[table] = {
            "query": query,
            "rows": len(result["rows"]),
            "total_records_reported": result["total_records"],
            "pages": result["pages"],
        }
        changes.extend(change_record(row, table, paths) for row in result["rows"])
    return changes, sources


def collect_deployments(subscription_id, cred, collector: Collector):
    def _clients():
        from azure.mgmt.resource.deployments import DeploymentsMgmtClient  # lazy

        try:
            from azure.mgmt.resource.resources import ResourceManagementClient  # lazy
        except ImportError:  # pragma: no cover - depends on installed SDK version
            from azure.mgmt.resource import ResourceManagementClient  # lazy

        return (
            DeploymentsMgmtClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
            ResourceManagementClient(credential=cred, subscription_id=subscription_id, **arm_client_kwargs()),
        )

    clients = collector.guard("deployments.DeploymentsMgmtClient (init)", _clients)
    if clients is None:
        return [], [], None
    deploy, resources = clients

    deployments = collector.guard(
        "deployments.list_at_subscription_scope",
        lambda: [deployment_record(d, "subscription") for d in deploy.deployments.list_at_subscription_scope()],
        default=[],
    )
    groups = collector.guard(
        "resource.resource_groups.list",
        lambda: sorted(model_attr(g, "name") for g in resources.resource_groups.list()),
    )
    at_cap = []
    for group in groups or []:
        rows = collector.guard(
            f"deployments.list_by_resource_group({group})",
            lambda g=group: [deployment_record(d, "resource_group") for d in deploy.deployments.list_by_resource_group(g)],
        )
        if rows is None:
            continue
        if len(rows) >= DEPLOYMENT_HISTORY_CAP:
            at_cap.append(group)
        deployments.extend(rows)
    return sorted(deployments, key=lambda d: d["id"] or ""), at_cap, groups


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("azure").setLevel(logging.WARNING)
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    days = lookback_days(collector)
    exclusions = ResourceExclusions.from_env()
    exclusions.record_invalid(collector)
    paths = ValuePaths.from_env()
    paths.record_invalid(collector)
    value_limit = max_value_changes(collector)
    # As with an invalid limit, a bad value_paths pattern keeps no values rather than guess at the list.
    if paths.invalid:
        value_limit = 0

    sub = resolve_subscription(collector)
    subscription_id = sub["subscription_id"]
    cred = collector.guard("azure.identity.DefaultAzureCredential", lambda: pinned_credential(subscription_id))

    changes, sources, deployments, at_cap, groups = [], {}, [], [], None
    if subscription_id and cred is not None:
        changes, sources = collect_changes(subscription_id, cred, days, collector, paths)
        deployments, at_cap, groups = collect_deployments(subscription_id, cred, collector)
    elif not subscription_id:
        collector.record(
            "resolve_subscription",
            RuntimeError(
                "no subscription id (set AZURE_SUBSCRIPTION_ID or configure an "
                "ambient Azure credential that can list subscriptions)"
            ),
        )

    pipelines = pipeline_principals()
    attributed = attribute(changes, deployments, frozenset(pipelines))
    # Attributed against every change and deployment first, so an in-scope change keeps an origin an excluded one gave.
    in_scope, excluded = split_changes(attributed, exclusions)
    in_scope = keep_values(in_scope, value_limit)
    exclusions.warn_unmatched(logger)
    existing = None if groups is None else {g.lower() for g in groups}
    counts = exclusions.summary(excluded, ("change",), {"changes": len(in_scope)})
    # Unknown, not none, when a change table wasn't read.
    if set(sources) != set(CHANGE_TABLES):
        counts.update(excluded_changes=None, in_scope_changes=None,
                      **dict.fromkeys(value_summary([]), None))
    evidence = build_payload(
        subscription_id=subscription_id,
        subscription_source=sub["subscription_source"],
        collector=collector,
        results={
            "changes": in_scope,
            "deployments": deployment_runs(deployments, attributed),
            "lookback_days": days,
            "pipeline_principals": sorted(pipelines),
            "property_value_paths_added": paths.extra,
            "max_property_value_changes": value_limit,
            "window_start": iso(datetime.now(timezone.utc) - timedelta(days=days)),
            "change_sources": sources,
            "resource_groups_read": len(groups or []),
            "excluded": excluded,
        },
        summary={
            **summarize(in_scope, deployments, at_cap, existing),
            **counts,
        },
    )

    filename = f"azure_change_provenance_{sanitize_for_filename(subscription_id or 'unknown')}.json"
    path = write_evidence(output_dir, filename, evidence)

    if not collector.ok:
        report_failure(failure_reason(collector.failures), classify_failure_code(collector.failures))
        return 1
    logger.info("Evidence saved to %s (%d changes, %d deployments)", path, len(in_scope), len(deployments))
    return 0


if __name__ == "__main__":
    sys.exit(main())
