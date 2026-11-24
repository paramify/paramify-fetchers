"""Defender for Cloud vulnerability sub-assessments in Azure Resource Graph: the KQL and record shaping.

Shared by azure_defender_vulnerability_findings (evidence: counts per image and server plus a capped list) and
azure_defender_vulnerability_report (issue report: every open finding as one CSV row for a Paramify
vulnerability assessment), so both read the same findings the same way.

Field names were checked against a live tenant (2026-11-24): the current (MDVM) container schema keeps the
package under additionalData.softwareDetails.packageName, and the CVE under vulnerabilityDetails.cveId as well
as properties.id. No field records when a finding was first detected: properties.timeGenerated is rewritten on
every scan, vulnerabilityDetails.publishedDate is the CVE's publication date, and
artifactDetails.lastPushedToRegistryUTC is when the image was last pushed.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

CONTAINER_TYPES = ("AzureContainerRegistryVulnerability", "ContainerRegistryVulnerability")
SERVER_TYPES = ("ServerVulnerability",)
ALL_TYPES = CONTAINER_TYPES + SERVER_TYPES
SEVERITIES = ("Critical", "High", "Medium", "Low")


# Shared KQL prefix. `art` is the sub-assessment type; the rest coalesces the MDVM and
# legacy field names so one projection serves both schemas.
_BASE = """securityresources
| where type =~ "microsoft.security/assessments/subassessments"
| extend art = tostring(properties.additionalData.assessedResourceType)
| where art in~ ({types})
| extend assessmentKey = tolower(extract(@"(?i)providers/Microsoft.Security/assessments/([^/]*)", 1, id)),
         statusCode = tostring(properties.status.code),
         severity = tostring(properties.status.severity),
         resourceId = tolower(tostring(properties.resourceDetails.id)),
         parentAt = indexof(tolower(id), "/providers/microsoft.security/assessments/"),
         registry = coalesce(tostring(properties.additionalData.artifactDetails.registryHost), tostring(properties.additionalData.registryHost)),
         repository = coalesce(tostring(properties.additionalData.artifactDetails.repositoryName), tostring(properties.additionalData.repositoryName)),
         digest = coalesce(tostring(properties.additionalData.artifactDetails.digest), tostring(properties.additionalData.imageDigest)),
         fixedVersion = tostring(properties.additionalData.softwareDetails.fixedVersion),
         patchableRaw = tostring(properties.additionalData.patchable),
         publishedAt = coalesce(tostring(properties.additionalData.vulnerabilityDetails.publishedDate), tostring(properties.additionalData.publishedTime)),
         cvss = todouble(coalesce(properties.additionalData.cvssV30Score, properties.additionalData.cvss["3.0"].base, properties.additionalData.cvss["2.0"].base))
| extend patchable = case(patchableRaw =~ "true", "true", patchableRaw =~ "false", "false", isnotempty(fixedVersion), "true", ""),
         parentId = iff(parentAt > 0, tolower(substring(id, 0, parentAt)), "")
"""


def _types(types) -> str:
    return ", ".join(f'"{t}"' for t in types)


def totals_query() -> str:
    return _BASE.format(types=_types(ALL_TYPES)) + (
        "| summarize findings = count() by art, assessmentKey, statusCode, severity\n"
        "| extend id = strcat(art, '|', assessmentKey, '|', statusCode, '|', severity)\n"
        "| order by id asc"
    )


def images_query() -> str:
    return _BASE.format(types=_types(CONTAINER_TYPES)) + (
        "| summarize findings = count(), unhealthy = countif(statusCode =~ 'Unhealthy'),\n"
        "    critical = countif(statusCode =~ 'Unhealthy' and severity =~ 'Critical'),\n"
        "    high = countif(statusCode =~ 'Unhealthy' and severity =~ 'High'),\n"
        "    medium = countif(statusCode =~ 'Unhealthy' and severity =~ 'Medium'),\n"
        "    low = countif(statusCode =~ 'Unhealthy' and severity =~ 'Low'),\n"
        "    patchable_unhealthy = countif(statusCode =~ 'Unhealthy' and patchable == 'true'),\n"
        "    latest_scanned = max(todatetime(properties.timeGenerated)),\n"
        "    oldest_open_published = minif(todatetime(publishedAt), statusCode =~ 'Unhealthy'),\n"
        "    resources = make_set(parentId, 5), assessment_keys = make_set(assessmentKey, 5)\n"
        "    by art, registry, repository, digest\n"
        "| extend id = tolower(strcat(art, '|', registry, '/', repository, '@', digest))\n"
        "| order by id asc"
    )


def servers_query() -> str:
    return _BASE.format(types=_types(SERVER_TYPES)) + (
        "| summarize findings = count(), unhealthy = countif(statusCode =~ 'Unhealthy'),\n"
        "    critical = countif(statusCode =~ 'Unhealthy' and severity =~ 'Critical'),\n"
        "    high = countif(statusCode =~ 'Unhealthy' and severity =~ 'High'),\n"
        "    medium = countif(statusCode =~ 'Unhealthy' and severity =~ 'Medium'),\n"
        "    low = countif(statusCode =~ 'Unhealthy' and severity =~ 'Low'),\n"
        "    patchable_unhealthy = countif(statusCode =~ 'Unhealthy' and patchable == 'true'),\n"
        "    latest_scanned = max(todatetime(properties.timeGenerated)),\n"
        "    oldest_open_published = minif(todatetime(publishedAt), statusCode =~ 'Unhealthy')\n"
        "    by art, parentId\n"
        "| extend id = strcat(tolower(art), '|', parentId)\n"
        "| order by id asc"
    )


def findings_query() -> str:
    return _BASE.format(types=_types(ALL_TYPES)) + (
        "| where statusCode =~ 'Unhealthy'\n"
        "| project id, art, assessmentKey, severity, statusCode, resourceId, parentId, registry, repository, digest,\n"
        "    cveId = tostring(properties.id), displayName = tostring(properties.displayName),\n"
        "    timeGenerated = tostring(properties.timeGenerated), publishedAt, cvss, patchable, fixedVersion,\n"
        "    package = coalesce(tostring(properties.additionalData.softwareDetails.packageName),\n"
        "        tostring(properties.additionalData.softwareDetails.name)),\n"
        "    packageVersion = tostring(properties.additionalData.softwareDetails.version),\n"
        "    packageCategory = tostring(properties.additionalData.softwareDetails.category),\n"
        "    exploitStepsPublished = tostring(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.exploitStepsPublished)\n"
        "| order by id asc"
    )


# ---- records -----------------------------------------------------------------------------

def _str(value: Any) -> Optional[str]:
    text = str(value).strip() if value is not None else ""
    return text or None


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _bool_str(value: Any) -> Optional[bool]:
    text = (_str(value) or "").lower()
    return True if text == "true" else False if text == "false" else None


def _age_days(value: Any, now: datetime) -> Optional[int]:
    text = _str(value)
    if not text:
        return None
    try:
        ts = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return max((now - ts).days, 0)


def image_record(row: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    oldest = _str(row.get("oldest_open_published"))
    registry, repository, digest = _str(row.get("registry")), _str(row.get("repository")), _str(row.get("digest"))
    return {
        "image": f"{registry or ''}/{repository or ''}@{digest or ''}" if (registry or repository or digest) else None,
        "registry": registry,
        "repository": repository,
        "digest": digest,
        "assessment_type": row.get("art"),
        "assessment_keys": sorted(str(k) for k in (row.get("assessment_keys") or []) if k),
        "resource_ids": sorted(str(r) for r in (row.get("resources") or []) if r),
        "findings": _int(row.get("findings")),
        "open_findings": _int(row.get("unhealthy")),
        "open_by_severity": {s.lower(): _int(row.get(s.lower())) for s in SEVERITIES},
        "open_patchable": _int(row.get("patchable_unhealthy")),
        "latest_scanned_at": _str(row.get("latest_scanned")),
        "oldest_open_published_at": oldest,
        "oldest_open_age_days": _age_days(oldest, now),
    }


def server_record(row: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    oldest = _str(row.get("oldest_open_published"))
    return {
        "resource_id": _str(row.get("parentId")),
        "assessment_type": row.get("art"),
        "findings": _int(row.get("findings")),
        "open_findings": _int(row.get("unhealthy")),
        "open_by_severity": {s.lower(): _int(row.get(s.lower())) for s in SEVERITIES},
        "open_patchable": _int(row.get("patchable_unhealthy")),
        "latest_scanned_at": _str(row.get("latest_scanned")),
        "oldest_open_published_at": oldest,
        "oldest_open_age_days": _age_days(oldest, now),
    }


def finding_record(row: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    art = row.get("art") or ""
    return {
        "id": row.get("id"),
        "assessment_type": art,
        "kind": "container_image" if art in CONTAINER_TYPES else "server",
        "assessment_key": row.get("assessmentKey"),
        # properties.id is the CVE id in the MDVM schema, but a scanner-specific id (for
        # example a Qualys QID) in the legacy one: only a CVE-shaped id is reported as a CVE.
        "vulnerability_id": _str(row.get("cveId")),
        "cve_id": _str(row.get("cveId")) if (_str(row.get("cveId")) or "").upper().startswith("CVE-") else None,
        "display_name": (_str(row.get("displayName")) or "")[:200] or None,
        "severity": _str(row.get("severity")),
        "status": _str(row.get("statusCode")),
        "cvss": row.get("cvss") if isinstance(row.get("cvss"), (int, float)) else None,
        "patchable": _bool_str(row.get("patchable")),
        "fixed_version": _str(row.get("fixedVersion")),
        "package": _str(row.get("package")),
        "package_version": _str(row.get("packageVersion")),
        "package_category": _str(row.get("packageCategory")),
        "exploit_steps_published": _bool_str(row.get("exploitStepsPublished")),
        "published_at": _str(row.get("publishedAt")),
        "age_days": _age_days(row.get("publishedAt"), now),
        # timeGenerated is when Defender last (re)generated the sub-assessment, rewritten on each scan; it is not
        # when the CVE was first found, so it must not be read as a detection time.
        "last_scanned_at": _str(row.get("timeGenerated")),
        "resource_id": _str(row.get("parentId")),
        "assessed_resource_detail_id": _str(row.get("resourceId")),
        "registry": _str(row.get("registry")),
        "repository": _str(row.get("repository")),
        "digest": _str(row.get("digest")),
    }


def report_findings_query() -> str:
    """Every open (Unhealthy) container image and server finding, with the fields an issue report needs.

    Unlike findings_query this keeps the image's tags and push time, the package's fix status and the
    exploitability flags, so a vulnerability assessment can show them on the issue. Never capped.
    """
    return _BASE.format(types=_types(ALL_TYPES)) + (
        "| where statusCode =~ 'Unhealthy'\n"
        "| project id, art, severity, resourceId, parentId, registry, repository, digest,\n"
        "    cveId = coalesce(tostring(properties.additionalData.vulnerabilityDetails.cveId), tostring(properties.id)),\n"
        "    displayName = tostring(properties.displayName),\n"
        "    timeGenerated = tostring(properties.timeGenerated), publishedAt, cvss, patchable, fixedVersion,\n"
        "    cvss4 = todouble(properties.additionalData.vulnerabilityDetails.cvss[\"4.0\"].base),\n"
        "    package = coalesce(tostring(properties.additionalData.softwareDetails.packageName),\n"
        "        tostring(properties.additionalData.softwareDetails.name)),\n"
        "    packageVersion = tostring(properties.additionalData.softwareDetails.version),\n"
        "    packageCategory = tostring(properties.additionalData.softwareDetails.category),\n"
        "    fixStatus = tostring(properties.additionalData.softwareDetails.fixStatus),\n"
        "    tags = properties.additionalData.artifactDetails.tags,\n"
        "    pushedAt = tostring(properties.additionalData.artifactDetails.lastPushedToRegistryUTC),\n"
        "    exploitStepsPublished = tostring(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.exploitStepsPublished),\n"
        "    exploitStepsVerified = tostring(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.exploitStepsVerified),\n"
        "    inExploitKit = tostring(properties.additionalData.vulnerabilityDetails.exploitabilityAssessment.isInExploitKit)\n"
        "| order by id asc"
    )
