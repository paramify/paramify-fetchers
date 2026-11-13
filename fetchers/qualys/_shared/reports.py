"""Versioned CSV contracts assembled from read-only Qualys APIs.

These are explicit equivalents of the Wiz assembled-report exception: VMDR
needs a join with KnowledgeBase and QVS; STIG needs per-instance control joins.
They require their own intake mappings, not a native Qualys report preset.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from qualys_report_client import (
    DETECTIONS,
    KNOWLEDGE_BASE,
    POLICIES,
    POSTURE,
    QVS,
    QualysError,
    value,
)

VM_COLUMNS = [
    "Record ID",
    "Host ID",
    "Asset ID",
    "Host Name",
    "IP",
    "Operating System",
    "QID",
    "Unique Vulnerability ID",
    "Port",
    "Protocol",
    "SSL",
    "Title",
    "Type",
    "Status",
    "Ignored",
    "Disabled",
    "Qualys Severity",
    "CVSS Base",
    "CVSS Vector",
    "CVSS v3 Base",
    "CVSS v3 Vector",
    "CVEs",
    "Description",
    "Consequence",
    "Remediation",
    "Results",
    "First Detected",
    "Last Detected",
    "Last Tested",
    "Last Fixed",
    "Last Reopened",
    "Times Reopened",
    "Resolved At",
    "QVS Maximum",
    "QVS Coverage",
    "CISA KEV",
    "CISA Due Date",
    "CVE Enrichment",
]
STIG_COLUMNS = [
    "Record ID",
    "Policy ID",
    "Policy Title",
    "Posture ID",
    "Host ID",
    "Asset ID",
    "Host Name",
    "IP",
    "Operating System",
    "Control ID",
    "Control Title",
    "STIG ID",
    "Control References",
    "Technology ID",
    "Technology",
    "Instance",
    "Result",
    "Previous Result",
    "Qualys Criticality",
    "Qualys Criticality Value",
    "Remediation",
    "Evaluated At",
    "Modified At",
    "First Failed",
    "Last Failed",
    "First Passed",
    "Last Passed",
    "Resolved At",
    "Last Compliance Scan",
    "Exception Status",
    "Exception Expires",
]


def record_id(*parts: str) -> str:
    # Structured encoding avoids delimiter collisions, e.g. a database instance
    # containing colons. Never use a mutable title, hostname, or severity as ID.
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode()).hexdigest()


def resolved_at(is_resolved: bool, source_date: str) -> str:
    """Only current resolution can populate Paramify's Date Closed field."""
    if not is_resolved:
        return ""
    try:
        datetime.fromisoformat(source_date.replace("Z", "+00:00"))
    except ValueError as exc:
        raise QualysError(
            "Resolved finding lacks a valid source resolution date"
        ) from exc
    return source_date


def insert_row(rows: dict, row: dict, max_records: int):
    key = row["Record ID"]
    if key in rows:
        raise QualysError(
            "Duplicate finding identity; collection changed or pagination overlapped"
        )
    rows[key] = row
    if len(rows) > max_records:
        raise QualysError("Qualys record limit exceeded; no complete report available")


def hostname(host) -> str:
    return (
        value(host, "DNS_DATA/FQDN")
        or value(host, "DNS")
        or value(host, "DNS_DATA/HOSTNAME")
        or value(host, "IP")
        or value(host, "ID")
    )


def batches(items, size):
    ordered = sorted(set(items))
    for start in range(0, len(ordered), size):
        yield ordered[start : start + size]


def kb_records(client, qids):
    records = {}
    for batch in batches(qids, 100):
        response = client.xml(
            KNOWLEDGE_BASE,
            {"action": "list", "ids": ",".join(batch), "details": "All"},
            "KNOWLEDGE_BASE_VULN_LIST_OUTPUT",
        )
        if response.findall(".//WARNING"):
            raise QualysError(
                "KnowledgeBase returned a warning; enrichment may be incomplete"
            )
        for item in response.findall("VULN_LIST/VULN"):
            qid = value(item, "QID", required=True)
            if qid not in batch or qid in records:
                raise QualysError("KnowledgeBase returned unexpected or duplicate QIDs")
            value(item, "TITLE", required=True)
            records[qid] = item
        if any(qid not in records for qid in batch):
            raise QualysError("KnowledgeBase omitted requested QIDs")
    return records


def qvs_records(client, cves):
    records = {}
    for batch in batches(cves, 25):
        try:
            data = json.loads(
                client.request(
                    QVS, {"action": "list", "cve": ",".join(batch), "details": "All"}
                )
            )
        except (ValueError, UnicodeError):
            raise QualysError("QVS returned invalid JSON") from None
        if not isinstance(data, dict) or set(data) - set(batch):
            raise QualysError("QVS returned an unexpected response or error object")
        for cve, item in data.items():
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("base"), dict)
                or item["base"].get("id") != cve
                or not isinstance(item.get("contributingFactors", {}), dict)
            ):
                raise QualysError("QVS returned malformed CVE enrichment")
            try:
                score = float(item["base"]["qvs"])
                if not 0 <= score <= 100:
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                raise QualysError("QVS returned an invalid score") from None
            records[cve] = item
        # Omitted CVEs in a successful, valid object mean unavailable, never
        # a score of zero or an assertion that CISA does not list the CVE.
    return records


def cisa_date(raw) -> str:
    if raw is None or raw == "":
        return ""
    try:
        stamp = int(raw)
        if stamp <= 0:
            raise ValueError
        if stamp >= 100_000_000_000:
            stamp /= 1000
        return datetime.fromtimestamp(stamp, timezone.utc).date().isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        raise QualysError("QVS returned an invalid CISA date") from None


def cisa_flag(raw) -> bool | None:
    if raw is None or raw == []:
        return None
    values = raw if isinstance(raw, list) else [raw]
    tokens = {str(item).strip().lower() for item in values}
    if tokens <= {"yes", "true", "1"}:
        return True
    if tokens <= {"no", "false", "0"}:
        return False
    raise QualysError("QVS returned an invalid CISA KEV flag")


def enrichment(cves, qvs):
    per_cve, scores, dates, flags = {}, [], [], []
    for cve in cves:
        if cve not in qvs:
            per_cve[cve] = {"availability": "unavailable"}
            flags.append(None)
            continue
        item = qvs[cve]
        factors = item.get("contributingFactors", {})
        flag = cisa_flag(factors.get("cisaVuln"))
        due = cisa_date(factors.get("cisaDueDate"))
        added = cisa_date(factors.get("cisaAddedDate"))
        if flag is False and (due or added):
            raise QualysError("QVS returned contradictory CISA enrichment")
        per_cve[cve] = {
            "availability": "available",
            **item,
            "cisa_kev": flag,
            "cisa_due_date": due or None,
            "cisa_added_date": added or None,
        }
        scores.append(float(item["base"]["qvs"]))
        flags.append(flag)
        if due:
            dates.append(due)
    available = len(scores)
    coverage = (
        "not_applicable"
        if not cves
        else "complete"
        if available == len(cves)
        else "partial"
        if available
        else "unavailable"
    )
    kev = (
        "true"
        if True in flags
        else "false"
        if flags and all(f is False for f in flags)
        else "unknown"
    )
    return {
        "QVS Maximum": format(max(scores), "g") if scores else "",
        "QVS Coverage": coverage,
        "CISA KEV": kev,
        "CISA Due Date": min(dates) if dates else "",
        "CVE Enrichment": json.dumps(per_cve, sort_keys=True, separators=(",", ":")),
    }


def collect_vm(client, host_ids="", asset_group_ids=""):
    params = {
        "truncation_limit": client.page_size,
        "status": "New,Active,Re-Opened,Fixed",
        "show_igs": 0,
        "include_ignored": 1,
        "include_disabled": 1,
        "show_results": 1,
        "show_reopened_info": 1,
        "show_asset_id": 1,
    }
    if host_ids:
        params["ids"] = host_ids
    if asset_group_ids:
        params["ag_ids"] = asset_group_ids
    rows, qids, seen_hosts = {}, set(), set()
    for response in client.pages(DETECTIONS, params, "HOST_LIST_VM_DETECTION_OUTPUT"):
        hosts = response.findall("HOST_LIST/HOST")
        if not hosts and response.findall(".//WARNING"):
            raise QualysError("Qualys returned a truncated page without hosts")
        for host in hosts:
            host_id = value(host, "ID", required=True)
            if host_id in seen_hosts:
                raise QualysError("Qualys repeated a host across detection pages")
            seen_hosts.add(host_id)
            for detection in host.findall("DETECTION_LIST/DETECTION"):
                qid = value(detection, "QID", required=True)
                qids.add(qid)
                uid, port, protocol, ssl = (
                    value(detection, key)
                    for key in ("UNIQUE_VULN_ID", "PORT", "PROTOCOL", "SSL")
                )
                row = {
                    "Record ID": record_id(
                        client.base_url, "vm", host_id, qid, uid, port, protocol, ssl
                    ),
                    "Host ID": host_id,
                    "Asset ID": value(host, "ASSET_ID"),
                    "Host Name": hostname(host),
                    "IP": value(host, "IP"),
                    "Operating System": value(host, "OS"),
                    "QID": qid,
                    "Unique Vulnerability ID": uid,
                    "Port": port,
                    "Protocol": protocol,
                    "SSL": ssl,
                    "Type": value(detection, "TYPE", required=True),
                    "Status": value(detection, "STATUS", required=True),
                    "Qualys Severity": value(detection, "SEVERITY", required=True),
                    "Ignored": value(detection, "IS_IGNORED", required=True),
                    "Disabled": value(detection, "IS_DISABLED", required=True),
                    "Results": value(detection, "RESULTS"),
                    "First Detected": value(
                        detection, "FIRST_FOUND_DATETIME", required=True
                    ),
                    "Last Detected": value(
                        detection, "LAST_FOUND_DATETIME", required=True
                    ),
                    "Last Tested": value(detection, "LAST_TEST_DATETIME"),
                    "Last Fixed": value(detection, "LAST_FIXED_DATETIME"),
                    "Last Reopened": value(detection, "LAST_REOPENED_DATETIME"),
                    "Times Reopened": value(detection, "TIMES_REOPENED"),
                }
                row["Resolved At"] = resolved_at(
                    row["Status"] == "Fixed", row["Last Fixed"]
                )
                insert_row(rows, row, client.max_records)
    logging.info(
        "Collected %d detections; enriching %d distinct QIDs", len(rows), len(qids)
    )
    kb = kb_records(client, qids)
    cves_by_qid = {}
    for qid, item in kb.items():
        cves = sorted(
            {value(cve, "ID", required=True) for cve in item.findall("CVE_LIST/CVE")}
        )
        if any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) for cve in cves):
            raise QualysError("KnowledgeBase returned an invalid CVE ID")
        cves_by_qid[qid] = cves
    cves = {cve for cves in cves_by_qid.values() for cve in cves}
    logging.info(
        "Fetching required QVS/CISA enrichment for %d distinct CVEs", len(cves)
    )
    qvs = qvs_records(client, cves)
    enriched = {qid: enrichment(cves, qvs) for qid, cves in cves_by_qid.items()}
    for row in rows.values():
        qid = row["QID"]
        item = kb[qid]
        row.update(
            {
                "Title": value(item, "TITLE"),
                "Description": value(item, "DIAGNOSIS"),
                "Consequence": value(item, "CONSEQUENCE"),
                "Remediation": value(item, "SOLUTION"),
                "CVSS Base": value(item, "CVSS/BASE"),
                "CVSS Vector": value(item, "CVSS/VECTOR_STRING"),
                "CVSS v3 Base": value(item, "CVSS_V3/BASE"),
                "CVSS v3 Vector": value(item, "CVSS_V3/VECTOR_STRING"),
                "CVEs": ";".join(cves_by_qid[qid]),
                **enriched[qid],
            }
        )
    return sorted(rows.values(), key=lambda row: row["Record ID"])


def collect_stig(client, policy_id):
    response = client.xml(
        POLICIES,
        {"action": "list", "ids": policy_id, "details": "Basic"},
        "POLICY_LIST_OUTPUT",
    )
    policies = response.findall("POLICY_LIST/POLICY")
    if (
        response.findall(".//WARNING")
        or len(policies) != 1
        or value(policies[0], "ID") != policy_id
    ):
        raise QualysError(
            "Qualys policy is unavailable or its lookup was incomplete", "bad_config"
        )
    title = value(policies[0], "TITLE", required=True)
    rows = {}
    for response in client.pages(
        POSTURE,
        {
            "policy_id": policy_id,
            "details": "All",
            "show_remediation_info": 1,
            "hide_evidence": 1,
            "truncation_limit": client.page_size,
        },
        "POSTURE_INFO_LIST_OUTPUT",
    ):
        # Single-policy responses have appeared both directly under RESPONSE
        # and under RESPONSE/POLICY in Qualys documentation.
        wrappers = response.findall("POLICY")
        if wrappers:
            if len(wrappers) != 1 or value(wrappers[0], "ID") != policy_id:
                raise QualysError(
                    "Posture response does not match the requested policy"
                )
            scope = wrappers[0]
        else:
            scope = response
        infos = scope.findall("INFO_LIST/INFO")
        if not infos and (
            scope.find("SUMMARY/CONTROL_INSTANCES/TOTAL") is None
            or value(scope, "SUMMARY/CONTROL_INSTANCES/TOTAL") != "0"
            or response.findall(".//WARNING")
        ):
            raise QualysError(
                "Qualys returned no postures without an explicit zero summary"
            )
        glossary = scope.find("GLOSSARY")
        if infos and glossary is None:
            raise QualysError("Qualys posture response is missing its glossary")
        hosts = {
            value(n, "ID", True): n for n in scope.findall("GLOSSARY/HOST_LIST/HOST")
        }
        controls = {
            value(n, "ID", True): n
            for n in scope.findall("GLOSSARY/CONTROL_LIST/CONTROL")
        }
        technologies = {
            value(n, "ID", True): n
            for n in scope.findall("GLOSSARY/TECHNOLOGY_LIST/TECHNOLOGY")
        }
        for info in infos:
            host_id, control_id, tech_id = (
                value(info, key, True)
                for key in ("HOST_ID", "CONTROL_ID", "TECHNOLOGY_ID")
            )
            if (
                host_id not in hosts
                or control_id not in controls
                or tech_id not in technologies
            ):
                raise QualysError(
                    "Posture glossary omitted a referenced host, control, or technology"
                )
            host, control = hosts[host_id], controls[control_id]
            reference = value(control, "REFERENCE")
            stig_ids = sorted(set(re.findall(r"\bV-\d+\b", reference)))
            if not stig_ids:
                stig_ids = sorted(
                    set(re.findall(r"\bSV-[\w.-]+|\bSRG-[\w.-]+", reference))
                )
            if not stig_ids:
                raise QualysError(
                    "A posture control has no STIG reference; verify the selected policy"
                )
            instance = value(info, "INSTANCE")
            for stig_id in stig_ids:
                row = {
                    "Record ID": record_id(
                        client.base_url,
                        "stig",
                        policy_id,
                        host_id,
                        control_id,
                        tech_id,
                        instance,
                        stig_id,
                    ),
                    "Policy ID": policy_id,
                    "Policy Title": title,
                    "Posture ID": value(info, "ID", True),
                    "Host ID": host_id,
                    "Asset ID": value(host, "ASSET_ID"),
                    "Host Name": hostname(host),
                    "IP": value(host, "IP"),
                    "Operating System": value(host, "OS"),
                    "Control ID": control_id,
                    "Control Title": value(control, "STATEMENT", True),
                    "STIG ID": stig_id,
                    "Control References": reference,
                    "Technology ID": tech_id,
                    "Technology": value(technologies[tech_id], "NAME", True),
                    "Instance": instance,
                    "Result": value(info, "STATUS", True),
                    "Previous Result": value(info, "PREVIOUS_STATUS"),
                    "Qualys Criticality": value(control, "CRITICALITY/LABEL"),
                    "Qualys Criticality Value": value(control, "CRITICALITY/VALUE"),
                    "Remediation": value(info, "REMEDIATION"),
                    "Evaluated At": value(info, "EVALUATION_DATE"),
                    "Modified At": value(info, "POSTURE_MODIFIED_DATE"),
                    "First Failed": value(info, "FIRST_FAIL_DATE"),
                    "Last Failed": value(info, "LAST_FAIL_DATE"),
                    "First Passed": value(info, "FIRST_PASS_DATE"),
                    "Last Passed": value(info, "LAST_PASS_DATE"),
                    "Last Compliance Scan": value(
                        host, "LAST_COMPLIANCE_SCAN_DATETIME"
                    ),
                    "Exception Status": value(info, "EXCEPTION/STATUS"),
                    "Exception Expires": value(info, "EXCEPTION/END_DATETIME"),
                }
                row["Resolved At"] = resolved_at(
                    row["Result"] == "Passed", row["Evaluated At"]
                )
                insert_row(rows, row, client.max_records)
    return sorted(rows.values(), key=lambda row: row["Record ID"])


def write_report(path: Path, columns: list[str], rows: list[dict], allow_empty: bool):
    if not rows and not allow_empty:
        raise QualysError(
            "No findings returned; verify scope or explicitly set allow_empty=true"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    # Require a fresh run directory. A failed rerun must not leave an earlier
    # successful report masquerading as this invocation's output.
    if path.exists():
        raise QualysError(
            "Report already exists; use a fresh output directory", "bad_config"
        )
    temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=".qualys-",
            suffix=".part",
            delete=False,
        ) as handle:
            temp = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        temp.replace(path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)
