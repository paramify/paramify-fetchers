"""OpenSCAP benchmark results: for each scanned target, the latest XCCDF evaluation and its rule results.

Reads the result files oscap writes (XCCDF results, `--results`, or an ARF report, `--results-arf`, optionally
gzipped) from an Azure Blob Storage container, GET only, or from a local directory. Every XCCDF TestResult found is
read; for each target the newest one counts. Only rule IDs, results and severities are kept, never rule text, check
content or system details beyond the target name.

Collection-failure convention (docs/authoring_fetcher_guide.md, step 3): a file that cannot be listed, read or parsed
is recorded in `api_failures` and leaves every judged summary field null; the run exits non-zero.
"""

import fnmatch
import gzip
import json
import logging
import os
import sys
import time
import xml.etree.ElementTree as StdET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

import requests
from defusedxml import DefusedXmlException
from defusedxml import ElementTree as SafeET
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

NAME = "openscap_benchmark_results"
OUTPUT = "openscap_benchmark_results.json"
XCCDF_NAMESPACES = {"http://checklists.nist.gov/xccdf/1.1", "http://checklists.nist.gov/xccdf/1.2"}
RESULTS = ("pass", "fail", "error", "unknown", "notapplicable", "notchecked", "notselected", "informational", "fixed")
SEVERITIES = ("high", "medium", "low", "info", "unknown")
FILE_PATTERNS = ("*.xml", "*.xml.gz", "*.arf", "*.arf.gz")
MAX_FILE_BYTES = 256 * 1024 * 1024
STORAGE_SCOPE = "https://storage.azure.com/.default"
BLOB_API_VERSION = "2023-11-03"
TIMEOUT = 120
MAX_RETRIES = 3
RETRY_STATUS = {429, 500, 502, 503, 504}
CODES = {401: "auth_failed", 403: "not_authorized", 404: "bad_config"}

logger = logging.getLogger(NAME)


# --- parsing ---

def _local(tag: str) -> Tuple[Optional[str], str]:
    if tag.startswith("{"):
        ns, _, name = tag[1:].partition("}")
        return ns, name
    return None, tag


def _child(el, name: str):
    return next((c for c in el if _local(c.tag)[1] == name), None)


def _time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _stamp(when: Optional[datetime]) -> Optional[str]:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if when else None


def test_results(data: bytes, file_name: str) -> List[Dict[str, Any]]:
    """Every XCCDF TestResult in one results or ARF file. Raises ValueError when the file is not parseable XML."""
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise ValueError(f"not a readable gzip file: {exc}") from exc
    try:
        root = SafeET.fromstring(data)
    except (StdET.ParseError, DefusedXmlException) as exc:
        raise ValueError(f"not parseable XML: {exc}") from exc
    found = []
    for el in root.iter():
        ns, name = _local(el.tag)
        if name != "TestResult" or ns not in XCCDF_NAMESPACES:
            continue
        counts = {r: 0 for r in RESULTS}
        failed, waived = [], []
        for rr in el:
            if _local(rr.tag)[1] != "rule-result":
                continue
            result_el = _child(rr, "result")
            result = (result_el.text or "").strip() if result_el is not None else ""
            if result not in counts:
                result = "unknown"
            counts[result] += 1
            severity = rr.get("severity") if rr.get("severity") in SEVERITIES else "unknown"
            if result == "fail":
                failed.append({"rule": rr.get("idref"), "severity": severity})
            override = _child(rr, "override")
            if override is not None:
                old, new = _child(override, "old-result"), _child(override, "new-result")
                waived.append({"rule": rr.get("idref"), "old_result": (old.text or "").strip() if old is not None else None,
                               "new_result": (new.text or "").strip() if new is not None else None})
        target_el, profile_el, score_el = _child(el, "target"), _child(el, "profile"), _child(el, "score")
        benchmark_el = _child(el, "benchmark")
        try:
            score = float(score_el.text) if score_el is not None and score_el.text else None
        except ValueError:
            score = None
        found.append({
            "file": file_name,
            "target": (target_el.text or "").strip() or None if target_el is not None else None,
            "profile": profile_el.get("idref") if profile_el is not None else None,
            "benchmark": (benchmark_el.get("id") or benchmark_el.get("href")) if benchmark_el is not None else None,
            "start_time": _stamp(_time(el.get("start-time"))),
            "end_time": _stamp(_time(el.get("end-time"))),
            "score": score,
            "rule_results": counts,
            "failed_rules": sorted(failed, key=lambda f: (SEVERITIES.index(f["severity"]), f["rule"] or "")),
            "waived_rules": sorted(waived, key=lambda w: w["rule"] or ""),
        })
    return found


def latest_per_target(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The newest TestResult for each target (by end time, then start time); a result without a target is its own."""
    latest: Dict[str, Dict[str, Any]] = {}
    for r in results:
        key = (r["target"] or f"(no target in {r['file']})").lower()
        when = r["end_time"] or r["start_time"] or ""
        held = latest.get(key)
        if held is None or when > (held["end_time"] or held["start_time"] or ""):
            latest[key] = r
    return sorted(latest.values(), key=lambda r: (r["target"] or "", r["file"]))


def summarize(source: Optional[str], files: Optional[int], unreadable: int, without_results: int,
              results: List[Dict[str, Any]], expected: Optional[List[str]], max_age_days: Optional[int],
              now: datetime) -> Dict[str, Any]:
    """Counts over each target's latest result; a judgement that needs an unread file is null, not 0."""
    latest = latest_per_target(results)
    judged = files is not None and unreadable == 0
    ages = []
    for r in latest:
        when = _time(r["end_time"] or r["start_time"])
        ages.append(round((now - when).total_seconds() / 86400, 1) if when else None)
    scanned = {(r["target"] or "").lower() for r in latest if r["target"]}
    missing = sorted(t for t in (expected or []) if t.lower() not in scanned) if expected is not None else None
    failing = [r for r in latest if r["rule_results"]["fail"]]
    by_severity = {s: 0 for s in SEVERITIES}
    for r in latest:
        for f in r["failed_rules"]:
            by_severity[f["severity"]] += 1
    j = lambda value: value if judged else None  # noqa: E731
    return {
        "results_source": source,
        "files_found": files,
        "files_unreadable": unreadable,
        "files_without_test_results": without_results,
        "test_results_read": len(results),
        "targets_scanned": j(len(latest)),
        "profiles": sorted({r["profile"] for r in latest if r["profile"]}),
        "expected_targets": expected,
        "expected_targets_missing": j(len(missing)) if missing is not None else None,
        "expected_targets_missing_names": j(missing) if missing is not None else None,
        "max_age_days": max_age_days,
        "oldest_latest_scan_age_days": j(max((a for a in ages if a is not None), default=None)),
        "targets_scan_older_than_max_age": j(sum(1 for a in ages if a is None or a > max_age_days)) if max_age_days else None,
        "rules_failed": j(sum(r["rule_results"]["fail"] for r in latest)),
        "rules_failed_by_severity": j(by_severity),
        "rules_errored": j(sum(r["rule_results"]["error"] + r["rule_results"]["unknown"] for r in latest)),
        "rules_waived": j(sum(len(r["waived_rules"]) for r in latest)),
        "targets_with_failures": j(len(failing)),
        "targets_with_failures_names": j(sorted(r["target"] or r["file"] for r in failing)),
        "targets_with_errors": j(sum(1 for r in latest if r["rule_results"]["error"] or r["rule_results"]["unknown"])),
        "all_targets_pass": j(not any(r["rule_results"]["fail"] or r["rule_results"]["error"]
                                      or r["rule_results"]["unknown"] for r in latest)) if latest else None,
    }


# --- sources ---

def _wanted(path: str, prefix: str) -> bool:
    return path.startswith(prefix) and any(fnmatch.fnmatch(path.lower(), p) for p in FILE_PATTERNS)


class DirectorySource:
    kind = "directory"

    def __init__(self, root: str, prefix: str = ""):
        self.root, self.prefix = Path(root), prefix

    def list(self) -> List[str]:
        if not self.root.is_dir():
            raise FileNotFoundError(f"{self.root} is not a directory")
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*")
                      if p.is_file() and _wanted(p.relative_to(self.root).as_posix(), self.prefix))

    def read(self, name: str) -> bytes:
        path = self.root / name
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"larger than {MAX_FILE_BYTES} bytes")
        return path.read_bytes()


class BlobSource:
    """GETs against one container's Blob REST API with a Storage token; the token goes nowhere else."""

    kind = "container"

    def __init__(self, container_url: str, token_provider: Callable[[], str], prefix: str = "", session: Any = None):
        parts = urlsplit(container_url.rstrip("/"))
        if parts.scheme != "https" or not parts.netloc or parts.path.count("/") != 1 or parts.query:
            raise ValueError("results_container_url must be https://<account>.blob.<suffix>/<container>")
        self.base = f"https://{parts.netloc}{parts.path}"
        self.prefix, self.token_provider = prefix, token_provider
        self.session = session or requests.Session()

    def _get(self, url: str, params: Optional[Dict[str, str]] = None) -> requests.Response:
        if not url.startswith(self.base + "/") and url != self.base:
            raise ValueError("refusing to send the storage token outside the container")
        headers = {"Authorization": f"Bearer {self.token_provider()}", "x-ms-version": BLOB_API_VERSION}
        response = None
        for attempt in range(MAX_RETRIES + 1):
            response = self.session.get(url, params=params, headers=headers, timeout=TIMEOUT, allow_redirects=False)
            if response.status_code in RETRY_STATUS and attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 30))
                continue
            break
        if response.status_code != 200:
            raise HttpError(response.status_code, (response.text or "")[:300])
        return response

    def list(self) -> List[str]:
        names, marker = [], ""
        while True:
            params = {"restype": "container", "comp": "list", "prefix": self.prefix, "maxresults": "5000"}
            if marker:
                params["marker"] = marker
            root = SafeET.fromstring(self._get(self.base, params).content)
            for blob in root.iter("Blob"):
                name = blob.findtext("Name") or ""
                size = int(blob.findtext("Properties/Content-Length") or 0)
                if _wanted(name, self.prefix) and size <= MAX_FILE_BYTES:
                    names.append(name)
                elif _wanted(name, self.prefix):
                    raise ValueError(f"{name} is larger than {MAX_FILE_BYTES} bytes")
            marker = root.findtext("NextMarker") or ""
            if not marker:
                return sorted(names)

    def read(self, name: str) -> bytes:
        return self._get(f"{self.base}/{quote(name)}").content


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def _storage_token() -> Callable[[], str]:
    from azure.identity import DefaultAzureCredential  # lazy, so tests need no Azure SDK
    credential = DefaultAzureCredential()
    return lambda: credential.get_token(STORAGE_SCOPE).token


# --- run ---

def _failure(operation: str, exc: Exception) -> Tuple[Dict[str, str], str]:
    code = CODES.get(getattr(exc, "status", None), "partial_failure")
    return {"operation": operation, "type": type(exc).__name__, "message": str(exc)[:300]}, code


def collect(source: Any, expected: Optional[List[str]], max_age_days: Optional[int],
            now: Optional[datetime] = None) -> Tuple[Dict[str, Any], List[Dict[str, str]], List[str]]:
    now = now or datetime.now(timezone.utc)
    failures: List[Dict[str, str]] = []
    codes: List[str] = []
    results: List[Dict[str, Any]] = []
    files: Optional[List[str]] = None
    without, unreadable = 0, 0
    try:
        files = source.list()
    except Exception as exc:  # noqa: BLE001 - any listing failure leaves the whole run unjudged
        failure, code = _failure("list result files", exc)
        failures.append(failure)
        codes.append(code)
    for name in files or []:
        try:
            found = test_results(source.read(name), name)
        except Exception as exc:  # noqa: BLE001 - one unreadable file could hide a target's latest result
            failure, code = _failure(f"read {name}", exc)
            failures.append(failure)
            codes.append(code)
            unreadable += 1
            continue
        without += 0 if found else 1
        results += found
    latest = latest_per_target(results)
    summary = summarize(source.kind, len(files) if files is not None else None, unreadable, without, results,
                        expected, max_age_days, now)
    return {"results": {"targets": latest, "as_of": _stamp(now)}, "summary": summary}, failures, codes


def main() -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    out_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata: Dict[str, Any] = {"datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    failures: List[Dict[str, str]] = []

    raw_age = (os.environ.get("OPENSCAP_MAX_AGE_DAYS") or "").strip()
    max_age = int(raw_age) if raw_age.isdigit() and 1 <= int(raw_age) <= 3650 else None
    if raw_age and max_age is None:
        failures.append({"operation": "config OPENSCAP_MAX_AGE_DAYS", "type": "ValueError",
                         "message": f"OPENSCAP_MAX_AGE_DAYS={raw_age!r} must be a whole number from 1 to 3650"})
    raw_expected = os.environ.get("OPENSCAP_EXPECTED_TARGETS")
    expected = sorted({t.strip() for t in raw_expected.split(",") if t.strip()}, key=str.lower) if raw_expected else None
    container = (os.environ.get("OPENSCAP_RESULTS_CONTAINER_URL") or "").strip()
    directory = (os.environ.get("OPENSCAP_RESULTS_DIR") or "").strip()
    prefix = (os.environ.get("OPENSCAP_RESULTS_PREFIX") or "").strip()

    source = None
    if bool(container) == bool(directory):
        failures.append({"operation": "config", "type": "ValueError",
                         "message": "Set exactly one of OPENSCAP_RESULTS_CONTAINER_URL and OPENSCAP_RESULTS_DIR"})
    else:
        try:
            source = BlobSource(container, _storage_token(), prefix) if container else DirectorySource(directory, prefix)
            metadata["results_location"] = source.base if container else directory
        except ValueError as exc:
            failures.append({"operation": "config", "type": "ValueError", "message": str(exc)})
    code = "bad_config" if failures else None

    evidence: Dict[str, Any] = {"results": {}, "summary": summarize(None, None, 0, 0, [], expected, max_age,
                                                                     datetime.now(timezone.utc))}
    if source is not None:
        evidence, collected, codes = collect(source, expected, max_age)
        failures += collected
        code = code or (codes[0] if codes else None)
    metadata["api_failures"] = failures
    metadata["partial_failure"] = bool(failures)
    path = out_dir / OUTPUT
    path.write_text(json.dumps({"metadata": metadata, **evidence}, indent=2, sort_keys=True))
    logger.info("Evidence saved to %s", path)
    if failures:
        first = failures[0]
        report_failure(f"OpenSCAP {first['operation']} failed: {first['type']}", code)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
