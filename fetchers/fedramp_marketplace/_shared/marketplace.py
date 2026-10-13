"""FedRAMP Marketplace client shared by the fedramp_marketplace fetchers.

Reads FedRAMP's own published marketplace data (github.com/FedRAMP/
marketplace-fedramp-gov-data) and turns one package ID into one vendor record:
the listing, its certification state, its class, and the latest status change.
Stdlib + requests only; nothing here knows about Paramify.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("fedramp_marketplace")

DEFAULT_DATA_BASE_URL = "https://raw.githubusercontent.com/FedRAMP/marketplace-fedramp-gov-data/main"
MARKETPLACE_PRODUCT_URL = "https://www.fedramp.gov/marketplace/products/{package_id}/"
REQUEST_TIMEOUT = 60

DATA_FILE = "data.json"
CHANGELOG_FILE = "fedramp-status-changelog.json"
CSO_PKG_FILE = "fedramp-frc-cso-pkg.json"

CERTIFIED = "certified"
IN_PROCESS = "in_process"
READY = "ready"
IN_REMEDIATION = "in_remediation"
DELISTED = "delisted"
NOT_LISTED = "not_listed"

# When one name matches several listings, the strongest state wins.
STATE_RANK = {CERTIFIED: 0, IN_PROCESS: 1, READY: 2}

# data.json still says "Authorized"; the changelog already says "Certified".
LISTING_STATUS = {
    "FedRAMP Authorized": CERTIFIED,
    "FedRAMP Certified": CERTIFIED,
    "FedRAMP Ready": READY,
    "FedRAMP In Process": IN_PROCESS,
    "Agency In Process": IN_PROCESS,
}

CHANGELOG_STATUS = {
    "FedRAMP Certified": CERTIFIED,
    "FedRAMP Authorized": CERTIFIED,
    "FedRAMP Certified (In Remediation)": IN_REMEDIATION,
    "No Status Found (Delisted)": DELISTED,
    "No Status Found": DELISTED,
    "FedRAMP Ready": READY,
    "FedRAMP In Process": IN_PROCESS,
    "Agency Authorization In Process": IN_PROCESS,
    "Initial Implementation": IN_PROCESS,
    "JAB Review": IN_PROCESS,
    "Initial Program Review": IN_PROCESS,
    "Final Program Review": IN_PROCESS,
}

# Fallback only, for a package FedRAMP publishes no class for.
DERIVED_CLASS = {
    "LI-SaaS": "A",
    "Low": "B",
    "20x Low": "B",
    "Moderate": "C",
    "20x Moderate": "C",
    "High": "D",
    "20x High": "D",
}

PACKAGE_ID_PATTERN = re.compile(r"\b(FR\d{10}[A-Z]{0,3}|F\d{10}[A-Z]{0,3})\b")
_CLASS_PATTERN = re.compile(r"^(?:Class\s+)?([A-D])$", re.IGNORECASE)


class CollectionError(Exception):
    """A failure that must end the invocation, carrying its contract `code`."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", value).strip("_").lower() or "vendor"


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_class(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    match = _CLASS_PATTERN.match(value.strip())
    return match.group(1).upper() if match else None


def _get_json(url: str) -> Dict[str, Any]:
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"})
    except requests.exceptions.RequestException as exc:
        raise CollectionError(f"GET {url} failed: {type(exc).__name__}: {exc}", "target_unreachable") from exc
    if response.status_code != 200:
        raise CollectionError(
            f"GET {url} returned HTTP {response.status_code}; body starts: {response.text[:200]!r}",
            "target_unreachable",
        )
    try:
        document = response.json()
    except ValueError as exc:
        raise CollectionError(f"GET {url} returned a body that is not JSON", "target_unreachable") from exc
    if not isinstance(document, dict):
        raise CollectionError(f"GET {url} returned JSON that is not an object", "target_unreachable")
    return document


class Marketplace:
    """The three FedRAMP files, indexed by package ID."""

    def __init__(
        self,
        data: Dict[str, Any],
        changelog: Dict[str, Any],
        cso_pkg: Dict[str, Any],
        *,
        source_urls: Dict[str, str],
        now: Optional[datetime] = None,
    ) -> None:
        products = (data.get("data") or {}).get("Products")
        rows = (changelog.get("data") or {}).get("certprocessstatuschangelog")
        packages = (cso_pkg.get("data") or {}).get("frc-cso-pkg")
        if not isinstance(products, list) or not products:
            raise CollectionError(f"{DATA_FILE} has no data.Products list", "target_unreachable")
        if not isinstance(rows, list) or not rows:
            raise CollectionError(f"{CHANGELOG_FILE} has no data.certprocessstatuschangelog list", "target_unreachable")
        if not isinstance(packages, list):
            raise CollectionError(f"{CSO_PKG_FILE} has no data.frc-cso-pkg list", "target_unreachable")

        self.products: Dict[str, Dict[str, Any]] = {
            p["id"]: p for p in products if isinstance(p, dict) and p.get("id")
        }
        self.changelog: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            if isinstance(row, dict) and row.get("product_id"):
                self.changelog.setdefault(row["product_id"], []).append(row)
        for history in self.changelog.values():
            history.sort(key=lambda r: (r.get("transition_date") or "", r.get("recorded_date") or ""))
        self.cso_pkg: Dict[str, Dict[str, Any]] = {}
        for pkg in packages:
            ident = (pkg.get("serviceIdentification") or {}) if isinstance(pkg, dict) else {}
            if ident.get("fedRampPackageId"):
                self.cso_pkg[ident["fedRampPackageId"]] = ident

        self.source_urls = source_urls
        self.data_last_change = (data.get("meta") or {}).get("last_change")
        self.changelog_exported = (changelog.get("metadata") or {}).get("export_timestamp")
        self.cso_pkg_exported = (cso_pkg.get("metadata") or {}).get("export_timestamp")
        self.now = now or datetime.now(timezone.utc)

    @classmethod
    def load(cls, base_url: Optional[str] = None) -> "Marketplace":
        base = (base_url or os.environ.get("FEDRAMP_MARKETPLACE_DATA_URL") or DEFAULT_DATA_BASE_URL).rstrip("/")
        urls = {name: f"{base}/{name}" for name in (DATA_FILE, CHANGELOG_FILE, CSO_PKG_FILE)}
        return cls(
            _get_json(urls[DATA_FILE]),
            _get_json(urls[CHANGELOG_FILE]),
            _get_json(urls[CSO_PKG_FILE]),
            source_urls=urls,
        )

    # -- feed ---------------------------------------------------------------

    def feed(self) -> Dict[str, Any]:
        # Age is the OLDER of the two status files: a validator reading it must
        # fail if either one stopped refreshing.
        stamps = [_parse_time(self.data_last_change), _parse_time(self.changelog_exported)]
        known = [s for s in stamps if s is not None]
        age = int((self.now - min(known)).total_seconds() // 3600) if len(known) == len(stamps) else None
        return {
            "source_urls": self.source_urls,
            "data_last_change": self.data_last_change,
            "changelog_exported": self.changelog_exported,
            "cso_pkg_exported": self.cso_pkg_exported,
            "listed_products": len(self.products),
            "feed_age_hours": age,
        }

    # -- one package --------------------------------------------------------

    def latest_change(self, package_id: str) -> Optional[Dict[str, Any]]:
        mapped = [r for r in self.changelog.get(package_id, []) if r.get("to_status") in CHANGELOG_STATUS]
        return mapped[-1] if mapped else None

    def listing_state(self, package_id: str) -> Optional[str]:
        product = self.products.get(package_id)
        return LISTING_STATUS.get(product.get("status")) if product else None

    def state(self, package_id: str) -> Tuple[str, bool]:
        """(certification_state, status_sources_disagree)."""
        listed = package_id in self.products
        change = self.latest_change(package_id)
        change_state = CHANGELOG_STATUS[change["to_status"]] if change else None
        listing_state = self.listing_state(package_id)
        if not listed:
            return (DELISTED if change else NOT_LISTED), False
        if change_state in (DELISTED, IN_REMEDIATION):
            return change_state, listing_state != change_state
        if change_state is None:
            return listing_state or NOT_LISTED, False
        # The changelog is the newer, per-transition record; it wins a tie-break.
        return change_state, listing_state is not None and listing_state != change_state

    def certification_class(self, package_id: str) -> Tuple[Optional[str], Optional[str]]:
        """(class, class_source), from the most authoritative source FedRAMP publishes."""
        stated = normalize_class((self.cso_pkg.get(package_id) or {}).get("certificationClass"))
        if stated:
            return stated, "cso_pkg"
        for row in reversed(self.changelog.get(package_id, [])):
            stated = normalize_class(row.get("cert_class"))
            if stated:
                return stated, "changelog"
        impact = (self.products.get(package_id) or {}).get("impact_level")
        derived = DERIVED_CLASS.get(impact) if isinstance(impact, str) else None
        return (derived, "derived") if derived else (None, None)

    def replacements(self, package_id: str) -> List[str]:
        """Listed IDs that look like a re-issue of this one (FR2000863987 -> FR2000863987A)."""
        prefix = re.sub(r"(?<=\d)[A-Z]+$", "", package_id)
        return sorted(
            pid for pid in self.products
            if pid != package_id and pid.startswith(prefix) and self.listing_state(pid) == CERTIFIED
        )

    def record(self, vendor_name: str, package_id: str, **extra: Any) -> Dict[str, Any]:
        state, disagree = self.state(package_id)
        product = self.products.get(package_id) or {}
        change = self.latest_change(package_id)
        cls, cls_source = self.certification_class(package_id)
        replaced_by = self.replacements(package_id) if state in (DELISTED, NOT_LISTED) else []
        listed_name = " - ".join(x for x in (product.get("csp"), product.get("cso")) if x) or None
        last = self.changelog.get(package_id, [])
        cert_type = (self.cso_pkg.get(package_id) or {}).get("certificationType") or (
            last[-1].get("cert_type") if last else None
        )
        return {
            "vendor_name": vendor_name,
            "package_id": package_id,
            "marketplace_url": MARKETPLACE_PRODUCT_URL.format(package_id=package_id),
            "listed_name": listed_name,
            "certification_state": state,
            "package_id_resolves": state != NOT_LISTED and not replaced_by,
            "suggested_package_ids": replaced_by,
            "certification_class": cls,
            "class_source": cls_source,
            "certification_type": cert_type,
            "impact_level": product.get("impact_level"),
            "fedramp_status": product.get("status"),
            "certification_path": product.get("auth_type"),
            "certification_date": product.get("fedramp_auth") if _parse_time(product.get("fedramp_auth")) else None,
            "latest_status_change": (
                {
                    "from_status": change.get("from_status"),
                    "to_status": change.get("to_status"),
                    "transition_date": change.get("transition_date"),
                    "recorded_date": change.get("recorded_date"),
                    "comments": change.get("comments") or None,
                }
                if change
                else None
            ),
            "status_sources_disagree": disagree,
            "pmo_note": _note(product.get("fedramp_msg")),
            **extra,
        }

    # -- name matching (workspace fetcher) ----------------------------------

    def match_name(self, name: str) -> Tuple[Optional[str], str, List[str]]:
        """(package_id, how, candidates) for a vendor known only by name.

        An exact name wins; otherwise a trailing " - <qualifier>" or
        "(<qualifier>)" is dropped and kept as a hint. Several matches are
        narrowed by state (certified > in process > ready) and then by the hint
        naming an impact level. Anything still ambiguous is returned unmatched.
        """
        hits = self._listings_named(name)
        hint = ""
        if not hits:
            stripped = re.sub(r"\s*(?:[-–—:]\s*[^-–—:]+|\([^)]*\))\s*$", "", name).strip()
            if stripped and stripped != name.strip():
                hint = name.strip()[len(stripped):]
                hits = self._listings_named(stripped)
        if not hits:
            return None, "unmatched", []
        if len(hits) == 1:
            return hits[0], "name", hits

        ranked = sorted(hits, key=lambda pid: STATE_RANK.get(self.listing_state(pid) or "", 9))
        best_rank = STATE_RANK.get(self.listing_state(ranked[0]) or "", 9)
        best = [pid for pid in ranked if STATE_RANK.get(self.listing_state(pid) or "", 9) == best_rank]
        if len(best) == 1:
            return best[0], "name_preferred_state", hits
        hinted = [pid for pid in best if _mentions(hint or name, self.products[pid].get("impact_level"))]
        if len(hinted) == 1:
            return hinted[0], "name_impact_level", hits
        return None, "ambiguous", hits

    def _listings_named(self, name: str) -> List[str]:
        key = _norm(name)
        if not key:
            return []
        out = []
        for pid, p in self.products.items():
            names = {p.get("cso"), p.get("name"), p.get("service_offering")}
            names |= {f"{p.get('csp')} {p.get('cso')}", f"{p.get('csp')} - {p.get('cso')}"}
            if key in {_norm(n) for n in names if n}:
                out.append(pid)
        return sorted(out)


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def _mentions(text: str, impact_level: Any) -> bool:
    if not isinstance(impact_level, str) or not impact_level:
        return False
    return re.search(rf"(?<![a-z0-9]){re.escape(_norm(impact_level))}(?![a-z0-9])", _norm(text)) is not None


# -- evidence --------------------------------------------------------------

def summarize(vendors: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(vendors)

    def count(pred) -> int:
        return sum(1 for v in rows if pred(v))

    state = lambda v: v.get("certification_state")  # noqa: E731
    return {
        "vendors_total": len(rows),
        "vendors_certified": count(lambda v: state(v) == CERTIFIED),
        "vendors_in_process": count(lambda v: state(v) == IN_PROCESS),
        "vendors_ready": count(lambda v: state(v) == READY),
        "vendors_in_remediation": count(lambda v: state(v) == IN_REMEDIATION),
        "vendors_delisted_or_not_listed": count(lambda v: state(v) in (DELISTED, NOT_LISTED)),
        "vendors_not_certified": count(lambda v: state(v) != CERTIFIED),
        "vendors_not_certified_or_in_process": count(
            lambda v: state(v) not in (CERTIFIED, IN_PROCESS, READY)
        ),
        "vendors_unresolved": count(lambda v: not v.get("package_id_resolves")),
    }


def build_evidence(vendors: List[Dict[str, Any]], market: Marketplace, **header: Any) -> Dict[str, Any]:
    # summary and feed come first: validators read the FIRST match of each count.
    return {
        "collected_at": current_timestamp(),
        **header,
        "summary": summarize(vendors),
        "feed": market.feed(),
        "vendors": vendors,
    }


def write_outputs(
    output_dir: Path,
    file_stem: str,
    vendors: List[Dict[str, Any]],
    market: Marketplace,
    output_mode: str,
    **header: Any,
) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_mode == "per_vendor" and vendors:
        targets = [
            (f"{file_stem}_{sanitize_for_filename(v['vendor_name'])}.json", [v]) for v in vendors
        ]
    else:
        targets = [(f"{file_stem}.json", vendors)]
    paths = []
    for name, rows in targets:
        path = output_dir / name
        with open(path, "w") as handle:
            json.dump(build_evidence(rows, market, output_mode=output_mode, **header), handle, indent=2, default=str)
        paths.append(path)
    return paths


def failure_evidence(reason: str, code: str, operation: str, **header: Any) -> Dict[str, Any]:
    return {
        "collected_at": current_timestamp(),
        **header,
        "vendors": [],
        "metadata": {
            "partial_failure": True,
            "api_failures": [{"operation": operation, "type": code, "message": reason}],
        },
    }


def output_mode_from_env(name: str = "FEDRAMP_OUTPUT_MODE") -> str:
    mode = (os.environ.get(name) or "combined").strip().lower()
    if mode not in ("combined", "per_vendor"):
        raise CollectionError(f"{name} must be 'combined' or 'per_vendor', got {mode!r}", "bad_config")
    return mode


def parse_pairs(raw: str, setting: str) -> List[Tuple[str, str]]:
    """'Okta Gov=FR2131856836, AWS GovCloud=F1603047866' -> [(name, id), ...]."""
    pairs = []
    for chunk in re.split(r"[,;\n]", raw or ""):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, package_id = chunk.rpartition("=")
        name, package_id = name.strip(), package_id.strip().upper()
        if not sep or not name or not package_id:
            raise CollectionError(
                f"{setting}: {chunk!r} is not 'Vendor Name=PACKAGE_ID'", "bad_config"
            )
        pairs.append((name, package_id))
    return pairs


def fail(output_dir: Path, file_stem: str, reason: str, code: str, operation: str, **header: Any) -> int:
    """Write an honest failure file, then report why. Logging last keeps the reason on stderr's tail."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / f"{file_stem}.json", "w") as handle:
            json.dump(failure_evidence(reason, code, operation, **header), handle, indent=2, default=str)
    except OSError as exc:
        logger.info("Could not write the failure evidence file: %s", exc)
    report_failure(reason, code)
    return 1


def _note(value: Any) -> Optional[str]:
    text = (value or "").strip() if isinstance(value, str) else ""
    return None if text.upper() in ("", "N/A") else text
