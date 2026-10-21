"""Evidence samples: one representative record per fetcher, captured once.

A sample answers "what does this fetcher surface?" without anyone running it.
Where a fetcher's payload repeats a record (one entry per EC2 instance, per
user, per subnet), the sample keeps ONE of them — the most filled-in, not the
first — and records how many were seen and how often each field was present.
Everything else in the payload (summary blocks, scalar settings) is kept as is.

Samples live beside the fetcher as `sample.json` and are committed, so they are
sanitized before they are written: identifiers are swapped for stable fakes of
the same shape, and a leak check refuses to write a sample that still contains
any identifier found in the source file. Free-text values (hostnames, resource
names, descriptions) are beyond what a rule can know, which is why every
backfilled sample starts `"reviewed": false` until a person has read it.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from framework.envelope import is_enveloped

SAMPLE_FILENAME = "sample.json"
SAMPLE_SCHEMA_VERSION = "1.0"

# Lists of scalars (tag values, subnet names) are trimmed too, to this many items.
_SCALAR_LIST_KEEP = 3


# --------------------------------------------------------------------------- #
# Shape: find the repeated records and keep the fullest one
# --------------------------------------------------------------------------- #

def _is_record_list(o: Any) -> bool:
    return isinstance(o, list) and bool(o) and all(isinstance(x, dict) for x in o)


_FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_keyed_map(o: Any) -> bool:
    """A dict keyed by data rather than by field names — {email: status},
    {region: {...}}, {module title: {...}}. Field names are identifiers; these
    keys have @, -, spaces or digits up front."""
    if not isinstance(o, dict) or len(o) < 4:
        return False
    odd = sum(1 for k in o if not _FIELD_NAME.match(k))
    return odd / len(o) >= 0.8


def _filled(v: Any) -> bool:
    return v not in (None, "", [], {})


def fullness(o: Any) -> int:
    """Count of non-empty leaf values — how much a record shows a reader."""
    if isinstance(o, dict):
        return sum(fullness(v) for v in o.values())
    if isinstance(o, list):
        return sum(fullness(v) for v in o)
    return 1 if _filled(o) else 0


def profile(payload: Any) -> List[dict]:
    """Every repeated collection in the payload, with record count and per-field
    presence. Nested collections are counted across ALL parents (every key of
    every vault, not just the vault the sample keeps). The payload's own
    `metadata` block is collection bookkeeping, not evidence, and is skipped."""
    found: Dict[str, dict] = {}

    def add(p: str, recs: List[Any]) -> dict:
        entry = found.setdefault(p, {"path": p, "records": 0, "fields": {}})
        entry["records"] += len(recs)
        for rec in recs:
            if not isinstance(rec, dict):
                continue
            for k, v in rec.items():
                if _filled(v):
                    entry["fields"][k] = entry["fields"].get(k, 0) + 1
                else:
                    entry["fields"].setdefault(k, 0)
        return entry

    def walk(o: Any, path: str) -> None:
        if _is_keyed_map(o):
            p = f"{path}{{}}"
            add(p, list(o.values()))
            for v in o.values():
                walk(v, p)
        elif isinstance(o, dict):
            for k, v in o.items():
                if path == "" and k == "metadata":
                    continue
                walk(v, f"{path}.{k}" if path else k)
        elif _is_record_list(o):
            p = f"{path}[]"
            add(p, o)
            for rec in o:
                walk(rec, p)

    walk(payload, "")
    return list(found.values())


def trim(o: Any) -> Any:
    """Keep the fullest record of every record list (ties go to the first) and
    the first few items of every scalar list; recurse into what is kept. A keyed
    map keeps its fullest entry when the entries are records, else its first few."""
    if _is_keyed_map(o):
        keys = list(o)
        if all(isinstance(v, dict) for v in o.values()):
            best = max(range(len(keys)), key=lambda i: (fullness(o[keys[i]]), -i))
            return {keys[best]: trim(o[keys[best]])}
        return {k: trim(o[k]) for k in keys[:_SCALAR_LIST_KEEP]}
    if isinstance(o, dict):
        return {k: trim(v) for k, v in o.items()}
    if _is_record_list(o):
        best = max(range(len(o)), key=lambda i: (fullness(o[i]), -i))
        return [trim(o[best])]
    if isinstance(o, list):
        return [trim(v) for v in o[:_SCALAR_LIST_KEEP]]
    return o


def has_records(profiled: List[dict]) -> bool:
    return any(c["records"] for c in profiled)


# --------------------------------------------------------------------------- #
# Sanitize: stable fakes of the same shape, then a leak check
# --------------------------------------------------------------------------- #

# Identity-bearing target/metadata keys. Their string values are replaced
# wherever they appear (a GCP project id inside a service-account email, an
# account id inside a bucket name). Location keys (region, zone) stay: they are
# not identifying and a reader needs them.
_IDENTITY_KEYS = {
    "account", "account_id", "arn", "profile", "project", "project_id",
    "project_number", "subscription", "subscription_id", "tenant", "tenant_id",
    "tenant_name", "organization", "organization_id", "org", "org_id", "domain",
    "instance", "instance_url", "workspace", "host", "hostname", "base_url",
    "url", "caller", "caller_arn", "principal",
}
# Identity values too generic to replace everywhere: `profile: default` must not
# turn every network named "default" into "example-profile".
_COMMON_VALUES = {"default", "test", "prod", "production", "staging", "dev", "none", "null"}

# Values under these keys name a person; replaced whole, whatever they contain.
_PERSON_KEY = re.compile(
    r"^(first|last|given|family|full|middle)_?name$|^surname$",
    re.I,
)
# `display_name` / `name` name a person only inside a user record (one that also
# carries a login); on a role or a policy they are the thing an assessor reads.
_USER_NAME_KEY = re.compile(r"^(display_?name|name)$", re.I)
# Login-ish keys: replaced whole too (an Azure guest UPN is not a valid email).
_LOGIN_KEY = re.compile(
    r"^(user_?principal_?name|upn|user_?name|login|username|user|email|mail|manager)$",
    re.I,
)
# Credential-shaped keys. Evidence should never carry these; if one does, the
# sample does not repeat it.
_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|api_?key|private_?key|access_?key|credential)s?$",
    re.I,
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+#'-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_ACCOUNT_ID = re.compile(r"(?<!\d)\d{12}(?!\d)")
# Key ids, fingerprints, hashes: identifiers, and long enough that a secret
# scanner reads them as credentials.
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_LONG_NUMBER = re.compile(r"(?<!\d)\d{10,}(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

# Email domains that belong to a cloud provider, not to the tenant. Kept, so a
# Google-managed service account still reads as one.
_PROVIDER_DOMAINS = (
    "gserviceaccount.com", "amazon.com", "amazonaws.com", "openssh.com",
    "example.com", "example.org", "example.net", "example",
)


def _provider_domain(domain: str) -> bool:
    d = domain.lower()
    return any(d == p or d.endswith("." + p) for p in _PROVIDER_DOMAINS)


@dataclass
class Needles:
    """Identifiers taken from the full source file. Each is replaced in the
    sample, and the leak check fails the sample if any one survives."""
    literals: Dict[str, str] = field(default_factory=dict)   # real -> fake
    persons: set = field(default_factory=set)                # names under person keys
    scrub: List[str] = field(default_factory=list)           # caller-supplied words

    def merge(self, other: "Needles") -> "Needles":
        """Fold in identifiers from other files (this file's fakes win), so an
        account id or profile name from one run is caught in another's sample."""
        for real, fake in other.literals.items():
            self.literals.setdefault(real, fake)
        self.persons |= other.persons
        return self


class _Faker:
    """Deterministic, per-sample replacement maps — the same real value always
    gets the same fake, and re-running a backfill gives byte-identical output."""

    def __init__(self) -> None:
        self.maps: Dict[str, Dict[str, str]] = {}

    def fake(self, kind: str, real: str, make) -> str:
        m = self.maps.setdefault(kind, {})
        if real not in m:
            m[real] = make(len(m) + 1)
        return m[real]


def _fake_account(n: int) -> str:
    return str(n % 10) * 12 if n % 10 else f"{n:012d}"


def _fake_uuid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def collect_needles(envelope: dict, scrub: Iterable[str] = ()) -> Needles:
    """Gather the identifiers in one evidence file: identity-keyed target and
    payload-metadata values, every email domain that is not a provider's, and
    every value under a person or login key anywhere in the payload."""
    needles = Needles(scrub=[s for s in scrub if s])
    meta = envelope.get("metadata") or {}
    payload = envelope.get("payload")

    def take_identity(d: Any) -> None:
        if not isinstance(d, dict):
            return
        for k, v in d.items():
            # Account ids and UUIDs are left to the shape-keeping regex fakes
            # below, so an ARN still reads as an ARN.
            if (k.lower() in _IDENTITY_KEYS and isinstance(v, str) and len(v) >= 4
                    and v.lower() not in _COMMON_VALUES
                    and not _ACCOUNT_ID.fullmatch(v) and not _UUID.fullmatch(v)):
                needles.literals.setdefault(v, f"example-{k.lower().replace('_', '-')}")

    take_identity(meta.get("target"))
    if isinstance(payload, dict):
        take_identity(payload.get("metadata"))

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            user = _is_user_record(o)
            for k, v in o.items():
                if isinstance(v, str) and v:
                    if (_PERSON_KEY.match(k) or _LOGIN_KEY.match(k)
                            or (user and _USER_NAME_KEY.match(k))):
                        needles.persons.add(v)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str):
            for m in _EMAIL.finditer(o):
                domain = m.group(0).rsplit("@", 1)[1]
                if not _provider_domain(domain):
                    needles.literals.setdefault(domain, "")

    walk(payload)
    # Domains get numbered fakes in a stable (sorted) order.
    n = 0
    for real in sorted(needles.literals):
        if needles.literals[real] == "":
            n += 1
            needles.literals[real] = f"example-{n}.com"
    return needles


def _sanitize_str(s: str, needles: Needles, faker: _Faker) -> str:
    def email(m: re.Match) -> str:
        local, domain = m.group(0).rsplit("@", 1)
        if _provider_domain(domain):
            # Keep the provider's shape; only the numbers in it identify anyone.
            local = _LONG_NUMBER.sub(
                lambda x: faker.fake("num", x.group(0), lambda n: f"{n:012d}"), local
            )
            return f"{local}@{domain}"
        return faker.fake("email", m.group(0), lambda n: f"user{n}@example.com")

    s = _EMAIL.sub(email, s)
    # Longest first, so a project id is not half-replaced by a shorter needle.
    # Case-insensitive: Azure upper-cases resource group names in resource ids.
    low = s.lower()
    for real in sorted(needles.literals, key=len, reverse=True):
        if real.lower() in low:
            s = re.sub(re.escape(real), needles.literals[real], s, flags=re.I)
            low = s.lower()
    for word in needles.scrub:
        s = re.sub(re.escape(word), "example", s, flags=re.I)
    s = _UUID.sub(lambda m: faker.fake("uuid", m.group(0).lower(), _fake_uuid), s)
    s = _ACCOUNT_ID.sub(lambda m: faker.fake("account", m.group(0), _fake_account), s)
    s = _LONG_HEX.sub(
        lambda m: faker.fake("hex", m.group(0).lower(), lambda n: f"{n:0{len(m.group(0))}x}"), s
    )

    def ip(m: re.Match) -> str:
        try:
            addr = ipaddress.ip_address(m.group(1))
        except ValueError:
            return m.group(0)
        if addr.is_unspecified or addr.is_loopback or addr.is_link_local:
            return m.group(0)
        if addr.is_private:
            return faker.fake("ip", m.group(1), lambda n: f"10.0.{n // 256}.{n % 256}")
        return faker.fake("ip", m.group(1), lambda n: f"203.0.113.{n % 256}")

    return _IPV4.sub(ip, s)


def _is_user_record(d: dict) -> bool:
    return any(
        _LOGIN_KEY.match(k) and isinstance(v, str) and "@" in v for k, v in d.items()
    )


def sanitize(
    o: Any, needles: Needles, faker: Optional[_Faker] = None, key: str = "",
    in_user: bool = False,
) -> Any:
    """Return a copy of `o` with identifiers replaced. Only strings are touched:
    a 12-digit integer is a byte count, not an account id."""
    faker = faker or _Faker()
    if isinstance(o, dict):
        user = _is_user_record(o)
        return {
            _sanitize_str(k, needles, faker): sanitize(v, needles, faker, k, user)
            for k, v in o.items()
        }
    if isinstance(o, list):
        return [sanitize(v, needles, faker, key) for v in o]
    if isinstance(o, str) and o:
        if _SECRET_KEY.search(key) and not key.lower().endswith(("_name", "_arn", "_id")):
            return "<redacted>"
        if _PERSON_KEY.match(key) or (in_user and _USER_NAME_KEY.match(key)):
            return faker.fake("person", o, lambda n: f"Person{n}")
        if _LOGIN_KEY.match(key):
            if _EMAIL.fullmatch(o):
                return _sanitize_str(o, needles, faker)
            return faker.fake("login", o, lambda n: f"user{n}")
        return _sanitize_str(o, needles, faker)
    return o


def find_leaks(sample: Any, needles: Needles) -> List[str]:
    """Every source identifier that still appears in the sanitized sample.
    Person names are matched as whole words (a last name of "Key" must not trip
    on "KeyRotation"); everything else as a substring, case-insensitively."""
    text = json.dumps(sample, ensure_ascii=False)
    low = text.lower()
    leaks = []
    for real in needles.literals:
        if real.lower() in low:
            leaks.append(real)
    for word in needles.scrub:
        if word.lower() in low:
            leaks.append(word)
    for name in needles.persons:
        if len(name) >= 3 and re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", text):
            leaks.append(name)
    for m in _EMAIL.finditer(text):
        if not _provider_domain(m.group(0).rsplit("@", 1)[1]):
            leaks.append(m.group(0))
    return sorted(set(leaks))


# --------------------------------------------------------------------------- #
# Build: pick the best source file, then trim + sanitize + check
# --------------------------------------------------------------------------- #

@dataclass
class Candidate:
    path: Path
    envelope: dict
    profiled: List[dict]

    @property
    def meta(self) -> dict:
        return self.envelope.get("metadata") or {}

    def score(self, current_version: str) -> Tuple:
        nonempty = sum(1 for c in self.profiled if c["records"])
        return (
            has_records(self.profiled),
            self.meta.get("fetcher_version") == current_version,
            self.meta.get("exit_code", 0) == 0,
            nonempty,
            fullness(trim(self.envelope.get("payload"))),
            str(self.meta.get("collected_at") or ""),
        )


def scan_evidence(evidence_dir: Path) -> Dict[str, List[Candidate]]:
    """Every enveloped evidence file under `evidence_dir`, grouped by fetcher.
    Underscore files (_run_metadata.json, sidecars) and unreadable files are
    skipped."""
    out: Dict[str, List[Candidate]] = {}
    for p in sorted(Path(evidence_dir).rglob("*.json")):
        if p.name.startswith("_"):
            continue
        try:
            raw = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not is_enveloped(raw):
            continue
        name = (raw.get("metadata") or {}).get("fetcher_name")
        if not name:
            continue
        out.setdefault(name, []).append(Candidate(p, raw, profile(raw.get("payload"))))
    return out


def best_candidate(candidates: List[Candidate], current_version: str) -> Candidate:
    return max(candidates, key=lambda c: c.score(current_version))


def collect_all_needles(candidates: Dict[str, List[Candidate]]) -> Needles:
    """The union of identifiers across every scanned evidence file."""
    out = Needles()
    for cs in candidates.values():
        for c in cs:
            out.merge(collect_needles(c.envelope))
    return out


def build_sample(
    candidate: Candidate, scrub: Iterable[str] = (), extra: Optional[Needles] = None,
) -> Tuple[dict, List[str]]:
    """The sample document for one source file, and any leaks found in it. A
    caller must not write a sample whose leak list is non-empty. `extra` adds
    identifiers from other evidence files (see `collect_all_needles`)."""
    meta = candidate.meta
    needles = collect_needles(candidate.envelope, scrub)
    if extra is not None:
        needles.merge(extra)
    faker = _Faker()
    payload = sanitize(trim(candidate.envelope.get("payload")), needles, faker)
    collections = [
        {**c, "path": _sanitize_str(c["path"], needles, faker),
         "fields": {_sanitize_str(k, needles, faker): v for k, v in c["fields"].items()}}
        for c in candidate.profiled
    ]
    collected = str(meta.get("collected_at") or "")
    doc = {
        "sample_schema_version": SAMPLE_SCHEMA_VERSION,
        "fetcher_name": meta.get("fetcher_name"),
        "fetcher_version": meta.get("fetcher_version"),
        "source": "live",
        "captured_on": collected[:10] or None,
        "reviewed": False,
        "collections": collections,
        "payload": payload,
    }
    return doc, find_leaks({"c": collections, "p": payload}, needles)


def sample_path(fetcher_dir: Path) -> Path:
    return Path(fetcher_dir) / SAMPLE_FILENAME


def read_sample(fetcher_dir: Path) -> Optional[dict]:
    p = sample_path(fetcher_dir)
    if not p.is_file():
        return None
    return json.loads(p.read_text())


def write_sample(fetcher_dir: Path, doc: dict) -> Path:
    p = sample_path(fetcher_dir)
    p.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return p
