"""FedRAMP significant change notifications: parse a change request's SCN section and validate it against FedRAMP's schema."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "fedramp_scn_2026-06-24.json"
SCHEMA_ID = "https://fedramp.gov/schemas/fedramp-significant-change-notifications-schema-2026-06-24.json"

# --- marker + section detection -------------------------------------------------
# A ticked task-list checkbox whose label mentions a significant change / SCN.
# Tolerates -, *, +; [x] or [X]; hyphen, en dash or em dash; trailing instructions.
MARKER_RE = re.compile(
    r"^\s*[-*+]\s*\[[xX]\]\s*.*significant\s+change.*$", re.MULTILINE | re.IGNORECASE
)
# Same line UNticked — used only to tell "author saw the box and left it off"
# apart from "the template isn't installed", which is a different conversation.
UNTICKED_MARKER_RE = re.compile(
    r"^\s*[-*+]\s*\[\s*\]\s*.*significant\s+change.*$", re.MULTILINE | re.IGNORECASE
)
# The sibling checkbox: an explicit SCN-RTR "routine recurring, no notification"
# declaration. Ticking it is a decision and belongs in the audit trail.
ROUTINE_RECURRING_RE = re.compile(
    r"^\s*[-*+]\s*\[[xX]\]\s*.*routine\s+recurring.*$", re.MULTILINE | re.IGNORECASE
)
EMERGENCY_RE = re.compile(
    r"^\s*[-*+]\s*\[[xX]\]\s*.*emergency\s+change.*$", re.MULTILINE | re.IGNORECASE
)

HEADING_RE = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<title>.+?)\s*$")
HR_RE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")
KV_RE = re.compile(r"^\s*\*\*(?P<key>[^*:]+?)\s*:?\s*\*\*\s*:?\s*(?P<value>.*)$")
BULLET_RE = re.compile(r"^\s*[-*+]\s+(?P<item>.+?)\s*$")
CHECKBOX_RE = re.compile(r"^\s*[-*+]\s*\[(?P<mark>[ xX])\]\s*(?P<label>.*?)\s*$")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
CHECKBOX_LINE_RE = re.compile(r"^\s*[-*+]\s*\[[ xX]\]\s*")
ISO_DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
# Greedy on the URL so a link target containing parens — the CPO URI ends in
# "(1).json" — survives extraction.
MD_LINK_RE = re.compile(r"^\[[^\]]*\]\((?P<url>.+)\)$")
MD_LINK_ANY_RE = re.compile(r"\[(?P<text>[^\]]*)\]\([^)]*(?:\([^)]*\)[^)]*)*\)")
BACKTICK_SPAN_RE = re.compile(r"`([^`]+)`")
# `**[REQUIRED]**`, `**\[REQUIRED within planAndTimeline\]**` — annotation, not value.
BOLD_BRACKET_TOKEN_RE = re.compile(r"\*\*\s*\\?\[[^\]]*\\?\]\s*\*\*")
PARENTHETICAL_RE = re.compile(r"\((?:[^()]|\([^()]*\))*\)")
BOLD_LABEL_RE = re.compile(r"\*\*[^*]*\*\*")
# A line that is nothing but bold label(s) — `**Impact Analysis**`, `** SCN Details**`.
# In the change-request template these are grouping headers, so they end the
# preceding field rather than belonging to it.
BOLD_ONLY_LINE_RE = re.compile(r"^\s*(?:\*\*[^*]+\*\*\s*)+$")
DATE_TOKEN_RE = re.compile(r"`?\b(?:\d{4}-\d{2}-\d{2}|Y{4}-M{2}-D{2})\b`?", re.IGNORECASE)

# --- the schema-key annotation the change-request template carries ---------------
# Paramify's template writes each field as e.g.
#     **Categorization Explanation** *(`changeTypeExplanation`)*
#     **Impacted KSIs or Rev5 Controls** *(`impactedControls[]`)*
# The backticked key is the field. Whitelisted so a stray backticked identifier
# in prose can never be mistaken for one.
KNOWN_SCHEMA_KEYS = {
    "certificationPackageOverviewUri",
    "assessorName",
    "relatedVulnerability",
    "changeType",
    "changeTypeExplanation",
    "changeDescription",
    "reason",
    "customerImpact",
    "impactAnalysis",
    "impactedControls",
    "planAndTimeline",
    "planAndTimeline.summary",
    "planAndTimeline.plannedStart",
    "planAndTimeline.plannedCompletion",
    "planAndTimeline.milestones",
}
SCHEMA_MARKER_RE = re.compile(
    r"\(\s*`(?P<key>[A-Za-z][A-Za-z0-9_.]*)(?:\[\])?`\s*\)"
)

# Heading text (normalized) -> SCN field, for templates with no schema markers.
HEADING_FIELD_MAP: Dict[str, str] = {
    "description": "changeDescription",
    "change description": "changeDescription",
    "short description": "changeDescription",
    "requested changes": "changeDescription",
    "change type": "changeType",
    "change type explanation": "changeTypeExplanation",
    "categorization explanation": "changeTypeExplanation",
    "reason": "reason",
    "reason for change": "reason",
    "customer impact": "customerImpact",
    "impact analysis": "impactAnalysis",
    "business or security impact analysis": "impactAnalysis",
    "security impact analysis": "impactAnalysis",
    "impact and security analysis": "impactAnalysis",
    "impacted controls": "impactedControls",
    "impacted ksis or rev5 controls": "impactedControls",
    "impacted ksis": "impactedControls",
    "plan and timeline": "planAndTimeline.summary",
    "plan": "planAndTimeline.summary",
    "timeline": "planAndTimeline.summary",
    "plan and timeline summary": "planAndTimeline.summary",
    "milestones": "planAndTimeline.milestones",
    "planned start": "planAndTimeline.plannedStart",
    "planned completion": "planAndTimeline.plannedCompletion",
    "planned end": "planAndTimeline.plannedCompletion",
    "related vulnerability": "relatedVulnerability",
    "assessor": "assessorName",
    "assessor name": "assessorName",
    "certification package overview uri": "certificationPackageOverviewUri",
}

# `**Key:** value` inline pairs -> SCN field (or payload-side provenance).
KV_FIELD_MAP: Dict[str, str] = {
    "change type": "changeType",
    "type": "changeType",
    "assessor": "assessorName",
    "assessor name": "assessorName",
    "related vulnerability": "relatedVulnerability",
    "vulnerability": "relatedVulnerability",
    "planned start": "planAndTimeline.plannedStart",
    "planned completion": "planAndTimeline.plannedCompletion",
    "planned end": "planAndTimeline.plannedCompletion",
    "certification package overview uri": "certificationPackageOverviewUri",
    # Provenance, not schema fields — SCN-CSO-INF wants an approver but the
    # FedRAMP JSON schema v0.1.2 has nowhere to put one.
    "approver": "_approver.name",
    "approver title": "_approver.title",
    "approver name": "_approver.name",
}

# --- SCN-CSO-INF: the information a notification must actually carry ------------
# FedRAMP's JSON schema requires only three properties. SCN-CSO-INF asks for far
# more, and the gap is not academic: a notification can validate perfectly while
# saying nothing about which controls the change touches, when it happens, or who
# approved it. Schema validity proves the document is well-formed; this table is
# what proves it is worth sending.
#
# "(if applicable)" items — assessorName, relatedVulnerability — are deliberately
# absent: SCN-CSO-INF conditions them, so their absence is not a defect.
SCN_CSO_INF_REQUIREMENTS: List[Tuple[str, str]] = [
    ("changeType", "change type (Adaptive or Transformative)"),
    ("changeTypeExplanation", "explanation of why the change was categorized that way"),
    ("changeDescription", "short description of the change"),
    ("reason", "reason for the change"),
    ("customerImpact", "summary of customer impact, including customer configuration responsibilities"),
    ("impactAnalysis", "business or security impact analysis"),
    ("impactedControls", "the KSIs or Rev5 controls verified, assessed or validated as part of the change"),
    ("planAndTimeline.summary", "plan and timeline summary, including the verification approach"),
    ("planAndTimeline.plannedStart", "the date changes to the system begin"),
    ("planAndTimeline.plannedCompletion", "the date the change is considered complete"),
    ("certificationPackageOverviewUri", "certification package overview URI"),
    ("_approver.name", "approver name"),
    ("_approver.title", "approver title"),
]

CHANGE_TYPE_CANON = {"adaptive": "Adaptive", "transformative": "Transformative"}

# Fields whose value is a URI and therefore arrives mangled by whatever pasted
# it: GitLab autolinks, a Markdown editor, or someone wrapping it in backticks.
URI_FIELDS = {"certificationPackageOverviewUri"}
DATE_FIELDS = {"planAndTimeline.plannedStart", "planAndTimeline.plannedCompletion"}
LIST_FIELDS = {"impactedControls"}
TEXT_FIELDS_WITH_LABEL_PREFIX = re.compile(r"^\s*(?:date|value|text)\s*:\s*", re.IGNORECASE)

# Template text nobody replaced. Emitting these is worse than emitting nothing:
# "YYYY-MM-DD" fails schema validation for a reason that tells you nothing, and
# "N/A" in an optional field is noise a reviewer has to read past.
PLACEHOLDER_RE = re.compile(
    r"""^(?:
        n\s*/?\s*a | tbd | tba | none | todo | tbc | \?+ | -+ |
        y{4}\s*-\s*m{2}\s*-\s*d{2} | mm/dd/yyyy | dd/mm/yyyy | hh:mm |
        [a-z]{2,5}-x+(?:-x+)? |
        [a-z]{2,5}-\?+ |
        x+
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("/", "_").replace(" ", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def normalize(text: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace — for fuzzy heading match."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).split())


def normalize_heading(title: str) -> str:
    """Heading text -> HEADING_FIELD_MAP key.

    Templates decorate a heading with its requiredness — `### **Change Type**
    **\\[REQUIRED\\]**`. That marker is presentation; the field name is what is
    left once it comes off.
    """
    return normalize(BOLD_BRACKET_TOKEN_RE.sub(" ", title or ""))


def is_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("`").strip("*").strip()
    v = MD_LINK_ANY_RE.sub(r"\1", v).strip()
    if not v:
        return True
    return bool(PLACEHOLDER_RE.match(v))


# --- markdown parsing -----------------------------------------------------------


def strip_comments(text: str) -> str:
    """Drop HTML comments — in a template most of the instructions live in them."""
    return HTML_COMMENT_RE.sub("", text or "")


def extract_section(
    description: str, heading: str, stop_at_any_heading: bool = False
) -> Optional[str]:
    """Return the body under the heading whose text CONTAINS `heading`.

    Fuzzy on purpose: the section is `## Significant Change` in one template and
    `## FedRAMP Significant Change Notification (SCN)` in another, and both mean
    the same thing. Ends at the next heading of the same or higher level, at a
    horizontal rule (which is how the change-request template closes the SCN
    block before `### Schedule`), or — with stop_at_any_heading — at any heading.
    """
    lines = (description or "").splitlines()
    needle = normalize(heading)

    start = None
    level = 0
    for i, line in enumerate(lines):
        m = HEADING_RE.match(line.strip())
        if m and needle in normalize(m.group("title")):
            start = i + 1
            level = len(m.group("hashes"))
            break
    if start is None:
        return None

    for j in range(start, len(lines)):
        stripped = lines[j].strip()
        m = HEADING_RE.match(stripped)
        if m and (stop_at_any_heading or len(m.group("hashes")) <= level):
            return "\n".join(lines[start:j])
        if HR_RE.match(stripped):
            return "\n".join(lines[start:j])
    return "\n".join(lines[start:])


def clean_uri_value(value: str) -> str:
    """Unwrap a URI from the Markdown people paste it inside.

    `[CPO](https://…)`, `<https://…>`, and `` `https://…` `` all reach us as the
    raw text of a field. Left alone they fail the absolute-URI check for a reason
    that has nothing to do with the URI.
    """
    v = (value or "").strip()
    m = MD_LINK_RE.match(v)
    if m:
        v = m.group("url").strip()
    v = v.strip("`").strip()
    if v.startswith("<") and v.endswith(">"):
        v = v[1:-1].strip()
    return v.strip()


URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s`<>\"]+")


def extract_uri(body: str) -> Optional[str]:
    """Find the URI in a block, whatever it is wrapped in.

    Deliberately NOT built on strip_annotations: that helper strips parenthesised
    instruction text, and the CPO URI ends in "(1).json", so running it over an
    already-extracted URI silently amputates the "(1)". Ask for the URI directly.
    """
    text = (body or "").strip()
    for span in BACKTICK_SPAN_RE.findall(text):
        if "://" in span:
            return span.strip()
    unwrapped = clean_uri_value(text)
    if "://" in unwrapped and not unwrapped.split("://", 1)[1].startswith(" "):
        if len(unwrapped.split()) == 1:
            return unwrapped
    m = URL_RE.search(text)
    if m:
        return m.group(0).rstrip("`)>\"',.")
    return None


def clean_body(body: str) -> str:
    """Drop checkbox lines, unwrap soft-wrapped prose, collapse blank runs.

    Markdown editors hard-wrap paragraphs at ~80 columns. Those newlines are a
    rendering artifact, not authorial intent, and carrying them into
    `changeDescription` gives FedRAMP a field with line breaks mid-sentence. So
    prose paragraphs get joined into one line, while list items, code fences,
    tables, and quotes keep their structure — `planAndTimeline.summary` is
    explicitly allowed to be Markdown.
    """
    kept = [l for l in body.splitlines() if not CHECKBOX_LINE_RE.match(l)]

    out: List[str] = []
    para: List[str] = []
    in_code = False

    def flush() -> None:
        if para:
            out.append(" ".join(part.strip() for part in para))
            para.clear()

    for line in kept:
        stripped = line.strip()
        if stripped.startswith("```"):
            flush()
            in_code = not in_code
            out.append(line)
            continue
        if in_code:
            out.append(line)
            continue
        if not stripped:
            flush()
            out.append("")
            continue
        if re.match(r"^\s*([-*+]|\d+[.)])\s+|^\s*>|^\s*\||^#{1,6}\s", line):
            flush()
            out.append(line)
            continue
        para.append(line)
    flush()

    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


def parse_list(body: str) -> List[str]:
    """Bullet list, or a single comma-separated line. Both are in the wild."""
    items = [m.group("item").strip() for m in (BULLET_RE.match(l) for l in body.splitlines()) if m]
    if items:
        return [i for i in items if i]
    flat = " ".join(body.split())
    if not flat:
        return []
    return [part.strip() for part in flat.split(",") if part.strip()]


def parse_milestones(body: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """`YYYY-MM-DD | description`, `date — description`, `description (date)`.

    A milestone whose date is still the `YYYY-MM-DD` placeholder keeps its
    description and loses the date — the description is real information and
    dropping the whole row would hide that someone planned the step.
    """
    milestones: List[Dict[str, Any]] = []
    notes: List[str] = []
    undated = 0

    for item in parse_list(body):
        date_match = ISO_DATE_RE.search(item)
        target_date = date_match.group(1) if date_match else None

        text = DATE_TOKEN_RE.sub(" ", item)
        text = text.replace("`", " ").strip()
        text = text.strip("()[]").strip()
        text = re.sub(r"^[\s\-–—:•|]+", "", text)
        text = re.sub(r"[\s\-–—:|]+$", "", text).strip()
        text = " ".join(text.split())

        if not text and not target_date:
            continue
        if is_placeholder(text):
            continue

        entry: Dict[str, Any] = {"milestoneDescription": text or item.strip()}
        if target_date:
            entry["targetDate"] = target_date
        else:
            undated += 1
        milestones.append(entry)

    if undated:
        notes.append(
            f"{undated} milestone(s) have no target date — the YYYY-MM-DD placeholder was left in place"
        )
    return milestones, notes


def ticked_labels(body: str) -> List[str]:
    """Labels of ticked checkboxes, with Markdown links reduced to their text."""
    out: List[str] = []
    for line in (body or "").splitlines():
        m = CHECKBOX_RE.match(line)
        if m and m.group("mark").lower() == "x":
            label = MD_LINK_ANY_RE.sub(r"\1", m.group("label"))
            label = label.replace("*", "").strip()
            label = re.sub(r"^[\s\-–—]+|[\s\-–—]+$", "", label)
            if label:
                out.append(label)
    return out


def strip_annotations(text: str) -> str:
    """Remove a marker line's decoration, leaving only an actual value.

    A marker line is mostly annotation:
        **Certification Package Overview URI** *(`…Uri`)* **[REQUIRED]** `https://…`
        **Impacted KSIs or Rev5 Controls** *(`impactedControls[]`)* (List KSI … one per line.)
    The first carries a real value in backticks; the second carries only
    instructions. Backticked spans win when present, because that is where this
    template puts values; otherwise strip the annotation and see what is left.
    """
    t = SCHEMA_MARKER_RE.sub(" ", text or "")
    spans = BACKTICK_SPAN_RE.findall(t)
    if spans:
        return " ".join(s.strip() for s in spans).strip()
    t = BOLD_BRACKET_TOKEN_RE.sub(" ", t)
    t = PARENTHETICAL_RE.sub(" ", t)
    t = BOLD_LABEL_RE.sub(" ", t)
    t = t.replace("*", " ")
    return " ".join(t.split()).strip()


def parse_schema_markers(section: str) -> Dict[str, str]:
    """Split a section on its `*(`schemaKey`)*` annotations into key -> raw body.

    Everything from a marker to the next marker belongs to that field, including
    the remainder of the marker's own line.
    """
    blocks: Dict[str, List[str]] = {}
    current: Optional[str] = None

    for line in (section or "").splitlines():
        m = SCHEMA_MARKER_RE.search(line)
        key = m.group("key") if m else None
        if key and key in KNOWN_SCHEMA_KEYS:
            current = key
            blocks.setdefault(current, [])
            remainder = strip_annotations(line)
            if remainder:
                blocks[current].append(remainder)
            continue
        if BOLD_ONLY_LINE_RE.match(line):
            # A grouping header like `**Impact Analysis**` closes the field above
            # it. Without this, `N/A` under **Assessor Name** absorbs the header
            # and stops looking like the placeholder it is.
            current = None
            continue
        if current:
            blocks[current].append(line)

    return {k: "\n".join(v).strip() for k, v in blocks.items()}


def parse_section(section: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Split a section into (heading -> body, inline key -> value).

    Sub-headings of any level become blocks. `**Key:** value` lines are pulled out
    wherever they appear — including inside a block — because that is how people
    actually write them (a `**Planned Start:**` under `### Plan and Timeline`).
    """
    blocks: Dict[str, List[str]] = {}
    kvs: Dict[str, str] = {}
    current = ""
    blocks[current] = []

    for raw in (section or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        m = HEADING_RE.match(stripped)
        if m:
            current = normalize_heading(m.group("title"))
            blocks.setdefault(current, [])
            continue

        kv = KV_RE.match(stripped)
        if kv and not SCHEMA_MARKER_RE.search(stripped):
            key = kv.group("key").strip().lower()
            value = kv.group("value").strip()
            if value:
                kvs[key] = value
            # A `**Key:** value` line is metadata, not prose — keep it out of the
            # block body so summaries don't end up with label noise in them.
            continue

        blocks[current].append(line)

    return {k: "\n".join(v).strip() for k, v in blocks.items()}, kvs


def set_nested(target: Dict[str, Any], dotted: str, value: Any) -> None:
    head, _, tail = dotted.partition(".")
    if not tail:
        target[head] = value
        return
    target.setdefault(head, {})
    set_nested(target[head], tail, value)


def coerce_field(
    field: str, body: str, notes: List[str], label: str
) -> Optional[Any]:
    """Turn a raw block into the value the schema wants, or None to omit it."""
    if field == "changeType":
        ticked = [t for t in ticked_labels(body) if normalize(t) in CHANGE_TYPE_CANON]
        if len(ticked) > 1:
            notes.append(f"{label}: more than one change type is ticked ({', '.join(ticked)})")
            return None
        if ticked:
            return CHANGE_TYPE_CANON[normalize(ticked[0])]
        flat = strip_annotations(body) or clean_body(body)
        canon = CHANGE_TYPE_CANON.get(normalize(flat))
        if canon:
            return canon
        # A checkbox pair with nothing ticked is the common case, and quoting 60
        # characters of the explanatory blurb back at the reader helps nobody.
        if any(CHECKBOX_RE.match(l) for l in (body or "").splitlines()):
            notes.append(f"{label}: neither Adaptive nor Transformative is ticked")
        elif is_placeholder(flat) or not flat:
            notes.append(f"{label}: no change type given — add Adaptive or Transformative")
        else:
            notes.append(f"{label}: '{flat[:60]}' is not Adaptive or Transformative")
        return None

    if field in URI_FIELDS:
        value = extract_uri(body)
        if not value or is_placeholder(value):
            return None
        return value

    if field in DATE_FIELDS:
        m = ISO_DATE_RE.search(body or "")
        if not m:
            notes.append(f"{label}: no date filled in (still the YYYY-MM-DD placeholder)")
            return None
        return m.group(1)

    if field == "planAndTimeline.milestones":
        milestones, milestone_notes = parse_milestones(body)
        notes.extend(f"{label}: {n}" for n in milestone_notes)
        return milestones or None

    if field in LIST_FIELDS:
        raw = parse_list(clean_body(body))
        items = [i.strip().strip("`").strip() for i in raw]
        real = [i for i in items if i and not is_placeholder(i)]
        dropped = [i for i in items if i and is_placeholder(i)]
        if dropped:
            notes.append(
                f"{label}: {len(dropped)} placeholder entr{'y' if len(dropped) == 1 else 'ies'} "
                f"left unfilled ({', '.join(dropped[:4])})"
            )
        return real or None

    text = clean_body(body)
    text = TEXT_FIELDS_WITH_LABEL_PREFIX.sub("", text).strip()
    if not text or is_placeholder(text):
        return None
    return text


def build_scn(
    section: str,
    full_description: str,
    default_cert_uri: str,
    fallback_description: str,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
    """Assemble an SCN object from one MR.

    Returns (scn, provenance_extras, parse_notes). Parse notes are human-readable
    remarks about what the MR did not supply — they are evidence in their own
    right and are surfaced in the payload.
    """
    scn: Dict[str, Any] = {}
    extras: Dict[str, Any] = {}
    notes: List[str] = []

    # (a) Schema-key annotations — authoritative when the template carries them.
    marker_blocks = parse_schema_markers(section)
    for field, body in marker_blocks.items():
        if field == "planAndTimeline":
            continue  # a grouping label, not a leaf field
        value = coerce_field(field, body, notes, field)
        if value is not None:
            set_nested(scn, field, value)

    blocks, kvs = parse_section(section)

    # (b) `**Key:** value` inline pairs, for templates without annotations.
    for key, value in kvs.items():
        field = KV_FIELD_MAP.get(key)
        if not field:
            continue
        if field.startswith("_"):
            if not is_placeholder(value):
                set_nested(extras, field.lstrip("_"), value)
            continue
        if _already_set(scn, field):
            continue
        coerced = coerce_field(field, value, notes, key)
        if coerced is not None:
            set_nested(scn, field, coerced)

    # (c) Heading names, for templates without annotations.
    for heading, body in blocks.items():
        field = HEADING_FIELD_MAP.get(heading)
        if not field or _already_set(scn, field):
            continue
        value = coerce_field(field, body, notes, heading)
        if value is not None:
            set_nested(scn, field, value)

    # Approver: SCN-CSO-INF requires a name and title; the schema has no field.
    for key in ("approver", "approver name"):
        if key in kvs and not is_placeholder(kvs[key]):
            extras.setdefault("approver", {})["name"] = kvs[key]
    if "approver title" in kvs and not is_placeholder(kvs["approver title"]):
        extras.setdefault("approver", {})["title"] = kvs["approver title"]

    # Fields the change-request template holds OUTSIDE the SCN section. Looking
    # there is not a liberty: the content is on the same merge request, written
    # for this change, and the alternative is a required field falling back to a
    # branch name. Every borrow is recorded.
    if not scn.get("changeDescription"):
        borrowed, source = _borrow_by_marker(full_description, "changeDescription")
        if not borrowed:
            borrowed, source = _borrow(full_description, ["Requested Changes", "Summary", "Description"])
        if borrowed:
            scn["changeDescription"] = borrowed
            notes.append(f"changeDescription taken from the MR's '{source}' section")
        elif fallback_description:
            scn["changeDescription"] = fallback_description
            notes.append("changeDescription fell back to the MR title")
        else:
            notes.append("changeDescription missing and no MR title to fall back on")

    if not scn.get("impactAnalysis"):
        borrowed, source = _borrow_by_marker(full_description, "impactAnalysis")
        if not borrowed:
            borrowed, source = _borrow(
                full_description,
                ["Impact and Security Analysis", "Impact Analysis", "Security Impact Analysis"],
            )
        if borrowed:
            scn["impactAnalysis"] = borrowed
            notes.append(f"impactAnalysis taken from the MR's '{source}' section")

    if not scn.get("certificationPackageOverviewUri") and default_cert_uri:
        scn["certificationPackageOverviewUri"] = default_cert_uri

    if "changeType" not in scn and not any(
        "change type" in n.lower() or "changetype" in n.lower() for n in notes
    ):
        notes.append("changeType missing — tick Adaptive or Transformative")

    plan = scn.get("planAndTimeline")
    if isinstance(plan, dict) and "summary" not in plan:
        # planAndTimeline.summary is required *if* the object exists. Dates or
        # milestones with no summary would fail validation on a technicality.
        notes.append(
            "planAndTimeline has dates or milestones but no summary — "
            "the summary is required whenever the block is present"
        )

    return scn, extras, notes


def _already_set(scn: Dict[str, Any], dotted: str) -> bool:
    node: Any = scn
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return node not in (None, "", [], {})


def _borrow_by_marker(description: str, field: str) -> Tuple[Optional[str], Optional[str]]:
    """Body of a heading OUTSIDE the SCN section annotated with this schema key.

    `changeDescription` and `impactAnalysis` are FedRAMP fields the change-request
    template has no slot for inside the SCN block — the content lives further up,
    under `## Requested Changes` and `### Impact and Security Analysis`. Annotating
    those headings, e.g.

        ## Requested Changes *(`changeDescription`)*

    makes the mapping explicit and portable: a team can point the field at any
    heading they like without anyone editing the alias list in this file.
    """
    lines = (description or "").splitlines()
    for i, line in enumerate(lines):
        h = HEADING_RE.match(line.strip())
        if not h:
            continue
        m = SCHEMA_MARKER_RE.search(h.group("title"))
        if not m or m.group("key") != field:
            continue
        level = len(h.group("hashes"))
        body: List[str] = []
        for nxt in lines[i + 1:]:
            if HEADING_RE.match(nxt.strip()) or HR_RE.match(nxt.strip()):
                break
            body.append(nxt)
        text = clean_body("\n".join(body))
        if text and not is_placeholder(text):
            title = SCHEMA_MARKER_RE.sub("", h.group("title")).strip()
            return text, title
        # An annotated-but-empty heading is a deliberate choice, not an oversight:
        # fall through to the name-based aliases rather than reporting nothing.
        _ = level
    return None, None


def _borrow(description: str, headings: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """First non-empty, non-placeholder section body among `headings`."""
    for heading in headings:
        body = extract_section(description, heading, stop_at_any_heading=True)
        if body is None:
            continue
        text = clean_body(body)
        if text and not is_placeholder(text):
            return text, heading
    return None, None


def parse_change_request_form(description: str) -> Dict[str, Any]:
    """Provenance from the change-request form wrapped around the SCN section.

    None of this belongs in the FedRAMP object, and all of it matters to whoever
    reads the evidence: an emergency change follows SCN-CSO-EMG rather than the
    normal path, and the completion checkbox is what starts the "within N business
    days of finishing" clock.
    """
    form: Dict[str, Any] = {
        "emergency_change": bool(EMERGENCY_RE.search(description or "")),
        "routine_recurring_declared": bool(ROUTINE_RECURRING_RE.search(description or "")),
    }
    scope = extract_section(description, "Scope", stop_at_any_heading=True)
    if scope:
        form["scope"] = ticked_labels(scope)
    impact = extract_section(description, "Impact", stop_at_any_heading=True)
    if impact:
        classes = [l for l in ticked_labels(impact) if re.match(r"^C\d\b", l)]
        if classes:
            form["impact_class"] = classes
    results = extract_section(description, "Results", stop_at_any_heading=True)
    if results:
        form["result"] = ticked_labels(results)
    return form


# --- validation -----------------------------------------------------------------


def assess_completeness(scn: Dict[str, Any], extras: Dict[str, Any]) -> Dict[str, Any]:
    """Check an SCN against SCN-CSO-INF, not just against the JSON schema.

    Returns {complete, missing:[{field, requirement}]}. Every field here is
    OPTIONAL as far as the schema is concerned, which is exactly why this exists:
    the schema cannot tell an empty notification from a complete one, and the
    empty one is the failure that actually costs you at review time.
    """
    missing: List[Dict[str, str]] = []
    for dotted, requirement in SCN_CSO_INF_REQUIREMENTS:
        source = extras if dotted.startswith("_") else scn
        node: Any = source
        for part in dotted.lstrip("_").split("."):
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if node in (None, "", [], {}):
            missing.append({"field": dotted.lstrip("_"), "requirement": requirement})
    return {"complete": not missing, "missing": missing}


def load_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text())
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_scn(validator: Draft202012Validator, scn: Dict[str, Any]) -> List[str]:
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(validator.iter_errors(scn), key=lambda e: list(e.absolute_path))
    ]
    # jsonschema only checks `format: uri` when rfc3987 is installed, which it
    # is not here. Check it ourselves rather than let a bare string through.
    uri = scn.get("certificationPackageOverviewUri")
    if isinstance(uri, str):
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            errors.append("certificationPackageOverviewUri: not an absolute URI")
    return errors
