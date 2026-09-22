#!/usr/bin/env python3
"""Check an onboarding's state directory against the gates it claims to have passed.

The onboard-platform skill decides its gates by what is on disk in
`.onboarding/<platform>/`, not by what anyone remembers. This reads that
directory, plus the fetchers it produced, and reports per stage what is
recorded, what is missing, and what contradicts the rules.

    python .claude/skills/onboard-platform/scripts/check_onboarding.py splunk
    python .claude/skills/onboard-platform/scripts/check_onboarding.py splunk --through slate
    python .claude/skills/onboard-platform/scripts/check_onboarding.py splunk --json

Stages run in the order the flow reaches them, and each includes the ones
before it:

    claim     step 3            claim.md and its provenance
    sandbox   step 5 / Gate 2   research, sandbox.json, teardown, measured.md
    slate     step 6 / Gate 1   the approved plan and every unbuilt row's state
    build     steps 7-8 / Gate 3 each built fetcher's completeness and verdict
    close     Gate 4            the sandbox's fate, and what is uncommitted

A stage passes when it reports no FAIL. WARN is for a human to look at and
never blocks; INFO is context. This checks what can be decided mechanically —
that a decision was recorded, that two counts match, that a file exists. It
cannot tell you the decision was right, and a clean run is not a substitute for
reading the files.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from pathlib import Path

# scripts/ -> onboard-platform/ -> skills/ -> .claude/ -> repo root. Overridable
# with --repo, which is how the checker is exercised against a fixture tree.
REPO = Path(__file__).resolve().parents[4]

STAGES = ["claim", "sandbox", "slate", "build", "close"]
LABEL = {
    "claim": "step 3",
    "sandbox": "step 5 · Gate 2",
    "slate": "step 6 · Gate 1",
    "build": "steps 7-8 · Gate 3",
    "close": "Gate 4",
}
# A slate row's state is the earliest of these words in its Status cell, since
# the cell leads with it and prose after it may mention another state.
STATE_WORDS = {
    "built": r"\bbuilt\b",
    "bailed": r"\bbail(?:ed)?\b",
    "parked": r"\bpark(?:ed)?\b",
    "cut": r"\bcut\b",
    "reassigned": r"\breassign(?:ed)?\b",
}
NOT_BUILT = ("bailed", "parked", "cut", "reassigned")
# Per-fetcher by nature, so a shared name across fetchers is not duplication.
PER_FETCHER = {"main", "collect"}
# A small helper that exists in two versions has almost certainly drifted; a
# large one with the same name is more likely legitimate per-fetcher logic.
SMALL_HELPER_LINES = 12
SECRET_KEY = re.compile(r"(?:^|_)(password|passwd|secret|token|api_?key)$", re.I)
ENV_REF = re.compile(r"^(\$\{env:[A-Za-z_][A-Za-z0-9_]*\}|[A-Z][A-Z0-9_]*)$")


class Report:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, stage: str, level: str, msg: str) -> None:
        self.rows.append({"stage": stage, "level": level, "message": msg})

    def ok(self, s: str, m: str) -> None:
        self.add(s, "PASS", m)

    def fail(self, s: str, m: str) -> None:
        self.add(s, "FAIL", m)

    def warn(self, s: str, m: str) -> None:
        self.add(s, "WARN", m)

    def info(self, s: str, m: str) -> None:
        self.add(s, "INFO", m)

    def fails(self, stage: str) -> int:
        return sum(1 for r in self.rows if r["stage"] == stage and r["level"] == "FAIL")


def read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def headings(text: str) -> list[str]:
    return [h.strip() for h in re.findall(r"^#{1,6}\s+(.*)$", text, re.M)]


def section(text: str, heading_pattern: str) -> str:
    """The body under the first heading matching the pattern, to the next heading."""
    m = re.search(rf"^(#{{1,6}})\s+{heading_pattern}.*$", text, re.M | re.I)
    if not m:
        return ""
    level = len(m.group(1))
    rest = text[m.end():]
    end = re.search(rf"^#{{1,{level}}}\s", rest, re.M)
    return rest[: end.start()] if end else rest


def bullets(text: str) -> list[str]:
    """Markdown bullets with their indented continuation lines, so a wrapped bullet is read whole."""
    out: list[str] = []
    for line in text.splitlines():
        if re.match(r"^\s*[-*]\s+", line):
            out.append(line.strip())
        elif out and line.strip() and line[:1].isspace():
            out[-1] += " " + line.strip()
    return out


def code_lines(script: str) -> list[str]:
    """Shell lines with comments removed, so a comment saying 'never prune' is not a prune."""
    out = []
    for line in script.splitlines():
        stripped = re.sub(r"(^|\s)#.*$", "", line).strip()
        if stripped:
            out.append(stripped)
    return out


def slate_table(text: str) -> tuple[list[str], list[dict]]:
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().startswith("|") and re.search(r"\bFetcher\b", line) and re.search(r"\bStatus\b", line, re.I):
            header = [c.strip() for c in line.strip().strip("|").split("|")]
            rows = []
            for row in lines[i + 2:]:
                if not row.lstrip().startswith("|"):
                    break
                cells = [c.strip() for c in row.strip().strip("|").split("|")]
                rows.append(dict(zip(header, cells)))
            return header, rows
    return [], []


def row_state(status: str) -> str:
    s = status.lower()
    hits = [(m.start(), state) for state, pat in STATE_WORDS.items() if (m := re.search(pat, s))]
    return min(hits)[1] if hits else "pending"


def row_fetcher(row: dict) -> tuple[str, str] | None:
    cell = next((v for k, v in row.items() if k.lower() == "fetcher"), "")
    m = re.search(r"\b([a-z0-9_]+)/([a-z0-9_]+)\b", cell)  # with or without backticks / strikethrough
    return (m.group(1), m.group(2)) if m else None


def gate_lines(notes: str, key: str) -> list[str]:
    return [m.strip() for m in re.findall(rf"^\s*(?:[-*]\s*)?`?{key}`?:\s*(.+)$", notes, re.M | re.I)]


def scan_secrets(obj, path: str = "") -> list[str]:
    """Key paths holding what looks like a literal credential. Never returns the value."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{path}.{k}" if path else str(k)
            if SECRET_KEY.search(str(k)) and isinstance(v, str) and v.strip() and not ENV_REF.match(v.strip()):
                found.append(here)
            found += scan_secrets(v, here)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found += scan_secrets(v, f"{path}[{i}]")
    return found


def functions(path: Path) -> dict[str, tuple[str, int]]:
    """Top-level functions -> (structure with docstring and formatting ignored, line count)."""
    src = read(path)
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {}
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body = body[1:]
            shape = ast.dump(node.args) + "".join(ast.dump(b) for b in body)
            out[node.name] = (shape, node.end_lineno - node.lineno + 1)
    return out


def tls_off_defaults(category: str) -> list[str]:
    """Places a TLS-verification setting defaults to off: a YAML config default, or a Python parameter default."""
    hits = []
    try:
        import yaml  # the repo venv has it; degrade rather than crash without it
    except ImportError:
        yaml = None

    def walk(node, where):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, dict) and re.search(r"verify", str(k), re.I) and v.get("default") is False:
                    hits.append(f"{where}: `{k}` defaults to false")
                walk(v, where)
        elif isinstance(node, list):
            for v in node:
                walk(v, where)

    if yaml:
        yamls = [REPO / "fetchers" / "_categories" / f"{category}.yaml"]
        yamls += sorted((REPO / "fetchers" / category).glob("*/fetcher.yaml"))
        for y in yamls:
            try:
                walk(yaml.safe_load(read(y)) or {}, str(y.relative_to(REPO)))
            except Exception:
                pass
    for py in sorted((REPO / "fetchers" / category).rglob("*.py")):
        try:
            tree = ast.parse(read(py))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args.args + node.args.kwonlyargs
                defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + list(node.args.defaults) \
                    + list(node.args.kw_defaults)
                for a, d in zip(args, defaults):
                    if re.search(r"verify", a.arg, re.I) and isinstance(d, ast.Constant) and d.value is False:
                        hits.append(f"{py.relative_to(REPO)}: `{node.name}({a.arg}=False)`")
    return hits


# ---------------------------------------------------------------------------


def check_claim(r: Report, st: Path) -> None:
    claim = read(st / "claim.md")
    if not claim:
        r.fail("claim", "claim.md missing — write the claim before researching (step 3)")
        return
    if re.search(r"^\*\*(Source|Provenance):\*\*\s*\S", claim, re.M) or re.search(r"pasted by user", claim, re.I):
        r.ok("claim", "claim.md records its provenance")
    else:
        r.fail("claim", "claim.md has no provenance — a `**Source:**` capability id + date, or `pasted by user, <date>`")


def check_sandbox(r: Report, st: Path) -> None:
    research = read(st / "research.md")
    if not research:
        r.fail("sandbox", "research.md missing (step 4)")
    else:
        todo = sum(1 for line in research.splitlines() if line.strip() == "TODO")
        if todo:
            r.warn("sandbox", f"research.md: {todo} heading(s) still read TODO — nothing was learned there; "
                              "carry them as open questions or re-brief narrowly")
        else:
            r.ok("sandbox", "research.md present, every skeleton heading filled")

    raw = read(st / "sandbox.json")
    try:
        sb = json.loads(raw) if raw else None
    except json.JSONDecodeError as e:
        r.fail("sandbox", f"sandbox.json is not valid JSON ({e.msg}, line {e.lineno})")
        sb = None
    if sb is None:
        if not raw:
            r.fail("sandbox", "sandbox.json missing — it is the approved-sandbox registry")
    else:
        leaks = scan_secrets(sb)
        if leaks:
            r.fail("sandbox", "sandbox.json holds what looks like a literal credential at "
                              + ", ".join(leaks) + " — store the env var NAME, never the value")
        if sb.get("approved_by") and sb.get("approved_at"):
            r.ok("sandbox", f"sandbox approved ({sb['approved_by']}, {sb['approved_at']})")
        else:
            r.fail("sandbox", "sandbox.json lacks approved_by/approved_at — the tenant is not approved")
        if isinstance(sb.get("cost_estimate_usd_month"), (int, float)):
            r.ok("sandbox", f"cost estimate recorded (${sb['cost_estimate_usd_month']}/month)")
        else:
            r.fail("sandbox", "cost_estimate_usd_month is not a number — state it in dollars, 0 included")

        teardown = REPO / str(sb.get("teardown") or f".onboarding/{st.name}/teardown.sh")
        if not teardown.is_file():
            r.fail("sandbox", f"teardown script missing ({teardown.relative_to(REPO)}) — write it before provisioning")
        else:
            if not teardown.stat().st_mode & 0o111:
                r.fail("sandbox", f"{teardown.name} is not executable")
            prunes = [line for line in code_lines(read(teardown)) if re.search(r"\bprune\b", line)]
            if prunes:
                r.fail("sandbox", f"{teardown.name} prunes: `{prunes[0]}` — teardown removes only what it names")
            else:
                r.ok("sandbox", f"{teardown.name} present and removes by name, not by prune")

        seeding = sb.get("seeding")
        if not seeding:
            r.fail("sandbox", "sandbox.json has no `seeding` decision — record NOT REQUIRED (with why) or the plan")
        elif str(seeding).strip().upper().startswith("NOT REQUIRED"):
            r.ok("sandbox", "seeding recorded as NOT REQUIRED")
        elif not (st / "seed.sh").is_file():
            r.fail("sandbox", "seeding is required but seed.sh is missing — seeding is a reviewable file")
        else:
            r.ok("sandbox", "seeding required and seed.sh present")

        verified = sb.get("verified") if isinstance(sb.get("verified"), dict) else {}
        if verified.get("failure_case_present"):
            r.ok("sandbox", "sandbox verified, failure case recorded")
        else:
            r.fail("sandbox", "sandbox.json has no verified.failure_case_present — without one, no validator "
                              "can be proven to fail at Gate 3")

    measured = read(st / "measured.md")
    if not measured:
        r.fail("sandbox", "measured.md missing — reconcile research against the live sandbox (step 5)")
    else:
        if any(re.search(r"true count", h, re.I) for h in headings(measured)):
            r.ok("sandbox", "measured.md has a true-counts section")
        else:
            r.fail("sandbox", "measured.md has no `## True counts` section — step 7.5 compares every fetcher "
                              "against it, measured through a path independent of the fetcher's")
        loose = [b for b in bullets(section(measured, r"Corrected\b")) if not re.search(r"fixed in:", b, re.I)]
        if loose:
            r.warn("sandbox", f"measured.md: {len(loose)} correction(s) without `fixed in:` — fix the superseded "
                              "fact where it lives, then say where")


def check_slate(r: Report, st: Path) -> tuple[list[dict], str]:
    slate = read(st / "slate.md")
    if not slate:
        r.fail("slate", "slate.md missing (step 6)")
        return [], ""
    if re.search(r"^\*\*Approved by:\*\*\s*\S", slate, re.M):
        r.ok("slate", "slate approval recorded")
    else:
        r.fail("slate", "slate.md has no `**Approved by:**` line — a slate without one is a proposal, not a plan")
    hs = headings(slate)
    if any(re.search(r"platform-wide", h, re.I) for h in hs):
        r.ok("slate", "platform-wide decisions recorded")
    else:
        r.fail("slate", "no `## Platform-wide decisions` — runtime, auth, hosts and fanout are settled once, here")

    n = len(slate.splitlines())
    if n > 300:
        r.fail("slate", f"slate.md is {n} lines — it is a plan, not a build log; move detail to notes/")
    elif n > 200:
        r.warn("slate", f"slate.md is {n} lines and growing — keep build detail in notes/")

    header, rows = slate_table(slate)
    if not rows:
        r.fail("slate", "no slate table found (a markdown table with Fetcher and Status columns)")
        return [], slate
    if any(re.search(r"provable", h, re.I) for h in header):
        r.ok("slate", f"slate table has {len(rows)} row(s) and a provable-on-sandbox column")
    else:
        r.fail("slate", "slate table has no `Provable on sandbox?` column")

    for row in rows:
        row["_state"] = row_state(next((v for k, v in row.items() if k.lower() == "status"), ""))
        row["_fetcher"] = row_fetcher(row)
    for i, row in enumerate(rows, 1):
        state, fid = row["_state"], row["_fetcher"]
        if not fid:
            # Never skip a row silently: an unreadable name means nothing below was checked for it.
            r.fail("slate", f"slate row {i}: cannot read a `<category>/<fetcher>` name in its Fetcher cell, "
                            "so nothing about it can be checked")
            continue
        if state not in NOT_BUILT:
            continue
        short = fid[1]
        stem = {"bailed": "bail", "parked": "park", "cut": "cut", "reassigned": "reassign"}[state]
        heading = next((h for h in hs if re.match(stem, h, re.I) and short in h), None)
        if not heading:
            r.fail("slate", f"{fid[0]}/{short} is {state} but has no `## {stem.capitalize()}… — {fid[0]}/{short}` "
                            "section saying " + {"bail": "why (the diagnosis)", "park": "what would unpark it",
                                                 "cut": "what it would have covered",
                                                 "reassign": "which platform owns it"}[stem])
        elif state == "parked" and not re.search(r"unpark", section(slate, re.escape(heading)), re.I):
            r.fail("slate", f"{fid[0]}/{short}: its Park section never says what would unpark it")
        else:
            r.ok("slate", f"{fid[0]}/{short}: {state}, with its own section")
    if any(row["_state"] in ("parked", "cut", "reassigned") for row in rows) or any(re.match(r"cut\b", h, re.I) for h in hs):
        if re.search(r"standing consequence", slate, re.I):
            r.ok("slate", "standing consequence recorded for the unbuilt rows")
        else:
            r.warn("slate", "rows are parked/cut/reassigned but no standing consequence is recorded — confirm "
                            "none was the only coverage for a clause of the claim")
    pending = sum(1 for row in rows if row["_state"] == "pending")
    if pending:
        r.info("slate", f"{pending} row(s) not yet started")
    return rows, slate


def check_build(r: Report, st: Path, rows: list[dict]) -> set[str]:
    built = [row["_fetcher"] for row in rows if row.get("_state") == "built" and row.get("_fetcher")]
    if not built:
        r.fail("build", "no fetcher built yet — Gate 3 needs fetcher #1 end to end")
        return set()
    for cat, short in built:
        name = f"{cat}/{short}"
        if not (REPO / "fetchers" / cat / short / "fetcher.yaml").is_file():
            r.fail("build", f"{name}: slate says built but fetchers/{name}/fetcher.yaml does not exist")
        notes = read(st / "notes" / f"{short}.md")
        if not notes:
            r.fail("build", f"{name}: notes/{short}.md missing")
            continue
        comp = gate_lines(notes, "completeness")
        if not comp:
            r.fail("build", f"{name}: no `completeness:` line in notes/{short}.md — record collected vs true count")
        for c in comp:
            got, true = re.search(r"collected\s*=\s*(\d+)", c), re.search(r"\btrue\s*=\s*(\d+)", c)
            if got and true:
                if got.group(1) == true.group(1):
                    r.ok("build", f"{name}: complete (collected {got.group(1)} = true {true.group(1)})")
                else:
                    r.fail("build", f"{name}: INCOMPLETE — collected {got.group(1)} of {true.group(1)}; truncated "
                                    "evidence published as complete is the failure nobody sees")
            elif c.lower().startswith("n/a") and len(c) > 6:
                r.warn("build", f"{name}: completeness not countable — {c}")
            else:
                r.fail("build", f"{name}: unreadable completeness line `{c}` — want `collected=N true=N source=…`")
        pred, real = gate_lines(notes, "predicted_verdict"), gate_lines(notes, "real_verdict")
        if not pred or not real:
            r.fail("build", f"{name}: record `predicted_verdict:` and `real_verdict:` in notes/{short}.md — "
                            "predict before scoring the real evidence")
        else:
            p, v = pred[0].split()[0].upper(), real[0].split()[0].upper()
            if p == v:
                r.ok("build", f"{name}: real-evidence verdict {v}, as predicted")
            elif gate_lines(notes, "surprise_resolved"):
                r.warn("build", f"{name}: predicted {p}, got {v} — resolved: {gate_lines(notes, 'surprise_resolved')[0]}")
            else:
                r.fail("build", f"{name}: predicted {p} but got {v} — the tenant, the evidence or the validator is "
                                "not what you think; resolve it and record `surprise_resolved:` before fanning out")
    return {cat for cat, _ in built}


def check_category(r: Report, cat: str, n_built: int) -> None:
    root = REPO / "fetchers" / cat
    if n_built >= 2:
        if any((root / "_shared").glob("*.py")):
            r.ok("build", f"{cat}: shared code lives in fetchers/{cat}/_shared/")
        else:
            r.fail("build", f"{cat}: {n_built} fetchers built and no fetchers/{cat}/_shared/ — lift the common "
                            "client before the next sibling, not after")
    per: dict[str, list[tuple[str, int, str]]] = {}
    for f in sorted(root.glob("*/fetcher.py")):
        if f.parent.name.startswith("_"):
            continue
        for fn, (shape, n) in functions(f).items():
            if fn not in PER_FETCHER:
                per.setdefault(fn, []).append((shape, n, f.parent.name))
    for fn, copies in sorted(per.items()):
        if len(copies) < 2:
            continue
        variants = len({c[0] for c in copies})
        where = ", ".join(c[2] for c in copies)
        if variants == 1:
            r.warn("build", f"{cat}: `{fn}` copied identically into {len(copies)} fetchers ({where}) — lift into _shared/")
        elif max(c[1] for c in copies) <= SMALL_HELPER_LINES:
            r.warn("build", f"{cat}: `{fn}` exists in {variants} versions across {where} — a small helper that "
                            "has drifted; lift one version into _shared/")
    tls = tls_off_defaults(cat)
    if tls:
        for t in tls:
            r.fail("build", f"TLS verification defaults off: {t} — default on, opt the sandbox out per target")
    else:
        r.ok("build", f"{cat}: TLS verification defaults on")


def check_close(r: Report, st: Path, cats: set[str]) -> None:
    try:
        sb = json.loads(read(st / "sandbox.json") or "{}")
    except json.JSONDecodeError:
        sb = {}
    td = sb.get("teardown_decision")
    if not isinstance(td, dict) or not td.get("decision"):
        r.fail("close", "no teardown_decision in sandbox.json — check whether the sandbox is running, ask the "
                        "user, then record {decision, by, at, why, review_by}")
    else:
        d = str(td["decision"]).lower()
        if d not in ("torn down", "left running"):
            r.fail("close", f"teardown_decision.decision is `{td['decision']}` — want `torn down` or `left running`")
        elif not (td.get("by") and td.get("at")):
            r.fail("close", "teardown_decision lacks `by`/`at` — a decision nobody owns is not one")
        elif d == "left running" and not td.get("review_by"):
            r.fail("close", "sandbox left running with no review_by date — when does someone look again?")
        else:
            r.ok("close", f"sandbox {d} ({td['by']}, {td['at']})")
    paths = [f"fetchers/{c}" for c in sorted(cats)] + [f"fetchers/_categories/{c}.yaml" for c in sorted(cats)]
    paths.append("validators")
    try:
        out = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", *paths],
                             capture_output=True, text=True, timeout=20).stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        out = []
    if out:
        r.info("close", f"{len(out)} onboarding file(s) uncommitted — list them for the user and let them commit "
                        "by explicit path; never fold them into an unrelated commit")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("platform", help="the .onboarding/<platform>/ directory name")
    ap.add_argument("--through", choices=STAGES, default="close", help="check stages up to and including this one")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--repo", type=Path, help="repo root (default: the repo this script lives in)")
    args = ap.parse_args()
    if args.repo:
        global REPO
        REPO = args.repo.resolve()

    st = REPO / ".onboarding" / args.platform
    r = Report()
    wanted = STAGES[: STAGES.index(args.through) + 1]
    if not st.is_dir():
        r.fail("claim", f".onboarding/{args.platform}/ does not exist — step 0 creates it")
    else:
        if "claim" in wanted:
            check_claim(r, st)
        if "sandbox" in wanted:
            check_sandbox(r, st)
        rows: list[dict] = []
        if "slate" in wanted:
            rows, _ = check_slate(r, st)
        cats: set[str] = set()
        if "build" in wanted:
            cats = check_build(r, st, rows)
            for cat in sorted(cats):
                check_category(r, cat, sum(1 for row in rows if row.get("_state") == "built"
                                           and row.get("_fetcher") and row["_fetcher"][0] == cat))
        if "close" in wanted:
            check_close(r, st, cats or {args.platform})

    clean = None
    for s in wanted:
        if r.fails(s):
            break
        clean = s
    blocked = next((s for s in wanted if r.fails(s)), None)
    code = 1 if blocked else 0

    if args.json:
        print(json.dumps({"platform": args.platform, "through": args.through, "clean_through": clean,
                          "blocked_at": blocked, "results": r.rows}, indent=2))
        return code

    print(f"onboarding: {args.platform}  (.onboarding/{args.platform}/)")
    for s in wanted:
        rows_s = [x for x in r.rows if x["stage"] == s]
        if not rows_s:
            continue
        print(f"\n── {s} · {LABEL[s]}")
        for x in rows_s:
            print(f"  {x['level']:4s}  {x['message']}")
    print()
    if blocked:
        print(f"Clean through: {clean or 'nothing'} — blocked at {blocked} ({r.fails(blocked)} FAIL). "
              f"That gate is not passed until this reports clean.")
    else:
        print(f"Clean through: {clean}.")
    return code


if __name__ == "__main__":
    sys.exit(main())
