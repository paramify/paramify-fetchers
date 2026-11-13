#!/usr/bin/env python3
"""Stand up a fake GitLab API and run the SCN fetcher against it.

Not a unit-test convention (the repo hasn't settled on one yet) — this is the
end-to-end wiring + parsing check described in docs/authoring_fetcher_guide.md
(step 3), done against a fake tenant instead of a real one.

The headline fixture is CHANGE_MR: a change-request template filled in the way
people actually fill them in — some fields written, some left as placeholders.

  python fetchers/gitlab/significant_change_notifications/tests/mock_gitlab.py
"""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
FETCHER = HERE.parent / "fetcher.py"
REPO = HERE.parents[3]

# A Certification Package Overview URI with percent-encoded spaces, which is
# enough to break naive URI handling on its own.
CPO_URI = (
    "https://trust.example.com/artifacts/"
    "11111111-2222-3333-4444-555555555555/66666666-7777-8888-9999-000000000000/"
    "Certification%20Package%20Overview%20-%2020x%20Class%20C.json"
)
# The same document under an older filename carrying literal parentheses, the
# signature of a duplicate browser download. Kept as a fixture because
# the greedy Markdown-link unwrap that survives "(1).json" is still live code and
# a URI with parens can reappear from any re-upload.
LEGACY_CPO_URI = (
    "https://trust.example.com/artifacts/"
    "11111111-2222-3333-4444-555555555555/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/"
    "cpo%20(1).json"
)
# What the fetcher gets when the env var is set but the MR says nothing.
FALLBACK_URI = "https://example.invalid/fallback-cpo.json"

# ---------------------------------------------------------------------------
# A change-request template filled in for a scanner replacement, including the
# unfilled placeholders — those are the point.
# ---------------------------------------------------------------------------
CHANGE_MR = """\
# Change Request
- [ ] Emergency Change (add Justification to Summary below)

### Scope
- [ ] Application Release (Helm), ticket: [ABC-??](https://example.atlassian.net/browse/ABC-??)
- [ ] Deployed Software (Helm)
- [X] Infrastructure (Terraform)
- [ ] Other (manual changes)

### Impact
- [ ] C1: High Impact/Risk, may cause Production downtime
- [ ] C2: Med Impact/Risk, may cause Production slowness, or Staging downtime
- [X] C3: Low Impact/Risk, may require complex manual changes
- [ ] C4: No Impact/Risk, common changes or fully automated

## Requested Changes
Replacing the incumbent third-party vulnerability scanner with a cloud security posture management platform across the authorization boundary. The replacement covers container runtime, cloud posture and source-code scanning in one tool.

### Impact and Security Analysis
Broader vulnerability coverage and more automated triage. Introduces a new third-party vendor with read access to cloud configuration metadata. Data-scanning features that would reach customer data are deliberately left disabled, so the vendor sees configuration state only.

## FedRAMP Significant Change Notification (SCN)
- [ ] [Routine Recurring](https://www.fedramp.gov/2026/providers/20x/rules/significant-change-notification/#routine-recurring-changes)  — SCN not required
- [X] Significant Change — SCN required (expand section below)

** SCN Details** — expand if Significant Change is checked above
Fields marked **\\[REQUIRED\\]** map to required FedRAMP schema properties.

**Change Type** *(`changeType`)* **\\[REQUIRED\\]**
- [X] Adaptive
- [ ] Transformative

[Adaptive](https://www.fedramp.gov/2026/providers/20x/rules/significant-change-notification/#adaptive-changes) changes typically require careful planning that focuses on engineering execution instead of customer adoption, can be verified with minor changes to existing automated validation procedures, and do not require large changes to operational procedures, deployment plans, or documentation.

Transformative changes typically introduce major features or capabilities that may change how a customer uses the service (in whole or in part) and require extensive updates to security assessments, operational procedures, deployment plans, and documentation.

**Categorization Explanation** *(`changeTypeExplanation`)*
This is a like-for-like component replacement. FedRAMP gives exactly this as an example of an adaptive change: replacing a component where some security plan or procedure adjustments are required, such as a scanning tool or managed database swap.

**Reason for Change** *(`reason`)*
Broader coverage across container runtime, cloud posture and source code, plus the automation needed to support risk-based vulnerability triage.

**Related Vulnerability** *(`relatedVulnerability`)*
N/A

**Assessor Name** *(`assessorName`)*
N/A

**Impact Analysis**
**Customer Impact** *(`customerImpact`)*
No customer impact anticipated. The scanner is a backend security tool and is not exposed to customers. No change to customer configuration responsibilities.

**Impacted Controls** **Impacted KSIs or Rev5 Controls** *(`impactedControls[]`)* (List KSI or control identifiers that will be verified, assessed, or validated as part of this change. One per line.)

- KSI-XXX-XX
- AC-X
- SI-X

**Plan and Timeline** **Summary** *(`planAndTimeline.summary`)* **\\[REQUIRED within planAndTimeline\\]** (Plan and timeline summary, including verification/assessment/validation approach for impacted KSIs or controls)

**Planned Start** *(`planAndTimeline.plannedStart`)*
Date: `YYYY-MM-DD`

**Planned Completion** *(`planAndTimeline.plannedCompletion`)*
Date: `YYYY-MM-DD`

**Milestones** *(`planAndTimeline.milestones[]`)*
- `YYYY-MM-DD` | Proof of Concept
- `YYYY-MM-DD` | Decision and Procurement
- `YYYY-MM-DD` | Setup and Onboarding
- `YYYY-MM-DD` | Fully functional

**Certification Package** **Certification Package Overview URI** *(`certificationPackageOverviewUri`)* **\\[REQUIRED\\]** `%CPO%`

---

### Schedule

Date/Time of Change: MM/DD/YYYY @ HH:MM

### Deployment Steps, Rollback Plan (if applicable)

(Provide code snippets or screenshots as needed)

## Results (after completion)

- [X] Change was completed successfully
- [ ] Change was NOT completed successfully but will be rescheduled
- [ ] Change was NOT completed successfully and will be canceled

/assign me
""".replace("%CPO%", CPO_URI)

# Same template, but actually finished: dates and controls filled in, plan
# summary written. This is what a compliant SCN looks like coming out.
CHANGE_MR_COMPLETE = (
    CHANGE_MR.replace(
        "- KSI-XXX-XX\n- AC-X\n- SI-X",
        "- KSI-CMT-VTD\n- KSI-MLA-OSM\n- RA-5\n- SI-2",
    )
    .replace(
        "*(`planAndTimeline.summary`)* **\\[REQUIRED within planAndTimeline\\]** "
        "(Plan and timeline summary, including verification/assessment/validation "
        "approach for impacted KSIs or controls)",
        "*(`planAndTimeline.summary`)* **\\[REQUIRED within planAndTimeline\\]**\n\n"
        "The replacement scanner runs in parallel with the incumbent until coverage is "
        "confirmed equivalent, after which the incumbent is retired. KSI-MLA-OSM and "
        "RA-5 are re-verified against the new output before decommissioning.",
    )
    .replace(
        "**Planned Start** *(`planAndTimeline.plannedStart`)*\nDate: `YYYY-MM-DD`",
        "**Planned Start** *(`planAndTimeline.plannedStart`)*\nDate: `2026-09-01`",
    )
    .replace(
        "**Planned Completion** *(`planAndTimeline.plannedCompletion`)*\nDate: `YYYY-MM-DD`",
        "**Planned Completion** *(`planAndTimeline.plannedCompletion`)*\nDate: `2026-11-14`",
    )
    .replace("- `YYYY-MM-DD` | Proof of Concept", "- `2026-09-08` | Proof of Concept")
    .replace("- `YYYY-MM-DD` | Decision and Procurement", "- `2026-09-29` | Decision and Procurement")
    .replace("- `YYYY-MM-DD` | Setup and Onboarding", "- `2026-10-20` | Setup and Onboarding")
    .replace("- `YYYY-MM-DD` | Fully functional", "- `2026-11-14` | Fully functional")
    .replace(
        "**Categorization Explanation** *(`changeTypeExplanation`)*",
        "**Approver:** A. Approver\n**Approver Title:** Director of Security Engineering\n\n"
        "**Categorization Explanation** *(`changeTypeExplanation`)*",
    )
)

# The routine-recurring path: SCN box unticked, SCN-RTR ticked instead.
ROUTINE_MR = """\
# Change Request
- [ ] Emergency Change

## Requested Changes
Monthly patching of the bastion AMI.

## FedRAMP Significant Change Notification (SCN)
- [X] [Routine Recurring](https://www.fedramp.gov/2026/providers/20x/rules/significant-change-notification/#routine-recurring-changes)  — SCN not required
- [ ] Significant Change — SCN required (expand section below)
"""

# An emergency change that IS significant — SCN-CSO-EMG, not the standard path.
EMERGENCY_MR = """\
# Change Request
- [X] Emergency Change (add Justification to Summary below)

## Requested Changes
Emergency rotation of the ingress TLS private key after a suspected exposure.

## FedRAMP Significant Change Notification (SCN)
- [ ] Routine Recurring  — SCN not required
- [X] Significant Change — SCN required

**Change Type** *(`changeType`)* **\\[REQUIRED\\]**
- [X] Adaptive
- [ ] Transformative

**Reason for Change** *(`reason`)*
Suspected exposure of the ingress TLS private key via a third-party log sink.

**Plan and Timeline** **Summary** *(`planAndTimeline.summary`)*
Key rotated immediately; certificate re-issued and pinned clients notified within 24 hours.

**Certification Package Overview URI** *(`certificationPackageOverviewUri`)* `%CPO%`
""".replace("%CPO%", CPO_URI)

# The older, heading-style template — no schema-key annotations at all. Proves
# the name-based fallback still works for teams that never adopt the new one.
HEADING_STYLE_MR = """\
## Significant Change

- [x] Significant Change — SCN required

**Change Type:** Transformative
**Approver:** Jane Doe
**Approver Title:** Director of Security Engineering
**Certification Package Overview URI:** [Paramify CPO](%LEGACY%)

### Description

Migrate the primary datacenter from us-east-1 to us-west-2.

### Plan and Timeline

Staged cutover with a read-only rehearsal window.

**Planned Start:** 2026-09-01
**Planned Completion:** 2026-09-15
""".replace("%LEGACY%", LEGACY_CPO_URI)

# Ticked the box, wrote nothing. Must fail loudly.
BROKEN_MR = """\
## FedRAMP Significant Change Notification (SCN)
- [X] Significant Change — SCN required

**Reason for Change** *(`reason`)*
We needed to.
"""

# The shipped template's [ADDED] annotations: schema keys on headings OUTSIDE the
# SCN section. Proves the annotation drives the mapping rather than decorating it —
# note the headings are renamed, so a name-based lookup would find nothing.
ANNOTATED_OUTER_MR = """\
# Change Request

## What We Are Changing *(`changeDescription`)*
Replace the ingress controller with an HTTP/3-capable build across all clusters.

### Security Review Notes *(`impactAnalysis`)*
No new data flows. The controller terminates TLS in the same trust boundary as
its predecessor, and no customer-facing certificate changes.

## FedRAMP Significant Change Notification (SCN)
- [X] Significant Change — SCN required

**Change Type** *(`changeType`)* **\\[REQUIRED\\]**
- [X] Adaptive
- [ ] Transformative

**Reason for Change** *(`reason`)*
HTTP/3 support was requested by two agency customers.

**Certification Package Overview URI** *(`certificationPackageOverviewUri`)* `%CPO%`
""".replace("%CPO%", CPO_URI)

PLAIN_MR = """\
## Requested Changes
Fix a typo in the README.
"""


def mr(iid, title, description, **over):
    base = {
        "iid": iid, "title": title, "state": "merged", "description": description,
        "author": {"name": "Sam Dev", "username": "sdev"},
        "created_at": "2026-08-01T10:00:00Z", "merged_at": "2026-08-04T16:20:00Z",
        "merged_by": {"name": "Jane Doe"}, "merge_commit_sha": f"sha{iid}",
        "source_branch": f"branch-{iid}", "target_branch": "main",
        "web_url": f"https://gitlab.example.com/acme/platform/-/merge_requests/{iid}",
        "labels": [],
    }
    base.update(over)
    return base


MERGE_REQUESTS = [
    mr(201, "Replace the vulnerability scanner", CHANGE_MR,
       labels=["significant-change"]),
    mr(202, "Replace the vulnerability scanner (fully filled in)", CHANGE_MR_COMPLETE),
    mr(203, "Monthly bastion AMI patching", ROUTINE_MR),
    mr(204, "Emergency TLS key rotation", EMERGENCY_MR),
    mr(205, "Datacenter migration to us-west-2", HEADING_STYLE_MR),
    mr(206, "Something significant but undocumented", BROKEN_MR),
    mr(207, "README typo", PLAIN_MR),
    mr(208, "HTTP/3 ingress controller", ANNOTATED_OUTER_MR),
]

APPROVALS = {
    "approvals_required": 2,
    "approved_by": [{"user": {"name": "Jane Doe"}}, {"user": {"name": "Chris Rev"}}],
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        if path.endswith("/merge_requests"):
            body = MERGE_REQUESTS
        elif path.endswith("/approvals"):
            body = APPROVALS
        else:
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def main() -> int:
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    status_path = Path("/tmp/scn-mock-status.json")
    if status_path.exists():
        status_path.unlink()
    out_dir = Path("/tmp/scn-mock-evidence")
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.json"):
        stale.unlink()

    # EVERY env var the fetcher reads, pinned explicitly — including the ones we
    # want unset, which are pinned to "".
    #
    # fetcher.py calls load_dotenv(), and python-dotenv resolves .env by walking
    # up from the CALLING FILE, not the CWD. So a developer's own repo-root .env
    # reaches this subprocess no matter where we run it from. It cannot clobber
    # what we set (load_dotenv defaults to override=False), but it happily fills
    # anything we leave out — which silently rewrites assertions. An empty string
    # still counts as "already in os.environ", so pinning to "" is what actually
    # holds the door shut.
    env = {
        "PATH": "/usr/bin:/bin",
        "GITLAB_URL": f"http://127.0.0.1:{port}",
        "GITLAB_API_TOKEN": "fake-token",
        "GITLAB_PROJECT_ID": "acme/platform",
        # Unset on purpose: MR !206 must fall through to the shared variable
        # below, which is what proves the SCN cites the same Certification
        # Package Overview as the paramify VER fetchers.
        "FEDRAMP_CERT_PACKAGE_URI": "",
        "PARAMIFY_CERT_PACKAGE_URI": FALLBACK_URI,
        "GITLAB_SCN_STATE": "merged",
        "GITLAB_SCN_DAYS_BACK": "3650",
        "GITLAB_SCN_MAX_RESULTS": "100",
        "GITLAB_SCN_MARKER_LABEL": "",
        "GITLAB_SCN_SECTION_HEADING": "Significant Change",
        "GITLAB_SCN_STRICT": "true",
        "GITLAB_SCN_REQUIRE_COMPLETE": "true",
        "EVIDENCE_DIR": str(out_dir),
        "LOG_LEVEL": "INFO",
        # The runner sets this and reads the failure reason back out of it. Left
        # unset, the whole report_failure channel goes untested and the envelope
        # silently falls back to the stderr tail — which is issue #24 all over.
        "FETCHER_STATUS_FILE": str(status_path),
    }
    # Belt and braces: run from an empty directory too. Every path the fetcher
    # touches is absolute, so nothing needs the repo root.
    with tempfile.TemporaryDirectory(prefix="scn-mock-cwd-") as sterile_cwd:
        proc = subprocess.run(
            [sys.executable, str(FETCHER)],
            env=env, capture_output=True, text=True, cwd=sterile_cwd,
        )
    server.shutdown()

    print("--- stderr ---")
    print(proc.stderr.strip())
    print(f"--- fetcher exit code: {proc.returncode} ---")

    files = sorted(out_dir.glob("*.json"))
    if not files:
        print("FAIL: no evidence file written")
        return 1
    ev = json.loads(files[0].read_text())
    print("--- summary ---")
    print(json.dumps(ev["summary"], indent=2))

    by_iid = {n["merge_request"]["iid"]: n for n in ev["notifications"]}
    skipped = {s["iid"]: s for s in ev["skipped_unticked"]}
    checks = []

    def check(name, cond):
        checks.append((name, bool(cond)))

    s = ev["summary"]
    check("8 MRs scanned", ev["merge_requests_scanned"] == 8)
    check("6 flagged (201,202,204,205,206,208)", s["flagged_count"] == 6)
    check("1 routine-recurring declared", s["routine_recurring_count"] == 1)
    check("1 emergency change", s["emergency_change_count"] == 1)
    check("no API failures", ev["api_failures"] == [])
    check("CPO URI came from the shared PARAMIFY_CERT_PACKAGE_URI",
          ev["metadata"]["certification_package_overview_uri_source"] == "PARAMIFY_CERT_PACKAGE_URI")
    check("no config warnings when only one CPO URI is set", ev["config_warnings"] == [])

    # --- 201: the template as people actually fill it in -------------------
    n201 = by_iid[201]
    scn = n201["scn"]
    check("201 flagged from the ticked [X] box", n201["merge_request"]["marked_via"] in ("checkbox", "label"))
    check("201 changeType Adaptive from the checkbox", scn.get("changeType") == "Adaptive")
    check("201 CPO URI read off the marker line, verbatim", scn.get("certificationPackageOverviewUri") == CPO_URI)
    check("201 changeDescription borrowed from Requested Changes",
          "vulnerability scanner" in (scn.get("changeDescription") or ""))
    check("201 changeDescription is NOT the MR title", scn.get("changeDescription") != MERGE_REQUESTS[0]["title"])
    check("201 impactAnalysis borrowed from Impact and Security Analysis",
          "configuration metadata" in (scn.get("impactAnalysis") or ""))
    check("201 changeTypeExplanation captured", "like-for-like" in (scn.get("changeTypeExplanation") or "").lower())
    check("201 reason captured", "risk-based vulnerability triage" in (scn.get("reason") or ""))
    check("201 customerImpact captured", (scn.get("customerImpact") or "").startswith("No customer impact"))
    check("201 customerImpact did not absorb the **Impact Analysis** header",
          "**" not in (scn.get("customerImpact") or ""))
    check("201 assessorName N/A dropped", "assessorName" not in scn)
    check("201 relatedVulnerability N/A dropped", "relatedVulnerability" not in scn)
    check("201 placeholder controls dropped", "impactedControls" not in scn)
    check("201 notes name the placeholder controls",
          any("KSI-XXX-XX" in n for n in n201["parse_notes"]))
    check("201 no YYYY-MM-DD anywhere in the SCN", "YYYY-MM-DD" not in json.dumps(scn))
    check("201 plannedStart omitted, not emitted as a placeholder",
          "plannedStart" not in scn.get("planAndTimeline", {}))
    check("201 milestone descriptions survived without dates",
          [m["milestoneDescription"] for m in scn["planAndTimeline"]["milestones"]]
          == ["Proof of Concept", "Decision and Procurement", "Setup and Onboarding", "Fully functional"])
    check("201 milestones carry no targetDate",
          all("targetDate" not in m for m in scn["planAndTimeline"]["milestones"]))
    check("201 INVALID — plan summary was left blank", not n201["validation"]["valid"])
    check("201 error points at planAndTimeline/summary",
          any("summary" in e for e in n201["validation"]["errors"]))
    check("201 note explains the missing summary",
          any("summary is required" in n for n in n201["parse_notes"]))
    check("201 no Markdown annotation leaked into the SCN", "[REQUIRED]" not in json.dumps(scn))
    form = n201["merge_request"]["change_request_form"]
    check("201 not an emergency change", form["emergency_change"] is False)
    check("201 scope captured", form.get("scope") == ["Infrastructure (Terraform)"])
    check("201 impact class C3 captured", form.get("impact_class") and form["impact_class"][0].startswith("C3"))
    check("201 completion result captured",
          form.get("result") == ["Change was completed successfully"])

    # --- 202: the same template, finished ---------------------------------
    n202 = by_iid[202]
    scn2 = n202["scn"]
    check("202 VALID once the plan summary is written", n202["validation"]["valid"])
    check("202 real controls parsed", scn2.get("impactedControls") == ["KSI-CMT-VTD", "KSI-MLA-OSM", "RA-5", "SI-2"])
    check("202 plannedStart parsed from backticks", scn2["planAndTimeline"].get("plannedStart") == "2026-09-01")
    check("202 plannedCompletion parsed", scn2["planAndTimeline"].get("plannedCompletion") == "2026-11-14")
    check("202 milestone dates parsed from `date` | description",
          scn2["planAndTimeline"]["milestones"][0] == {
              "milestoneDescription": "Proof of Concept", "targetDate": "2026-09-08"})
    check("202 plan summary captured", "runs in parallel" in scn2["planAndTimeline"]["summary"])
    check("202 no annotation leaked into the summary", "REQUIRED" not in scn2["planAndTimeline"]["summary"])
    check("202 COMPLETE under SCN-CSO-INF", n202["completeness"]["complete"])
    check("202 approver captured", n202.get("approver", {}).get("name") == "A. Approver")

    # 201 is the case the JSON schema cannot catch: valid, and hollow.
    check("201 completeness FAILS even though schema passes",
          not n201["completeness"]["complete"])
    missing201 = {m["field"] for m in n201["completeness"]["missing"]}
    check("201 missing impactedControls", "impactedControls" in missing201)
    check("201 missing plannedStart", "planAndTimeline.plannedStart" in missing201)
    check("201 missing approver name/title",
          {"approver.name", "approver.title"} <= missing201)
    check("201 conditional fields NOT demanded",
          not ({"assessorName", "relatedVulnerability"} & missing201))
    check("summary counts completeness",
          s["scn_cso_inf_complete_count"] + s["scn_cso_inf_incomplete_count"] == s["flagged_count"])

    # --- 203: routine recurring -------------------------------------------
    check("203 skipped, not flagged", 203 in skipped and 203 not in by_iid)
    check("203 recorded as an explicit SCN-RTR declaration",
          skipped[203]["routine_recurring_declared"] is True)
    check("203 reason names Routine Recurring", "Routine Recurring" in skipped[203]["reason"])

    # --- 204: emergency ----------------------------------------------------
    n204 = by_iid[204]
    check("204 VALID", n204["validation"]["valid"])
    check("204 emergency flag captured",
          n204["merge_request"]["change_request_form"]["emergency_change"] is True)
    check("204 note raises SCN-CSO-EMG", any("SCN-CSO-EMG" in n for n in n204["parse_notes"]))

    # --- 205: the old heading-style template still works --------------------
    n205 = by_iid[205]
    scn5 = n205["scn"]
    check("205 VALID via the heading fallback", n205["validation"]["valid"])
    check("205 changeType from **Change Type:** line", scn5.get("changeType") == "Transformative")
    check("205 legacy paren URI unwrapped from a Markdown link",
          scn5.get("certificationPackageOverviewUri") == LEGACY_CPO_URI)
    check("205 greedy unwrap kept the '(1)' segment",
          "(1)" in str(scn5.get("certificationPackageOverviewUri")))
    check("205 unwrapped URI kept its .json", str(scn5.get("certificationPackageOverviewUri")).endswith(".json"))
    check("205 approver carried beside the SCN",
          n205.get("approver", {}).get("title") == "Director of Security Engineering")
    check("205 plan dates from **Planned Start:** lines",
          scn5["planAndTimeline"].get("plannedStart") == "2026-09-01")

    # --- 206 / 207 ---------------------------------------------------------
    n206 = by_iid[206]
    check("206 INVALID", not n206["validation"]["valid"])
    check("206 falls back to the env CPO URI",
          n206["scn"].get("certificationPackageOverviewUri") == FALLBACK_URI)
    check("206 flags the missing changeType",
          any("changeType" in e for e in n206["validation"]["errors"]))
    check("206 changeDescription from Requested Changes or title",
          bool(n206["scn"].get("changeDescription")))
    check("207 not flagged at all", 207 not in by_iid and 207 not in skipped)

    # --- 208: annotations on outer headings drive the mapping ---------------
    n208 = by_iid[208]
    scn8 = n208["scn"]
    check("208 VALID", n208["validation"]["valid"])
    check("208 changeDescription from the *(`changeDescription`)* heading",
          "HTTP/3-capable" in (scn8.get("changeDescription") or ""))
    check("208 did NOT fall back to the MR title",
          scn8.get("changeDescription") != "HTTP/3 ingress controller")
    check("208 impactAnalysis from the *(`impactAnalysis`)* heading",
          "trust boundary" in (scn8.get("impactAnalysis") or ""))
    check("208 note credits the renamed heading",
          any("What We Are Changing" in n for n in n208["parse_notes"]))
    check("208 heading annotation stripped from the note",
          not any("`changeDescription`" in n for n in n208["parse_notes"]))

    # --- run-level ---------------------------------------------------------
    check("exit code 1 under strict", proc.returncode == 1)
    # The runner reads this file, not stderr. If it is missing the envelope's
    # metadata.error degrades to the stderr tail, whose last line may well be
    # "Evidence saved to ..." — a success message reported as the failure reason.
    status = json.loads(status_path.read_text()) if status_path.exists() else {}
    check("status file written for the strict failure", bool(status.get("error")))
    check("status file names the offending MR", "!201" in status.get("error", ""))
    check("status file carries a machine-readable code", status.get("code") == "partial_failure")
    check("status file error is NOT the stderr tail", "Evidence saved" not in status.get("error", ""))
    check("failure names the incomplete MRs", "!201" in proc.stderr and "!206" in proc.stderr)

    print("--- checks ---")
    failed = 0
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        failed += 0 if ok else 1
    print(f"--- {len(checks) - failed}/{len(checks)} passed ---")

    print("--- SCN from MR !202 (the finished one), verbatim FedRAMP object ---")
    print(json.dumps(scn2, indent=2))
    print("--- parse notes from MR !201 (partially filled in) ---")
    print(json.dumps(n201["parse_notes"], indent=2))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
