# `.onboarding/<platform>/` — the state directory

Read at any step of `onboard-platform` that writes or reads state.

## Why this exists

Subagents cannot read the main session's context. Steps 4 and 8–10 are
delegated, which means everything they need has to be on disk before they start
and everything they find has to be on disk when they finish. A finding that
lives only in a subagent's reply is a finding that gets re-derived.

It is also what makes this a **resumable** flow. Platform onboarding spans
sessions; the directory is what the next session reads instead of restarting.

One directory per platform, gitignored, alongside the existing `.paramify/`
local-state convention:

```
.onboarding/<platform>/
  claim.md        the narrative or pasted claim, with provenance
  research.md     step 4 output, docs-only, every claim marked
  measured.md     step 5, the live sandbox reconciled against research.md
  slate.md        the step 6 plan, its approval, and a status per fetcher
  sandbox.json    tenant ids, cost, approval — the approved-sandbox registry
  seed.sh         only if the platform's defaults don't supply the data (gated)
  teardown.sh     written before provisioning, executable
  notes/          one <fetcher>.md of build detail per fetcher, written at step 8
```

**`slate.md` stays small and `notes/` absorbs the detail.** They are read by
different things: the main session and the gates read `slate.md` and need it
scannable, while `notes/` is written once and read only when someone picks that
fetcher back up. Collapsing them grew the slate to 1,749 lines on the first
real run — see the warning at step 8.

**Never put credentials here.** Gitignored is a backstop against accidents, not
a keystore. Secrets are `${env:VAR}` refs resolved from the environment.

## claim.md

One claim, its provenance, and the control it serves. Steps 7–10 and every
subagent assert against this sentence, so there is exactly one of it.

```markdown
# Claim — <platform>

> The @Security Team reviews all privileged role grants in Snowflake at least
> quarterly and revokes any that are no longer justified.

**Source:** solution capability `1174772e-…` (`paramify capabilities show`), read 2026-09-21
**Family:** Logical Identity & Access / Privileged Access
**KSIs:** KSI-IAM-APM

## What this claim needs evidence of
- the set of privileged grants, at a point in time
- that a review happened, and when

## Why this one anchors the onboarding
The only candidate whose narrative carries a number — a validator can key on
"quarterly" and be falsified by one stale grant. The adjacent claims below are
prose-only and make weaker first validators.

## Adjacent claims — for the step 6 slate, not for fetcher #1
| Capability | id | Narrative, in short |
|---|---|---|
| Network Access Control | `3c6f3e41-…` | Access restricted to approved IP ranges, reviewed quarterly |
| Session Management | `9703e763-…` | Idle sessions terminate; re-auth required after timeout |

Both names resolve to two ids each in the workspace; these are the ones read on
2026-09-22.

## The coverage gap worth aiming at
`paramify ksi`, 2026-09-22: KSI-MLA-ALA is open, and Snowflake role RBAC is
precisely its subject.
```

Provenance is either a capability id and the date it was read, or
`pasted by user, <date>`. Both are fine; an unattributed claim is not, because
nobody can later tell whether it came from the workspace or from a guess.

## research.md

Step 4's deliverable, written by the subagent. Structure and standard are in
`references/researching.md`. The one invariant: every factual claim carries a
marker — a fetched URL, `UNVERIFIED`, or (rarely, since the sandbox usually
does not exist yet at step 4) `MEASURED`.

## measured.md

Step 5's deliverable, written by the main session once the sandbox is up. It
is a **reconciliation pass over `research.md`**, and its three sections say so:

```markdown
# MEASURED against the live sandbox — 2026-09-22
Target: https://localhost:8089, splunk/splunk:9.4.2 — a container, not Splunk
Cloud; every line inherits that gap.

## Confirmed from research.md
- `count` defaults to 30; `count=0` returns all. paging.total=133, default
  request returned 30, count=0 returned 133.

## Corrected
- research said `/services/saved/searches` lists every saved search. It
  returns 7; `/servicesNS/-/-/saved/searches` returns 133.
  fixed in: sandbox.json (verified.empty_surface), research.md

## Closed an UNVERIFIED
- envelope shape `{entry:[{name, content{}, acl{}}], paging:{total}}` — as
  predicted.

## True counts (for step 7.5)
- saved searches 133 · indexes 13 · roles 5 · data inputs 70
```

**The true-counts section is load-bearing.** Step 7.5 compares every fetcher's
collected count against it, and it has to come from a path independent of the
one the fetcher uses — otherwise both undercount together and agree.

When a later step overturns a line here, **edit this file and mark it
corrected**. Noting the correction somewhere newer leaves two files that
disagree, and a subagent handed the old one cannot know.

**Every `## Corrected` bullet ends with `fixed in:`** naming each file that
held the superseded fact and has now been fixed — or `fixed in: n/a (only
here)`. It is the one part of "correct it where it lives" a script can check:
the checker warns on any correction that doesn't say where it was fixed.

## slate.md

The plan, its approval, and — as step 8 runs — what actually happened to each
line. It is the file that turns a bail into a record instead of a dead end.

```markdown
# Slate — <platform>

**Approved by:** connor, 2026-09-22 (cut `query_history`, added `network_policies`, reordered)

## Platform-wide decisions, settled at step 4
- **runtime: python** — no first-class CLI; needs an SDK, paging, field extraction.
- **auth: bearer token** per deployment, `${env:SNOWFLAKE_TOKEN}`.
- **fanout: `supports_targets: true`**, target = one account.
  `target_schema: { name, account, token_env }`. Kept true although this org has
  one account — retrofitting fanout rewrites every entry script.

| # | Fetcher | Kind | Gathers | KSI | Provable on sandbox? | Status |
|---|---|---|---|---|---|---|
| 1 | snowflake/privileged_grants | evidence | role grants + grantees | KSI-IAM-APM | **yes — today** | built, validator proven |
| 2 | snowflake/network_policies  | evidence | allowed IP ranges       | KSI-CNA-NTW | yes | built |
| 3 | snowflake/login_history     | evidence | auth events, 90d        | KSI-MLA-LOG | yes | **bailed** |
| — | snowflake/org_policies      | evidence | org-level policy set    | KSI-IAM-APM | **no — Enterprise only** | **parked** |

## Bail — snowflake/login_history
3 attempts. `LOGIN_HISTORY` view returns rows only to ACCOUNTADMIN; the sandbox
role is SYSADMIN and the grant was refused at the step-5 gate. Needs either an
approved privilege escalation in the sandbox or a different source view.
Detail: `notes/login_history.md`.

## Park — snowflake/org_policies
Not attempted. Needs an Enterprise-tier account; the sandbox is Standard.
**Unparks when** an Enterprise trial is approved at the step-5 gate.
**Standing consequence:** the org-policy half of `claim.md` is UNEVIDENCED —
nothing on this slate proves it.
```

**Bailed and parked are different states**, and so are cut and reassigned —
see step 6 for all four. Bailed was attempted and failed; parked was never
attempted because the sandbox cannot prove it. A park always carries what would
unpark it, and — when it is the only row that covered part of the claim — a
standing consequence saying so.

**Each unbuilt row gets a section headed by its state and its fetcher**:
`## Bail — <category>/<fetcher>`, `## Park — …`, `## Cut — …`,
`## Reassigned — …`. The checker finds the section by exactly that — a
heading starting with the state word and naming the fetcher — so a
reassignment written up under "The archival half is not a Splunk fetcher at
all" reads to it as missing. The heading can carry more after the name; it
cannot lead with something else.

**A slate with no recorded approval has not passed Gate 1.** The approval line
is how a later session, or a subagent, can tell the difference between a
proposal and a plan.

## notes/<fetcher>.md

One per fetcher, written during its build (step 7 for #1, step 8 for the
rest). Mostly free-form build detail — endpoints called, field-shape surprises,
decisions a sibling should copy. **But it opens with the gate facts**, one per
line, because Gate 3 is decided by them and the checker reads them:

```
completeness: collected=133 true=133 source=measured.md true counts (paging.total)
completeness: collected=13 true=13 source=GET data/indexes paging.total
predicted_verdict: FAIL
real_verdict: FAIL
surprise_resolved: <only if predicted and real differed — what it turned out to be>
```

- **`completeness:`** — one per collection the fetcher reads. `collected` is
  what the fetcher emitted; `true` is the independent count from `measured.md`.
  They must be equal. `completeness: n/a <why>` is allowed where there is
  nothing to count, and is shown to a human rather than passed.
- **`predicted_verdict:` / `real_verdict:`** — the set verdict you expected
  from `measured.md`, written *before* scoring, then the verdict the real
  evidence got. A mismatch blocks Gate 3 until `surprise_resolved:` explains it.

Written as plain lines rather than prose because prose was what the second run
produced — "**Real evidence: set verdict FAIL.**" in paragraph four — and prose
is not something a gate can be checked against.

## sandbox.json

The approved-sandbox registry. Step 7 refuses to seed or run against a tenant
that is not in here.

```json
{
  "platform": "snowflake",
  "tenant_id": "ab12345.us-east-1",
  "tenant_label": "paramify-fetchers-sandbox",
  "provisioned_by": "terraform",
  "provision_path": ".onboarding/snowflake/infra/",
  "teardown": ".onboarding/snowflake/teardown.sh",
  "cost_estimate_usd_month": 40,
  "cost_owner": "security-eng",
  "approved_by": "connor",
  "approved_at": "2026-09-22",
  "notes": "Trial expires 2026-10-20 — slate must finish before then.",
  "seeding": "NOT REQUIRED — every surface populated on a stock account, and a failure case pre-exists (see verified). No seed.sh written, so the seeding gate never opened.",
  "teardown_decision": {
    "decision": "left running",
    "by": "connor",
    "at": "2026-09-23",
    "why": "resuming the parked row next week",
    "review_by": "2026-10-20"
  },
  "verified_at": "2026-09-22",
  "verified": {
    "version": "8.40.3",
    "edition": "Standard (production target is Enterprise)",
    "rest_api": "https://ab12345.us-east-1.snowflakecomputing.com responds to bearer auth",
    "retention_field_confirmed": "SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' -> value",
    "failure_case_present": "SCRATCH_DB ships at 1 day, below the claim's 90 — a non-compliant object exists before seed.sh runs"
  }
}
```

The **`verified`** block is what separates "I provisioned a sandbox" from "I
confirmed it answers the calls the fetchers will make". `failure_case_present`
earns its place on its own: it is what lets step 6 order the slate by what can
clear Gate 3 today, and finding it here beats discovering at step 7 that every
object is compliant and the validator has nothing to fail against.

`approved_by` and `approved_at` are what make this a registry rather than a
note. Absent either, the tenant is not approved, whatever else the file says.

**`seeding`** records the decision either way. "Not required" is a fine
answer — the platform's defaults often supply both populated data and a
failure case — but it is written down, with the reason, so nobody later
mistakes the missing `seed.sh` for a skipped step.

**`teardown_decision`** is written at close-out (Gate 4) and nowhere else. A
sandbox with no `teardown_decision` is one nobody has decided about.

**Re-provisioned?** Move the previous decision into
`"history": [{"provisioned": <date>, "teardown_decision": {...}}]`, then treat
the rebuild as new: fresh approval, fresh `verified` and `verified_at`, and its
own `teardown_decision` at the end. The checker fails a `verified_at` older
than `approved_at`.

## teardown.sh

Written at step 5 **before** anything is provisioned, executable, idempotent,
and safe to run against an account where nothing exists. It is read back at
close-out, which is the moment someone decides whether the sandbox stays up.

## Resuming

If `.onboarding/<platform>/` already exists, read it and resume — do not start
over. `check_onboarding.py <platform>` reports "Clean through: <stage>", and the
first stage it blocks on is where to resume. By hand, the step reads off the
files:

| Present | Resume at |
|---|---|
| nothing | step 0 |
| `claim.md` only | step 4 |
| `+ research.md` | step 5 |
| `+ sandbox.json` and `measured.md` | step 6 |
| `slate.md` with an approval line | step 7, or step 8 if row 1 is built |
| every row has a status (bailed, parked, cut and reassigned all count) | step 9 |
| `sandbox.json` has a `teardown_decision` | done |

Say which step you are resuming at before doing anything, so the user can
correct you cheaply.
