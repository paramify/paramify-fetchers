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
  research.md     step 4 output, every claim cited
  slate.md        the step 6 plan, its approval, and a status per fetcher
  sandbox.json    tenant ids, cost, approval — the approved-sandbox registry
  seed.sh         makes the data the fetchers need exist (step 5, gated)
  teardown.sh     written before seed, executable
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
fetched URL or the literal marker `UNVERIFIED`.

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

**Bailed and parked are different states.** Bailed was attempted and failed;
parked was never attempted because the sandbox cannot prove it. A park always
carries what would unpark it, and — when it is the only row that covered part
of the claim — a standing consequence saying so.

**A slate with no recorded approval has not passed Gate 1.** The approval line
is how a later session, or a subagent, can tell the difference between a
proposal and a plan.

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

## teardown.sh

Written at step 5 **before** anything is provisioned, executable, idempotent,
and safe to run against an account where nothing exists. It is read back at
close-out, which is the moment someone decides whether the sandbox stays up.

## Resuming

If `.onboarding/<platform>/` already exists, read it and resume — do not start
over. Which step you are at reads off the files:

| Present | Resume at |
|---|---|
| nothing | step 0 |
| `claim.md` only | step 4 |
| `+ research.md` | step 5 |
| `+ sandbox.json` | step 6 |
| `slate.md` with an approval line | step 7, or step 8 if row 1 is built |
| every row has a status (parked counts) | step 9 |

Say which step you are resuming at before doing anything, so the user can
correct you cheaply.
