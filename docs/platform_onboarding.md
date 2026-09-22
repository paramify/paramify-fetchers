# Onboarding a Platform

**Status:** The flow is implemented as the `onboard-platform` Claude Code skill
(`.claude/skills/onboard-platform/`). This page is the human-readable version —
what the flow is, why each gate exists, and how to run it without an agent.
**Date:** 2026-09-21
**Solves:** the build loop for a brand-new platform lived in one person's head.
`create-fetcher`, `wire-manifest`, and `suggest-validator` each assume you
already know which fetcher you want, and nothing owned the sandbox that makes
"does this fetcher actually collect anything" answerable.

---

## What this is for

Adding one more AWS fetcher is a solved job: run `create-fetcher`, wire it into
a manifest, author a validator. Onboarding a platform **nobody has integrated**
is a different job, and running it as the first one fails in two specific ways.

**The control claim gets reconstructed too late.** "What tool, what evidence?"
presumes the answer. By the time a validator is being authored, the narrative
it has to substantiate is being recovered from a fetcher that already exists —
which is how validators end up keyed on fields the fetcher never collected.

**Nobody owns the sandbox.** The fake-credential smoke test is green on an empty
payload. Without a tenant holding real data, a whole slate can be built against
nothing and every check will pass.

So the flow puts the claim first and makes populated evidence a gate.

## The shape

One orchestrator that owns research, the slate, the sandbox, the gates, and the
on-disk state. It **calls** the three existing skills rather than absorbing
them — they keep owning their own mechanics, and there is still exactly one
copy of the fetcher contract.

```
onboard-platform
├── create-fetcher      steps 7, 8    scaffold and build one fetcher
├── wire-manifest       steps 7, 8    make it actually run
└── suggest-validator   steps 7, 9-10 author and prove validators
```

`create-fetcher` remains independently invocable. Adding a sibling to a
platform that already works should not walk ten steps.

## The ten steps

`main` runs in the main session; `sub` is delegated to a subagent that writes
its findings to disk.

| # | Step | Where |
|---|---|---|
| 1 | Which service, specifically | main |
| 2 | What data is worth gathering | main |
| 3 | What claim would support a control | main |
| 4 | Research the API / CLI / SDK | sub |
| 5 | Sandbox: what exists, what we can build; measure it | main → **Gate 2** |
| 6 | State the plan — the slate | main → **Gate 1** |
| 7 | Build fetcher #1 end to end | main → **Gate 3** |
| 8 | Loop the rest of the slate, one at a time | sub |
| 9 | Validators for the remainder | sub |
| 10 | Sweep the validator pass over all new evidence | sub |
| — | Close out: decide the sandbox's fate | main → **Gate 4** |

Steps 1–3 are one conversation, not three rounds. Step 3's output is a claim
**to test** — step 4 can invalidate it, and step 6 is where it becomes binding.

Step 1 has a granularity bar worth knowing before you hit it: naming the
platform is not yet an answer, because it doesn't say which pages of the API
docs step 4 should open. "Snowflake" fails that test; "Snowflake's role grants
and its login history" passes. If you don't know the platform well enough to
name its surfaces, say so — step 4 enumerates what it exposes and brings the
list back, which is a supported path rather than a skipped step.

## Where the claim comes from

This is the part the design turns on, and the part that measured differently
than expected.

The claim should be the **solution capability's narrative** — the sentence an
assessor actually reads — because that is what a validator has to substantiate.
It is read with:

```bash
paramify capabilities list --family "Logical Identity & Access"
paramify capabilities show <id>
```

Measured against `stage.paramify.com` on **2026-09-21**: 591 capabilities, of
which **589 carry a PROVIDER narrative**, and `risk` / `risk_family` /
`main_component` are populated on 584. The narrative is there.

Measured against `app.paramify.com` on **2026-09-17**: `functions`, `risk`,
`riskFamily`, `mainComponent` were **absent keys** — not nulls — across all 85
capabilities, and `GET /{id}` was byte-identical to the list projection.

Both measurements are real. So the flow **attempts the call and degrades**:

1. `capabilities show` — use the narrative if one comes back.
2. Otherwise **ask the user to paste the claim.** One paste at the top of a
   multi-session onboarding, and it beats designing a fetcher against a guess.

Two operational notes, both measured, both of which break the naive call:

- **Narrow twice before you look.** 591 capabilities across 17 families on the
  workspace measured, and the families run 18 to 80 each — so `--family` alone
  barely narrows the big ones. Filter by family, then again on `subfamily`
  (no flag for it; the field is in `--json`), which gets you to ~20 or fewer.
- **Resolve by id, never by name.** Names are duplicated freely — three
  separate "Access Agreements" on the workspace measured — and
  `capabilities show <name>` refuses an ambiguous one:
  *"matches 2 capabilitys by name; use the id instead"*.

**What is not a fallback:** deriving lineage from the reference id.
`RS-01-02-03` encodes capability 03 of solution `RS-01-02` under risk `RS-01`,
which reads like a usable rung. On the workspace measured, `reference_id` and
`template_reference_id` were **empty on all 591 capabilities**. Check yours
before spending a turn on it.

### What else is and isn't reachable

| Source | Status |
|---|---|
| **Solution capability** | Workspace-dependent — see above. Attempt it; degrade to a paste. |
| **Risk solution** | Indirect and lossy. No `/risks` endpoint; risk solutions are `/elements` filtered to subtype `COM_RISK_SOLUTION`, and `GET /elements` returns no `referenceId`, so nothing joins a named element to a capability. Not wrapped in this repo, and not wrapped by this work. |
| **Control narrative** | Not available as data. Both `/projects/{id}/control-implementations` and `/audit-assessments/{id}/control-implementations` return `{id, name, control, requirement}` — control and requirement as *names*, no reference id, no link back to a capability. |
| **KSIs** | Local copy, `framework/reference/ksis.yaml`, which `paramify ksi` joins against. Zero occurrences of "KSI" in the API spec — there is nothing to fetch. The flow reads the local copy and asks whether you have a newer release. |
| **Existing fetchers** | Local and free — `paramify catalog`, `paramify ksi`. |
| **Tool API / CLI / SDK docs** | Web research at step 4, every claim cited. |

## The gates

Four, and they are the point of the flow. It is not designed to run unattended.

**Each gate is checked by a script, not by memory:**

```bash
python .claude/skills/onboard-platform/scripts/check_onboarding.py <platform>                  # every stage
python .claude/skills/onboard-platform/scripts/check_onboarding.py <platform> --through slate  # up to Gate 1
```

A gate is passed when the checker reports clean through its stage. It checks
what can be decided mechanically — the approval is recorded, the collected
count equals the true count, the unbuilt rows each have their section, no TLS
default is off, the teardown names what it removes, the sandbox has a
recorded fate — and reports the first stage it blocks on, which is also where
a resumed onboarding picks up. It cannot judge whether a decision was right;
that is still a person reading the files.

It exists because the instructions alone did not hold. The first complete run
skipped a close-out step the skill spelled out, and marked the slate complete
anyway.

**Gate 1 — after step 6, the slate.** The human cuts, adds, and reorders before
anything is built. The approval and its date are recorded in `slate.md`; a
slate with no recorded approval has not passed.

**Gate 2 — before any seeding.** The provisioning plan is approved *and every
seeder execution is approved individually* — not the plan once and then a free
hand. Teardown is already written and handed back alongside the plan.

**Gate 3 — end of step 7.** Fetcher #1 produced **populated and complete
evidence** — its collected count matches an independent count of the same
objects — and a validator that was **proven to fail**, whose verdict on the
real sandbox evidence matched what was predicted. The slate does not fan out
until all of that is true.

**Gate 4 — close-out.** The sandbox's fate is decided by a human and recorded
in `sandbox.json` as a `teardown_decision`: torn down, or left running with a
reason and a review date. The onboarding is not complete while a sandbox is up
with nobody having said it should be.

Gate 3 is the expensive one to skip. From building the GCP and Azure libraries:
a validator keys on a specific field, and you find out the fetcher never
collected it at validator-authoring time — after N siblings have been cloned
from the same shape. Proving one fetcher all the way through first turns that
into one fix instead of N.

**"Complete" was added to Gate 3 after the first complete run.** Two Splunk
calls returned populated, well-formed evidence that was wrong: a default page
size of 30 silently cut 133 saved searches to 30, and a user-scoped path
returned 7 of the same 133. Neither raised an error, and both passed the
populated check. Truncated evidence published as complete is the failure no
one sees, so the count is now checked against a true count measured at step 5,
and the shared client fails the collection on a mismatch.

**Gate 4 was added for the same reason in the other direction:** the same run
built every fetcher, proved every validator, marked the slate complete — and
left the sandbox running with nothing recording whether that was intended.

## The constraints

- **Success is populated and complete evidence, not exit 0.** Non-empty
  *measured* values, and all of them — a count matching an independent count.
- **No field that reads as compliant while meaning the opposite.** A retention
  period with no archive destination means the data is deleted at that age,
  not kept; emit fields like that together so no validator can use one alone.
- **TLS verification defaults on.** A self-signed sandbox opts out per target;
  that convenience must never become the default shipped to customers.
- **Teardown is written before seed**, handed back with the plan.
- **Nothing is seeded into a tenant absent from the approved-sandbox registry.**
  Being named "test" is not approval. The registry is
  `.onboarding/<platform>/sandbox.json`, and a tenant gets in through Gate 2.
- **Seed the failure case too — if the defaults don't already supply one.** A
  uniformly compliant sandbox gives a validator nothing to fail against, so
  Gate 3 cannot be honestly passed. Check the stock tenant first; the first
  complete run found three pre-existing failure cases and needed no seeding at
  all, which it recorded as a decision rather than leaving `seed.sh` absent.
- **Teardown removes only what it names.** Never a prune or a wildcard; the
  machine or account it runs on holds other things.
- **Bail after 3 attempts on one fetcher**, write the diagnosis, continue the
  slate.

## State on disk

Load-bearing, because subagents cannot read the main session's context. Steps 4
and 8–10 are delegated, so everything they need is on disk before they start and
everything they find is on disk when they finish. It is also what makes the flow
**resumable** — platform onboarding spans sessions.

```
.onboarding/<platform>/          gitignored, one per platform
  claim.md        the narrative or pasted claim, with provenance
  research.md     step 4 output, docs-only, every claim marked
  measured.md     step 5, the live sandbox reconciled against research.md
  slate.md        the plan, its approval, and a status per fetcher
  sandbox.json    tenant id, cost, approval, teardown decision — the registry
  seed.sh         only if the platform's defaults don't supply the data
  teardown.sh     written before provisioning, idempotent, names what it removes
  notes/          per-fetcher build detail, so slate.md stays scannable
```

Field shapes and worked examples are in
`.claude/skills/onboard-platform/references/state.md`.

**No credentials in here.** Gitignored is a backstop against accidents, not a
keystore. Secrets stay `${env:VAR}` refs resolved from the environment.

## Running it without an agent

The steps are ordinary work; the skill is a checklist with the failure modes
attached. By hand:

1. Pick the capability, or write the claim down, in `claim.md`. Do this first.
2. Read the platform's API docs and write `research.md` — including *what has to
   exist in a tenant for each call to return something non-empty*. That answer
   is what step 5 is built on and it is the one most often left thin.

   **Give yourself a budget and take two passes.** This is the step that eats a
   day, because API research has no natural end — there is always another page.
   Answer every heading badly first, then deepen what matters for the claim,
   and mark anything you didn't confirm `UNVERIFIED` rather than chasing it. A
   thin-but-complete file is something step 6 can cut a slate from; one
   exhaustive heading and seven empty ones is not. Most of what you skip
   resolves itself at step 7, when a real call either works or it doesn't.
3. Stand up the sandbox. Write the teardown before you create anything. Record
   the tenant in `sandbox.json`.
4. Write the slate, get it cut, record who approved it.
5. Build one fetcher. Run it against the sandbox, not fake creds. Confirm the
   payload has measured values in it:
   ```bash
   python .claude/skills/suggest-validator/scripts/find_evidence.py <fetcher_name>
   ```
6. Author its validator and prove it fails on a non-compliant artifact. Only
   then build the rest.

The checker works just as well without an agent — run it at each gate. The
conventions it reads (the three gate lines at the top of each
`notes/<fetcher>.md`, the `## <State> — <category>/<fetcher>` headings on the
slate, `fixed in:` on every correction) are documented in
`.claude/skills/onboard-platform/references/state.md`.

## Non-goals

- **Running validators.** `framework/verify/` does not exist yet and nothing
  consumes the contract's `validators:` block. Authoring and proving are in
  scope; a verify runner is not.
- **Fully unattended operation.** The gates are the point.

## See also

| Doc | For |
|---|---|
| [`authoring_a_fetcher.md`](authoring_a_fetcher.md) | Writing one fetcher from scratch |
| [`issue_report_fetchers.md`](issue_report_fetchers.md) | The second kind of fetcher |
| [`validators_design.md`](validators_design.md) | What a validator is and how the registry works |
| [`fetcher_contract.md`](fetcher_contract.md) | The binding runner↔fetcher contract |
| [`ksi_mapping.md`](ksi_mapping.md) | Which fetchers map to which KSIs, and the gaps |
