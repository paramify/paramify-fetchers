---
name: onboard-platform
description: >
  Onboard a platform nobody has integrated yet — research its API, decide what
  is worth collecting and which claim it supports, stand up a sandbox with real
  data in it, then build and prove a slate of fetchers against that data. Use
  when the user names a platform that has no fetchers yet ("we need Snowflake
  coverage", "onboard Cloudflare", "nothing covers Datadog"), when they ask what
  a tool could even produce evidence for, or when a whole slate of fetchers is
  wanted rather than one. For adding one more fetcher to a platform already
  integrated, use `create-fetcher` directly — this skill calls it, and there is
  no reason to walk ten steps for a sibling of something that already works.
---

# Onboard a Platform

`create-fetcher`, `wire-manifest`, and `suggest-validator` each assume you
already know which fetcher you want. Onboarding a platform nobody has
integrated is a different job, and it fails in two specific ways when treated
as the same one:

- **The claim gets reconstructed too late.** "What tool, what evidence" presumes
  the answer. Recovering the narrative *after* the fetcher exists is how
  validators end up keyed on fields the fetcher never collected.
- **Nobody owns the sandbox.** A fake-cred smoke test is green against an empty
  payload, so a whole slate can be built against nothing and look fine.

This skill owns research, the slate, the sandbox, the gates, and the on-disk
state. It **calls** the other three skills for their mechanics and does not
restate them.

| Skill | Called at | For |
|---|---|---|
| `create-fetcher` | steps 7, 8 | scaffolding and building one fetcher |
| `wire-manifest`  | steps 7, 8 | making that fetcher actually run |
| `suggest-validator` | steps 7, 9, 10 | authoring and proving validators |

**Read these when you reach them, not before:**

| File | When |
|---|---|
| `references/research.md` | Step 4 — the subagent brief, citation discipline |
| `references/sandbox.md` | Step 5 — provisioning, cost, teardown-before-seed |
| `references/state.md` | Any step — the `.onboarding/<platform>/` file shapes |

## Golden rules

- **Success is populated evidence, not exit 0.** Non-empty *measured* values in
  the payload. A green fake-cred smoke test is what `create-fetcher` can prove
  on its own; closing the gap between that and real data is the entire reason
  this skill owns a sandbox.
- **Teardown is written before anything is seeded** and handed back alongside
  the provisioning plan — not offered afterwards.
- **Nothing is seeded into a tenant that is not recorded in
  `.onboarding/<platform>/sandbox.json`.** Being named "test" is not approval.
  The tenant gets into that file only through the step-5 gate.
- **Fetcher #1 carries its validator, before the slate fans out.** Learned
  building the GCP and Azure libraries: the validator keys on a specific field,
  and you discover the fetcher never collected it at validator-authoring
  time — after N siblings have been cloned from the same shape.
- **State lives on disk because subagents cannot read this session.** Every
  delegated step writes its findings to `.onboarding/<platform>/`; the main
  session reads them and runs the gates. A finding that exists only in a
  subagent's reply is a finding you will re-derive.
- **Bail after 3 failed attempts on one fetcher**, write the diagnosis into
  `slate.md`, and continue the slate. One stuck fetcher does not stall the rest.

---

## Step 0 — Set up the state directory

```bash
PLATFORM=<platform>        # lowercase, the category name: snowflake, cloudflare
mkdir -p .onboarding/$PLATFORM
```

Gitignored, one directory per platform onboarding, alongside the existing
`.paramify/` local-state convention. It survives across sessions — if it
already exists, **read what is there and resume** rather than starting over.
Say which step you are resuming at. File shapes are in `references/state.md`.

---

## Steps 1–3 — What, why, and the claim

Run as an interview in this session. Keep it short; these three questions are
one conversation, not three rounds.

**1. Which service.** Ask plainly and openly — *"which platform, and which
parts of it?"* — and do **not** lead with an example. An example given up front
gets answered instead of the question, and you will get its surfaces back
rather than the ones the user actually cares about.

Then judge what comes back against one test: **could you now say which pages of
that platform's API docs step 4 should open?** "Snowflake" fails it. "Snowflake's
role grants and its login history" passes.

If the answer is too thin, the gap is almost never unwillingness — most people
don't know how fine-grained an answer is useful until they see one. So show
them, once, built from **their** platform rather than a stock one:

> Snowflake's a big surface — which parts matter here? Something like "role
> grants and login history" or "network policies and session timeouts" is the
> altitude I'm after. What's on your list?

That is an illustration of the *granularity*, not a menu. Do not turn it into
options to pick from: the point is to show the shape so they can supply their
own, and a list invites picking one and stopping.

**One follow-up, then move on.** If they still can't name the surfaces, they
may genuinely not know the platform well enough yet — that is what step 4 is
for. Say so, take the platform name alone, and brief the research subagent to
**enumerate what the platform exposes** so step 6's slate can be cut from a
real list. Do not keep asking; it reads as a quiz the user is failing.

Derive the `<category>` name here either way; it is the directory every fetcher
lands in.

**2. What data is worth gathering.** What does this platform know that an
assessor would want to see? Do not converge yet — step 4 will invalidate some
of it, and a wide list is cheaper to cut than a narrow one is to widen.

**3. What claim would support a control.** The output is a claim **to test**,
not a commitment. Step 4 can invalidate it; step 6 is where it becomes binding.

### The claim, in order of preference

Try each rung and stop at the first that produces a sentence.

**3a. The workspace's solution capability.** This is the narrative an assessor
actually reads, which is what a validator has to substantiate.

```bash
paramify capabilities list --family "<family>"   # narrow first — see below
paramify capabilities show <id>                  # the narratives it claims
```

Two things make the naive call fail, both measured against a live workspace on
2026-09-21:

- **Narrow twice before you look.** A workspace holds hundreds of capabilities
  (591 across 17 families on the workspace measured). `--family` alone is not
  enough — the families run 18 to 80 capabilities each, so the largest ones
  barely narrow at all. Filter by family, then **narrow again on `subfamily`**,
  which gets you to ~20 or fewer:
  ```bash
  paramify capabilities list --json \
    | jq -r '.capabilities[] | select(.family=="Logical Identity & Access")
             | "\(.subfamily)\t\(.name)\t\(.id)"' | sort
  ```
  There is no `--subfamily` flag; the field is in the JSON, so filter it
  yourself. Reading 80 capability names to find the three about session
  timeouts is the thing this avoids.
- **Resolve by id, never by name.** Names are duplicated freely — three separate
  "Access Agreements" on the workspace measured — and `capabilities show <name>`
  refuses an ambiguous one outright: *"matches 2 capabilitys by name; use the id
  instead"*. Present the user a short numbered list from `list --json` and take
  the id from their pick.

**3b. Ask the user to paste the claim.** Rung 3a returns no narrative on some
workspaces — the same capability endpoint that served 589 narratives out of 591
on stage served none at all on prod as recently as 2026-09-17. When `functions`
comes back empty, say so plainly and ask for the sentence. This is a fine
outcome: it is one paste at the top of a multi-session onboarding, and it beats
designing a fetcher against a guess.

> **Not a rung: deriving lineage from the reference id.** `RS-01-02-03` encodes
> capability 03 of solution `RS-01-02` under risk `RS-01`, which reads like a
> usable fallback. On the workspace measured, `reference_id` and
> `template_reference_id` were **empty on all 591 capabilities**, so it derives
> nothing. Check whether yours are populated before spending a turn on it; if
> they are, it is a legitimate way to group, but it is not a source of a claim.

**Whichever rung produced it, write the claim to
`.onboarding/$PLATFORM/claim.md`** with its provenance — capability id, or
"pasted by user, <date>". Every later step and every subagent asserts against
that one sentence, and they can only do that if it is on disk.

Also capture the KSI side while you are here. `framework/reference/ksis.yaml` is
the local copy `paramify ksi` joins against; there is no KSI endpoint to fetch.
**Ask whether the user has a newer release** — if theirs differs, take it.

```bash
paramify ksi           # coverage today, and the gaps this platform might fill
```

---

## Step 4 — Research the target  (delegate to a subagent)

The API, the CLI, the SDK: what can actually be read, with what permission, at
what rate limit. This is wide, disposable reading — exactly what a subagent is
for, and exactly what should not be in this session's context.

Brief the subagent from `references/research.md`. Two things are not negotiable
and belong in the brief verbatim:

- **Every claim is cited to a URL that was actually fetched, or marked
  `UNVERIFIED`.** An uncited API shape is how a fetcher gets built against an
  endpoint that does not exist.
- **It writes `.onboarding/$PLATFORM/research.md` and reports only a summary.**
  The file is the deliverable.

Read the file when it lands. If a finding invalidates the step-3 claim — the
data is not exposed, the endpoint needs an admin grant nobody will approve —
say so and revise the claim before step 6, not after.

---

## Step 5 — Sandbox: is there infra, and can we make data exist

Main session. Fetchers cannot be proven against an empty tenant, so something
has to hold real data.

1. **Is there existing infra?** An account the team already has, a free tier, a
   trial. Cheapest path wins.
2. **Can we build it?** CLI, Terraform, a seeder script. Read
   `references/sandbox.md` before proposing anything.
3. **State a cost estimate.** Dollars per month and who pays, out loud, before
   the plan is approved. "Probably free" is not an estimate.
4. **Write `teardown.sh` first.** Before a single resource is created. Hand it
   back *with* the provisioning plan.

Record the tenant/account id, the cost estimate, and the teardown path in
`.onboarding/$PLATFORM/sandbox.json`. That file is the approved-sandbox
registry: the seed step in step 7 refuses any tenant not in it.

> **GATE — every seeder execution is approved individually.** Not the plan once,
> then a free hand. Each `terraform apply`, each seed script, each time.

---

## Step 6 — State the plan

Write `.onboarding/$PLATFORM/slate.md`: the fetchers to build, what each
gathers, and which KSI each serves. One line per fetcher, ordered — the order is
the build order, so put the one that proves the most of the platform first.

Mark which are evidence fetchers and which are issue reports; they have
different contracts and `create-fetcher` Phase 0 routes on it.

> **GATE 1 — the human cuts, adds, and orders.** Present the slate and stop.
> Nothing is built until they have edited it. Record the approval and its date
> in `slate.md`; a slate with no recorded approval has not passed this gate.
>
> The user also builds or approves the sandbox infra here.

---

## Step 7 — Build fetcher #1, end to end

Main session, one fetcher, all the way through. This is the step that proves the
whole approach works before it is repeated N times.

1. **Build it** — invoke `create-fetcher`. It owns scaffolding, the contract,
   and the wiring verification; do not restate its phases. Hand it the claim
   from `claim.md` so its interview starts from the control, not from "what
   evidence".
2. **Make it run** — invoke `wire-manifest`.
3. **Run it against the sandbox.** Not fake creds. The tenant must be the one in
   `sandbox.json`.
4. **Confirm the evidence is populated** — non-empty *measured* values, not just
   a well-formed envelope. A payload carrying only a control name and an empty
   results array is not populated. `suggest-validator`'s
   `scripts/find_evidence.py` reports this per run:
   ```bash
   python .claude/skills/suggest-validator/scripts/find_evidence.py <fetcher_name>
   ```
5. **Author its validator** — invoke `suggest-validator`, working from
   `claim.md` as the narrative.
6. **Prove the validator can fail.** Its Phase 5 direction 2. A validator that
   has never failed has demonstrated nothing.

> **GATE 3 — fetcher #1 produced populated evidence, and a validator that was
> proven to fail.** The slate does not fan out until both are true. If the
> evidence is empty, the problem is the sandbox (step 5) or the research
> (step 4) — go back rather than fanning out and discovering it eight more
> times.

---

## Step 8 — Loop the rest of the slate  (delegate, one at a time)

One subagent per fetcher, each taken **fully through** steps 7.1–7.4 before the
next begins. Not a fan-out: a parallel slate built from the same wrong shape is
eight fetchers to fix instead of one.

Each subagent gets `claim.md`, `research.md`, `sandbox.json`, and its own line
from `slate.md`, and appends its outcome to `slate.md` — built, or bailed with
the diagnosis. Read it between fetchers; a second failure with the same cause is
a signal to stop the loop and fix the cause.

**Bail rule: 3 attempts on one fetcher, then write the diagnosis and move on.**

---

## Steps 9–10 — Validators for the remainder  (delegate)

**9.** Author validators for everything built in step 8, one subagent per
evidence set, each invoking `suggest-validator` against that fetcher's real
evidence and `claim.md`.

**10.** Sweep `suggest-validator` over the new evidence as a set — the
cross-cutting pass that catches what per-fetcher authoring misses: two
validators asserting the same thing under different names, an evidence set with
no completeness validator, a count-based rule with no integrity partner.

Then verify the registry gate:

```bash
.venv/bin/python -m pytest tests/test_validators_registry.py -q
```

---

## Closing out

Report: what was built, what bailed and why, the coverage delta from
`paramify ksi`, and **whether the sandbox is still running and what it costs**.
Point at `teardown.sh`. Ask whether to run it now or leave it up — do not decide
that on the user's behalf, and do not leave it unsaid.

`.onboarding/<platform>/` is gitignored and safe to keep; it is what makes the
next session on this platform a resume rather than a restart.

---

## Anti-patterns

- **Fanning out the slate before fetcher #1 has populated evidence and a
  failing validator.** Gate 3 exists because this is the expensive mistake.
- Treating exit 0 as success. The smoke test is green on an empty payload.
- Seeding into whatever tenant is handy because it has "test" in the name.
- Offering teardown after the resources exist.
- Letting a subagent report findings only in its reply. It writes to
  `.onboarding/`, or the finding is lost and re-derived.
- Restating `create-fetcher` / `wire-manifest` / `suggest-validator` mechanics
  here. Call them. Three copies of the fetcher contract drift apart.
- Opening step 1 with an example of a good answer. It gets answered instead of
  the question, and you learn the example's surfaces rather than the user's.
- Asking step 1 a third time. One follow-up, then hand the enumeration to
  step 4 — past that it reads as a quiz the user is failing.
- Listing all 591 capabilities and reading them. Narrow by family first.
- Looking a capability up by name. Names are duplicated; resolve by id.
- Walking all ten steps to add one more fetcher to a platform that already has
  some. That is `create-fetcher` on its own.
