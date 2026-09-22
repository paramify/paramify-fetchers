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
| `references/researching.md` | Step 4 — the subagent brief, citation discipline |
| `references/provisioning.md` | Step 5 — provisioning, cost, teardown-before-seed |
| `references/state.md` | Any step — the `.onboarding/<platform>/` file shapes |

## The gates are checked, not remembered

Every rule below that can be decided mechanically — a decision recorded, two
counts equal, a section present, a default not off — is checked by one script:

```bash
python .claude/skills/onboard-platform/scripts/check_onboarding.py $PLATFORM                    # all stages
python .claude/skills/onboard-platform/scripts/check_onboarding.py $PLATFORM --through slate    # up to Gate 1
```

**A gate is not passed until the checker reports clean through its stage.**
Run it at every gate below, fix every FAIL, and read every WARN. This exists
because the instructions alone did not hold: the first complete run skipped a
close-out step the skill spelled out explicitly, and marked the slate COMPLETE
anyway. Prose tells the agent what matters; the checker catches it when the
agent is sure it's done.

It checks that things were **recorded**, not that they were **right**. A clean
run means every decision is on disk in a checkable shape — whether the claim was
the right one, or the teardown the right call, is still read and judged by a
person. The conventions it reads are in `references/state.md`.

## Golden rules

- **Success is populated *and complete* evidence, not exit 0.** Non-empty
  *measured* values in the payload — and *all* of them. A green fake-cred smoke
  test is what `create-fetcher` can prove on its own; closing the gap between
  that and real data is the entire reason this skill owns a sandbox. But a
  payload holding 30 of 133 objects is populated too, and it is the more
  dangerous failure, because nothing about it looks wrong. See step 7.
- **Correct a superseded fact where it lives.** When a later measurement
  overturns something an earlier state file says, fix that file and mark it
  corrected — do not just note the correction somewhere newer. A state
  directory whose files contradict each other is worse than one that is merely
  out of date: a subagent handed the stale one has no way to know.
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
  delegated step writes its findings to `.onboarding/<platform>/` **as it goes,
  not at the end** — the main session reads them and runs the gates. A finding
  that exists only in a subagent's reply is a finding you will re-derive, and
  an agent that stalls before its single final write produced nothing at all.
  Writing incrementally is what makes a delegated step recoverable instead of
  restartable.
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
Say which step you are resuming at — run the checker with no `--through`, and
its "Clean through:" line tells you: resume at the first stage it blocks on.
File shapes are in `references/state.md`.

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

**When several capabilities fit, prefer the one whose narrative carries a
number.** "Retains 90 days searchable and 280 days archival" gives a validator
something to key on and something a single misconfigured object can falsify;
"logs are centrally managed and reviewed" does not. Gate 3 needs a validator
*proven to fail*, and a prose-only claim makes that hard at exactly the moment
you least want extra difficulty. Say which criterion you used, so a human
disagreeing with the pick can see what it turned on.

**Keep the runners-up.** Write the other candidate capabilities into `claim.md`
as an adjacent-claims table — name, id, narrative in one line. They are the raw
material for the rest of the slate at step 6, and recovering them later means
re-querying and re-reading the workspace. Note where a name resolved to several
ids, and which one you took.

**Name the coverage gap you are aiming at.** `paramify ksi` lists the open
ones; say which this platform could plausibly close. That turns into step 6's
second ordering criterion, and it is the argument for why this onboarding is
worth doing at all.

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

**This is the step that hangs.** API research has no natural end — there is
always another page — so an agent told to "research the platform" runs until
something stops it. `references/researching.md` has the brief; read it before
delegating, and do not paraphrase these four out of it:

- **Its first tool call is a write, and it alternates from there.** The
  skeleton — eight headings, `TODO` under each — goes to
  `.onboarding/$PLATFORM/research.md` *before* the first fetch. Then one fetch,
  one edit, repeat: **never two fetches in a row without an edit between
  them.** "Write as you go" is not enough to say; an agent given that still
  batches six fetches and then writes. Give it the cadence, not the aspiration.
  A run that stalls having written nothing produced nothing — this is the fix
  for the hang, and the budget is secondary to it.
- **Breadth before depth.** Every heading answered badly before any heading is
  answered well, so running out of budget leaves a thin-but-complete file
  rather than one exhaustive heading and seven empty ones.
- **A budget, and permission to stop.** ~25 fetches, and stopping at it with
  gaps named is **a success**. Say that explicitly — an agent will not hand
  back incomplete work unless the brief says incomplete is expected.
- **Every claim cited to a URL actually fetched, or marked `UNVERIFIED`** — and
  `UNVERIFIED` is cheap, to be used rather than spending fetches to be sure.
  An uncited API shape is how a fetcher gets built against an endpoint that
  does not exist.

**Hand it at most five items** from step 2, chosen for the claim, with the rest
named as out of scope. Step 2 produces a wide list on purpose; passing all of
it is a dozen research jobs in one prompt.

Read the file when it lands. If a finding invalidates the step-3 claim — the
data is not exposed, the endpoint needs an admin grant nobody will approve —
say so and revise the claim before step 6, not after.

**If it runs long or never returns, read the partial file rather than re-running
it** — the second run is as open-ended as the first and buries the first one's
findings. `references/researching.md` § "When the subagent runs long" has the
recovery.

---

## Step 5 — Sandbox: is there infra, and can we make data exist

Main session. Fetchers cannot be proven against an empty tenant, so something
has to hold real data.

1. **Is there existing infra?** An account the team already has, a free tier, a
   trial. Cheapest path wins.
2. **Can we build it?** CLI, Terraform, a seeder script. Read
   `references/provisioning.md` before proposing anything.
3. **State a cost estimate.** Dollars per month and who pays, out loud, before
   the plan is approved. "Probably free" is not an estimate.
4. **Write `teardown.sh` first.** Before a single resource is created. Hand it
   back *with* the provisioning plan.

5. **Verify it, then reconcile research against it in `measured.md`.** Once
   it is up, call the endpoints step 4 said the fetchers would call. Step 4 ran
   before the sandbox existed, so `research.md` is docs-only by construction —
   this is the first moment anything can be `MEASURED`. Write
   `.onboarding/$PLATFORM/measured.md` as a **reconciliation pass over
   `research.md`**: every line either *confirms* a research finding, *corrects*
   one, or *closes* an `UNVERIFIED`. That framing is the point — it forces the
   docs and the server to be compared line by line, which is where the
   silent-truncation traps in step 7.5 were found on the first real run.

   Measure **the true count of every collection** here, through a path
   independent of the one the fetcher will use — `paging.total`, a second
   endpoint, the UI. Step 7.5 compares the fetcher against it.

   Put a short summary in a `verified` block in `sandbox.json` — version, the
   field that carries the measured value, whether a failure case exists — and
   the detail in `measured.md`. "I provisioned a sandbox" and "I confirmed the
   sandbox answers the calls the fetchers will make" are different claims, and
   only the second is worth anything at step 6.

   **Look specifically for a failure case that already exists.** A platform's
   defaults usually supply one — on the run this was written from, Splunk ships
   `_dsphonehome` at 7 days against a 90-day claim, so a non-compliant index
   existed before `seed.sh` ran at all. Finding it here is what lets step 6
   order the slate by "can clear Gate 3 today", and it is cheaper to notice now
   than to discover at step 7 that every object in the sandbox is compliant and
   the validator has nothing to fail against.

Record the tenant/account id, the cost estimate, the teardown path, and that
`verified` block in `.onboarding/$PLATFORM/sandbox.json`. That file is the
approved-sandbox registry: the seed step in step 7 refuses any tenant not in it.

> **GATE 2 — every seeder execution is approved individually.** Not the plan
> once, then a free hand. Each `terraform apply`, each seed script, each time.
> Before moving to step 6: `check_onboarding.py $PLATFORM --through sandbox`
> reports clean.

---

## Step 6 — State the plan

Write `.onboarding/$PLATFORM/slate.md`: one row per fetcher, ordered, with what
it gathers, which KSI it serves, whether it is evidence or an issue report
(different contracts — `create-fetcher` Phase 0 routes on it), and:

**A "provable on this sandbox?" column.** Yes / partially / no, answered from
`sandbox.json` and step 4 — not from hope. This is the column that makes step 5
pay off at planning time instead of at build time, and it is what produces the
parked state below. A row marked *no* that gets built anyway is a fetcher that
will be green on an empty payload, which is the failure this whole skill exists
to prevent.

### A row that isn't built is one of four things

Each means something different about whether to try again, so the slate names
which:

| State | Means | Carries |
|---|---|---|
| **Bailed** | Built, failed three times | the diagnosis |
| **Parked** | Not attempted — this sandbox cannot prove it | what would unpark it |
| **Cut** | A human removed it at Gate 1 — a scope decision | what it would have covered |
| **Reassigned** | The clause is not this platform's to evidence at all | which platform owns it |

Collapsing them loses the signal. Bailed says *broken*; parked says *fine but
unprovable here*; cut says *deliberately not wanted*; reassigned says *wrong
platform*. Only the first is a failure.

**Reassigned** is the one easiest to miss, because it first looks like
parked. On the first real run, Splunk's 280-day archival clause was parked as
"no Splunk Cloud stack to prove it on" — until research showed Splunk stops
tracking data entirely once it freezes, so the archival duration lives in the
**storage provider's lifecycle policy**, not in Splunk. No Splunk sandbox, of
any kind, could ever prove it. That is not a deferral, it is a different
owner: the gap needs a fetcher in another category (S3, GCS, Azure blob
lifecycle). The capability narrative had said so all along — it attributed
archival to *[Cloud Storage]*, not the SIEM. **Read who the narrative says
does each thing before assuming it is all this platform's.**

Whenever any of the four removes the only fetcher that proved part of the
claim, **say so as a standing consequence** — a cut included, since a human
choosing not to build something does not make the clause it covered evidenced: *"the 280-day archival half of `claim.md` is
currently UNEVIDENCED, and no fetcher on this slate proves it."* A claim
half-covered without anyone noticing is how a slate looks finished while the
narrative it was built for is not actually substantiated.

### Ordering

The order is the build order. Two criteria, in this order:

1. **First: whichever can clear Gate 3 today.** Not the most interesting or the
   most central — the one that runs against the sandbox now, returns populated
   values, and **already has a failure case** so its validator can be proven to
   fail. Best of all is a failure case that exists *before* `seed.sh` runs; the
   platform's own defaults often supply one. #1 also sets the auth path, the
   paging convention and the envelope shape every sibling inherits, so it should
   be a fetcher whose shape you want copied.
2. **Then: whichever closes a coverage gap.** `paramify ksi` names the open
   ones. A fetcher that closes a named gap is worth more than a second fetcher
   in a family already covered, and the gap is the argument for building it.

### Settle the platform-wide decisions once, here

Before the rows, record the decisions that apply to every fetcher in the
category, with the reason: **runtime** (bash vs python), **auth model**, the
**hosts/base URLs**, and **fanout** — `supports_targets`, the proposed
`target_schema`, `aggregation`. Step 4 has the answers; this is where they stop
being research and become the contract the slate is built against.

Fanout especially: **decide it here even when you are unsure, and prefer
`true`.** Retrofitting fanout means rewriting the entry script of every fetcher
already built, while an unused `targets:` on a single-deployment org costs
nothing.

> **GATE 1 — the human cuts, adds, and orders.** Run
> `check_onboarding.py $PLATFORM --through slate` and fix what it flags *before*
> presenting, so the human is judging the plan rather than its formatting.
> Present the slate and stop.
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
5. **Confirm it is complete — the count matches an independent count.** Take
   the number of objects the fetcher collected and compare it against the
   platform's own figure from `measured.md`: a `paging.total`, a count from a
   second endpoint, the number the UI shows. **They must be equal.** Measured on
   the first real run, both of these returned populated, well-formed evidence
   and were wrong: a default page size of 30 silently truncated 133 saved
   searches to 30, and a plain `/services/` path returned 7 where the
   namespaced `/servicesNS/-/-/` path returned all 133. Neither raises an error.
   Both pass step 4.

   Build the check into the shared client, not into each fetcher's good
   intentions: request everything (`count=0` or the platform's equivalent),
   compare against the reported total, and **fail the collection on a
   mismatch** rather than publish it. Truncated evidence published as complete
   is a finding nobody can see.
6. **Check that no field reads as compliant while meaning the opposite.** For
   each field the validator will key on, ask what it means when the field next
   to it is empty. On the first real run, Splunk's `frozenTimePeriodInSecs`
   reads exactly like "retained for N days" — but with `coldToFrozenDir` empty,
   the data is **deleted** at N days, not archived. Evidence carrying only the
   first field would read as compliant while describing deletion. Where that
   is possible, **emit the fields together** and make it part of the fetcher's
   contract, so no validator can be written against one without the other.
7. **Never default TLS verification off because the sandbox needs it.** A
   self-signed sandbox cert makes `verify_ssl=false` tempting as the default;
   that default ships to every customer. Verification defaults **on**, and the
   sandbox opts out per target in its own manifest entry.
8. **Author its validator** — invoke `suggest-validator`, working from
   `claim.md` as the narrative.
9. **Prove the validator can fail.** Its Phase 5 direction 2. A validator that
   has never failed has demonstrated nothing.
10. **Run it against the real evidence, and predict the verdict first.** The
    synthetic cases prove the validator *can* fail; the sandbox evidence says
    whether it *does*, which is a finding about the tenant. Before scoring,
    write down the verdict `measured.md` predicts — the sandbox has known
    failure cases, so you usually know. Then score it
    (`suggest-validator`'s `scripts/score_evidence.py`) and record the set
    verdict on this fetcher's slate row.

    **FAIL is a legitimate outcome here**, not a defect — on the first real
    run, role access and alerting both FAILED on the sandbox, exactly as
    predicted, because the stock tenant really is non-compliant there. What
    matters is whether it matches the prediction. A surprise in either
    direction means the tenant, the evidence, or the validator is not what you
    think, and that gets resolved before the slate fans out — a validator that
    unexpectedly passes a tenant you know is broken is the worst thing to
    clone.

**Record the gate facts as three lines at the top of `notes/<short_name>.md`**,
so they are checkable rather than buried in prose:

```
completeness: collected=133 true=133 source=measured.md true counts (paging.total)
predicted_verdict: FAIL
real_verdict: FAIL
```

One `completeness:` line per collection the fetcher reads. Where there is
genuinely nothing to count — a single settings object — write
`completeness: n/a <why>`, which the checker surfaces for a human rather than
passing silently. If the verdict surprised you and you resolved it, add
`surprise_resolved: <what it turned out to be>`.

> **GATE 3 — fetcher #1 produced populated, complete evidence, and a validator
> that was proven to fail — whose verdict on the real evidence matched the
> prediction.** The slate does not fan out until all of that is true. If the
> evidence is empty or short, the problem is the sandbox (step 5) or the
> research (step 4) — go back rather than fanning out and discovering it eight
> more times. `check_onboarding.py $PLATFORM --through build` reports clean.

---

## Step 8 — Loop the rest of the slate  (delegate, one at a time)

One subagent per fetcher, each taken **fully through** steps 7.1–7.7 before the
next begins. Not a fan-out: a parallel slate built from the same wrong shape is
eight fetchers to fix instead of one.

Each subagent gets `claim.md`, `research.md`, `sandbox.json`, and its own row
from `slate.md`. It writes its build notes to
`.onboarding/$PLATFORM/notes/<fetcher>.md` — **starting with the three gate
lines from step 7**, which go in the brief verbatim — and updates **only its own row's
status** in `slate.md` — built, or bailed with a one-line diagnosis pointing at
its notes file. Between fetchers, run `check_onboarding.py $PLATFORM --through
build`: a sibling that skipped its completeness check or cloned a helper shows
up there, before the next one copies it. Read the status column; a second failure with
the same cause is a signal to stop the loop and fix the cause.

> **`slate.md` is a plan, not a build log.** Keep it to the header, the status
> table, and a few lines per bail — page or two, readable at a glance. Build
> detail goes in `notes/`. Measured on the first real run: letting each fetcher
> append its findings grew the slate to **1,749 lines / 99 KB across 74
> headings** by fetcher five. That breaks this step specifically — you cannot
> hand a subagent "its own row" out of a 99 KB file without spending its whole
> context on the other four, which is the thing delegation was for.

### Share the client before the second fetcher, not after the fifth

The moment fetcher #2 needs the same auth or the same request helper as #1,
stop and lift the shared parts into `fetchers/<category>/_shared/` — before
building #2, not as a cleanup pass later. `create-fetcher` Phase 3 says to make
that directory; at step 8 it stops being optional, because you are about to
write the fourth copy.

Measured on the first real run, which skipped this: five sibling fetchers
carried **seven duplicated helpers** each, and they had already drifted by the
time the slate finished — `get_json` with `timeout=120` in two of them and
`timeout=60` in three, `to_int` in three different versions, with nothing
recording which was intended. Nobody chose that; it is what cloning produces.
A behavioural difference between siblings that no one decided is worse than
either value.

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

## Closing out — the slate is not done until the sandbox has a decision

> **GATE 4 — the sandbox's fate is decided and recorded.** The onboarding is
> not complete while a sandbox is running with nobody having said it should
> be. This is a gate, not a courtesy: it was the one instruction the first
> complete run skipped — every fetcher built, every validator proven, the
> slate marked COMPLETE, and the container still up with nothing on disk
> saying whether that was intended. On a laptop it cost nothing. On a paid
> cloud tenant it is the bill this whole section exists to prevent.

1. **Check it, don't remember it.** Is the sandbox actually still running?
   (`docker ps`, the cloud console, whatever `provisioned_by` says.) What does
   it cost per month right now — not what step 5 estimated?
2. **Reconcile the state files against what was learned.** Reread
   `sandbox.json`, `claim.md` and `slate.md` against every correction in
   `measured.md` and every `notes/` file. Anything an earlier file still says
   that a later measurement overturned gets fixed where it lives, and the
   correction in `measured.md` names the file with `fixed in: <file>`. The
   first complete run corrected a measurement in `measured.md` and left
   `sandbox.json` saying the opposite — "alerting requires seeding" beside
   "seeding not required". Nothing downstream could have known which to trust.
3. **Ask, with `teardown.sh` in hand.** Run it now, or leave it up? Leaving it
   up is often right — a later session resumes against it, and rebuilding has
   its own cost. But it is the user's call, not yours, and it is never left
   unsaid.
4. **Record the answer in `sandbox.json`** as `teardown_decision`:
   `{"decision": "torn down" | "left running", "by": ..., "at": ..., "why": ...,
   "review_by": <date>}`. A left-running sandbox gets a `review_by` date — the
   trial expiry, if there is one. The next session reads this instead of
   guessing, and "left running on purpose until 11-21" is a very different
   state from "nobody checked".
5. **Run `check_onboarding.py $PLATFORM`** — every stage — and it reports
   clean. It also lists the onboarding files still uncommitted — see below.

Then report: what was built; what was bailed, parked, cut, or reassigned, and
why; the coverage delta from `paramify ksi`; each fetcher's real-evidence
verdict; and every standing consequence — each clause of the claim nothing on
the slate evidences.

`.onboarding/<platform>/` is gitignored and safe to keep; it is what makes the
next session on this platform a resume rather than a restart.

### Say what is uncommitted

An onboarding leaves a lot of new files in the working tree: fetchers,
validators, case files, a category file, sometimes a shared validator it
extended. **List them for the user and leave committing to them.** Do not fold
them into an unrelated commit — a `git add -A` in a later step will sweep all
of it in without anyone having decided to, and it is easy to miss in a large
diff.

---

## Anti-patterns

- **Fanning out the slate before fetcher #1 has populated evidence and a
  failing validator.** Gate 3 exists because this is the expensive mistake.
- Treating exit 0 as success. The smoke test is green on an empty payload.
- Seeding into whatever tenant is handy because it has "test" in the name.
- Offering teardown after the resources exist.
- Letting a subagent report findings only in its reply. It writes to
  `.onboarding/`, or the finding is lost and re-derived.
- **Briefing a research agent with no budget and no permission to stop.** The
  step-4 hang, every time. It will not hand back partial work unless told
  partial work is the expected outcome.
- Letting it write the research file at the end. A run that stalls at minute
  forty having written nothing has produced nothing.
- Telling a subagent to "write as you go" and stopping there. Without a
  cadence — one fetch, one edit, never two fetches in a row — it batches, and
  batching is the same failure with extra words.
- Re-running a step-4 agent that ran long. The second run is as open-ended as
  the first, costs the same again, and buries the partial file. Read the
  partial and re-brief narrowly for the named gaps.
- Passing all of step 2's list to one research agent. Five items, the rest
  named out of scope.
- **Letting `slate.md` become the build log.** It is the file the gates and
  every step-8 subagent read; detail belongs in `notes/<fetcher>.md`.
- **Building the third sibling before lifting the shared client into
  `_shared/`.** The copies drift, silently, and nobody chose the difference.
  Lift every helper two fetchers share, not only the client class — the first
  complete run lifted the client and still cloned a timestamp helper that
  drifted into two versions.
- **Treating populated as complete.** A default page size or a user-scoped
  path returns real, well-formed, *partial* data with no error. Compare every
  collected count against an independent true count from `measured.md`.
- **Collecting a field whose meaning depends on one you didn't collect.** A
  retention period with no archive destination reads as "kept" and means
  "deleted".
- **Noting a correction in a newer file and leaving the old one wrong.** Fix it
  where it lives.
- **Marking the slate COMPLETE with the sandbox still running and no decision
  recorded.** Gate 4.
- **Parking a clause that belongs to another platform.** If no sandbox of this
  platform could ever prove it, it is reassigned, not parked.
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
