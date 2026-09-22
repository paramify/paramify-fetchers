# Step 4 — Researching the target

Read at step 4 of `onboard-platform`. This is the brief for the research
subagent and the standard its output is held to.

**This file is instructions. It is never written to.** The subagent's output is
a different file — `.onboarding/<platform>/research.md`, outside the skill,
gitignored, one per platform. This file lives under `.claude/skills/` and is
committed; nothing in the flow edits it. (It used to be named `research.md`
too, which was asking for exactly the mix-up this paragraph now rules out.)

## Why this is delegated

The reading is wide and most of it is wrong or irrelevant — three API versions,
a deprecated SDK, a docs page that describes a field the endpoint stopped
returning. None of that belongs in the main session's context, and none of it
needs to be there: the deliverable is a file on disk.

## Why it runs long, and what stops it

API research has no natural end. There is always another page, another SDK
version, another field worth confirming, so an agent told to "research the
platform" will keep going until something stops it. Nothing in the task says
when it has enough.

Three things in the brief below do that work, and **none of them is optional —
dropping any one reproduces the hang**:

1. **It writes the file from the first finding, and keeps writing.** The file is
   the deliverable, so the deliverable must exist before the agent is done.
   A run that is killed at minute forty having written nothing has produced
   nothing; the same run writing as it goes leaves a usable partial.
2. **Breadth before depth.** Every heading gets a shallow answer before any
   heading gets a thorough one. When the budget runs out — and it will — that
   leaves a complete-but-thin file, which step 6 can cut a slate from. The
   alternative leaves heading 1 exhaustive and headings 2–8 empty, which is
   worth less than nothing because it looks like progress.
3. **A stated budget and a stop rule.** A page count, and permission to stop.
   An agent will not grant itself permission to hand back incomplete work
   unless the brief says incomplete work is the expected outcome.

## The brief

Give the subagent, verbatim:

> Research `<platform>`'s API, CLI, and SDK for collecting: `<the data from
> step 2>`, in service of this claim: `<the sentence from claim.md>`.
>
> **Your first tool call is a write, before any research.** Create
> `.onboarding/<platform>/research.md` — that exact path, relative to the repo
> root, a file that does not exist yet — from the skeleton below. Eight
> headings, `TODO` under each. **Never write anything under `.claude/`**; that
> is the skill's own committed source, not your output. Do not fetch anything
> first. Do not plan first. The skeleton goes on disk, then you start.
>
> `<paste the skeleton from "The skeleton" below, with the claim and the ≤5
> items filled in>`
>
> **Then alternate: fetch, write, fetch, write.** After each page you read,
> edit the file — replace the relevant `TODO` with what you just learned and
> its URL — *before* you fetch the next one. **Never make two fetches in a row
> without an edit between them.** Not "write it up at the end", not "batch a
> few and then save": one fetch, one edit, repeat.
>
> This is not bookkeeping, it is the deliverable being produced incrementally.
> The file is what you are making; your reply is only a summary of it. **If you
> are stopped at any moment — budget, error, a timeout, someone kills the
> session — whatever is in the file at that instant is what you produced.**
> Work so that instant is never expensive.
>
> **Two passes, in this order.** First pass: answer *every* heading in one or
> two sentences, even poorly — `UNVERIFIED`, or "not found in 10 minutes", are
> answers. Only once every heading has something under it, go back and deepen
> the ones that matter most for the claim. Never research one heading
> thoroughly before the others have anything.
>
> **Budget: about 25 page fetches, or 3 per heading on the first pass.** When
> you reach it, stop, write `## Budget reached` at the end of the file listing
> what is still thin, and hand back. **Stopping at the budget with a
> complete-but-shallow file is a success, not a failure** — the main session
> will re-brief you for specific gaps if it needs more, which is cheaper than
> you guessing which gap mattered.
>
> **If a source is unreachable** — login wall, 403, JS-only docs, no official
> docs at all — write that down under the heading as `UNREACHABLE: <url>` and
> move on. Do not retry more than once and do not go hunting for an unofficial
> mirror. A named blocker is a finding the main session can act on; a silent
> forty-minute search for a workaround is not.
>
> **Every factual claim carries one of three markers.** Nothing goes in the
> file unmarked:
>
> - **`MEASURED`** — you called the live sandbox and this is what it returned.
>   **The strongest evidence there is**, stronger than any doc citation,
>   because it is the server's own answer for the version actually in front of
>   you. Prefer it whenever the sandbox is already up: one real call settles
>   what three doc pages leave ambiguous. Record the call alongside the answer.
> - **A fetched URL** — you read it on a page. Good, and the only option before
>   the sandbox exists. Do not write down an endpoint shape, a field name, a
>   rate limit, or a permission scope you did not read somewhere. If the docs
>   are ambiguous, say they are ambiguous.
> - **`UNVERIFIED`** — you did not confirm it. **Cheap, and meant to be used**
>   rather than spending fetches to be sure. It is the release valve on the
>   rule above, not an admission of failure.
>
> An unmarked claim is the dangerous one, because a later reader cannot tell
> which of the three it was. **When `MEASURED` and the docs disagree, the
> measurement wins** — and say so in the file, since a documented behaviour the
> server does not exhibit is itself worth knowing.
>
> **Say what the measurement is *of*.** A sandbox is often not the production
> target — a container instead of the hosted product, one edition instead of
> another — and a `MEASURED` line inherits that gap. Name it once at the top of
> the file rather than qualifying every line.

**Cap what you hand it.** Step 2 deliberately produces a wide list, and "per
item from step 2" against fifteen items is fifteen research jobs in one. Pass
**at most five**, chosen for the claim, and name the rest in the brief as
explicitly out of scope for this pass. If the slate later needs one of them,
that is a second, narrow subagent — which is fast, because it has one job.

### When step 1 produced only a platform name

Step 1 allows one follow-up and then moves on, so you will sometimes get here
with the platform named and its surfaces not. That is a legitimate handoff, not
a skipped step — a user onboarding a platform they don't yet know well cannot
invent the surface list, and guessing on their behalf is worse than looking.

Add to the brief:

> The surfaces were not established up front. **Before researching anything in
> depth, spend at most 5 fetches** — the API reference index or the docs table
> of contents is usually enough — to **enumerate what `<platform>` exposes that
> is security- or compliance-relevant**: identity and access, authentication
> events, network controls, encryption settings, audit logging, configuration
> baselines. One line each, saying whether it is readable via API, CLI, or not
> at all. Write it under `## Surfaces` **and stop there.**
>
> Hand that list back before going deeper. Do not research the surfaces in this
> pass — the point of the list is that someone else chooses from it.

Bring the enumeration back to the user before step 5. It is the list step 1
could not produce, and cutting it with them is how the slate at step 6 stops
being your guess about what they wanted.

## What research.md must answer

### The skeleton — hand this to the agent to write first

This is the literal first write, before any fetching. Eight headings, `TODO`
under each, so every later edit is a replacement rather than a decision about
where something goes:

```markdown
# Research — <platform>

**Claim:** <the sentence from claim.md>
**Researching:** <the ≤5 items from step 2>
**Out of scope this pass:** <the rest>

## Access surface
TODO
## Auth model
TODO
## Endpoints that carry the data
TODO
## Pagination, rate limits, cost
TODO
## Fanout
TODO
## Evidence or issue report
TODO
## What the sandbox needs
TODO
## Contradictions and gaps
TODO
```

A heading still reading `TODO` at the end is itself the finding that nothing
was learned there — which is why the skeleton is written up front rather than
grown. A file that grows heading by heading cannot distinguish "not researched"
from "researched and empty", and those call for different next steps.

### What goes under each

An empty heading with "not found" under it is a finding; a missing heading is
a gap.

**Access surface.** Is there a first-class CLI? An official SDK, in which
languages? A plain REST API? This decides `runtime:` — bash when the tool ships
a real CLI (`aws`, `az`, `kubectl`, `gcloud`), Python when it needs an SDK,
pagination, or non-trivial parsing.

**Auth model.** A long-lived token or key read from env (→ `secrets[]`), or an
ambient credential chain like a role, workload identity, or a managed identity
(→ declared but `required: false` on the category file). Name the exact env
vars. Say what has to be done in the platform's UI to mint a credential, and
**what permission or scope the read needs** — this is the single most common
reason a fetcher works for its author and fails for everyone else.

**The endpoints that carry the data.** Per item from step 2: the endpoint or
command, the shape it returns, and the field that would carry the measured
value. Cited.

**Pagination, rate limits, and cost.** Whether a full enumeration is one call or
a thousand, and whether any of them are billed.

**Fanout.** Does this platform have accounts, projects, regions, or tenants a
fetcher would need to run once per? That is `supports_targets: true`, a
`target_schema`, and `aggregation: per_target` — decide it here, not at build
time, because retrofitting fanout means rewriting the entry script.

**Evidence or issue report.** Does the platform *compute findings* — a
vulnerability scan, a CSPM export — or does the fetcher assert a state? The
first is an issue report with its own contract
(`docs/issue_report_fetchers.md`); the second is evidence. Getting this wrong
is a rebuild, not an edit.

**What the sandbox needs.** What has to exist in a tenant for each of these
calls to return something non-empty. Step 5 is built directly on this answer,
and it is the heading most often left thin: "an account" is not enough, "a
storage bucket with encryption enabled, and a second without" is.

**Contradictions and gaps.** Where the docs disagree with each other, and what
could not be determined. Named, not smoothed over.

## Reading it back

When the file lands, read it in the main session and check one thing before
anything else: **does it invalidate the step-3 claim?** If the data is not
exposed, or needs an admin grant nobody will approve, revise the claim now.
Step 6 is where it becomes binding, and a claim that survives to step 6 unread
is a slate built on it.

### When the subagent runs long or never comes back

Expected often enough to have a procedure. **Read the file — do not re-run the
agent.** It has been writing as it goes, so there is almost always something
there, and the recovery is nearly always cheaper than the restart.

1. **Read `research.md` and judge it against one question:** can step 6 cut a
   slate from this? Not "is it complete" — it will not be. A file naming three
   readable surfaces with an auth model is enough to plan against, even with
   every rate limit still `UNVERIFIED`.
2. **If yes, continue.** Carry the thin parts forward as open questions on the
   slate rather than blocking on them. Most resolve themselves at step 7, when
   a real call either works or doesn't — which is a better answer than the docs
   would have given.
3. **If no, re-brief narrowly for the specific gaps** — one or two headings, by
   name, with the fetch budget for those alone. A narrow re-brief finishes
   fast, because the reason the first one ran long is that it was open-ended.
   Re-running the original brief reproduces the original hang.
4. **If the file is empty or absent**, the agent stalled before its first write,
   which means the brief was wrong — most likely it was handed more than five
   items from step 2, or the enumerate-mode cap was left out. Fix the brief and
   re-run once. Twice means stop and do step 4 in the main session, where you
   can see what it is doing.

**Never silently re-run a step-4 agent that ran long.** The second run is as
open-ended as the first, costs the same again, and buries the partial findings
the first one wrote.
