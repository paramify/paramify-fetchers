# Step 4 — Researching the target

Read at step 4 of `onboard-platform`. This is the brief for the research
subagent and the standard its output is held to.

## Why this is delegated

The reading is wide and most of it is wrong or irrelevant — three API versions,
a deprecated SDK, a docs page that describes a field the endpoint stopped
returning. None of that belongs in the main session's context, and none of it
needs to be there: the deliverable is a file on disk.

## The brief

Give the subagent, verbatim:

> Research `<platform>`'s API, CLI, and SDK for collecting: `<the data from
> step 2>`, in service of this claim: `<the sentence from claim.md>`.
>
> Write your findings to `.onboarding/<platform>/research.md` using the
> structure below. Report back only a summary — the file is the deliverable.
>
> **Every factual claim is cited to a URL you actually fetched, or marked
> `UNVERIFIED`.** Do not write down an endpoint shape, a field name, a rate
> limit, or a permission scope you did not read on a page. If the docs are
> ambiguous, say they are ambiguous. An uncited API shape is how a fetcher gets
> built against an endpoint that does not exist.

### When step 1 produced only a platform name

Step 1 allows one follow-up and then moves on, so you will sometimes get here
with the platform named and its surfaces not. That is a legitimate handoff, not
a skipped step — a user onboarding a platform they don't yet know well cannot
invent the surface list, and guessing on their behalf is worse than looking.

Add to the brief:

> The surfaces were not established up front. Before researching in depth,
> **enumerate what `<platform>` exposes that is security- or
> compliance-relevant** — identity and access, authentication events, network
> controls, encryption settings, audit logging, configuration baselines — and
> say for each whether it is readable via API, CLI, or not at all. Put that
> enumeration first in the file, under "Surfaces". Then research the two or
> three that most plausibly serve the claim, in the depth the headings below
> ask for.

Bring the enumeration back to the user before step 5. It is the list step 1
could not produce, and cutting it with them is how the slate at step 6 stops
being your guess about what they wanted.

## What research.md must answer

Structure it under these headings. An empty heading with "not found" under it
is a finding; a missing heading is a gap.

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
