# Step 5 — The sandbox

Read at step 5 of `onboard-platform`, before proposing any provisioning.

## What this step is for

A fetcher cannot be proven against an empty tenant. The fake-cred smoke test
`create-fetcher` runs proves the env path is intact and nothing more — it exits
green on a payload with nothing in it. Gate 3 asks for *populated* evidence, and
something has to hold the data that populates it.

That something is this step's output, and it is the step with real-world
consequences: money, resources in someone's account, and credentials. Hence the
rules below, which are not style preferences.

## Order of preference

1. **Infra that already exists.** An account the team has, a shared dev tenant,
   a colleague's sandbox they will lend. Free and immediate.
2. **A free tier or trial.** Most platforms have one. Note the expiry — a trial
   that lapses mid-slate strands step 8.
3. **Build it.** CLI, Terraform, a seeder script. Last because it is the only
   option that costs money and leaves something running.

Say which of the three you are on, and why the cheaper ones were ruled out.

## The rules

**Teardown is written before anything is seeded.** Write `teardown.sh` and hand
it back *with* the provisioning plan, in the same message, before approval.
Not after the resources exist, and not "I can clean that up for you later".
A sandbox nobody remembered to tear down is the bill this rule prevents.

Make it safe to run twice and safe to run against an already-empty account —
it will be run by someone who is not sure whether it already ran. The named
arrays at the top are its documentation; a header comment repeating them is
not needed.

**It removes only what it names.** Every container, volume, network, bucket or
role it deletes is listed by exact name at the top of the script, and nothing
else is touched. Never a bare `docker system prune`, a `--filter` wide enough
to match unrelated resources, a tag-based sweep, or a wildcard delete. The
person running teardown is on a machine or account that holds other things,
and a teardown that cleans up by pattern is one surprise match away from
deleting someone's work. The first complete run wrote this rule into its own
script header — *"never runs a bare docker prune, so it cannot touch
containers, volumes or networks belonging to anything else"* — which is the
right instinct and is now the requirement.

Write teardown **before provisioning**, not merely before seeding. They are
often the same moment; when they are not, provisioning is the one that creates
something to clean up.

**State a cost estimate, in dollars.** Per month, and who is paying. "Probably
free" is not an estimate; neither is a number with no idea what the unit is.
If you genuinely cannot tell, say that and give the worst case you can bound.

**Nothing is seeded into a tenant absent from `sandbox.json`.** The tenant id
gets into that file through the gate below and no other way. Being named "test"
is not approval — the usual version of this accident is seeding into a
real tenant with "sandbox" in its display name.

**Every seeder execution is approved individually.** Not the plan approved once
and then a free hand. Each `terraform apply`, each seed script, each re-run
after a fix. The approval is for that execution.

**Seed only what the defaults don't already give you.** Check first: a stock
tenant frequently has both populated surfaces and a failure case out of the
box — the first complete run needed no seeding at all, with three failure
cases pre-existing. When that is the case, write `"seeding": "NOT REQUIRED"`
with the reason into `sandbox.json` and skip `seed.sh` entirely. Seeding you
didn't need is still resources created, still a gate opened, still something
teardown has to know about.

**When seeding is needed, the seeder is a file, `seed.sh`, not a sequence of
ad-hoc commands.** It sits next to `teardown.sh` in the state directory and is
re-runnable. The gate above
is on *executing* it, which presumes there is a reviewable thing to approve —
a pasted block of commands cannot be re-read later to answer "what is actually
in this sandbox", and that question gets asked every time a fetcher returns
something surprising.

**Seed the failure case too.** Research told you what has to exist for a call to
return something non-empty. It also has to return something *non-compliant*, or
step 7's validator has nothing to fail against and Gate 3 cannot be honestly
passed. One encrypted bucket and one unencrypted one; one user with MFA and one
without. A sandbox that is uniformly compliant proves only that the fetcher can
read a compliant tenant.

## sandbox.json

Written at the end of this step, once the gate has passed. Field shapes are in
`references/state.md`. What matters:

- The **tenant/account id** is the literal id the fetcher will authenticate
  against, so it can be compared against what a run is about to touch.
- **`approved_by` and `approved_at`** are what make this a registry rather than
  a note. A tenant with no approval recorded has not been approved.
- The **cost estimate and teardown path** are read back at close-out, which is
  when someone decides whether to shut it down.

## Credentials

The sandbox's credentials are secrets like any other: `${env:VAR}` refs in the
manifest, values in the environment, never in `sandbox.json` and never in
`.onboarding/` at all. The directory is gitignored, which is a backstop against
mistakes, not a place to keep keys.
