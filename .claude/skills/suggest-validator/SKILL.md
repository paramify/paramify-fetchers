---
name: suggest-validator
description: >
  Author regex validators for a Paramify evidence set and record them in the
  central validators/ registry. Works from real evidence — a local fetcher run,
  or an artifact pulled from the workspace — and from the solution capability's
  narrative, so the validators assert the claim an assessor actually reads
  rather than whatever the payload happens to contain. Proposes candidate
  assertions for the user to choose from, proves each one can fail, and writes
  it to validators/<category>/<key>.yaml. Use this whenever the user mentions
  validators, validating evidence, or proving a control — "suggest a
  validator", "author a validator", "regex validator", "validate this
  evidence", "what regex proves this control", "does this evidence prove the
  control", "add a validator for this fetcher" — and also when they ask what
  *could* be validated about an evidence file, which is this skill's Phase 3.
---

# Author a Validator

The third beat in the fetcher lifecycle, after `create-fetcher` (build) and
`wire-manifest` (run). Once real evidence exists, this authors the validators
that assert it proves what it is supposed to, and records them in the registry.

**The shape of the work:** establish three things — the evidence file, the
narrative it is supposed to substantiate, and the control that narrative serves
— then propose what could be asserted, let the user choose, and build only
those. Phases 1–3 are an interview and should feel like one. Phases 4–6 are
mechanical and each has a reference file.

**Read these when you reach them, not before:**

| File | When |
|---|---|
| `references/authoring.md` | Phase 4 — roles, rule forms, the regex engine |
| `references/proving.md` | Phase 5 — case files and the three directions |
| `references/registry.md` | Phase 6 — file layout, naming, sync |

Two bundled scripts save re-deriving the same thing every run:
`scripts/find_evidence.py` (Phase 1) and `scripts/score_evidence.py` (Phase 5).

## Golden rules

- **One control needs a validator *set*, not a validator.** An evidence set
  passes only when every validator on it passes, so the work is deciding which
  two or three assertions cover the claim.
- **It needs real, populated evidence.** A fake-cred smoke test (what
  `create-fetcher` produces) yields an empty payload, and you cannot author a
  meaningful "proves the control" regex from that.
- **Uncountable must never read as zero.** The costliest failure and the
  hardest to see: a validator that concludes compliance from a *count* reads a
  renamed upstream key as zero violations, and therefore as compliant. Every
  count-based assertion needs something proving the field was there to count.
- **Every validator ships with three things: what it asserts, what it does NOT
  assert, and when it correctly fails.** A regex without its failure mode is a
  false sense of coverage. The first two go in `statement`; the third is
  Phase 5.

---

## Phase 1 — Which evidence, and where is it

**Ask what the validators are for before hunting for files.** A fetcher name, a
control, an evidence set reference — any of those narrows the search. Hunting
first means sifting hundreds of files with no way to tell which one matters.

Then resolve it, in this order:

**1a. Local runs first.** This is the evidence the user just produced, it is
already gitignored, and it costs nothing to read.

```bash
python .claude/skills/suggest-validator/scripts/find_evidence.py <fetcher_name>
```

Newest first, with the run status and whether the payload carries any measured
value. Pick the newest `success` that looks populated. For a fanout fetcher
(one file per target) take the largest as representative and note the siblings
share its shape.

**1b. The workspace, when nothing local fits.** Some evidence this repo never
produced — a customer upload, another team's fetcher — and it is only readable
from Paramify:

```bash
paramify artifacts list                     # every evidence set + artifact count
paramify artifacts list EVD-FOO             # that set's artifacts, newest first
paramify artifacts pull EVD-FOO             # -> ./evidence/pulled/, gitignored
```

`pull` reports whether what landed is **enveloped**. If it is not, stop and say
so: a workspace holds PDFs, screenshots and spreadsheets, and a regex validator
authored against one is authored against a shape this repo does not produce.
What you pulled is real workspace evidence — it stays out of commits and out of
case files.

**1c. A path from the user, when neither works.** Ask for a path, not a paste:
evidence payloads run to thousands of lines and pasting real tenant data into
the conversation is the thing Phase 5 forbids for case files.

**Nothing anywhere?** The fetcher has not been run. Route the user to
`wire-manifest` → `paramify run` against a **real tenant** and stop — this
skill has nothing to read without that.

### Before reading further: is it actually populated?

The script's verdict is triage and it is wrong in **both** directions.

- **False "populated": static descriptive fields mask empty measurements.** A
  payload carrying a control name, a `ksi` string, or a `related_controls` list
  reads as full even when every *measured* value is zero. The authoritative
  check is field-specific and happens in Phase 5: if your chosen metric matches
  **0 times** on a `success` run, the evidence is empty *for that metric*.
- **False "HOLLOW": some fetchers are inverted, where empty IS compliant.**
  Findings-style fetchers — access analyzer, guard duty, vulnerability scanning
  — report problems. Zero findings means the control is working. **Do not stop
  on these.** The population you must prove non-empty is the *scanner*, not the
  findings: that an analyzer exists and is `ACTIVE`, that the findings array is
  present.

A genuinely-zero tenant is valid. If the user confirms the zeros are real, you
can still author a presence assertion — but say plainly it cannot assert a
non-zero posture.

---

## Phase 2 — What is this supposed to prove

Evidence on its own does not tell you what matters in it. A payload has fifty
fields; two of them bear on the control. The narrative is what separates them.

**2a. The solution capability, from the workspace.** A capability carries the
narrative an assessor reads — the claim the evidence substantiates:

```bash
paramify capabilities list --family "Audit"     # narrow by family or subfamily
paramify capabilities show "Audit Logging Criteria"
```

`show` prints the written narratives. That sentence is the input to Phase 3.

**The capability → evidence set link is not readable** — it is write-only in
the API — so nothing can tell you which capability a set belongs to. Show the
user the candidates and let them pick. If the capability has no narrative
written yet, say so: there is no claim to validate against, and asserting
something plausible instead is how a validator ends up proving the wrong thing.

**2b. A Paramify export, when the API is not reachable.** Ask the user to
attach or point at their export and read the capability from there.

**2c. The control itself.** `GET /projects/{id}/control-implementations`
returns control *ids* only (`3.1.1 a.`), not text, so the text comes from:

1. `framework/reference/ksis.yaml` for FedRAMP 20x KSIs — in the repo,
   authoritative, no network.
2. The fetcher's own `ksis:` and `evidence_set.instructions` in
   `fetchers/<category>/<name>/fetcher.yaml`.
3. Web search, last — for an unfamiliar framework. **Show the user what you
   found and have them confirm it** before it informs a single regex. A
   hallucinated or wrong-revision control text produces a validator that is
   confidently wrong, and nothing downstream catches it.

**2d. Establish the polarity out loud.** Does more data mean better posture, or
worse? A coverage rate or an enabled flag is *normal* polarity: higher and
present is compliant. Findings, violations and exposures are *inverted*: zero
is compliant and a non-empty list is the failure. Getting this backwards
produces a validator that is exactly wrong and reads as plausible either way.

---

## Phase 3 — Propose, then let the user choose

You now have the evidence, the narrative, and the control. Lay out what *could*
be asserted and let the user pick — this is the step that decides what gets
built, and it is theirs to make.

Present each candidate as: **what it asserts**, **the field it reads**, and
**why it bears on the narrative**. One or two lines each. Something like:

> 1. **Every bucket is encrypted** — `payload.results.summary.encryption_percentage`
>    is 100. Directly substantiates "data at rest is encrypted"; fails the
>    moment one bucket is created without it.
> 2. **No bucket is publicly readable** — zero matches for `"isPublic": true`.
>    The narrative claims access is restricted, and a public bucket contradicts
>    it regardless of encryption.
> 3. **The collection succeeded** — `exit_code` is 0. Not a compliance claim;
>    it stops a failed collection from reading as a clean verdict.

Rank them by how directly they bear on the narrative, and say which ones you
would pick and why. Note what each one does *not* cover — that gap is what the
next candidate in the list is for.

**Prefer the strongest anchor available:**

- **(a) A rollup metric** — a rate, percentage or count. Strongest, because a
  non-zero value means the control is *working*, not merely configured.
- **(b) A status or enum whose value denotes compliance** — `"status":"ACTIVE"`,
  `"enabled":true`. Good when there is no rollup.
- **(c) A count of violations that must be zero** — the only option for
  inverted polarity, and the only way to assert something about *every* item in
  a list. Carries the counting trap; Phase 4 handles it.

Skip anchors that are trivially true — keys present in every run regardless of
posture — and flag any candidate you are proposing only because it is easy to
match. Two well-chosen assertions beat five that cannot fail.

Then build only what the user picks.

---

## Phase 4 — Build the set

**Read `references/authoring.md` now.** It has the three roles
(`completeness` / `configuration` / `integrity`), the two rule forms and when
each needs an integrity partner, and the regex engine's real behaviour —
ECMAScript not Python, `MATCH_GROUP` reads the first match only, and why the
collection-health guards are written positively.

---

## Phase 5 — Prove it, in three directions

**Read `references/proving.md` now.** Write the case files, then run
`paramify validators check --select <key>`. Stop on any failure.

The three directions are compliant (it passes), non-compliant (it fails), and
**key renamed** (it does not pass). The third is the one that gets skipped and
the one the whole phase exists for.

**Then run it against the real evidence, and report the result.**

```bash
python .claude/skills/suggest-validator/scripts/score_evidence.py <evidence.json>
```

With no `--select` it runs every validator whose `evidence_sets` matches the
set the file names — the same set Paramify would apply — and prints each rule's
two sides and whether it held. A FAIL here is a legitimate outcome — the tenant may genuinely not meet the
narrative, and saying so is the point of the exercise. But that reading is only
available when the synthetic compliant case passes:

- synthetic compliant PASSes, real evidence FAILs → the tenant is
  non-compliant. Report it as a finding.
- synthetic compliant FAILs → the validator is broken. It cannot pass on a
  hand-built good artifact, so it is not measuring what it claims.

Without that discriminator, "the evidence doesn't meet the narrative" becomes
the excuse that ships a bad regex.

---

## Phase 6 — Record it, and hand back

**Read `references/registry.md` now** for the file layout, the naming rules,
reuse-before-you-create, and the registry gate
(`pytest tests/test_validators_registry.py -q`).

When you hand back, report for each validator: its key, its role, what it
asserts, and when it correctly fails. Say plainly that these are derived from
one evidence sample — templates to confirm against more runs.

**Syncing is a separate, explicit step and the user's call.**
`paramify validators sync` writes to a live workspace, often production. Offer
it; do not run it as the closing move of an interview.

---

## Anti-patterns

- **Hunting for evidence before asking what it is for.** Phase 1 sifts hundreds
  of files with no criterion otherwise.
- **Authoring against the fetcher description instead of the narrative.** The
  description says what was collected; the narrative says what it must prove.
  They are not the same, and only one of them is what an assessor reads.
- **Asking the user to paste an evidence file.** Ask for a path.
- **Taking a web-searched control text as authoritative** without showing the
  user. Wrong-revision control text produces a confidently wrong validator.
- **Authoring against a non-enveloped artifact** pulled from the workspace — a
  PDF or a screenshot is not a shape a regex validator can read.
- **Concluding compliance from a count without proving the counted field
  exists.** Invisible in review, because the validator looks and tests fine.
- **Stopping on "looks empty" for a findings-style fetcher**, where zero
  findings is the compliant state. Check the polarity first.
- **Getting the polarity backwards** — asserting a findings list is non-empty,
  or that a coverage rate is merely present.
- **Using `MATCH_GROUP` to assert something about every item in a list.** It
  reads the first match only; invert to a violation count.
- **Emitting Python-flavored syntax** — `(?P<name>…)` is a hard compile error
  in ECMAScript. Use `(?<name>…)`.
- **Building the whole set before showing the user the options.** Phase 3 is
  the user's decision, not a formality to narrate after the fact.
- **Handing over a validator without its failure mode,** or without running
  directions 2 and 3. A validator that cannot fail proves nothing.
- **Copying a validator to a second file** because it applies to a second
  evidence set. Add the `reference_id` to the existing file's `evidence_sets`.
- **Syncing on your own initiative.** It writes to a live workspace.
