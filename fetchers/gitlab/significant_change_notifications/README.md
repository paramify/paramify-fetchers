# gitlab_significant_change_notifications

Turns GitLab merge requests that engineering flagged as significant changes into
FedRAMP Significant Change Notifications (SCN-CSO-INF), validated against
[FedRAMP's SCN schema, 2026-06-24](https://www.fedramp.gov/schemas/fedramp-significant-change-notifications-schema-2026-06-24.json).

Evidence for change-management (KSI-CMT-LMC) and the SCN obligation itself.

## What it does

1. Lists merge requests for one project in the lookback window (paginated).
2. Keeps the ones carrying a **ticked** marker checkbox in the description —
   `- [x] Significant Change — SCN required` — or the label named in
   `GITLAB_SCN_MARKER_LABEL`.
3. Slices out the `## Significant Change` section and parses its `###` headings
   and `**Key:** value` lines into SCN fields.
4. Validates each assembled SCN two ways: against the vendored FedRAMP **schema**,
   and against **SCN-CSO-INF** — the information a notification must actually
   carry. The schema requires three properties; SCN-CSO-INF asks for a dozen.
5. Writes **one** evidence file holding the array of notifications plus per-MR
   provenance (author, approvers, merge commit, MR URL).

### Marker semantics

**Ticked means "this is an SCN."** The marker appears as `- [ ]` in the template;
the fetcher looks for `- [x]`. An MR
with the box present but unticked is not treated as a significant change — it is
recorded in `skipped_unticked` so "the author decided no" stays distinguishable
from "the template was never installed."

## Fanout-capable

Single-target per invocation; the runner fans out across projects via
`supports_targets: true`. See [`docs/run_manifest_guide.md`](../../../docs/run_manifest_guide.md#3-fan-out-with-targets).

## Required env vars

| Var | Source |
|-----|--------|
| `GITLAB_URL` | `target_schema.url` |
| `GITLAB_API_TOKEN` | per-target secret (scope: `read_api`) |
| `GITLAB_PROJECT_ID` | `target_schema.project_id` |
| `FEDRAMP_CERT_PACKAGE_URI` *or* `PARAMIFY_CERT_PACKAGE_URI` | one of the two is required — see below |
| `GITLAB_SCN_STATE` | optional, default `merged` |
| `GITLAB_SCN_DAYS_BACK` | optional, default `30` |
| `GITLAB_SCN_MAX_RESULTS` | optional, default `100` |
| `GITLAB_SCN_MARKER_LABEL` | optional, e.g. `significant-change` |
| `GITLAB_SCN_SECTION_HEADING` | optional, default `Significant Change` |
| `GITLAB_SCN_STRICT` | optional, default `true` |
| `GITLAB_SCN_REQUIRE_COMPLETE` | optional, default `true` |
| `EVIDENCE_DIR` | runner-set |

### The Certification Package Overview URI

Required by the FedRAMP schema, and constant per service offering — one workspace
publishes one. The three `paramify_*` VER fetchers write it into the same
`certificationPackageOverviewUri` field, reading it from
`PARAMIFY_CERT_PACKAGE_URI` (`platforms.paramify.config.cert_package_uri`).

**This fetcher reads that same variable**, so one manifest line drives every
artifact and an SCN cannot cite a different document than the VER reports. Set
`FEDRAMP_CERT_PACKAGE_URI` only to override it for a run targeting a different
service offering. One of the two must be set; which one was used is recorded in
`metadata.certification_package_overview_uri_source`, and a warning is raised
when both are set and disagree.

```bash
export FEDRAMP_CERT_PACKAGE_URI='https://trust.example.com/artifacts/<your-cpo>.json'
```

Quote it — these URIs commonly contain percent-encoded spaces. The MR template
carries the same value on a `**Certification Package Overview URI:**` line; when
the two differ, the merge request wins for that notification. Values pasted as
`` `backticks` ``, `<angle brackets>` or `[Markdown](links)` are unwrapped before
validation.

## MR template

[`templates/significant_change.md`](templates/significant_change.md) — a
change-request template with the SCN block wired in. Install as
`.gitlab/merge_request_templates/Change Request.md` in each targeted project.

## How the section is parsed

The SCN section runs from the heading containing "Significant Change" to the
next `---` rule (or the next heading of the same level). Within it the parser
tries two readings, in order:

**1. Schema-key annotations — authoritative.** The change-request template labels
every field with its schema key:

```markdown
**Categorization Explanation** *(`changeTypeExplanation`)*
**Impacted KSIs or Rev5 Controls** *(`impactedControls[]`)*
```

The backticked key is what the parser binds to, so the human-facing label can be
renamed freely. Annotation noise on the same line — `**[REQUIRED]**`, a trailing
`(List KSI identifiers…)` instruction — is stripped, and a backticked value on
the marker line (the CPO URI) is read off it.

**2. Headings and `**Key:** value` lines — fallback.** For templates with no
annotations: `### Reason for Change`, `**Change Type:** Adaptive`, and aliases
(`Impact Analysis` / `Business or Security Impact Analysis`). Only fills fields
reading 1 did not.

Both readings tolerate what people actually type: `changeType` from a ticked
`- [X] Adaptive` or from an inline value; lists as bullets or comma-separated;
milestone dates leading (`2026-09-01 — Ship`), trailing (`Ship (2026-09-01)`),
pipe-separated (`` `2026-09-01` | Ship ``), or backticked; URIs bare, in
backticks, in `<angle brackets>`, or as `[Markdown](links)`.

### Placeholders are dropped, not emitted

`YYYY-MM-DD`, `KSI-XXX-XX`, `AC-X`, `N/A`, `TBD`, `??` and friends are treated as
"not filled in": the field is omitted and a line is added to `parse_notes`. A
notification that stays silent about its planned start is honest; one that says
`"plannedStart": "YYYY-MM-DD"` is rejected for a reason that explains nothing.

A milestone whose date is still a placeholder keeps its description and loses the
date — the description is real information.

## Field mapping

| MR markdown | SCN field | Required |
|---|---|---|
| `*(`changeType`)*` — ticked `- [X] Adaptive`, or `**Change Type:** Adaptive` | `changeType` | ✅ |
| `*(`changeDescription`)*` anywhere in the MR (incl. an outer heading); else `## Requested Changes` by name; else the MR title | `changeDescription` | ✅ |
| `*(`certificationPackageOverviewUri`)*`; else the `FEDRAMP_CERT_PACKAGE_URI` env | `certificationPackageOverviewUri` | ✅ |
| `*(`changeTypeExplanation`)*` / `### Change Type Explanation` | `changeTypeExplanation` | |
| `*(`reason`)*` / `### Reason for Change` | `reason` | |
| `*(`customerImpact`)*` / `### Customer Impact` | `customerImpact` | |
| `*(`impactAnalysis`)*` anywhere in the MR; else `### Impact and Security Analysis` by name | `impactAnalysis` | |
| `*(`impactedControls[]`)*` / `### Impacted Controls` | `impactedControls[]` | |
| `*(`planAndTimeline.summary`)*` | `planAndTimeline.summary` | required *if* the block exists |
| `*(`planAndTimeline.plannedStart`)*` / `**Planned Start:**` | `planAndTimeline.plannedStart` | |
| `*(`planAndTimeline.plannedCompletion`)*` / `**Planned Completion:**` | `planAndTimeline.plannedCompletion` | |
| `*(`planAndTimeline.milestones[]`)*` / `#### Milestones` | `planAndTimeline.milestones[]` | |
| `*(`assessorName`)*` / `**Assessor:**` | `assessorName` | |
| `*(`relatedVulnerability`)*` / `**Related Vulnerability:**` | `relatedVulnerability` | |
| `**Approver:**` / `**Approver Title:**` | *(not in the schema)* → `notifications[].approver` | |

Two fields are read from outside the SCN section, because the change-request
template has no slot for them inside it. That is not a liberty — the content is
on the same merge request, written for this change, and the alternative is a
FedRAMP-required field falling back to a branch name.

Annotating the outer heading makes it explicit and lets the heading be renamed:

```markdown
## What We Are Changing *(`changeDescription`)*
```

Without an annotation the fetcher matches the heading by name instead
(`Requested Changes`, `Impact and Security Analysis`). Either way the source
heading is named in `parse_notes`, so the evidence records where each field
came from.

Note that FedRAMP treats `changeDescription` (*what* changed) and `reason`
(*why*) as distinct fields — pointing both at the same section produces a
notification that answers "what changed?" with a justification.

SCN-CSO-INF asks for an approver name and title, but FedRAMP's JSON schema
v0.1.2 has no field for one. It is carried next to the notification rather than
inside it, so the `scn` object stays a verbatim, submittable FedRAMP document.

## Change-request provenance

Everything outside the SCN section that a reviewer would want is captured under
`merge_request.change_request_form`:

| Field | Why it matters |
|---|---|
| `emergency_change` | SCN-CSO-EMG is a different notification path from the standard one. Also raised as a parse note. |
| `routine_recurring_declared` | A ticked "Routine Recurring — SCN not required" is an explicit SCN-RTR decision, recorded as such rather than as a skipped form. |
| `scope` / `impact_class` | The C1–C4 rating and Helm/Terraform scope, useful for sanity-checking an Adaptive call. |
| `result` | "Change was completed successfully" is what starts the *within N business days of finishing* clock. |

## Output

`<EVIDENCE_DIR>/gitlab_significant_change_notifications_<sanitized_project_id>.json`

One file per target. The runner discovers evidence by diffing `EVIDENCE_DIR` and
envelopes every `.json` it finds — writing N separate SCN files would envelope
each one and stop it being a valid FedRAMP document. So the array lives inside a
single payload, and every `notifications[].scn` is schema-valid on its own and
can be lifted out verbatim by whatever submits it.

```jsonc
{
  "metadata": { "project_id": "...", "fedramp_schema_id": "...", "..." : "..." },
  "status": "success",
  "merge_requests_scanned": 5,
  "notifications": [
    {
      "merge_request": { "iid": 101, "web_url": "...", "approvers": ["..."], "..": ".." },
      "scn": { "changeType": "Adaptive", "changeDescription": "...", "..": ".." },
      "validation": { "valid": true, "errors": [] },
      "parse_notes": [],
      "approver": { "name": "Jane Doe", "title": "Director of Security Engineering" }
    }
  ],
  "skipped_unticked": [ { "iid": 104, "reason": "checkbox present but not ticked" } ],
  "summary": {
    "flagged_count": 3, "schema_valid_count": 2, "schema_invalid_count": 1,
    "by_change_type": { "Adaptive": 1, "Transformative": 1, "unspecified": 1 },
    "unticked_marker_count": 1, "routine_recurring_count": 1,
    "emergency_change_count": 0, "notifications_with_parse_notes": 2
  },
  "api_failures": []
}
```

## Schema validity is not completeness

FedRAMP's JSON schema requires exactly three properties:
`certificationPackageOverviewUri`, `changeType`, `changeDescription`. Everything
else — impacted controls, planned dates, customer impact, the approver — is
optional to the validator.

SCN-CSO-INF asks for all of it. So a notification can validate perfectly and
still tell a reviewer nothing about which controls the change touches, when it
happens, or who signed it off. That document passes automated validation and
fails review, which is the worst of both: it looks green right up until it
doesn't.

Each notification therefore carries a `completeness` block naming exactly what
SCN-CSO-INF wants and didn't get:

```jsonc
"completeness": {
  "complete": false,
  "missing": [
    {"field": "impactedControls",
     "requirement": "the KSIs or Rev5 controls verified, assessed or validated as part of the change"},
    {"field": "planAndTimeline.plannedStart",
     "requirement": "the date changes to the system begin"},
    {"field": "approver.name", "requirement": "approver name"}
  ]
}
```

`GITLAB_SCN_REQUIRE_COMPLETE` (default `true`) fails the run when any flagged MR
is incomplete, separately from schema validity, and the failure reason names the
missing fields per MR.

The two fields SCN-CSO-INF marks *"if applicable"* — `assessorName` and
`relatedVulnerability` — are deliberately excluded. Their absence is a legitimate
answer, not an omission.

## Exit codes

- `0` — success
- `1` — required env var missing (`bad_config`), GitLab API failure
  (`partial_failure`), at least one flagged MR produced an SCN that fails schema
  validation (`GITLAB_SCN_STRICT`, default true), or at least one schema-valid
  SCN is incomplete under SCN-CSO-INF (`GITLAB_SCN_REQUIRE_COMPLETE`, default
  true). All are `partial_failure`, and the reason names the MRs and the missing
  fields.

The evidence file is written on every path, including failures, so a partial
collection is still readable.

## Vendored schema

[`schemas/fedramp_scn_2026-06-24.json`](schemas/fedramp_scn_2026-06-24.json) is
FedRAMP's schema with one edit: the remote `$ref` for
`certificationPackageOverviewUri` (into
`fedramp-common-definitions-schema-2026-06-24.json`) is inlined verbatim, so
validation needs no network call at collection time. Re-vendor when FedRAMP
publishes a newer dated schema — the date is in the filename and in
`metadata.fedramp_schema_id`, so evidence records which version it was checked
against.

## Testing

```bash
python fetchers/gitlab/significant_change_notifications/tests/mock_gitlab.py
```

Stands up a fake GitLab API with seven MRs and runs 57 assertions over the
result. The headline fixture is Paramify's change-request template filled in for
a completed version of the same MR, a routine-recurring declaration, an
emergency change, an old heading-style MR, an MR that ticks the box and writes
nothing, and one with no marker at all.
