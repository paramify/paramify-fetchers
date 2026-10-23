# Cornerstone Fetchers

Four fetchers measure security training completion in Cornerstone Learning
(Cornerstone OnDemand) through the **Reporting API (RAPI)**: read-only OData
views over Cornerstone's Real-time Data Warehouse. Each one evidences one part
of **KSI-CED-RAT**, which asks for general training for all employees,
role-specific training for high-risk roles, secure software delivery training
for engineers, and training for incident response and disaster recovery staff.

| Fetcher | Evidence set | KSI-CED-RAT clause | Courses env var |
|---|---|---|---|
| `cornerstone_security_awareness_training` | `EVD-CORNERSTONE-SECURITY-AWARENESS-TRAINING` | general training for all employees | `CSOD_SECURITY_AWARENESS_COURSES` |
| `cornerstone_role_based_training` | `EVD-CORNERSTONE-ROLE-BASED-TRAINING` | role-specific training for high-risk roles | `CSOD_ROLE_BASED_COURSES` |
| `cornerstone_secure_development_training` | `EVD-CORNERSTONE-SECURE-DEVELOPMENT-TRAINING` | secure software delivery training for engineers | `CSOD_SECURE_DEVELOPMENT_COURSES` |
| `cornerstone_incident_response_training` | `EVD-CORNERSTONE-INCIDENT-RESPONSE-TRAINING` | training for incident response or disaster recovery staff | `CSOD_INCIDENT_RESPONSE_COURSES` |

None of them writes to Cornerstone. The only POST is the OAuth token request;
every other call is a GET under `/services/api/x/odata/api/views/`.

---

## Setting up access in Cornerstone

1. **Enable the Reporting API.** Admin > Tools > Edge > Marketplace > *Reporting
   API* > Install, then turn it on under Admin > Tools > Edge > API Management.
   It is free in Pilot and Stage; **Production needs a purchase inquiry** from the
   same Marketplace tile, so start that early.
2. **Create a service user** with only the **Reporting API - Read Only** security
   permission. The OAuth application acts as this user.
3. **Register an OAuth 2.0 application** (Admin > Tools > Edge > API Management >
   Manage OAuth 2.0 Applications) bound to that user, and select only these
   Reporting API endpoints:
   - `vw_rpt_training` and `vw_rpt_transcript` (all four fetchers)
   - `vw_rpt_user`, only if you set `user_population_filter`
4. Copy the client ID and client secret. Cornerstone shows the secret once.

The fetchers request scopes `vw_rpt_training:read vw_rpt_transcript:read` (plus
`vw_rpt_user:read` when a population filter is set). Cornerstone cannot limit a
view by field or by division, so treat the secret as access to every row of
those views.

## Credentials and configuration

Declared once on the category ([`_categories/cornerstone.yaml`](../_categories/cornerstone.yaml)):

| Variable | Kind | Required | Description |
|---|---|---|---|
| `CSOD_PORTAL_URL` | config `portal_url` | Yes | `https://<corpname>.csod.com`; use the pilot or stage host to test. Only hosts one label under `csod.com` are accepted |
| `CSOD_CLIENT_ID` | secret `client_id` | Yes | OAuth 2.0 application client ID |
| `CSOD_CLIENT_SECRET` | secret `client_secret` | Yes | OAuth 2.0 application client secret |

Per fetcher:

| Config key | Env | Default | Description |
|---|---|---|---|
| `courses` | see table above | none (required) | Comma-separated courses, matched **exactly** against the training title, the Training Reference Number or the Course Code, or given as the training object id |
| `retraining_interval_days` | `CSOD_RETRAINING_INTERVAL_DAYS` | `365` | A user whose last completion is older than this (or who never completed) is `needs_retraining` |
| `content_review_interval_days` | `CSOD_CONTENT_REVIEW_INTERVAL_DAYS` | `365` | Flags a course whose catalog entry has not changed within this many days |
| `population_filter` | `CSOD_<GROUP>_POPULATION_FILTER` | unset | This fetcher's own population (an OU, group or job-title filter for high-risk roles, engineers, or IR staff). Overrides the shared `CSOD_USER_POPULATION_FILTER` |

Shared by all four (also on the category):

| Config key | Env | Default | Description |
|---|---|---|---|
| `user_population_filter` | `CSOD_USER_POPULATION_FILTER` | unset | OData `$filter` over `vw_rpt_user` selecting everyone who must take security training, normally active employees. **Set it.** Without a population, users who were never assigned a course are invisible, `completion_rate_pct` is null and the run reports `partial_or_empty`. Confirm the column names in your portal's User RTDW spec |
| `withdrawn_status_ids` | `CSOD_WITHDRAWN_STATUS_IDS` | unset | Transcript status ids (from the portal's transcript status lookup) that mean the user withdrew |
| `failed_status_ids` | `CSOD_FAILED_STATUS_IDS` | unset | Transcript status ids that mean the attempt failed; a completion with `user_lo_pass` false is `failed` even without this |
| `page_size`, `max_pages`, `http_timeout`, `min_request_interval` | `CSOD_PAGE_SIZE`, `CSOD_MAX_PAGES`, `CSOD_HTTP_TIMEOUT`, `CSOD_MIN_REQUEST_INTERVAL` | 1000, 500, 120, 0.25 | Paging and throttling. The RAPI throttle is about 400 requests per minute per portal |

Course lists: a comma separates required courses; a `|` separates
alternatives that satisfy one course, so an annual rollover
(`"2025 Security Awareness|2026 Security Awareness"`) does not reset everyone
to 0%.

---

## What it collects

| Step | View | Columns |
|---|---|---|
| Resolve the configured courses (all names in as few queries as the URL limit allows) | `vw_rpt_training` | `object_id`, `lo_title`, `lo_type`, `lo_version`, `lo_active`, `lo_status`, `lo_create_dt`, `lo_modified_dt`, `training_version_effective_dt`, `is_latest_training_version`, `course_code`, `lo_training_ref` |
| Every registration for those courses | `vw_rpt_transcript` | `transc_user_id`, `transc_object_id`, `reg_num`, assigned / registered / start / completion / due dates, `user_lo_pct_complete`, `user_lo_pass`, `is_removed`, `archived`, `exempt_dt`, `is_assigned`, `is_required`, `is_latest_reg_num`, `user_lo_last_modified_dt` |
| User population (optional) | `vw_rpt_user` | `user_id` only |

Column names are from Cornerstone's *Training and Transcript RTDW Technical
Specification* v26.03. **Users are identified only by Cornerstone's numeric
`user_id`.** No names or email addresses are requested.

Every view read is complete or it fails: the view is counted first
(`$count=true&$top=0`), every page is followed through `@odata.nextLink`, rows
are de-duplicated on the view's unique key (Cornerstone warns rows can repeat
between pages while the warehouse syncs), and fewer unique rows than the count
is recorded as a failure. A nextLink that leaves the portal or the views root, a
repeated nextLink, an empty page that still links onward, or hitting
`CSOD_MAX_PAGES` are failures too.

### Per user, per course

| Field | Meaning |
|---|---|
| `status` | Of the latest registration: `withdrawn` or `failed` (configured status ids, or a completion with `user_lo_pass` false), `exempt`, `completed`, `overdue` (due date passed, not completed), `in_progress`, `not_started`, or `not_assigned` (in the population, no transcript record) |
| `last_completed_at`, `days_since_last_completion` | Most recent **passed** completion across all registrations, so last year's completion still counts while this year's re-assignment is open and not yet due |
| `last_exempt_at` | Most recent exemption; an exemption ages like a completion and must be renewed every interval |
| `current` / `needs_retraining` | Not overdue, and a passed completion or an exemption within `retraining_interval_days`. An overdue assignment makes the user `needs_retraining` even if an older completion is still inside the window |
| `latest_registration.cornerstone_status_id` | Cornerstone's own status code, so the derived status can be checked against it |
| `latest_registration` | Assigned, due and completed dates, `days_overdue`, passed, required, archived, exempt date |

Removed registrations and rows with no user id are excluded and counted in
`summary.removed_registrations_excluded` and `summary.rows_without_user_id_excluded`.

### Summary

Per course and overall: users in scope, counts by status, current,
needs_retraining, `completion_rate_pct` (current / population; null when no
population filter is set), and the largest `days_overdue`. Each matched catalog entry also reports its version, last
modified date, version effective date and whether its content changed within
`content_review_interval_days`.

**null means not measured; 0 means measured and zero.** A course name that
matches nothing reports its metrics, and the overall summary, as null;
`config_resolution` lists what did not resolve. That run exits 0 so a typo shows
up in the evidence instead of turning the nightly run red.

No fetcher decides pass or fail. Whether a completion rate is acceptable is
Paramify's call, downstream.

## Output

`$EVIDENCE_DIR/cornerstone_<short_name>.json`. When any call fails, the file is
still written with `metadata.partial_failure: true`, `metadata.api_failures[]`,
`metadata.complete: false` and `metadata.incomplete_reason`, and the run exits
non-zero with the reason in the envelope's `metadata.error`.

## Known limits

- **Not yet run against a live portal.** The collect path is covered offline by
  `tests/test_cornerstone_fetchers.py`; the first run against a pilot or stage
  portal is still the gate for populated, complete evidence.
- Population: without a population filter the counts cover only users who hold
  the course on their transcript, the rate is null and the status is
  `partial_or_empty`. Set `CSOD_USER_POPULATION_FILTER` (active employees) and,
  for the role-based, secure development and incident response fetchers, their
  own `population_filter` naming the role, OU or group.
- Withdrawn and failed statuses: Cornerstone's status ids are portal lookup
  values, so they are configured (`CSOD_WITHDRAWN_STATUS_IDS`,
  `CSOD_FAILED_STATUS_IDS`) rather than hard-coded; `user_lo_pass` false is
  always treated as failed.
- Cornerstone recommends its Data Exporter API (DEAPI, `transcript_core`) over
  RAPI where both cover the data and may deprecate RAPI views over time. The
  client's read path is the same OData shape, so porting is a change of root and
  view names.
