# Jira Fetchers

Six fetchers read a Jira Cloud site over the REST API v3 with an Atlassian
account email + API token (basic auth):

| Fetcher | Evidence | Collector needs |
|---|---|---|
| `jira_site_inventory` | Site, projects, schemes, service desks, recent issue activity | Browse Projects |
| `jira_remediation_items` | JQL-selected findings tickets with owner, due date, full status history | Browse Projects |
| `jira_audit_records` | Site audit log: who changed what configuration, when, from where | Administer Jira |
| `jira_access_roles` | Admin groups and members, product access, per-project privileged grants and role members | Administer Jira |
| `jira_change_requests` | Change, internal connection and exception tickets: CCB approval, deployment, tests, security review, exception expiry and review | Browse Projects |
| `jira_incident_postmortems` | Incidents: severity, category, minutes to report, phase history, linked post-mortems and action items | Browse Projects |

The two admin fetchers make only read calls, but Jira offers no lower permission
for the audit log, application roles or other projects' role members. Run them
under a separate collector account so the everyday fetchers keep a Browse-only
token.

---

## Credentials and configuration

Declared once on the category ([`_categories/jira.yaml`](../_categories/jira.yaml)):

| Variable | Kind | Required | Description |
|---|---|---|---|
| `JIRA_BASE_URL` | config `base_url` | Yes | `https://<site>.atlassian.net` (classic token) or `https://api.atlassian.com/ex/jira/<cloudId>` (scoped token). Other hosts are refused and redirects are not followed |
| `JIRA_EMAIL` | secret `email` | Yes | Email of the Atlassian account the token belongs to |
| `JIRA_API_TOKEN` | secret `api_token` | Yes | API token from [id.atlassian.com → Security → API tokens](https://id.atlassian.com/manage-profile/security/api-tokens) |

Use a dedicated service account. It needs **Browse Projects** on every project
you want in the evidence — projects it cannot see are simply absent, not
reported as errors — and, for Jira Service Management sites, agent access to the
service desks to be listed. `jira_site_inventory` and `jira_remediation_items`
need no Jira administrator permission; `jira_audit_records` and
`jira_access_roles` need **Administer Jira**, so run them under a separate admin
collector account (override `secrets:` for those two in the manifest).

### Read-only scoped token (recommended)

A classic API token can do anything its account can, which for the admin
collector includes changing Jira's configuration. Create a **scoped** token
instead (id.atlassian.com → Security → API tokens → *Create API token with
scopes* → app **Jira**) with only these granular read scopes. Do not add the
classic `manage:jira-configuration` scope: it can write.

| Needed by | Scopes |
|---|---|
| every fetcher (`/myself`) | `read:user:jira`, `read:group:jira`, `read:application-role:jira`, `read:avatar:jira` |
| `jira_remediation_items` | `read:issue-details:jira`, `read:field:jira`, `read:field.default-value:jira`, `read:field.option:jira`, `read:issue-meta:jira`, `read:issue.changelog:jira` |
| `jira_audit_records` | `read:audit-log:jira` |
| `jira_access_roles` | `read:field:jira`, `read:project:jira`, `read:project-role:jira`, `read:permission-scheme:jira`, `read:permission:jira`, `read:project-category:jira`, `read:issue-type:jira`, `read:issue-type-hierarchy:jira`, `read:project.property:jira`, `read:project-version:jira`, `read:project.component:jira` |
| `jira_change_requests` | the `jira_remediation_items` scopes, plus `read:field-configuration:jira`, `read:project:jira`, `read:project-category:jira` |
| `jira_incident_postmortems` | the `jira_change_requests` scopes, plus `read:issue:jira`, `read:status:jira`, `read:issue-security-level:jira`, `read:issue.vote:jira` (for `POST /rest/api/3/issue/bulkfetch`) |

A scoped token only works through the API gateway. Find the site's `cloudId` at
`https://<site>.atlassian.net/_edge/tenant_info` and set
`JIRA_BASE_URL=https://api.atlassian.com/ex/jira/<cloudId>`. The email is still
required. Scopes limit what the token can do; they do not grant permissions, so
the admin collector account still needs Administer Jira.

### `jira_site_inventory`

| Config key | Env | Default | Description |
|---|---|---|---|
| `lookback_days` | `JIRA_LOOKBACK_DAYS` | `90` | Collect issues updated in the last N days |
| `jql` | `JIRA_ISSUE_JQL` | — | Explicit JQL; overrides `lookback_days` |
| `max_issues` | `JIRA_MAX_ISSUES` | `2000` | Issue cap; `metadata.issues_truncated` records whether it was hit |

### `jira_remediation_items`

| Config key | Env | Default | Description |
|---|---|---|---|
| `jql` | `JIRA_REMEDIATION_JQL` | (required) | JQL selecting the findings tickets, closed ones included |
| `max_items` | `JIRA_REMEDIATION_MAX_ITEMS` | `2000` | Ticket cap; `metadata.items_truncated` records whether it was hit |

Calls `POST /rest/api/3/search/jql` and `POST /rest/api/3/changelog/bulkfetch`
(status field, full history, de-duplicated by history id). Summary: open,
closed, open overdue, open unassigned, open without due date, closed after due
date, days to close.

### `jira_audit_records`

| Config key | Env | Default | Description |
|---|---|---|---|
| `lookback_days` | `JIRA_AUDIT_LOOKBACK_DAYS` | `90` | Window of audit records to collect |
| `filter` | `JIRA_AUDIT_FILTER` | (none) | Optional API text filter |
| `max_records` | `JIRA_AUDIT_MAX_RECORDS` | `20000` | Record cap; `metadata.records_truncated` records whether it was hit |

Calls `GET /rest/api/3/auditing/record` (offset/limit 1000, from/to). Issue edits
are not in this log, and organization-level (admin.atlassian.com) audit is not
collected. Atlassian does not publish the audit `category` values, so a record
counts as a sensitive change when its category name contains a key word
(permission, user, group, workflow, security, scheme, project, field, screen,
system, global, application, role); whatever matched nothing is listed in
`summary.unclassified_categories` so the list can be checked against a real
site. Changed values are kept only for sensitive records, shortened to 200
characters with `<` and `>` escaped; other records keep the field name only.

### `jira_access_roles`

| Config key | Env | Default | Description |
|---|---|---|---|
| `project_keys` | `JIRA_PROJECT_KEYS` | all visible | Comma-separated project keys to scan |
| `admin_groups` | `JIRA_ADMIN_GROUPS` | (none) | Extra group names to treat as administrative |
| `all_roles` | `JIRA_ACCESS_ALL_ROLES` | `false` | Read every project role (2 + R calls per project) instead of only the roles named in a privileged grant |
| `max_projects` | `JIRA_ACCESS_MAX_PROJECTS` | `200` | Project cap; hitting it fails the run as partial |

Calls `GET /rest/api/3/group/bulk` (accessType site-admin and admin),
`/group/member`, `/applicationrole`, `/project/search`, and per project
`/project/{key}/permissionscheme?expand=all` and `/project/{key}/role/{id}` for
each role named in a privileged grant (the role index only with
`JIRA_ACCESS_ALL_ROLES`). Privileged permissions are administer project, delete
issues/comments/attachments/worklogs, edit all comments, set issue security and
modify reporter; grants of those to `anyone` or an application role are flagged
as `broad_privileged_grants`, and grants to holder types the fetcher cannot
resolve to accounts (`reporter`, `assignee`, user or group custom fields) are
listed per project as `unresolved_privileged_grants` so the counts are never
silently low. Organization admins (Atlassian Administration) are not visible to
these APIs and are not included.

### `jira_change_requests`

| Config key | Env | Default | Description |
|---|---|---|---|
| `jql` | `JIRA_CHANGE_JQL` | (required) | JQL selecting the change, internal connection and exception tickets |
| `field_names` | `JIRA_CHANGE_FIELDS` | see yaml | JSON mapping roles (`approver`, `approved_at`, `change_type`, `risk`, `security_review`, `test_results`, `deployed_at`, `exception_expiry`, `last_reviewed`) to the site's field names |
| `approved_statuses` | `JIRA_CHANGE_APPROVED_STATUSES` | (none) | Statuses that mean CCB-approved, when approval is a workflow step |
| `preapproved_change_types` | `JIRA_CHANGE_PREAPPROVED_TYPES` | `Standard` | Change types that need no CCB approval |
| `exception_issue_types` | `JIRA_EXCEPTION_ISSUE_TYPES` | `Configuration Exception` | Issue types treated as exceptions |
| `connection_issue_types` | `JIRA_CONNECTION_ISSUE_TYPES` | `Internal Connection` | Issue types treated as internal connection requests |
| `exception_review_days` | `JIRA_EXCEPTION_REVIEW_DAYS` | `365` | Open exceptions not reviewed within this window are flagged |
| `max_items` | `JIRA_CHANGE_MAX_ITEMS` | `2000` | Ticket cap; hitting it fails the run as partial |

Custom field names differ per site, so the fetcher looks them up by name with
`GET /rest/api/3/field` (case-insensitive). A name that matches no field, or
several fields, is listed in `metadata.field_problems` and fails the run as
`partial_failure`, because the findings that depend on that field would be wrong.
For an ambiguous name, `metadata.field_candidates` lists every matching field id;
pin the right one by setting that role to its `customfield_` id in
`JIRA_CHANGE_FIELDS`. Sites with Jira Service Management often have their own
"Change type" and "Change risk" fields, so pin those two by id. Team-managed
projects each create their own copy of a custom field, so a role may be pinned to
several ids (`"change_type": "customfield_10043,customfield_10120"` or a JSON
list); a ticket is read from whichever of them holds a value. Comment bodies are
not collected, only the count.

The default names are the ones used while building the fetcher, not a Jira
standard, so on a new site the first run usually fails with `field_problems`
until `JIRA_CHANGE_FIELDS` names that site's fields. That is deliberate: the
mapping has to be confirmed per site before any finding means anything.

Setting a role to an empty value turns its checks off. Every finding that can no
longer be produced is listed in `metadata.checks_disabled`, so an evidence file
never looks clean about a check that did not run. A setting that depends on a
turned-off field is refused as `bad_config` rather than silently passing or
failing every ticket: no approval source at all (`approver` or `approved_at` off
with no `JIRA_CHANGE_APPROVED_STATUSES`), and for incidents
`JIRA_POSTMORTEM_REQUIRED_SEVERITIES` with `severity` off,
`JIRA_INCIDENT_REQUIRED_PHASES` with `phase` off, or
`JIRA_INCIDENT_CATEGORY_TARGETS` / `JIRA_INCIDENT_REPORT_MINUTES` with
`category` or `detected_at` off.

When a change has no deployed-at field, its deployment time is the first move
into its current done status, so a ticket that was deployed, approved later, and
then reopened and closed again is still reported as approved after deployment;
`last_done_at` and `reopened` show the later move.

The same field rules apply to `JIRA_INCIDENT_FIELDS` below.

### `jira_incident_postmortems`

| Config key | Env | Default | Description |
|---|---|---|---|
| `jql` | `JIRA_INCIDENT_JQL` | (required) | JQL selecting the incident tickets |
| `field_names` | `JIRA_INCIDENT_FIELDS` | see yaml | JSON mapping roles (`severity`, `category`, `detected_at`, `reported_at`, `phase`) to field names |
| `report_minutes` | `JIRA_INCIDENT_REPORT_MINUTES` | `60` | Detection-to-report window |
| `category_targets` | `JIRA_INCIDENT_CATEGORY_TARGETS` | (none) | JSON of per-category notification targets in minutes, matched by name or prefix |
| `postmortem_issue_types` | `JIRA_POSTMORTEM_ISSUE_TYPES` | `Post-mortem` | Linked issue types that count as post-mortems; their sub-tasks are the action items |
| `postmortem_required_severities` | `JIRA_POSTMORTEM_REQUIRED_SEVERITIES` | (all) | Severities whose resolved incidents need a post-mortem |
| `max_items` | `JIRA_INCIDENT_MAX_ITEMS` | `1000` | Incident cap; hitting it fails the run as partial |

---

## What `jira_site_inventory` collects

| Section | Source |
|---|---|
| `site` | `GET /rest/api/3/serverInfo` |
| `collector` | `GET /rest/api/3/myself` — the account the evidence was collected as |
| `projects` | `GET /rest/api/3/project/search?expand=lead,insight,issueTypes` — type, lead, issue types, total issue count, last update |
| `issue_types`, `priorities`, `statuses` | `GET /rest/api/3/issuetype`, `/priority/search`, `/status` |
| `service_management` | `GET /rest/servicedeskapi/servicedesk`, called only when a `service_desk` project exists. A site with none has no Jira Service Management and is recorded as `available: false`, not a failure |
| `issues` | `POST /rest/api/3/search/jql` — key, summary, project, type, status, priority, assignee, reporter, created/updated/resolved, hours to resolve, labels |
| `summary` | Rollups: projects by type, issues by project/type/status category/priority, open vs resolved, open-and-unassigned, resolution time overall and per priority, and separate `change_issues` / `incident_issues` rollups |

Change and incident tickets are picked out by issue-type name — the Jira Service
Management defaults (`Change`, `Normal/Standard/Emergency Change`, `Incident`,
`Major Incident`, …). A site that names them differently still has every issue
in `issues`; narrow `jql` to the relevant projects to shape the evidence.

## Output

`$EVIDENCE_DIR/jira_site_inventory.json`. When any call fails, the file is still
written with `metadata.partial_failure: true` and `metadata.api_failures[]`, and
the run exits non-zero with the reason in the envelope's `metadata.error`.

Every Jira fetcher writes `metadata.complete`, `metadata.partial_failure` (its
opposite, which is what a validator reads) and `metadata.incomplete_reason`. A
run is partial when a call failed, a cap was hit, a field did not resolve, or a
linked issue could not be read. HTTP 429 and 5xx answers are retried up to four
times (honouring `Retry-After`, otherwise 2, 4, 8 and 16 seconds); a request that
still gets no answer is recorded as one failed call and the run continues, except
a host that never answers before the first successful call.
