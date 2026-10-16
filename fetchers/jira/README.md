# Jira Fetchers

Four fetchers read a Jira Cloud site over the REST API v3 with an Atlassian
account email + API token (basic auth):

| Fetcher | Evidence | Collector needs |
|---|---|---|
| `jira_site_inventory` | Site, projects, schemes, service desks, recent issue activity | Browse Projects |
| `jira_remediation_items` | JQL-selected findings tickets with owner, due date, full status history | Browse Projects |
| `jira_audit_records` | Site audit log: who changed what configuration, when, from where | Administer Jira |
| `jira_access_roles` | Admin groups and members, product access, per-project privileged grants and role members | Administer Jira |

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
collected.

### `jira_access_roles`

| Config key | Env | Default | Description |
|---|---|---|---|
| `project_keys` | `JIRA_PROJECT_KEYS` | all visible | Comma-separated project keys to scan |
| `admin_groups` | `JIRA_ADMIN_GROUPS` | (none) | Extra group names to treat as administrative |
| `max_projects` | `JIRA_ACCESS_MAX_PROJECTS` | `200` | Project cap |

Calls `GET /rest/api/3/group/bulk` (accessType site-admin and admin),
`/group/member`, `/applicationrole`, `/project/search`, and per project
`/project/{key}/permissionscheme?expand=all`, `/project/{key}/role` and
`/project/{key}/role/{id}`. Privileged permissions are administer project,
delete issues/comments/attachments/worklogs, edit all comments, set issue
security and modify reporter; grants of those to `anyone` or an application
role are flagged as `broad_privileged_grants`.

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
