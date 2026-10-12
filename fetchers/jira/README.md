# Jira Fetchers

One fetcher inventories a Jira Cloud site and its recent issue activity, using
an Atlassian account email + API token over basic auth.

---

## Credentials and configuration

Declared once on the category ([`_categories/jira.yaml`](../_categories/jira.yaml)):

| Variable | Kind | Required | Description |
|---|---|---|---|
| `JIRA_BASE_URL` | config `base_url` | Yes | Site URL, e.g. `https://<site>.atlassian.net` |
| `JIRA_EMAIL` | secret `email` | Yes | Email of the Atlassian account the token belongs to |
| `JIRA_API_TOKEN` | secret `api_token` | Yes | API token from [id.atlassian.com → Security → API tokens](https://id.atlassian.com/manage-profile/security/api-tokens) |

Use a dedicated service account. It needs **Browse Projects** on every project
you want in the evidence — projects it cannot see are simply absent, not
reported as errors — and, for Jira Service Management sites, agent access to the
service desks to be listed. No Jira administrator permission is required.

### `jira_site_inventory`

| Config key | Env | Default | Description |
|---|---|---|---|
| `lookback_days` | `JIRA_LOOKBACK_DAYS` | `90` | Collect issues updated in the last N days |
| `jql` | `JIRA_ISSUE_JQL` | — | Explicit JQL; overrides `lookback_days` |
| `max_issues` | `JIRA_MAX_ISSUES` | `2000` | Issue cap; `metadata.issues_truncated` records whether it was hit |

---

## What it collects

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
