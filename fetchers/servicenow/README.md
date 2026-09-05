# ServiceNow Fetchers

Two fetchers pull evidence from ServiceNow REST APIs using basic auth with a
shared service-account credential.

Each fetcher takes the **full endpoint URL**, path included. The path is not
assembled from a base URL, because these are scoped-application APIs and the
scope prefix differs per instance — there is no path that is correct everywhere.

---

## Credentials and environment variables

### Shared

| Variable | Required | Description |
|---|---|---|
| `SERVICENOW_USERNAME` | Yes | Service-account username. Shared by both fetchers. |
| `SERVICENOW_PASSWORD` | Yes | Service-account password. Shared by both fetchers. |

### `servicenow_cases`

| Variable | Required | Description |
|---|---|---|
| `SERVICENOW_CASES_API_URL` | Yes | Full URL of the cases endpoint, e.g. `https://<instance>.example.com/api/sn_customerservice/paramify_evidence/cases` |

| Config key | Required | Description |
|---|---|---|
| `last_run` | No | Watermark timestamp in `YYYY-MM-DD HH:MM:SS` format, sent as `sysparm_last_run`. When set, the API returns only cases modified since that time. Omit for a full pull. |

### `servicenow_changes`

| Variable | Required | Description |
|---|---|---|
| `SERVICENOW_CHANGES_API_URL` | Yes | Full URL of the changes endpoint, e.g. `https://<instance>.example.com/api/<scope>/paramify_itsm/changes` |

| Config key | Required | Description |
|---|---|---|
| `last_run` | No | Watermark timestamp in `YYYY-MM-DD HH:MM:SS` format, sent as `sysparm_last_run`. When set, the API returns only changes modified since that time. Omit for a full pull. |

`last_run` is manifest **config**, not a secret — a timestamp is not a
credential, and declaring it as an optional secret made it impossible to omit
(the runner honors `required: false` on a secret only when the manifest leaves
the key out, but the TUI wires every declared secret to a `${env:VAR}`
reference). It also reads from the env var `SERVICENOW_<FETCHER>_LAST_RUN` when
the runner injects it.

Neither fetcher persists a watermark of its own, so an incremental pull is only
as correct as the value you pass it. Evidence is normally a point-in-time full
set; a delta yields partial evidence that a completeness validator cannot
meaningfully assert against.

---

## Output files

| Fetcher | Output file |
|---|---|
| `servicenow_cases` | `$EVIDENCE_DIR/servicenow_cases.json` |
| `servicenow_changes` | `$EVIDENCE_DIR/servicenow_changes.json` |

Both fetchers write the raw JSON response from the API without any
transformation. The runner wraps each file in an evidence envelope.

---

## Manifest

```yaml
run:
  output_dir: ./evidence
  fetchers:
  - use: servicenow_cases
    secrets:
      username: ${env:SERVICENOW_USERNAME}
      password: ${env:SERVICENOW_PASSWORD}
      api_url: ${env:SERVICENOW_CASES_API_URL}
  - use: servicenow_changes
    secrets:
      username: ${env:SERVICENOW_USERNAME}
      password: ${env:SERVICENOW_PASSWORD}
      api_url: ${env:SERVICENOW_CHANGES_API_URL}
    # optional — omit for a full pull
    # config:
    #   last_run: '2026-08-01 00:00:00'
```

The framework is secret-source-agnostic: populate the runner's environment by
whatever mechanism you already use — a shell export, a secret manager, a CI
secret block, a Kubernetes secret mount, or a `.env` file.
