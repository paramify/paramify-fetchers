# ServiceNow Fetchers

Two fetchers pull evidence from ServiceNow Scripted REST APIs using basic auth
with a shared service-account credential.

Each fetcher takes the **full endpoint URL**, path included. The path is not
assembled from a base URL, because these are scoped-application APIs and the
scope prefix differs per instance — there is no path that is correct everywhere.

Both fetchers use one shared engine, `_shared/scripted_rest.py`. A fetcher only
declares its endpoint. The engine does the request and the checks. See
[Add an endpoint](#add-an-endpoint).

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

Both fetchers write the JSON response from the API without changing its
content. The runner wraps each file in an evidence envelope.

A run fails, and writes no evidence file, when:

| Condition | Failure code |
|---|---|
| A credential or the URL is not set, or the URL is not `https://` | `bad_config` |
| HTTP 401 | `auth_failed` |
| HTTP 403 | `not_authorized` |
| HTTP 429, after retries | `rate_limited` |
| HTTP 5xx or no connection, after retries | `target_unreachable` |
| A redirect, usually to a single sign-on page. The fetcher does not follow it. | `bad_config` |
| Other HTTP 4xx, for example a wrong URL | `bad_config` |
| A 200 response that is not JSON, for example a login or hibernation page | `bad_config` |
| A 200 response with `result.status` other than `success` | none |
| The evidence file cannot be written | `internal_error` |

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

Each fetcher entry maps its own `username` and `password`. If an endpoint uses a
different service account, point that entry at different variables, for
example `username: ${env:SERVICENOW_RECOVERY_USERNAME}`.

---

## Add an endpoint

1. Copy `changes/` to a new directory, for example `incidents/`.
2. In `fetcher.yaml`, change `name`, `description`, `output.path`, the
   `api_url` secret's `env`, the `last_run` config's `env` and the
   `evidence_set` block.
3. In `fetcher.py`, change the `Endpoint`:

   ```python
   ENDPOINT = Endpoint(
       label="incidents",                       # used in failure messages
       output="servicenow_incidents.json",      # same as output.path
       url_env="SERVICENOW_INCIDENTS_API_URL",  # same as the api_url secret
       since_env="SERVICENOW_INCIDENTS_LAST_RUN",
       since_param="sysparm_last_run",          # the endpoint's watermark parameter
   )
   ```

   Leave out `since_env` and `since_param` if the endpoint has no watermark.

4. If the endpoint pages, declare the paging and where the records are:

   ```python
   ENDPOINT = Endpoint(
       ...,
       paging=LimitOffset(limit=500),           # at or below the endpoint's maximum
       records_path=("result", "records"),
   )
   ```

   The engine asks for pages until it gets a page shorter than `limit`. If any
   page fails, the run fails. The output is then
   `{"record_count": ..., "page_count": ..., "records": [...]}` and not the
   response body. Set `limit` at or below the maximum that the endpoint
   documents: an endpoint that silently lowers a larger value returns a short
   first page, and the engine stops there.

5. Add the fetcher's name to `FETCHERS` in `tests/test_servicenow_fetchers.py`.
   The tests then check that the `Endpoint` and `fetcher.yaml` agree.
