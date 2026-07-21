# Datadog

Datadog fetchers pull security monitoring, logging, infrastructure, APM, and incident evidence from the Datadog API. The 13 fetchers in this category cover Cloud SIEM detection rules and signals, SIEM operational configuration, log pipelines, indexes, and archives, infrastructure host and container inventory, agent check results, APM service catalog, and incident records with timelines — providing broad coverage across KSIs for monitoring/logging, infrastructure, incident response, and availability.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATADOG_API_KEY` | Yes | Datadog API key (identifies the organization) |
| `DATADOG_APP_KEY` | Yes | Datadog application key (identifies the service account) |
| `DATADOG_BASE_URL` | No | API base URL (default: `https://api.ddog-gov.com`; use `https://api.datadoghq.com` for commercial) |
| `DATADOG_SIGNALS_LOOKBACK_DAYS` | No | Lookback window for SIEM signals (default: `30`) |
| `DATADOG_INCIDENTS_LOOKBACK_DAYS` | No | Lookback window for incident records (default: `90`) |

## Creating a service account and API credentials

Datadog requires two separate credentials: an **API Key** (identifies the organization) and an **Application Key** (identifies the user or service account making the request). Use a dedicated service account — not a personal account — so credentials survive personnel changes.

### 1. Create a service account

1. Log in to the Datadog console.
2. Navigate to **Organization Settings → Service Accounts**.
3. Click **New Service Account**.
4. Name it `paramify-evidence-fetchers`.
5. Assign the **Datadog Read Only** role — all fetchers are read-only.
6. Click **Create**.

### 2. Generate an application key

1. On the service account page, click **New Key**.
2. Name it `paramify-evidence-fetchers-appkey`.
3. Copy the application key value immediately — it is only shown once.
4. Store it in your secrets manager as `DATADOG_APP_KEY`.

### 3. Generate an API key

1. Navigate to **Organization Settings → API Keys**.
2. Click **New Key**.
3. Name it `paramify-evidence-fetchers-apikey`.
4. Copy the API key value.
5. Store it in your secrets manager as `DATADOG_API_KEY`.

## Required permissions

The service account role must include read access to:

| Datadog Product | Required Permission |
|---|---|
| Cloud SIEM | `security_monitoring_rules_read`, `security_monitoring_signals_read` |
| Log Management | `logs_read_data`, `logs_read_index_data`, `logs_read_archives` |
| Infrastructure | `metrics_read`, `hosts_read` |
| APM | `apm_read` |
| Monitors | `monitors_read` |
| Incidents | `incident_read` *(only if using Datadog Incident Management)* |

The built-in **Datadog Read Only** role covers all of these. Verify in **Organization Settings → Roles** that the role includes these scopes before running fetchers.

## Wiring into a manifest

All Datadog fetchers share the same three secrets (`api_key`, `app_key`, `base_url`). Two fetchers also take a lookback config secret.

**SIEM**

```bash
paramify manifest add datadog_siem_detection_rules
paramify manifest set-secret datadog_siem_detection_rules api_key DATADOG_API_KEY
paramify manifest set-secret datadog_siem_detection_rules app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_siem_detection_rules base_url DATADOG_BASE_URL

paramify manifest add datadog_siem_signals
paramify manifest set-secret datadog_siem_signals api_key DATADOG_API_KEY
paramify manifest set-secret datadog_siem_signals app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_siem_signals base_url DATADOG_BASE_URL
paramify manifest set-secret datadog_siem_signals signals_lookback_days DATADOG_SIGNALS_LOOKBACK_DAYS

paramify manifest add datadog_siem_configuration
paramify manifest set-secret datadog_siem_configuration api_key DATADOG_API_KEY
paramify manifest set-secret datadog_siem_configuration app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_siem_configuration base_url DATADOG_BASE_URL
```

**Logging**

```bash
paramify manifest add datadog_log_pipelines
paramify manifest set-secret datadog_log_pipelines api_key DATADOG_API_KEY
paramify manifest set-secret datadog_log_pipelines app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_log_pipelines base_url DATADOG_BASE_URL

paramify manifest add datadog_log_indexes
paramify manifest set-secret datadog_log_indexes api_key DATADOG_API_KEY
paramify manifest set-secret datadog_log_indexes app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_log_indexes base_url DATADOG_BASE_URL

paramify manifest add datadog_log_archives
paramify manifest set-secret datadog_log_archives api_key DATADOG_API_KEY
paramify manifest set-secret datadog_log_archives app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_log_archives base_url DATADOG_BASE_URL
```

**Infrastructure**

```bash
paramify manifest add datadog_monitors_list
paramify manifest set-secret datadog_monitors_list api_key DATADOG_API_KEY
paramify manifest set-secret datadog_monitors_list app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_monitors_list base_url DATADOG_BASE_URL

paramify manifest add datadog_agent_hosts
paramify manifest set-secret datadog_agent_hosts api_key DATADOG_API_KEY
paramify manifest set-secret datadog_agent_hosts app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_agent_hosts base_url DATADOG_BASE_URL

paramify manifest add datadog_containers
paramify manifest set-secret datadog_containers api_key DATADOG_API_KEY
paramify manifest set-secret datadog_containers app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_containers base_url DATADOG_BASE_URL

paramify manifest add datadog_infra_agent_checks
paramify manifest set-secret datadog_infra_agent_checks api_key DATADOG_API_KEY
paramify manifest set-secret datadog_infra_agent_checks app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_infra_agent_checks base_url DATADOG_BASE_URL
```

**APM**

```bash
paramify manifest add datadog_apm_services
paramify manifest set-secret datadog_apm_services api_key DATADOG_API_KEY
paramify manifest set-secret datadog_apm_services app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_apm_services base_url DATADOG_BASE_URL
```

**Incidents**

```bash
paramify manifest add datadog_incidents_list
paramify manifest set-secret datadog_incidents_list api_key DATADOG_API_KEY
paramify manifest set-secret datadog_incidents_list app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_incidents_list base_url DATADOG_BASE_URL
paramify manifest set-secret datadog_incidents_list incidents_lookback_days DATADOG_INCIDENTS_LOOKBACK_DAYS

paramify manifest add datadog_incident_timelines
paramify manifest set-secret datadog_incident_timelines api_key DATADOG_API_KEY
paramify manifest set-secret datadog_incident_timelines app_key DATADOG_APP_KEY
paramify manifest set-secret datadog_incident_timelines base_url DATADOG_BASE_URL
paramify manifest set-secret datadog_incident_timelines incidents_lookback_days DATADOG_INCIDENTS_LOOKBACK_DAYS
```

Use `paramify catalog` to see all available Datadog fetchers.

## Smoke test

```bash
curl -s \
  -H "DD-API-KEY: $DATADOG_API_KEY" \
  -H "DD-APPLICATION-KEY: $DATADOG_APP_KEY" \
  "$DATADOG_BASE_URL/api/v1/validate" | python3 -m json.tool
```

Expected response:

```json
{"valid": true}
```

If `valid` is `false` or you receive a 403, the credentials are invalid or the service account role is missing required permissions.

## Rotating credentials

### Application key rotation

1. Navigate to **Organization Settings → Service Accounts → paramify-evidence-fetchers**.
2. Click the existing key and select **Revoke**.
3. Click **New Key** and name it with today's date for traceability.
4. Copy the new value and update `DATADOG_APP_KEY` in your secrets manager.
5. Run the smoke test to confirm.

### API key rotation

1. Navigate to **Organization Settings → API Keys**.
2. Locate `paramify-evidence-fetchers-apikey` and click **Revoke**.
3. Click **New Key** and name it with today's date.
4. Copy the new value and update `DATADOG_API_KEY` in your secrets manager.
5. Run the smoke test to confirm.

## Fetcher reference

| Fetcher | What it collects | Evidence set ID |
|---|---|---|
| `datadog_siem_detection_rules` | Custom SIEM detection rules — enabled state, type, severity, last updated | `EVD-DD-SIEM-RULES` |
| `datadog_siem_signals` | Security signals generated by detection rules within the lookback window | `EVD-DD-SIEM-SIGNALS` |
| `datadog_siem_configuration` | Suppression rules and notification integrations (webhook domains only) | `EVD-DD-SIEM-CONFIG` |
| `datadog_log_pipelines` | Log processing pipeline configurations and filter queries | `EVD-DD-LOG-PIPELINES` |
| `datadog_log_indexes` | Log index retention settings and per-index filter queries | `EVD-DD-LOG-INDEXES` |
| `datadog_log_archives` | Long-term log archive destinations (S3, Azure, GCS) and state | `EVD-DD-LOG-ARCHIVES` |
| `datadog_monitors_list` | Monitor configurations — type, query, status, notification targets | `EVD-DD-MONITORS` |
| `datadog_agent_hosts` | Real-time host inventory — platform, cloud provider, agent version, mute state | `EVD-DD-AGENT-HOSTS` |
| `datadog_containers` | Real-time container inventory — image digest, state, namespace, environment | `EVD-DD-CONTAINERS` |
| `datadog_infra_agent_checks` | Agent check results across the host fleet — status per check per host | `EVD-DD-INFRA-CHECKS` |
| `datadog_apm_services` | APM service catalog — language, team, ownership, contact types | `EVD-DD-APM-SERVICES` |
| `datadog_incidents_list` | Incident records within the lookback window — severity, status, postmortem presence | `EVD-DD-INCIDENTS-LIST` |
| `datadog_incident_timelines` | Per-incident timeline cell metadata — cell types, timestamps, author count | `EVD-DD-INCIDENT-TIMELINES` |

## Notes

- Datadog GovCloud (`ddog-gov.com`) and commercial (`datadoghq.com`) are separate tenants with separate credentials. The fetchers default to GovCloud. Set `DATADOG_BASE_URL=https://api.datadoghq.com` for commercial tenants.
- Application keys are scoped to the creating service account. If the service account is deleted, the application key is invalidated immediately. Always use a dedicated service account, not a personal account.
- Datadog does not enforce API or application key expiration by default. Establish a rotation schedule (90 days is a common baseline) and track it outside the platform.
- The `incident_timelines` and `incidents_list` fetchers require Datadog Incident Management to be enabled on the tenant. If the feature is not active, both fetchers will return zero records without error.
