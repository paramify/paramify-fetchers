# Qualys VMDR

Qualys fetchers read the Qualys VM/PC API (XML) with one read-only API user:

| Fetcher | Shows |
|---|---|
| `qualys_scan_coverage` | Each host's last vulnerability scan and last authenticated scan, subscription IPs with no host record, excluded IPs |
| `qualys_scan_schedules` | Active scan schedules, how often they run, whether their option profiles authenticate, how recent scans ended |
| `qualys_vulnerability_findings` | Open detections by severity and type, and which are past their remediation timeframe |
| `qualys_vulnerability_remediation` | Detections fixed in the lookback window, on time or late, and reopened ones |

Install the parser with `pip install -e '.[qualys]'` (it adds `defusedxml`).

## The API user

The fetchers only list. Create one user for them in Qualys:

1. **A local user, not SSO.** Qualys API password authentication does not work for
   SSO users.
2. **Role: Reader.**
3. **API access on, in both places:** the role has the **API Access** permission in
   the Administration utility, and the VMDR user role allows **API**. A Manager has
   both by default.
4. **Asset groups: All.** A Reader sees only the hosts, detections and IPs in its
   asset groups. If the subscription uses tag-based user scoping, give it every tag
   instead. The evidence reports `scope_all`, which is true when the built-in All
   group is among the groups the user sees.
5. **Log in to the Qualys UI once** with the new user. Until the subscription's
   registration is complete, the API answers code 2003.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `QUALYS_API_URL` | Yes | API server URL of your platform; see below |
| `QUALYS_USERNAME` | Yes | The API user's login |
| `QUALYS_PASSWORD` | Yes | Its password |
| `QUALYS_SCAN_WINDOW_DAYS` | No | How recent a scan must be, and how far back the scan list reads. Default 30 |
| `QUALYS_REMEDIATION_DAYS` | No | Days allowed per severity 5 to 1. Default `5:30,4:30,3:90,2:180,1:180` |
| `QUALYS_REMEDIATION_LOOKBACK_DAYS` | No | `qualys_vulnerability_remediation` only. Default 90 |
| `QUALYS_INCLUDE_DETECTION_RECORDS` | No | `qualys_vulnerability_findings` only. `false` keeps only past-due records. Default `true` |

The default `QUALYS_REMEDIATION_DAYS` follows FedRAMP's historical
continuous-monitoring timeframes (high 30, moderate 90, low 180 days, reading
severity 5 and 4 as high). It is a convention, not a rule; set your policy's own.

### Picking the platform

Each Qualys platform has its own API server, and a user exists on only one. The
Qualys UI shows yours under **Help > About**. Use the API server URL
(`qualysapi.…`), not the web UI URL (`qualysguard.…`); the fetchers refuse the
latter. FedRAMP subscriptions are on US1, US2 or US3 (Moderate) or GOV1 (High).

| Platform | `QUALYS_API_URL` |
|---|---|
| US1 | `https://qualysapi.qualys.com` |
| US2 | `https://qualysapi.qg2.apps.qualys.com` |
| US3 | `https://qualysapi.qg3.apps.qualys.com` |
| US4 | `https://qualysapi.qg4.apps.qualys.com` |
| GOV1 | `https://qualysapi.gov1.qualys.us` |
| EU1 | `https://qualysapi.qualys.eu` |
| EU2 | `https://qualysapi.qg2.apps.qualys.eu` |
| EU3 | `https://qualysapi.qg3.apps.qualys.it` |
| IN1 | `https://qualysapi.qg1.apps.qualys.in` |
| CA1 | `https://qualysapi.qg1.apps.qualys.ca` |
| AE1 | `https://qualysapi.qg1.apps.qualys.ae` |
| UK1 | `https://qualysapi.qg1.apps.qualys.co.uk` |
| AU1 | `https://qualysapi.qg1.apps.qualys.com.au` |
| KSA1 | `https://qualysapi.qg1.apps.qualysksa.com` |

Source: https://www.qualys.com/platform-identification/. A private cloud platform
uses `https://qualysapi.<your base URL>`.

## Limits

Qualys limits API calls per subscription and per API: by default 2 at once and
300 an hour on a Standard subscription. Other integrations share the same budget.
The fetchers make one call at a time, one per page of 1000 hosts, and wait out a
rate or concurrency limit when Qualys says how long (up to 5 minutes). A run that
fails partway writes no summary and exits non-zero.
