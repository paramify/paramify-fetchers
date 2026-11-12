# Qualys

Qualys fetchers read the Qualys VM/PC API (XML) with one read-only API user:

| Fetcher | Shows |
|---|---|
| `qualys_scan_coverage` | Each host's last vulnerability scan and last authenticated scan, subscription IPs with no host record, excluded IPs |
| `qualys_scan_schedules` | Active scan schedules, how often they run, whether their option profiles authenticate, how recent scans ended |
| `qualys_vulnerability_findings` | Open detections by severity and type, and which are past their remediation timeframe |
| `qualys_vulnerability_remediation` | Detections fixed in the lookback window, on time or late, and reopened ones |

A detection's age, and its days to fix, count from its last reopening when
Qualys reopened it, and from first found otherwise.

Install the parser with `pip install -e '.[qualys]'` (it adds `defusedxml`).

## The API user

The fetchers only list. Create one user for them in Qualys. An API-only user
(GUI access off, API access on) is the recommended service account:

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
5. **Activate the user once.** Until registration is complete, the API fails (code
   2003 on the fetchers' calls). A user with GUI access logs in to the Qualys UI
   once and completes the First Login form. A user with API access only has no UI
   login, so it completes first login with the `acceptEULA.php` API function,
   sent to the platform URL with the user's login credentials. See
   [Qualys: user registration](https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-user/users/user_registration.htm)
   for the call.

Qualys support can turn on **Password Never Expires** for API-only accounts on a
subscription, so the fetchers do not stop when the password expires. A Manager
point of contact then sets it per user under the Security tab. See
[Qualys: password never expires](https://docs.qualys.com/en/vmdr/latest/setup/win_security.htm).

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `QUALYS_API_URL` | Yes | API server URL of your platform; see below |
| `QUALYS_PRIVATE_CLOUD_HOST` | No | A private cloud platform's API host; see below |
| `QUALYS_USERNAME` | Yes | The API user's login |
| `QUALYS_PASSWORD` | Yes | Its password |
| `QUALYS_SCAN_WINDOW_DAYS` | No | How recent a scan must be, and how far back the scan list reads. Default 31, so a monthly schedule fits |
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

Source: https://www.qualys.com/platform-identification/.

The fetchers send the credentials only to a `qualysapi.` host on a Qualys domain
(`qualys.com`, `qualys.us`, `qualys.eu` and the others above). Any other URL fails
as `bad_config` before anything is sent, so a typo cannot leak the password. A
private cloud platform uses `https://qualysapi.<your base URL>`; set
`QUALYS_PRIVATE_CLOUD_HOST` to that host name (for example
`qualysapi.qualys.example.com`) and `QUALYS_API_URL` to the same host.

## Limits

Qualys limits API calls per subscription and per API: by default 2 at once and
300 an hour on a Standard subscription. Other integrations share the same budget.
The fetchers make one call at a time, one per page of 1000 hosts, and wait out a
rate or concurrency limit when Qualys says how long (up to 5 minutes). A run that
fails partway writes no summary and exits non-zero.

## Assessment issue reports

The evidence fetchers above collect JSON evidence and summaries. Two additional
fetchers produce CSV reports for configured Paramify assessment intake presets:

| Fetcher | Purpose |
| --- | --- |
| [VMDR vulnerability findings](vmdr_vulnerability_findings/README.md) | Complete detections joined to KnowledgeBase and required QVS/CISA enrichment |
| [STIG compliance report](stig_compliance_report/README.md) | Per-policy postures, control references, remediation, and exception context |

See [assessment report setup and intake limitations](REPORTS.md). Report-specific
page/record limits, retries, pacing, and `allow_empty` do not change the evidence
fetchers' behavior. Evidence remediation-timeframe summaries do not define the
assessment reports' CISA deadline policy.
