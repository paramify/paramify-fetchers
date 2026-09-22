# Wiz

Read-only evidence fetchers for the Wiz cloud security platform (commercial and
Wiz for Government). All six share one GraphQL client (`_shared/wiz_client.py`)
and one pair of secrets. None of them writes to Wiz: the client refuses to send
a GraphQL mutation.

| Fetcher | Evidence | Wiz scopes |
|---|---|---|
| `wiz_scan_coverage` | Cloud accounts Wiz is connected to, their status and last scan time, connector status, open system health issues | `read:cloud_accounts`, `read:connectors`, `read:system_health_issues` |
| `wiz_posture_issues` | Open cloud-configuration / toxic-combination issues by severity and age, ticket linkage, resolved in window | `read:issues` |
| `wiz_infrastructure_vulnerabilities` | Open vulnerability findings on hosts and other non-container assets | `read:vulnerabilities` |
| `wiz_container_vulnerabilities` | Open vulnerability findings on container images and containers | `read:vulnerabilities` |
| `wiz_cloud_configuration_posture` | Cloud configuration rule pass/fail against one framework (default NIST SP 800-53 Rev 5) | `read:cloud_configuration`, `read:security_frameworks` |
| `wiz_host_configuration_posture` | OS benchmark pass/fail per benchmark and host (default DISA STIG) | `read:host_configuration` |

Read the vulnerability and issue evidence together with `wiz_scan_coverage`:
zero findings only means something if every account in the boundary is being
scanned.

## Service account

Wiz > Settings > Access Management > Service Accounts > Add Service Account,
type **Custom Integration (GraphQL API)**, all projects, `read:` scopes only
(the table above). Never grant `create:`, `update:`, `write:`, `delete:`,
`admin:` or `read:all` to a fetcher account.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `WIZ_CLIENT_ID` | Yes | Service account Client ID |
| `WIZ_CLIENT_SECRET` | Yes | Service account Client Secret |
| `WIZ_API_ENDPOINT_URL` | Yes | Tenant Info > API Endpoint URL, e.g. `https://api.us2.app.wiz.us/graphql` |
| `WIZ_AUTH_URL` | No | Tenant Info > Authentication URL. Defaults to Wiz for Gov `https://auth.app.wiz.us/oauth/token`; commercial is `https://auth.app.wiz.io/oauth/token` |
| `WIZ_MIN_REQUEST_INTERVAL` | No | Seconds between calls (default `1.0`). The tenant's rate limit is shared with every other integration |
| `WIZ_PAGE_SIZE` | No | Records per page (default 100, max 500) |

Per-fetcher settings (remediation windows, statuses, look-back) are listed by
`paramify describe <fetcher>`.

## Things verified against a live Wiz for Gov tenant (2026-09-22)

- Tokens last **900 seconds**, not the 24 hours older public docs describe. The
  client renews a minute early, so long pulls do not fail mid-walk.
- The root queries and node fields these fetchers select exist.
- Filter inputs used here (`status`, `type`, `statusChangedAt`, `securityFramework`,
  `result`) were read from the tenant's own schema.
- DISA STIG benchmarks in Wiz are operating-system benchmarks. Cloud
  control-plane checks map to NIST 800-53 / FedRAMP, which is why the two
  configuration fetchers default to different frameworks.
