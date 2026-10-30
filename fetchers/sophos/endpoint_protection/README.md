# sophos_endpoint_protection

Reports the protection state that Sophos Central gives for each managed
computer and server.

## Design card

```yaml
question:    What protection state does Sophos Central report for each managed computer and server?
type:        state
aspect:      threat_and_vulnerability_detection
subject:     sophos_endpoint          # one item is one endpoint that Sophos Central lists
identity:    [hostname, serial_number] # plus the Sophos endpoint id
measures:                              # each reads a fact parsed from GET /endpoint/v1/endpoints?view=full
  - services_all_running:          [KSI-CNA-RVP, sophos-ahc:protection]       # every health.services.serviceDetails[].status == running
  - tamper_protection_enabled:     [KSI-CNA-RVP, sophos-ahc:tamper-protection] # tamperProtectionEnabled == true
  - protection_product_installed:  [KSI-CNA-RVP, sophos-ahc:protection]       # an interceptX or endpointProtection product has status installed
  - threats_status_good:           [KSI-SVC-EIS]                               # health.threats.status == good
breakdown:   health_overall [good, suspicious, bad, unknown]   # the platform's own words
context:     [type, os_platform, os_name, health_services_status, stopped_or_missing_services,
              assigned_products (code, status, version), tamper_protection_supported,
              tenant_tamper_protection_enabled]
records:     IPs, MACs, group, tags, encryption, isolation, associated person -> sophos_endpoint_inventory
population:  every endpoint the tenant lists, computers and servers. No type, health or lockdown filter.
permissions: [Service Principal Read-Only: endpoint-state:read]
calls:       POST id.sophos.com/api/v2/oauth2/token; GET /whoami/v1;
             GET /endpoint/v1/endpoints?view=full&pageTotal=true (nextKey paging);
             GET /endpoint/v1/settings/tamper-protection
replaces:    none (new platform)
live test:   the client tenant. Pass case: an endpoint with all services running and
             tamper protection on. Fail case: any endpoint with a stopped or missing service,
             or tamper protection off. Whether the tenant has one is measured first.
```

## Rules this fetcher follows

- It always sends `view=full`. The default view is `summary`, and Sophos does
  not document which fields that view leaves out.
- It reads every page. Each page holds 50 items by default. It compares the
  count it collected with `pages.items`, and it fails the run if they differ.
- It never calls `GET /endpoints/{id}/tamper-protection`. That route returns
  the tamper protection passwords.
- If a fact is not in the response, the fact is `null`, and the item names it
  in `unread_facts`. A missing fact never counts as `false`.
- `tamper_protection_enabled` is per endpoint. The tenant-wide switch is
  context, because a switch that is off can make the per-endpoint flag misleading.

## Open decision

The aspect list has no malware-protection aspect. This card uses
`threat_and_vulnerability_detection`, whose KSIs are IAM-SUS, CNA-RVP and SVC-EIS.
The CrowdStrike and SentinelOne fetchers map endpoint protection to KSI-CNA-EIS,
which is in the `configuration_integrity` aspect. The aspect guard flags that
KSI here, so it is left out until the aspect list is decided.
