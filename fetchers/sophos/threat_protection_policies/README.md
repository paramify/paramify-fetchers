# sophos_threat_protection_policies

Reports what each Sophos threat protection policy says about scanning: the
scheduled scan and real-time (on-access) scanning.

## Design card

```yaml
question:    What does each Sophos Central threat protection policy, for computers and for servers, set for scheduled and on-access scanning?
type:        document
aspect:      threat_and_vulnerability_detection
subject:     sophos_endpoint_policy   # one item is one policy of type threat-protection or server-threat-protection, base policies included
identity:    [policy_id]
document:    settings                  # the settings map exactly as Sophos returns it
measures:                              # each reads a fact parsed from the document
  - enabled:                    [KSI-SVC-EIS]              # the policy is enabled
  - scheduled_scan_configured:  [KSI-SVC-EIS, nist:SI-3]   # endpoint.scans.scheduled.days is not empty
  - on_access_scanning_on:      [KSI-CNA-RVP, nist:SI-3]   # the on-access key, read from GET /policies/settings metadata
stats:
  - settings_off_vendor_baseline: [sophos-ahc:policy]      # count of settings where value != recommendedValue
breakdown:   policy_type [threat-protection, server-threat-protection]
context:     [name, priority, is_base_policy, applies_to (endpoints, groups, users, user groups),
              scheduled_scan_days, scheduled_scan_hour, settings_off_vendor_baseline_keys]
records:     created and updated dates and authors -> not collected (no inventory for policies yet)
population:  every policy of the two types, the base policies included, enabled or not
permissions: [Service Principal Read-Only: endpoint-policy:read]
calls:       GET /endpoint/v1/policies?policyType=...&pageTotal=true (page-number paging);
             GET /endpoint/v1/policies/{type}/base; GET /endpoint/v1/policies/settings
replaces:    none
live test:   the client tenant. A fail case is a policy with no scheduled-scan days, or a
             disabled policy. The base policy has a schedule only if the client set one.
```

## What this does not prove

- **A scan that ran.** The Sophos Central API has no last-scan time and no
  scan history for an endpoint. The SIEM events API keeps only the last 24
  hours, and scheduled scans usually run on set days. So this fetcher shows that
  scanning is **configured**, not that a scan **ran**. A device that is off at
  the scheduled time skips the scan.
- **Which policy applies to an endpoint.** A policy can apply to users or user
  groups instead of devices. `applies_to` is kept as context, but this fetcher
  does not resolve policies per endpoint.

## Open items to measure on the first live run

- The scheduled-scan keys appear only in Sophos's API examples. The fetcher
  reads the key list from `GET /policies/settings` and records which keys it used.
- The key name for on-access scanning is not documented. It is read from the
  same metadata.
