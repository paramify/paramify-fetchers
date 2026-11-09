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
  - scheduled_scan_configured:  [KSI-SVC-EIS, nist:SI-3]   # scheduled-scan.enabled is true and scheduled-scan.days is not empty
  - on_access_scanning_on:      [KSI-CNA-RVP, nist:SI-3]   # endpoint.threat-protection.malware-protection.on-access.enabled
stats:
  - settings_off_vendor_baseline: [sophos-ahc:policy]      # count of settings where value != recommendedValue;
                                                           # null when no setting has a recommendedValue
breakdown:   policy_type [threat-protection, server-threat-protection]
context:     [name, priority, is_base_policy, applies_to (endpoints, groups, users, user groups),
              scheduled_scan_enabled, scheduled_scan_days, scheduled_scan_time,
              settings_with_recommended_value, settings_off_vendor_baseline_keys]
records:     created and updated dates and authors -> not collected (no inventory for policies yet)
population:  every policy of the two types, the base policies included, enabled or not
permissions: [Service Principal Read-Only: endpoint-policy:read]
calls:       GET /endpoint/v1/policies?policyType=...&pageTotal=true (page-number paging);
             GET /endpoint/v1/policies/{type}/base
replaces:    none
live test:   a real tenant. A fail case is a policy with scheduled scans off, or a
             disabled policy. The base policy has a schedule only if an admin set one.
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

## Setting names

The fetcher reads these settings, which Sophos documents in the
[endpoint policy settings reference](https://developer.sophos.com/endpoint-policy-settings-all/).
The names are the same for both policy types.

| Setting | Value |
|---|---|
| `endpoint.threat-protection.malware-protection.scheduled-scan.enabled` | Boolean. The default is `false`. |
| `endpoint.threat-protection.malware-protection.scheduled-scan.days` | Integers, from 0 (Sunday) to 6 (Saturday). The default is `[6]`. |
| `endpoint.threat-protection.malware-protection.scheduled-scan.time` | A time, for example `"00:00"`. |
| `endpoint.threat-protection.malware-protection.on-access.enabled` | Boolean: real-time scanning is on. |

A scheduled scan counts as configured only when `scheduled-scan.enabled` is
`true` and `scheduled-scan.days` is not empty. The default days are `[6]` even
when scheduled scans are off, so the days alone do not show a schedule. If
`scheduled-scan.enabled` is missing, the fact is `null` and named in
`unread_facts`.

## Exclusion lists in the evidence

The evidence keeps every setting as Sophos returns it. This includes the scan
exclusion lists, which hold file paths and process names. Text such as
`/bin/sh` or `../` in a path can cause a web application firewall to reject
the upload. If an upload of this evidence fails with HTTP 403, look at the
exclusion lists first.
