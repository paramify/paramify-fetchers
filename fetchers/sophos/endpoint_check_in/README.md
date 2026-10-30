# sophos_endpoint_check_in

Reports when the Sophos agent on each managed endpoint last communicated
with Sophos Central.

## Design card

```yaml
question:    When did the Sophos agent on each managed computer and server last communicate with Sophos Central?
type:        status
aspect:      threat_and_vulnerability_detection
subject:     sophos_endpoint
identity:    [hostname, serial_number]
stats:
  - hours_since_last_seen:   [KSI-CNA-RVP]    # now - lastSeenAt; the validator sets the threshold
measures:
  - online:                  [KSI-CNA-RVP]    # online == true, at collection time
breakdown:   type [computer, server, securityVm]
context:     [last_seen_at, isolation_status, lockdown_status]
records:     -> sophos_endpoint_inventory
population:  every endpoint the tenant lists. Stale endpoints stay in the list. Age is
             a stat, not a filter.
permissions: [Service Principal Read-Only: endpoint-state:read]
calls:       the same endpoints list as sophos_endpoint_protection (shared client)
replaces:    none
live test:   the client tenant. A fail case is an endpoint that has not been seen for
             longer than the validator's threshold (for example, a decommissioned VM).
```

## Notes

- A community report says that the API sometimes leaves out `online`. Then the
  fetcher writes `null` for `online` and names it in `unread_facts`. The age
  stat still counts.
- The fetcher has no threshold. The validator sets "seen in the last 24 hours"
  or "in the last 7 days".
