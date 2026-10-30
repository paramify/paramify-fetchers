# sophos_agent_updates

Reports how recently the Sophos agent on each endpoint updated, and whether
Sophos offers a newer protection package for it.

## Design card

```yaml
question:    How long since the Sophos agent on each managed computer and server last updated, and does Sophos offer it a newer protection package?
type:        status
aspect:      patching_and_lifecycle
subject:     sophos_endpoint
identity:    [hostname, serial_number]
stats:
  - days_since_agent_update:  [KSI-CNA-IBP]   # now - lastAgentUpdateAt
measures:
  - protection_package_not_upgradable: [KSI-CNA-IBP, KSI-SVC-PRR]  # packages.protection.status != upgradable
context:     [last_agent_update_at, protection_package_name, protection_package_status,
              assigned_product_versions]
records:     -> sophos_endpoint_inventory
population:  every endpoint the tenant lists
permissions: [Service Principal Read-Only: endpoint-state:read]
calls:       the same endpoints list (shared client)
replaces:    none
live test:   the client tenant. A fail case is an endpoint with package status `upgradable`,
             or an old lastAgentUpdateAt.
```

## Limits

- The API has no definition (threat data) version and no "up to date" field.
  This fetcher reports the two facts the API does carry. It does not decide
  whether the endpoint is up to date.
- The question says "and". The two facts are both "is the agent current", and
  both come from one record. If a reviewer reads them as two questions, split
  out the package status.
