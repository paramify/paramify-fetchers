# sophos_endpoint_inventory

Lists every endpoint in Sophos Central, with its attributes, for the Paramify
asset inventory.

## Design card

```yaml
question:    Which computers and servers does Sophos Central manage, and what does it record about each?
kind:        inventory
subject:     sophos_endpoint
identity:    [hostname, serial_number]   # unique_asset_identifier = the Sophos endpoint id
attributes:  every field of GET /endpoint/v1/endpoints?view=full, as returned, except
             associatedPerson.name (see below)
population:  every endpoint the tenant lists. All or nothing: if a page fails, the fetcher
             writes data: [] and records_included: false, and exits non-zero.
permissions: [Service Principal Read-Only: endpoint-state:read]
ksis:        [KSI-PIY-GIV]
calls:       the same endpoints list (shared client)
replaces:    none
live test:   the client tenant. The collected count must equal pages.items and the
             Account Health Check totals.
```

## Agent coverage

This inventory is the Sophos side of agent coverage. It lists only enrolled
devices. A device without the agent is not in it. To show that
every in-scope host runs the agent, a comparator must join this inventory with
another inventory (cloud VMs or a CMDB) on `hostname` or `serial_number`. That
comparator is separate work.

## Personal data (open decision)

`associatedPerson` carries a display name and a login. Until the
team decides the personal-data rule, this inventory keeps `associatedPerson.viaLogin`
and leaves out `associatedPerson.name`.
