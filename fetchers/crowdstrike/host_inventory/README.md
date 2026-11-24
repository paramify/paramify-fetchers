# crowdstrike_host_inventory

Lists every host that runs the CrowdStrike Falcon sensor, one record each, for a
Paramify inventory pipeline. Each record uses the Falcon host ID as its key.

## Design card

```yaml
question:    Which hosts run the Falcon sensor, and what does Falcon record about each?
kind:        inventory
subject:     falcon_host
identity:    unique_asset_identifier = the Falcon host ID (device_id), in lowercase
asset_type:  endpoint, on every record
population:  every host the device scroll query returns. All or nothing: if a page,
             a batch or a record fails, the fetcher writes data: [] and
             records_included: false, and exits non-zero.
permissions: [Hosts: READ]
ksis:        [KSI-PIY-GIV]
calls:       the same calls as crowdstrike_hosts (shared client)
pairs with:  crowdstrike_spotlight_vulnerability_report (id_scheme crowdstrike-device-id)
live test:   a real tenant. The record count must equal the host count in the Falcon
             console (Host setup and management, Host management).
```

## The host ID

`unique_asset_identifier` is the Falcon host ID: the agent ID of the sensor, 32 hex
characters, for example `3f1c9a7e5b2d4c6e8a0b1c2d3e4f5a61`. The hosts API calls it
`device_id`. Spotlight calls it `aid` on each finding. The fetcher writes the ID in
lowercase, with no spaces. The Spotlight report writes its `Host ID` column with
the same code, so the two values are always equal. The ID scheme is
`crowdstrike-device-id`.

A host that gets a new sensor install (for example, after a reimage) gets a new
host ID. Paramify then shows it as a new Inventory item.

## Records

Each record has these keys. A missing value is `null`.

| Field | Falcon field |
|---|---|
| `unique_asset_identifier` | `device_id`, in lowercase |
| `asset_type` | always `endpoint` |
| `hostname` | `hostname` |
| `primary_ip_address` | `local_ip` |
| `external_ip_address` | `external_ip` |
| `mac_address` | `mac_address` |
| `os_platform` | `platform_name` (Windows, Mac, Linux) |
| `os_version`, `os_build`, `os_product_name` | `os_version`, `os_build`, `os_product_name` |
| `product_type` | `product_type_desc` (Workstation, Server, Domain Controller) |
| `machine_domain` | `machine_domain` |
| `serial_number` | `serial_number` |
| `system_manufacturer`, `system_product_name` | `system_manufacturer`, `system_product_name` |
| `sensor_version` | `agent_version` |
| `reduced_functionality_mode` | `reduced_functionality_mode` (`yes` or `no`) |
| `containment_status` | `status` (normal, contained, and the pending states) |
| `first_seen_at`, `last_seen_at` | `first_seen`, `last_seen` |
| `cloud_provider`, `cloud_account_id`, `cloud_instance_id` | `service_provider`, `service_provider_account_id`, `instance_id` |
| `falcon_customer_id` | `cid` |
| `tags` | `tags`, joined with `; ` |

The fetcher does not keep the last login user or the email address.

## Set up and run

1. Make a Falcon API client with READ on the Hosts scope. See
   [the category README](../README.md#creating-an-api-client).
2. Add the fetcher to a manifest. Set `cloud_region` as manifest config, for
   example `us-gov-1`.
3. Do the steps in [Running an inventory fetcher](../../../docs/inventory_fetchers_guide.md).
   `paramify preset crowdstrike_host_inventory` prints the values for the
   inventory pipeline.

## Failures

The fetcher writes no records and exits non-zero when one of these occurs:

- The token request fails (`auth_failed`), or the API client does not have the
  Hosts scope (`not_authorized`).
- A page of the scroll query or a batch of the host lookup fails, after the
  shared client retries rate limits and server errors.
- Falcon answers HTTP 200 with errors in the body.
- A host ID from the query comes back with no host record.
- A host record has no `device_id`.

An empty estate exits 0 with no records. The uploader does not send an empty
inventory.

## Tests

The tests use synthetic fixtures and a fake Falcon API. They make no network calls.

```bash
pytest tests/test_crowdstrike_host_inventory.py
```
