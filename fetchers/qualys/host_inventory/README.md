# qualys_host_inventory

Lists every host in Qualys VMDR that the API user can see, one record each,
for a Paramify inventory pipeline. Each record uses the Qualys host ID as its
key. The [VMDR findings report](../vmdr_vulnerability_findings/README.md) puts
the same ID in its `Host ID` column, so Paramify can link each finding to its
Inventory item.

This is an **inventory** fetcher (`kind: inventory`) and a pipeline fetcher
(`pipeline: {type: inventory, id_scheme: qualys-host-id}`). The file goes to
the evidence set `EVD-QUALYS-HOST-INVENTORY`. The inventory pipeline on that
set makes one Inventory item from each record. To run it, obey
[Running an inventory fetcher](../../../docs/inventory_fetchers_guide.md). The
[pipeline fetchers guide](../../../docs/pipeline_fetchers_guide.md#3-what-the-uploader-does-for-you)
tells how the uploader sends a pipeline file.

```
Qualys host list ──qualys_host_inventory──▶ qualys_host_inventory.json
  ──paramify upload (approved batch)──▶ EVD-QUALYS-HOST-INVENTORY
  ──inventory pipeline (payload.data)──▶ Inventory
```

## Before you start

- **Qualys:** the same read-only API user as the other Qualys fetchers. See
  [the API user](../README.md#the-api-user). Give it the All asset group. A
  Reader sees only the hosts in its asset groups, and the inventory holds only
  those hosts.
- **Settings:** `api_url` (`QUALYS_API_URL`), `username` (`QUALYS_USERNAME`)
  and `password` (`QUALYS_PASSWORD`) from the
  [qualys category](../../_categories/qualys.yaml). For a private cloud
  platform, also set `private_cloud_host` (`QUALYS_PRIVATE_CLOUD_HOST`).
- **Paramify:** an API key that can view and write evidence
  (`PARAMIFY_UPLOAD_API_TOKEN`). Before the first upload, make an inventory
  pipeline and attach it to `EVD-QUALYS-HOST-INVENTORY` (see the next section).

## Set up the inventory pipeline (one time)

1. Run the fetcher, then run `paramify preset qualys_host_inventory`. Add `-f
   manifest.yaml` or `-o <output dir>`. The command shows the sample file, the
   data path (`payload.data`), the unique ID (`unique_asset_identifier`, scheme
   `qualys-host-id`) and the `asset_type` value (`host`).
2. In Paramify, make the *Inventory* pipeline with those values.
3. Attach the pipeline to `EVD-QUALYS-HOST-INVENTORY` (the **Pipelines** tab of
   the set, **Manage Selection**). Do not make a new set.
4. Keep automatic approval on the set, and add no validators.

## How the inventory links to the findings

`qualys_vmdr_vulnerability_findings` writes one row for each detection on a
host. Its `Host ID` column is the `ID` of the host in the Qualys VM detection
list. The host list that this fetcher reads gives the same `ID` for the same
host. Thus `unique_asset_identifier` and `Host ID` hold the same value, for
example `101`. The report README also names `Host ID` as the stable asset key
in one Qualys subscription.

When you make the vulnerability pipeline for the report, map its `Host ID`
column to the asset. Do not use the `Host Name` or `IP` columns for this link:

- `Host Name` is a display value. It comes from the FQDN, the DNS name, the
  host name, the IP or the ID, in that order. A host can change its name, and
  two hosts can have the same name.
- `IP` changes when DHCP or a cloud platform gives the host a new address. A
  host that has only an IPv6 address has no `IP` value.

The record also holds `name`, `ip` and `asset_id`, with the same values as the
`Host Name`, `IP` and `Asset ID` columns of the report. Use them to look at
the data, not to link it.

## Records

All records under `payload.data` have the same 13 keys. A missing value is
`null`. Thus a mapping that you make from one sample is correct for all runs.

| Field | Inventory field | Source |
|---|---|---|
| `unique_asset_identifier` | Unique ID (required) | The Qualys host ID (`HOST/ID`). The same ID is the `Host ID` column of `qualys_vmdr_vulnerability_findings` |
| `asset_type` | Parent component (required) | Always `host` |
| `name` | Name | The FQDN, else the DNS name, else the host name, else the IP, else the host ID. The same value as the `Host Name` column of the report |
| `ip` | Host IP | The IPv4 address. If the host has no IPv4 address, the IPv6 address |
| `ipv6` | | The IPv6 address |
| `dns` | DNS Name | The FQDN, else the DNS name, else the host name |
| `netbios` | NetBIOS Name | The NetBIOS name |
| `os` | OS | The operating system that Qualys detected |
| `tracking_method` | | How Qualys tracks the host, for example `IP`, `DNS` or `QAGENT` |
| `asset_id` | | The Qualys asset ID (`ASSET_ID`). The same value as the `Asset ID` column of the report |
| `last_vuln_scan_datetime` | | The time of the last vulnerability scan |
| `last_vm_scanned_date` | | The end of the last VM scan |
| `last_vm_auth_scanned_date` | Authenticated Scan | The end of the last authenticated VM scan |

## Limits of the host ID

- A host ID is unique in one Qualys subscription only. If you send two
  subscriptions to one Paramify workspace, two hosts can have the same ID. Use
  one evidence set and one pipeline for each subscription.
- If an operator purges a host and Qualys finds it again, Qualys gives it a
  new host ID. Paramify then shows a new Inventory item.
- The report reads the VM detection list, and this fetcher reads the host list.
  The host list can include hosts with no detections. Every host in the report
  must also be in the host list for the same API user. A live subscription did
  not confirm this.

## Failure behavior

If a call fails, a page is missing, a host has no ID, or a host ID occurs two
times, the run fails (exit non-zero). The status file gives the cause. The
fetcher writes the file with a count but with no records
(`records_included: false`), and the uploader does not send it. If Qualys
returns no hosts, the run exits 0, but the uploader does not send the file.
A pipeline would read an empty file as an empty estate. The fetcher only
reads. It does not change Qualys.

## Verified

The tests use synthetic XML pages in the shape of the Qualys host list v5 and
VM detection v6 outputs. They run with no network. They show that each record
uses the host ID as its key, and that this ID is the `Host ID` of the report
row for the same host. They also show that a failed page, a page without a
next-page URL, a host without an ID, a repeated host and a bad login each
write no records. No live Qualys subscription ran this fetcher, and the
`show_asset_id` parameter on the host list is from the API guide only.

```
pytest -q tests/test_qualys_host_inventory.py
```
