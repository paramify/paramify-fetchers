# Wiz inventory into Paramify

`wiz_inventory` writes one record per cloud resource Wiz has discovered (Wiz >
Inventory > Cloud Resources). It is an inventory fetcher (`kind: inventory`, see
[`inventory_fetchers.md`](inventory_fetchers.md)): the file goes to the
evidence set `EVD-WIZ-INVENTORY`, and an **inventory pipeline** attached to that
evidence set turns each record into an Inventory item.

```
Wiz cloudResourcesV2 ──wiz_inventory──▶ wiz_inventory.json ──paramify upload──▶ EVD-WIZ-INVENTORY
                                                                                    │ upload runs the pipeline
                                                                                    ▼
                                                        inventory pipeline (data path payload.data) ──▶ Inventory
```

## Before you start

- **Wiz:** a *Custom Integration (GraphQL API)* service account with
  `read:resources`, plus the usual `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`,
  `WIZ_API_ENDPOINT_URL`.
- **Paramify:** an API key with View Evidences and Write Evidences
  (`PARAMIFY_UPLOAD_API_TOKEN`), and access to inventory pipelines in your
  workspace.

## 1. Run and upload

In the TUI: Manifest tab (`2`), `a`, add `wiz_inventory`, `e` to set
`api_endpoint_url`. Run tab (`3`), then Paramify tab (`5`), `ctrl+u`.
From the command line: `paramify run <manifest>` then `paramify upload`.

| Setting | Env var | Default |
|---|---|---|
| `resource_types` | `WIZ_INVENTORY_RESOURCE_TYPES` | VMs, containers, container images, clusters, DB servers, databases, buckets, serverless, load balancers, gateways, firewalls, VNets, subnets, volumes, keys, secrets. `ALL` takes every type. |
| `cloud_account_ids` | `WIZ_INVENTORY_CLOUD_ACCOUNT_IDS` | every account the service account sees |
| `project_ids` | `WIZ_INVENTORY_PROJECT_IDS` | every project |
| `environment_tag_keys` | `WIZ_ENVIRONMENT_TAG_KEYS` | `Environment,env` |
| `owner_tag_keys` | `WIZ_OWNER_TAG_KEYS` | `Owner` |
| `include_tags` | `WIZ_INVENTORY_INCLUDE_TAGS` | `false` (see [What leaves the tenant](#what-leaves-the-tenant)) |
| `max_records` | `WIZ_MAX_RECORDS` | 50000 |

## 2. Set up the inventory pipeline (once)

1. Create an inventory pipeline and add an uploaded `wiz_inventory.json` as its
   sample artifact.
2. **Data Stream:** data path `payload.data`.
3. **Field Configuration:** "Field from File" lists the record fields as
   `payload.data.<field>`. List fields (`ip_addresses`, `tags`) cannot be
   selected there; use `primary_ip_address` for the IP.
4. On the evidence set's **Pipelines** tab, select the pipeline. The next upload
   (a new run; the same run is not sent twice) creates Inventory.

| Inventory field | Record field |
|---|---|
| Unique ID | `unique_asset_identifier` (ARN on AWS, resource ID on Azure) |
| Asset Type | `asset_type` (`VIRTUAL_MACHINE`), or `technology` (`AWS EC2 Instance`) |
| Serial Number | `provider_unique_id` (instance ID) |
| Host IP | `primary_ip_address` (VMs only) |
| Internet Facing | `public` |
| Is Virtual | `virtual` (always true) |
| Security Baseline | `image` (VM image, e.g. the AMI) |
| Parent Component, Location, Subnet, Operating System, System Admin, Application Admin | Workspace data: set with an Advanced Configuration rule on `cloud_account_name`, `region`, `operating_system` or `owner` |
| URL, MAC Address, NetBIOS Name, Authenticated Scan, End of Life Date | Not collected |

Other fields useful in rules: `environment`, `owner`, `has_sensitive_data`,
`cloud_account_id`, `kubernetes_cluster`, `status`, `first_seen`, `last_seen`.

## What leaves the tenant

Each record carries the resource's cloud ID, name, type, account, region, IP
addresses (private and public), OS, image, owner (the owner tag, or the owner
Wiz attributes), the environment tag, and whether Wiz sees it as internet
facing or holding sensitive data. For secrets and keys that is their names and
IDs, never their values. Other tags are left out unless `include_tags` is on,
because tags are free text and can hold anything. Set `cloud_account_ids` to
the accounts in the boundary so resources outside it are not collected.

## Failure behavior

Same as the rest of the Wiz category: a GraphQL error, a cursor problem, the
record cap, or a resource without an ID fails the run and `metadata.error`
names it. The file is still written, but with counts only and no records
(`records_included: false`), so a pipeline never builds Inventory from a
partial list. `paramify upload` also checks this itself and does not send a
failed run's file. An empty inventory is `partial_or_empty`, not a failure: the
run exits 0, but the uploader does not send it either, because a pipeline would
read it as an empty estate. Two copies of the same resource (the estate
changed while paging) keep the newer one and are counted in
`analysis.duplicates_collapsed`. Nothing writes to Wiz.

## Verified

Against a Wiz for Gov tenant on 2026-10-06 with a read-only service account:
the query and every selected field, the type, account and project filters, and
that `read:resources` is the only scope needed. The uploaded file was read by a
Paramify inventory pipeline with data path `payload.data`. Commercial Wiz is
allowed by the host checks but not exercised.

```
python3 -m pytest -q tests/test_wiz_inventory.py
```
