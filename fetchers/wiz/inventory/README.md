# wiz_inventory

Lists every cloud resource Wiz has discovered (Wiz > Inventory > Cloud
Resources), one record each, for a Paramify inventory pipeline.

This is an **inventory** fetcher (`kind: inventory`) and a pipeline fetcher
(`pipeline: {type: inventory, id_scheme: wiz-resource-id}`). The file goes to
the evidence set `EVD-WIZ-INVENTORY`, and the inventory pipeline attached to
that set turns each record into an Inventory item. To run it, follow
[Running an inventory fetcher](../../../docs/inventory_fetchers_guide.md). How
the uploader treats a pipeline file is in the
[pipeline fetchers guide](../../../docs/pipeline_fetchers_guide.md#3-what-the-uploader-does-for-you).

```
Wiz cloudResourcesV2 ──wiz_inventory──▶ wiz_inventory.json
  ──paramify upload (approved batch)──▶ EVD-WIZ-INVENTORY
  ──inventory pipeline (payload.data)──▶ Inventory
```

## Before you start

- **Wiz:** a *Custom Integration (GraphQL API)* service account with the one
  scope `read:resources` (see [the Wiz README](../README.md#service-account)).
  Secrets `client_id` / `client_secret` (`WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`)
  and the config `api_endpoint_url` (`WIZ_API_ENDPOINT_URL`). A commercial
  tenant also sets `auth_url`.
- **Paramify:** an API key that can view and write evidence
  (`PARAMIFY_UPLOAD_API_TOKEN`), and an inventory pipeline built and attached
  to `EVD-WIZ-INVENTORY` before the first upload (below).

## Settings

| Setting | Env var | Default |
|---|---|---|
| `resource_types` | `WIZ_INVENTORY_RESOURCE_TYPES` | VMs, containers, container images, clusters, DB servers, databases, buckets, serverless, load balancers, gateways, firewalls, VNets, subnets, volumes, keys, secrets. `ALL` takes every type. |
| `cloud_account_ids` | `WIZ_INVENTORY_CLOUD_ACCOUNT_IDS` | every account the service account sees |
| `project_ids` | `WIZ_INVENTORY_PROJECT_IDS` | every project |
| `environment_tag_keys` | `WIZ_ENVIRONMENT_TAG_KEYS` | `Environment,env` |
| `owner_tag_keys` | `WIZ_OWNER_TAG_KEYS` | `Owner` |
| `include_tags` | `WIZ_INVENTORY_INCLUDE_TAGS` | `false` (see [What leaves the tenant](#what-leaves-the-tenant)) |
| `max_records` | `WIZ_MAX_RECORDS` | 50000 |

## Set up the inventory pipeline (once)

1. Run the fetcher, then `paramify preset wiz_inventory` (add `-f
   manifest.yaml` or `-o <output dir>`). It prints the sample file, the data
   path (`payload.data`), the unique ID (`unique_asset_identifier`, scheme
   `wiz-resource-id`) and the `asset_type` values of your last run.
2. In Paramify, build the *Inventory* pipeline with those values. Each
   record's `asset_type` (the Wiz resource type, such as `VIRTUAL_MACHINE`)
   gives the parent component.
3. Attach the pipeline to `EVD-WIZ-INVENTORY` (the set's **Pipelines** tab,
   **Manage Selection**), not to a new set.
4. Leave the set's approval automatic and add no validators. `paramify upload`
   sends the whole envelope in a batch that approves on submit, and the
   pipeline runs when the batch approves.

## Records

Every record under `payload.data` has the same 28 keys, with `null` for a
missing value, so a mapping built from one sample holds for every run.

| Field | Inventory field | Source |
|---|---|---|
| `unique_asset_identifier` | Unique ID (required) | The Wiz resource id (`cloudResourcesV2.id`). The same id is the `Asset ID` column of `wiz_vulnerability_findings` |
| `asset_type` | Parent component (required) | The Wiz resource type (`VIRTUAL_MACHINE`, `BUCKET`), or `CLOUD_RESOURCE` if Wiz sends none |
| `external_id` | | The cloud's own ID: the ARN on AWS, the resource ID on Azure |
| `provider_unique_id` | Serial Number | The provider's unique ID (the instance ID for an EC2 instance). The `Asset Provider ID` column of `wiz_vulnerability_findings` |
| `name`, `native_type`, `technology` | | Name, the cloud's own type, and the Wiz technology (`AWS EC2 Instance`) |
| `primary_ip_address` | Host IP | The first of `ip_addresses` (VMs only) |
| `ip_addresses` | | Every IP Wiz records (a list: map `primary_ip_address`) |
| `public` | Internet Facing | `isAccessibleFromInternet` |
| `virtual` | Is Virtual | Always `true` |
| `image` | Security Baseline | VM image, such as the AMI |
| `operating_system`, `instance_type`, `database_kind`, `kubernetes_cluster` | | From the resource's type fields |
| `cloud_platform`, `cloud_account_id`, `cloud_account_name`, `region`, `resource_group` | | Where the resource lives |
| `environment`, `owner` | | The first matching environment and owner tag. Without an owner tag, the first owner Wiz attributes |
| `has_sensitive_data`, `status`, `first_seen`, `last_seen` | | As Wiz records them |
| `tags` | | Every tag as `key=value`, only with `include_tags` (a list) |

Parent component, location, subnet, OS and admins can also be set with an
Advanced Configuration rule on `cloud_account_name`, `region`,
`operating_system` or `owner`. URL, MAC address, NetBIOS name, authenticated
scan and end-of-life date are not collected.

## What leaves the tenant

Each record carries the resource's Wiz and cloud IDs, name, type, account,
region, IP addresses (private and public), OS, image, owner (the owner tag, or
the owner Wiz attributes), the environment tag, and whether Wiz sees it as
internet facing or holding sensitive data. For secrets and keys that is their
names and IDs, never their values. Other tags are left out unless
`include_tags` is on, because tags are free text and can hold anything. Set
`cloud_account_ids` to the accounts in the boundary so resources outside it
are not collected.

## Failure behavior

A GraphQL error, a cursor problem, the record cap, a resource without an ID,
or more repeated IDs than resources fails the run (exit non-zero), and
`api_failures` names it. The file is still written, with counts but no records
(`records_included: false`), and the uploader does not send it. An empty
inventory exits 0 as `partial_or_empty`, but the uploader does not send it
either, because a pipeline would read it as an empty estate. A resource
repeated while paging keeps its newer copy and is counted in
`analysis.duplicates_collapsed`. Nothing writes to Wiz.

## Verified

PR #112 ran the query against a Wiz for Gov tenant on 2026-10-06 with a
read-only service account: every selected field, the type, account and project
filters, and that `read:resources` is the only scope needed. Commercial Wiz is
allowed by the host checks but not exercised. The `wiz-resource-id` key and
the batch upload have not yet run against a live tenant and workspace.

```
pytest -q tests/test_wiz_inventory.py
```
