# azure_asset_inventory

Lists every resource in one Azure subscription, one record each, for a
Paramify inventory pipeline.

This is an **inventory** fetcher (`kind: inventory`) and a pipeline fetcher
(`pipeline: {type: inventory, id_scheme: azure-resource-id}`). The file goes to
the evidence set `EVD-AZURE-ASSET-INVENTORY`. The inventory pipeline that you
attach to that set turns each record into an Inventory item. To run it, follow
[Running an inventory fetcher](../../../docs/inventory_fetchers_guide.md). The
[pipeline fetchers guide](../../../docs/pipeline_fetchers_guide.md#3-what-the-uploader-does-for-you)
tells how the uploader sends a pipeline file.

```
Resource Graph Resources ──azure_asset_inventory──▶ azure_asset_inventory_<subscription>.json
  ──paramify upload (approved batch)──▶ EVD-AZURE-ASSET-INVENTORY
  ──inventory pipeline (payload.data)──▶ Inventory
```

Its pair is
[`azure_defender_vulnerability_report`](../defender_vulnerability_report/README.md).
The `Asset ID` column of that report holds the same value as
`unique_asset_identifier` here, so Paramify can link each vulnerability finding
to its Inventory item.

## Before you start

- **Azure:** an identity with Reader on the subscription. The fetcher uses
  `DefaultAzureCredential`, as every Azure fetcher does (see the
  [Azure README](../README.md#credential-setup)). It needs no secret.
- **Paramify:** an API key that can view and write evidence, and an inventory
  pipeline that you build and attach to `EVD-AZURE-ASSET-INVENTORY` before the
  first upload (below).

## Settings

| Setting | Env var | Default |
|---|---|---|
| `subscription_id` (target) | `AZURE_SUBSCRIPTION_ID` | the first enabled subscription that the credential can see |
| `environment` (target) | `AZURE_ENVIRONMENT` | none. A label for the payload metadata |
| `resource_exclusions` | `AZURE_RESOURCE_EXCLUSIONS` | none. Every resource is in scope |

Set one target for each subscription. Each target writes its own file.

`resource_exclusions` takes `rg:`, `location:` and `id:` glob patterns. A
resource that a pattern matches gets no record. The payload lists it under
`results.excluded` with the pattern. Set the patterns once under
`platforms.azure.config`, so that this inventory and the vulnerability report
use the same scope. A finding has no location, so a `location:` pattern
removes a resource from the inventory but not its findings from the report.

```yaml
run:
  fetchers:
    - use: azure_asset_inventory
      targets:
        - subscription_id: 00000000-0000-0000-0000-000000000000
```

## Set up the inventory pipeline (once)

1. Run the fetcher. Then run `paramify preset azure_asset_inventory` (add
   `-f manifest.yaml` or `-o <output dir>`). It prints the sample file, the
   data path (`payload.data`), the unique ID (`unique_asset_identifier`,
   scheme `azure-resource-id`) and the `asset_type` values of your last run.
2. In Paramify, build the *Inventory* pipeline with those values. The
   `asset_type` of each record (the resource type, such as
   `microsoft.compute/virtualmachines`) gives the parent component.
3. Attach the pipeline to `EVD-AZURE-ASSET-INVENTORY` (the **Pipelines** tab of
   the set, **Manage Selection**). Do not attach it to a new set.
4. Keep the approval of the set automatic, and add no validators.

## Records

Every record under `payload.data` has the same 12 keys, with `null` for a
missing value. Thus a mapping that you build from one sample holds for every run.

| Field | Source |
|---|---|
| `unique_asset_identifier` | The Azure resource ID in lowercase. Map it to Unique ID |
| `asset_type` | The resource type, such as `microsoft.containerregistry/registries`. Resource Graph sends it in lowercase. Map it to the parent component |
| `resource_id` | The resource ID with the casing that Azure returned |
| `name` | The resource name |
| `location` | The region, such as `eastus`, or `global` |
| `resource_group` | The resource group, in lowercase |
| `subscription_id` | The subscription, from the resource ID |
| `kind` | The resource kind, such as `StorageV2`, or `null` |
| `sku_name`, `sku_tier` | Flat copies of the SKU name and tier, or `null` |
| `provisioning_state` | The provisioning state, such as `Succeeded` |
| `tags` | Every tag of the resource, as an object. Map a flat field instead |

The fetcher runs the `Resources` query and the row projection of
[`azure_resource_inventory`](../resource_inventory/fetcher.py). It loads that
code and does not copy it. It leaves out the Defender and Policy coverage of
that fetcher. Resource groups and the subscription itself are not in the
`Resources` table, so they get no record.

## The asset ID

Azure resource IDs are not case-sensitive. Resource Graph, ARM and Defender for
Cloud do not always return the same casing for one resource. Thus the fetcher
writes the ID in lowercase (`azure_common.arm_id_key`), for example:

```
/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-app/providers/microsoft.compute/virtualmachines/vm-runner
```

The vulnerability report writes its `Asset ID` column with the same function.
`resource_id` keeps the original casing for people who read the record. Two
resources whose IDs differ only in casing are the same resource. If Resource
Graph returns them both, the run fails.

## What leaves the tenant

Each record holds the resource ID, name, type, region, resource group, kind,
SKU, provisioning state and tags. Tags are free text and can hold anything, so
examine them before the first upload. The fetcher reads no secret value, key or
connection string. It never writes to Azure.

## Failure behavior

The output is all or nothing. These conditions fail the run (exit 1):

- A failed or throttled page, a truncated result, or fewer rows than Resource
  Graph reported.
- More than 1,000 pages (1,000,000 resources).
- A row without an ID, or two rows with the same ID.
- No subscription, no credential, or a bad `resource_exclusions` pattern.

The file is still written, with `records_included: false` and no records.
`metadata.api_failures` names the cause, and the uploader does not send the
file. An empty inventory exits 0. The uploader does not send it either,
because a pipeline would read it as an empty estate. Without Reader on the
subscription, Resource Graph returns no resources and no error.

## Verified

The tests use synthetic Resource Graph rows and a fake client. They page the
rows through the shared pager. No live Azure subscription or Paramify
workspace ran this fetcher yet.

```
pytest -q tests/test_azure_pipeline_pair.py
```
