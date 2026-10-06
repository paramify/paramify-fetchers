# Wiz inventory into Paramify

`wiz_inventory` collects the cloud resources Wiz has discovered and writes one
record per resource, joined with that resource's open **Inventory Management
findings** (Wiz > Findings > Inventory Management Findings: tag enforcement,
agent coverage and custom governance rules). It is an ordinary evidence fetcher.
Paramify turns the file into Inventory records with an **inventory pipeline**
attached to the evidence set, so this guide covers both halves.

```
Wiz cloudResourcesV2 + inventoryFindings
        │  wiz_inventory (read-only GraphQL)
        ▼
wiz_inventory.json  ── paramify upload / TUI ctrl+u ──▶  evidence set EVD-WIZ-INVENTORY
                                                              │  artifact upload triggers
                                                              ▼
                                       inventory pipeline (data path payload.data)
                                       field configuration + advanced configuration rules
                                                              │
                                                              ▼
                                                     Paramify Inventory
```

## Before you start

**In Wiz:** a service account of type *Custom Integration (GraphQL API)*, all
projects (or the projects in the boundary), read-only scopes:

| Scope | For |
|---|---|
| `read:resources` | `cloudResourcesV2`, the inventory itself |
| read access to Inventory Management findings | `inventoryFindings`. The exact scope name is not yet confirmed with a service-account token (see [Verified vs unverified](#verified-vs-unverified)). If the run fails on `inventoryFindings` with "not authorized", add the Inventory Management read scope, or set `include_inventory_findings: false` to collect the inventory alone. |

The same `WIZ_CLIENT_ID` / `WIZ_CLIENT_SECRET` / `WIZ_API_ENDPOINT_URL` as the
other Wiz fetchers.

**In Paramify:** pipelines are behind a feature flag (internal beta). You need an
inventory pipeline and the Pipelines tab on evidence sets; both are on stage.

## 1. Add and run the fetcher (TUI)

1. `paramify tui`, open your evidence manifest, **Manifest** tab (`2`), `a`, pick
   `wiz_inventory`.
2. `e` to edit its settings. The ones that matter for scope:

   | Setting | Env var | Default | Notes |
   |---|---|---|---|
   | `resource_types` | `WIZ_INVENTORY_RESOURCE_TYPES` | VMs, containers, images, clusters, DB servers, databases, buckets, serverless, load balancers, gateways, firewalls, VNets, subnets, volumes, keys, secrets | `ALL` takes everything, which is mostly IAM policies and service accounts. An unknown type is refused before any paging. |
   | `cloud_account_ids` | `WIZ_INVENTORY_CLOUD_ACCOUNT_IDS` | all | AWS account / Azure subscription / GCP project IDs in the boundary. |
   | `project_ids` | `WIZ_INVENTORY_PROJECT_IDS` | all | Wiz project IDs. Also limits the findings. |
   | `cloud_platforms` | `WIZ_INVENTORY_CLOUD_PLATFORMS` | all | `AWS,Azure,GCP`; case does not matter. |
   | `include_deleted` | `WIZ_INVENTORY_INCLUDE_DELETED` | false | |
   | `include_inventory_findings` | `WIZ_INVENTORY_INCLUDE_FINDINGS` | true | |
   | `finding_statuses` | `WIZ_INVENTORY_FINDING_STATUSES` | `OPEN,IN_PROGRESS` | The portal's *Unresolved*. |
   | `environment_tag_keys` | `WIZ_ENVIRONMENT_TAG_KEYS` | `Environment,env` | Tag copied into `environment`. Case-insensitive, first match wins. |
   | `owner_tag_keys` | `WIZ_OWNER_TAG_KEYS` | `Owner` | Tag copied into `owner`; falls back to the owner Wiz attributes. |
   | `max_records` | `WIZ_MAX_RECORDS` | 50000 | Checked against Wiz's count before paging, and again while paging. |

3. **Run** tab (`3`), `enter`. Then **Paramify** tab (`5`), `ctrl+u` to upload.
   The uploader get-or-creates the evidence set `EVD-WIZ-INVENTORY`
   ("Wiz Cloud Resource Inventory").

Command line: `paramify run <manifest>` then `paramify upload`.

## 2. Attach an inventory pipeline (once, in Paramify)

1. Create an inventory pipeline. Add a sample artifact: the `wiz_inventory.json`
   just uploaded.
2. **Data Stream:** data path `payload.data`. Each element is one resource.
3. **Evidence set > Pipelines tab:** select the pipeline on
   `EVD-WIZ-INVENTORY`. From then on every upload runs the pipeline.

## 3. Field configuration

Every record has the same keys (a value Wiz does not have is `null`, a list is
`[]`), so a mapping made from one sample holds for every run.

| Record field | Typical inventory field | Notes |
|---|---|---|
| `unique_asset_identifier` | Unique Asset Identifier (ID) | The cloud's own ID: ARN on AWS, resource ID on Azure. Falls back to the provider ID, then the Wiz ID. |
| `name` | Name / NetBIOS-DNS name | |
| `asset_type` | Asset Type | Wiz type, e.g. `VIRTUAL_MACHINE`. `native_type` and `technology` are finer grained (`rds/PostgreSQL/instance`, `AWS RDS PostgreSQL Instance`). |
| `primary_ip_address`, `ip_addresses` | IP address | Only VMs carry IPs in Wiz. EKS nodes list every pod IP. |
| `virtual` | Virtual | Always true. |
| `public` | Public | Wiz `isAccessibleFromInternet`. |
| `operating_system` | OS Name and Version | VM OS family (`LINUX`, `WINDOWS`) or container image distribution (`Alpine Linux`). |
| `region`, `cloud_account_name` | Location | Or a Workspace Data custom variable. |
| `owner`, `owners` | System / Application Administrator | Tag value, else Wiz's own owner attribution. |
| `tags` (`key=value` list), `projects` | Custom tags | Lists of text. |
| `environment` | (condition input) | For criticality rules. |
| Parent Component | (static or Workspace Data) | Not in Wiz; set it in the pipeline. |

## 4. Advanced configuration (condition engine) examples

The fields below are top level so a rule can test them directly:

| Condition | Action |
|---|---|
| `environment` equals `prod` or `production` | Asset criticality = high |
| `environment` equals `dev` or `test` | Asset criticality = low |
| `public` is true | Append custom tag `internet-facing` |
| `has_sensitive_data` is true | Asset criticality = high |
| `missing_owner_tag` is true | Append custom tag `needs-owner` |
| `inventory_finding_count` greater than 0 | Append custom tag `wiz-governance-finding` |
| `inventory_finding_max_severity` equals `HIGH` or `CRITICAL` | Append custom tag `wiz-governance-high` |
| `deleted` is true (with `include_deleted`) | Archive |

## What else is in the file

- `analysis`: counts by type, platform, account, region and status; how many
  resources miss the environment or owner tag; findings by rule and severity;
  `findings_outside_inventory_*`, the findings whose resource is not in this
  inventory (usually a type you did not collect, such as `NETWORK_ADDRESS`);
  `wiz_reported_total` and whether the collected count matches it.
- `scope`: the filters actually applied, and `pages_served_by_light_query`.
  If a page keeps failing at the smallest page size, it is fetched again
  without the heavy nested fields. Those records have `detail_complete: false`.
- Each record's `inventory_findings[]`: rule, rule type, severity, status, dates.

Read it with `wiz_scan_coverage`: a cloud account Wiz is not connected to
contributes no resources here and no error either.

## Failure behavior

Same contract as the rest of the Wiz category. A GraphQL error, a cursor
problem or the record cap fails the run (non-zero exit, `metadata.error` says
which operation); the evidence file is still written. A failed findings pull
fails the run too, so an inventory never silently arrives without its findings.
The pre-flight count is the exception: if Wiz will not answer it, the run goes
on and `wiz_reported_total` is `null`. Nothing writes to Wiz.

## Verified vs unverified

| Item | Status |
|---|---|
| `cloudResourcesV2`, `inventoryFindings`, every node field selected, and the filter inputs (`type`, `cloudPlatform`, `cloudAccountV2.externalId`, `project.idV2`, `includeDeleted`; `status`, `projects`) | **Verified** against the Wiz for Gov schema (introspection) and by running both queries on a live tenant, 2026-10-06. |
| `inventoryFindings.resource.id` equals `cloudResourcesV2.id` | **Verified** live. |
| Service-account scope for `inventoryFindings` | **UNVERIFIED.** Checked with a portal session, not a service-account token. |
| Paramify inventory pipeline reading `payload.data` from the uploaded envelope | **UNVERIFIED**, test on stage. |
| Commercial Wiz | Allowed by the host checks, not exercised. |

## Testing offline

```
python3 -m pytest -q tests/test_wiz_inventory.py
```
