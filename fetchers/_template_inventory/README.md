# \<fetcher_name>

\<One sentence: which assets this lists, from which system, over what scope.>

This is an **inventory** fetcher (`kind: inventory`): one record per asset,
uploaded to an evidence set where a Paramify inventory pipeline turns each
record into an Inventory item. See
[docs/inventory_fetchers.md](../../docs/inventory_fetchers.md).

## Records

Each record under `payload.data`:

| Field | Inventory field | Source |
|---|---|---|
| `unique_asset_identifier` | Unique ID | \<the asset's own stable ID> |
| `name` | | \<…> |
| `asset_type` | Asset Type | \<…> |

## Required env vars

| Var | Purpose |
|-----|---------|
| `<UPPER_SNAKE_ENV_VAR>` | \<what it's for, and which read-only scope it needs> |
| `EVIDENCE_DIR` | Output directory, set by the runner |

## Failure behavior

Any failed call, missing page or asset without an ID writes the file with no
records (`records_included: false`) and exits non-zero. The uploader does not
send an incomplete or empty inventory.
