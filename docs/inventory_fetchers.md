# Inventory fetchers

An **inventory** fetcher lists every asset of some kind (cloud resources, hosts,
devices, containers) as one record per asset, so that Paramify's Inventory can
be generated from an authoritative source instead of kept by hand
(KSI-PIY-GIV).

It is an evidence fetcher in every respect but two: its payload has a fixed
outer shape, and it is all or nothing. Everything in
[`authoring_a_fetcher.md`](authoring_a_fetcher.md) and
[`fetcher_contract.md`](fetcher_contract.md) applies.

```
source API ──fetcher──▶ <name>.json ──paramify upload──▶ evidence set
                                                            │ upload runs the pipeline
                                                            ▼
                                  inventory pipeline (data path payload.data) ──▶ Inventory
```

|  | evidence | inventory |
|---|---|---|
| `kind:` | `evidence` (default, omit it) | `inventory` |
| Payload | any JSON you build | `data` (records) + `records_included`, plus anything else |
| `evidence_set` | yes | **required** |
| `output.type` | `json`, `csv`, `html` | `json` |
| Enveloped | yes | yes, with `metadata.inventory` added |
| Uploaded by | `paramify upload` | `paramify upload`, **only when complete** |

## Why it is all or nothing

An inventory pipeline reads the uploaded file as the whole estate. A record
missing from the file reads as an asset that no longer exists. So a run that
lost a page, hit a rate limit, or met an asset it could not read must not send
the records it did get. The fetcher writes the file with `data: []` and
`records_included: false`, keeps its counts so an operator can see how far it
got, and exits non-zero.

## The payload contract

Checked by `framework/inventory.py` against
[`framework/schemas/inventory_schema.json`](../framework/schemas/inventory_schema.json)
when the runner envelopes the file:

- `data` is a list of objects.
- Every record has a non-empty string `unique_asset_identifier`, and no two
  records share one. It is what the pipeline matches Inventory items on, so use
  the asset's own stable ID (an ARN, an Azure resource ID), never a display
  name.
- `records_included` is a boolean. When it is `false`, `data` is empty.

Everything else is the fetcher's choice: the record fields, and any other
top-level keys (counts, scope, analysis). There is no shared record schema; each
inventory's fields are mapped to Inventory fields in its own pipeline. Two
habits make that mapping hold from run to run:

- Give every record the same keys, with `null` for a missing value. A pipeline
  mapping is built from one sample file.
- Keep list values (IP addresses, tags) alongside a scalar copy of the one a
  pipeline should map (`primary_ip_address`). The pipeline's field picker
  cannot select a list.

## What the framework adds

The runner writes the verdict into the envelope:

```json
"metadata": {
  "status": "success",
  "inventory": {
    "records": 1824,
    "records_included": true,
    "complete": true
  }
}
```

`complete` is true only when the fetcher exited 0, the payload holds the
contract, the records were included, and there is at least one record. When it
is false, `incomplete_because` lists why and `problems` lists any contract
breaks. The payload itself is left as the fetcher wrote it.

`paramify upload` (and the TUI's ctrl+u) skips an inventory whose `complete` is
not true and says why, regardless of `skip_failed`. An empty inventory is not
sent either: an empty estate is far likelier to be a filter or permission
mistake than a real one, and the pipeline cannot tell the difference.

## Setting up the pipeline

Once per workspace, in Paramify:

1. Create an inventory pipeline and give it an uploaded file as its sample.
2. **Data path:** `payload.data`. (If the uploader config sets
   `artifact_payload: payload`, the envelope is not uploaded and the path is
   `data`.)
3. Map the record fields to Inventory fields. `unique_asset_identifier` maps to
   Unique ID.
4. Attach the pipeline to the fetcher's evidence set (the set's **Pipelines**
   tab). The next upload builds Inventory.

## Writing one

Copy [`fetchers/_template_inventory/`](../fetchers/_template_inventory/). It
pages a source, raises on any gap, and writes the withheld shape on failure.
Test the failure paths more than the happy one: a failed page, an asset without
an ID, and a credential rejected mid-pagination should each produce a file that
`framework.inventory.check(payload, exit_code)` marks incomplete.
