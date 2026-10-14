# FedRAMP Marketplace

Third-party vendor risk: is each cloud service you depend on still FedRAMP
certified? These fetchers read FedRAMP's own published marketplace data from
[github.com/FedRAMP/marketplace-fedramp-gov-data](https://github.com/FedRAMP/marketplace-fedramp-gov-data)
and report, per vendor package, its certification state, class, impact level,
latest status change and a link to its listing at
`https://www.fedramp.gov/marketplace/products/<PACKAGE_ID>/`.

| Fetcher | Vendors come from | Credential |
|---|---|---|
| `fedramp_marketplace_vendor_certification_status` | `vendors` config: `Vendor Name=PACKAGE_ID, ...` | none |
| `fedramp_marketplace_workspace_vendor_certification_status` | Paramify workspace elements of subtype `COM_FEDRAMP_SYSTEM` (configurable) | `PARAMIFY_API_TOKEN` with read access to `/elements` |

## What a record says

- `certification_state`: `certified`, `in_process`, `ready`, `in_remediation`,
  `delisted` or `not_listed`. A package dropped from `data.json` or whose latest
  changelog row is "No Status Found (Delisted)" is delisted. When the two files
  disagree the changelog's latest transition wins and `status_sources_disagree`
  is true. FedRAMP publishes no corrective action plan (CAP) status.
- `certification_class` A–D and `class_source`: the CSO-PKG overview
  (`cso_pkg`), else the changelog's `cert_class` (`changelog`), else derived
  from impact level (`derived`: LI-SaaS A, Low B, Moderate C, High D).
- `package_id_resolves` is false for an unknown ID, a delisted ID with a
  certified re-issue (named in `suggested_package_ids`, never substituted), and
  a workspace element no listing matches.
- `summary` holds the counts the validators read; `feed.feed_age_hours` is the
  age of the older of the two status files.

## Matching workspace elements

Paramify elements carry no package ID field, so each element is matched in
this order, recorded in `match_method`:

1. `package_id_overrides` config (`Element Name=PACKAGE_ID`).
2. A package ID written in the element name, e.g. `Paramify Cloud (FR2428769635XL)`.
3. The element name against the listings, retried without a trailing
   ` - <qualifier>`. Several matches are narrowed to a certified listing over
   in process over ready, then to the one whose impact level the name mentions.

Anything still ambiguous is reported unmatched with its candidates, and fails
the certification and package-ID validators until it is renamed or overridden.

## Settings

| Setting | Env | Default |
|---|---|---|
| `output_mode` (category) | `FEDRAMP_OUTPUT_MODE` | `combined`; `per_vendor` writes one file per vendor, all under the same evidence set |
| `data_url` (category) | `FEDRAMP_MARKETPLACE_DATA_URL` | the FedRAMP repo's raw `main` branch |
| `element_subtypes` (workspace) | `FEDRAMP_ELEMENT_SUBTYPES` | `COM_FEDRAMP_SYSTEM`; add `COM_SAAS`, `COM_IAAS` to opt in |

## Validators

`validators/fedramp_marketplace/`: attach **one** of `fedramp_vendor_certified`
(strict) or `fedramp_vendor_certified_or_in_process` (Ready and In Process
pass), plus `fedramp_vendor_not_delisted`, `fedramp_vendor_not_in_remediation`,
`fedramp_vendor_package_id_resolves` and, optionally, `fedramp_feed_fresh`
(data under 72 hours old).
