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
  `delisted`, `not_listed` or `unknown`, from the changelog's latest transition, which is
  what fedramp.gov/marketplace shows: a latest row of "No Status Found
  (Delisted)" is delisted. `data.json` lags the changelog and omits some live
  packages, so it decides only for a package the changelog has never recorded;
  missing from `data.json` alone is not a delisting. `status_sources_disagree`
  is true when `data.json` shows a different state or omits an active package.
  A latest transition to a status this fetcher does not recognise reads as
  `unknown` (counted in `vendors_status_unknown`), which fails both
  certification validators rather than letting an older row decide. FedRAMP publishes no corrective action plan (CAP) status.
- `certification_class` A–D and `class_source`: the CSO-PKG overview
  (`cso_pkg`), else the changelog's `cert_class` (`changelog`), else derived
  from impact level (`derived`: LI-SaaS B, Low B, Moderate C, High D).
- `package_id_resolves` is false for an unknown ID, a delisted ID with a
  re-issue the changelog shows as certified (FR2023864279 -> FR2023864279A,
  named in `suggested_package_ids`, never substituted), and
  a workspace element no listing matches.
- `summary` holds the counts the validators read; `feed.feed_age_hours` is the
  age of the older of the two status files.

## Matching workspace elements

Paramify elements carry no package ID field, so each element is matched in
this order, recorded in `match_method`:

1. `package_id_overrides` config (`Element Name=PACKAGE_ID`).
2. A package ID written in the element name, e.g. `Paramify Cloud (FR2428769635XL)`.
3. The element name against each listing's **product** name (`cso`, the
   service offering, or `<company> <product>`), never the company name alone
   (a product named exactly like its company, such as `911inform`, still
   matches as a product). If nothing matches, the name is retried without one
   trailing qualifier: ` - <qualifier>` (a spaced hyphen or en/em dash, last
   segment only), `: <qualifier>` or `(<qualifier>)`. An unspaced hyphen such
   as `Cloud-Native` is not a qualifier.
4. **Impact level first.** A qualifier that names an impact level
   (`X (High)`, `X - 20x Moderate`) names the offering, so only a listing at
   exactly that level can match, even when it is the only candidate. If none
   is at that level, the element is unmatched (`impact_level_mismatch`) rather
   than resolved to a listing certified at a different level; `Moderate` and
   `20x Moderate` count as different levels. Without such a qualifier, several
   matches are narrowed to the most specific level the name mentions.
5. **Then certification state**, from the changelog as fedramp.gov shows it:
   certified over in process over ready.

A name that matches only a company, such as `Google LLC (Gmail)` or a bare
`Salesforce`, is reported unmatched (`company_only`), because a company name
says nothing about which product is in use. Unmatched elements carry their
candidates in `suggested_package_ids`. Anything unmatched or still ambiguous
fails the certification and package-ID validators until it is renamed or
overridden.

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
