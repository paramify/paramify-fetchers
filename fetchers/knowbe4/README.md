# KnowBe4

KnowBe4 fetchers pull security awareness and role-based training completion data from the KnowBe4 Reporting API.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `KNOWBE4_API_KEY` | Yes | KnowBe4 Reporting API key |
| `KNOWBE4_REGION` | Yes | KnowBe4 region subdomain: `us`, `eu`, `ca`, `uk`, or `de` |

`KNOWBE4_REGION` sets the API hostname (`https://{region}.api.knowbe4.com`). Find your region from your KnowBe4 tenant URL or admin console.

## Which group and campaign names to measure

Three of the four fetchers measure *specific* groups and campaigns, so they need to be told which ones. There are no defaults — the names are yours, and a name is matched **exactly** against the titles in your tenant (not as a substring, so `IT` will not pull in `AUDIT`). Each value is a comma-separated list; whitespace around each name is trimmed.

| Fetcher | Config key | Env var |
|---|---|---|
| `knowbe4_security_awareness_training` | `security_awareness_campaigns` | `KNOWBE4_SECURITY_AWARENESS_CAMPAIGNS` |
| | `retraining_interval_days` (optional, default 365) | `KNOWBE4_RETRAINING_INTERVAL_DAYS` |
| `knowbe4_high_risk_training` | `high_risk_groups` | `KNOWBE4_HIGH_RISK_GROUPS` |
| | `role_specific_campaigns` | `KNOWBE4_ROLE_SPECIFIC_CAMPAIGNS` |
| `knowbe4_developer_specific_training` | `developer_groups` | `KNOWBE4_DEVELOPER_GROUPS` |
| | `developer_campaigns` | `KNOWBE4_DEVELOPER_CAMPAIGNS` |
| `knowbe4_module_based_summary` | *none* | — |

`knowbe4_module_based_summary` reports on whatever the tenant has, so it needs no config and works against any tenant as-is.

To find the exact titles to use, run `knowbe4_discovery_beta`: it lists every group,
training campaign, module, policy and phishing campaign the key can see, without
any config, so you can copy exact names from its JSON output. It is never
uploaded. Or ask the API directly:

```bash
curl -s -H "Authorization: Bearer $KNOWBE4_API_KEY" \
  "https://${KNOWBE4_REGION}.api.knowbe4.com/v1/groups?per_page=500&cursor=0" | jq -r '.data[].name'
curl -s -H "Authorization: Bearer $KNOWBE4_API_KEY" \
  "https://${KNOWBE4_REGION}.api.knowbe4.com/v1/training/campaigns?per_page=500&cursor=0&exclude_percentages=true" | jq -r '.data[].name'
```

### What happens when a name does not match

A name that matches nothing in your tenant does **not** fail the fetcher — one typo should not turn a whole nightly run red. Instead the run exits 0 and the evidence says it could not measure:

```json
"config_resolution": {
  "status": "unresolved",
  "measurable": false,
  "groups": {
    "requested": ["Cloud Opps"],
    "matched": [],
    "unmatched": ["Cloud Opps"]
  },
  "groups_present_in_tenant": ["Cloud Ops", "IT Helpdesk", "Platform Team"]
},
"summary": {
  "total_high_risk_users": 0,
  "completed_training": null,
  "completion_rate": null
}
```

Read it like this:

- **`null` means "not measured."** **`0` means "measured, and it is zero."** A metric the fetcher could not compute is never reported as 0, because 0 reads as a genuine failing control. If `completion_rate` is `0`, nobody completed the training and that is a real finding.
- **`status`** is `resolved` (every name matched), `partial` (some matched), or `unresolved` (a dimension matched nothing, so nothing is measurable).
- **`*_present_in_tenant`** appears only when something failed to match, and lists what your tenant actually has — usually enough to spot the typo without opening a shell.
- Counts of what was *discovered* (`total_groups`, `total_campaigns`, `total_*_users`) stay real numbers even when unresolved.

A `WARN` line naming the unmatched values is also written to stderr, so it shows up in the run output.

A config key that is never wired at all is a different case: it is `required`, so `paramify validate` catches it before any run.

## Creating an API key

The KnowBe4 Reporting API is typically available to Platinum and Diamond customers. Contact KnowBe4 support if access is not enabled on your account.

1. Sign in to KnowBe4 as an Admin.
2. Navigate to **Account Settings → Account Integrations → API**.
3. Enable **Reporting API Access** if not already enabled.
4. Copy the **Secure API key** and store it in your secrets manager as `KNOWBE4_API_KEY`.

## Required permissions

- **Access:** Reporting API enabled for the account (Platinum/Diamond tier)
- **Role:** Admin with access to user and training reporting endpoints

## Wiring into a manifest

Every KnowBe4 fetcher takes the same two secrets; three of them also take config.

```bash
# No config needed — runs against any tenant.
paramify manifest add knowbe4_module_based_summary
paramify manifest set-secret knowbe4_module_based_summary api_key KNOWBE4_API_KEY
paramify manifest set-secret knowbe4_module_based_summary region KNOWBE4_REGION

# Needs the campaign name(s) to measure.
paramify manifest add knowbe4_security_awareness_training
paramify manifest set-secret knowbe4_security_awareness_training api_key KNOWBE4_API_KEY
paramify manifest set-secret knowbe4_security_awareness_training region KNOWBE4_REGION
paramify manifest set-config knowbe4_security_awareness_training \
  security_awareness_campaigns "2026 Annual Security Awareness Training"

# Needs both the groups and the campaign(s) they must complete.
paramify manifest add knowbe4_high_risk_training
paramify manifest set-secret knowbe4_high_risk_training api_key KNOWBE4_API_KEY
paramify manifest set-secret knowbe4_high_risk_training region KNOWBE4_REGION
paramify manifest set-config knowbe4_high_risk_training high_risk_groups "Cloud Ops,IT,DevOps"
paramify manifest set-config knowbe4_high_risk_training role_specific_campaigns \
  "Privileged Users Training (Before CloudOps Access)"
```

Then confirm every required value is set:

```bash
paramify validate
```

Use `paramify catalog` to see all available fetchers, and `paramify describe <fetcher>` for one fetcher's config and secrets. See `examples/knowbe4_run.yaml` for the manifest form.

## Smoke test

```bash
curl -s -H "Authorization: Bearer $KNOWBE4_API_KEY" \
  "https://${KNOWBE4_REGION}.api.knowbe4.com/v1/users?page=1" \
  | python3 -m json.tool | head -20
```

## Rotating the API key

1. Generate a new key in the KnowBe4 admin console.
2. Update `KNOWBE4_API_KEY` in your secrets store.
3. Run the smoke test to confirm.

## Notes

- Use the lowercase region subdomain (`us`). Hostnames are case-insensitive, so `US` also resolves, but the lowercase form matches KnowBe4's own documentation and `examples/knowbe4_run.yaml`.
- A comma separates names, and there is no escape for a name that itself contains a comma. Such a name will split into fragments that match nothing — which surfaces as `status: unresolved` naming the fragments, not as silently wrong numbers.
- Fetchers paginate using `page=N` until an empty page is returned, and stop at a 1000-page cap. A response that is not a JSON array (an error body returned with HTTP 200) is recorded as a failure rather than treated as data, and fails the fetcher.
- A failed API call still fails the fetcher (nonzero exit). Only config that does not resolve is reported as evidence instead.
