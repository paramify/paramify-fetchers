# Optional selected-subscription Azure reads

The default Azure collectors can discover related resources in other subscriptions
the credential can read. To collect only from an explicit subscription, export
`AZURE_TARGET_SUBSCRIPTION_ONLY=true` and `AZURE_SUBSCRIPTION_ID`. When using a
manifest, opt the strict setting into `run.platforms.azure.auth.passthrough_env`
alongside `AZURE_AUTHORITY_HOST` if using a sovereign cloud.

```yaml
run:
  platforms:
    azure:
      auth:
        passthrough_env: [AZURE_AUTHORITY_HOST, AZURE_TARGET_SUBSCRIPTION_ONLY]
```

Set `subscription_id` explicitly on each Azure target. A missing subscription or
an invalid strict-setting value fails before credential acquisition. This option
restricts collection; it does not change the identity's Azure permissions.

VNet egress skips subscription enumeration and cross-subscription hub discovery.
Private DNS constrains Resource Graph lookups to the selected subscription and
leaves foreign links unresolved. WAF and alert collectors retain foreign policy
and action-group references as outside the read scope rather than fetching them.
Resource diagnostic settings report `results.read_scope=target_subscription`.

Sentinel data sources do not execute pending service-supplied last-data KQL in
this mode, because a workspace reference or function can hide a broader query.
They retain its text, hash and `query_execution=not_executed_scope_unverified`;
last-data values and affected connectivity counts remain unknown. Existing local
table observations remain usable, as do fixed built-in queries.

These limits intentionally reduce cross-subscription visibility. An unresolved
relationship does not prove deletion, disconnection or compliance. Disable the
option to retain the existing broad discovery behavior.
