# SentinelOne

SentinelOne fetchers pull endpoint agent inventory, activity logs, cloud detection rules, XDR assets, and user configuration from the SentinelOne management console API.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SENTINELONE_API_TOKEN` | Yes | SentinelOne API token |
| `SENTINELONE_API_URL` | Yes | SentinelOne console base URL, no trailing slash (e.g. `https://your-instance.s1gov.net`) |

## Creating a service user and API token

SentinelOne API tokens are tied to service users, not personal accounts. Use a dedicated service user for evidence collection.

1. Log in to the SentinelOne console.
2. Navigate to **Settings → Users → Service Users**.
3. Click **Actions → Create New Service User**.
4. Name it `paramify-evidence-fetchers`, set scope to **Account** level.
5. Assign the **Viewer** role — all fetchers are read-only.
6. Select the service user, click **Actions → Generate API Token**.
7. Set an expiration (SentinelOne recommends a maximum of 6 months).
8. Complete SSO re-authentication if prompted.
9. Copy the token immediately and store it in your secrets manager as `SENTINELONE_API_TOKEN`.

## Required permissions

- **Scope:** Account level
- **Role:** Viewer (read-only access to all resources)

## Wiring into a manifest

All SentinelOne fetchers share the same two secrets:

```bash
paramify manifest add sentinelone_agents
paramify manifest set-secret sentinelone_agents api_token SENTINELONE_API_TOKEN
paramify manifest set-secret sentinelone_agents api_url SENTINELONE_API_URL
```

Repeat `add` + `set-secret` for each additional SentinelOne fetcher. Use `paramify catalog` to see all available fetchers.

## Smoke test

```bash
curl -s -H "Authorization: ApiToken $SENTINELONE_API_TOKEN" \
  "$SENTINELONE_API_URL/web/api/v2.1/agents?limit=1" | python3 -m json.tool | head -10
```

## Rotating the token

1. Navigate to **Settings → Users → Service Users**.
2. Select `paramify-evidence-fetchers`.
3. Click **Actions → Regenerate API Token** and set a new expiration.
4. Complete SSO re-authentication when prompted.
5. Update `SENTINELONE_API_TOKEN` in your secrets store.
6. Run the smoke test to confirm.

## Notes

- Track token expiration and rotate before it lapses — an expired token causes all SentinelOne fetchers to exit non-zero.
- The `cloud_detection_rules` fetcher uses `Bearer` auth for the PowerQuery endpoint; the same token value works for both auth schemes.
