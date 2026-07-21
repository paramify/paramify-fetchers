# KnowBe4

KnowBe4 fetchers pull security awareness and role-based training completion data from the KnowBe4 Reporting API.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `KNOWBE4_API_KEY` | Yes | KnowBe4 Reporting API key |
| `KNOWBE4_REGION` | Yes | KnowBe4 region identifier: `US`, `EU`, `CA`, `UK`, or `DE` |

`KNOWBE4_REGION` sets the API hostname (`https://{region}.api.knowbe4.com`). Find your region from your KnowBe4 tenant URL or admin console.

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

All KnowBe4 fetchers share the same two secrets:

```bash
paramify manifest add knowbe4_security_awareness_training
paramify manifest set-secret knowbe4_security_awareness_training api_key KNOWBE4_API_KEY
paramify manifest set-secret knowbe4_security_awareness_training region KNOWBE4_REGION
```

Repeat `add` + `set-secret` for each additional KnowBe4 fetcher. Use `paramify catalog` to see all available fetchers.

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

- Use uppercase for the region value (`US`, not `us`).
- Fetchers paginate using `page=N` until an empty page is returned.
