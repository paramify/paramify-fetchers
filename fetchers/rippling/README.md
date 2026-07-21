# Rippling

Rippling fetchers pull employee roster and device inventory from the Rippling Platform API — active employees, all employees (including terminated), and managed device inventory.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `RIPPLING_API_TOKEN` | Yes | Rippling Platform API token |
| `RIPPLING_BASE_URL` | No | API base URL (default `https://api.rippling.com`) |

`RIPPLING_BASE_URL` is a category-level config value shared across all Rippling fetchers. It defaults to `https://api.rippling.com` and does not need to be set for most tenants. To override it, add a platforms block to your manifest rather than wiring it as a secret:

```yaml
run:
  platforms:
    rippling:
      config:
        base_url: https://your-custom-host.rippling.com
```

## Creating an API token

Rippling API tokens are issued through the Rippling Developer Hub and require developer access on your account.

1. Sign in to the [Rippling Developer Hub](https://developer.rippling.com).
2. Open your application and navigate to its API token settings.
3. Create a new token named `paramify-evidence-fetchers`.
4. Select read-only scopes for the resources the fetchers you plan to run need access to: employee data for `rippling_current_employees` and `rippling_all_employees`, device data for `rippling_devices`.
5. Copy the token immediately — Rippling will not show it again.
6. Store it in your secrets manager as `RIPPLING_API_TOKEN`.

## Required permissions

- **Access:** Rippling Developer Hub access with permission to issue API tokens
- **Role:** Admin that can read employee and device data
- **Scopes:** Read-only access to the resources corresponding to the fetchers you run

## Wiring into a manifest

All Rippling fetchers share the `RIPPLING_API_TOKEN` secret:

```bash
paramify manifest add rippling_current_employees
paramify manifest set-secret rippling_current_employees api_token RIPPLING_API_TOKEN

paramify manifest add rippling_devices
paramify manifest set-secret rippling_devices api_token RIPPLING_API_TOKEN
```

## Smoke test

```bash
curl -s -H "Authorization: Bearer $RIPPLING_API_TOKEN" \
  "${RIPPLING_BASE_URL:-https://api.rippling.com}/platform/api/employees?limit=1" \
  | python3 -m json.tool | head -20
```

## Rotating the token

1. Create a second token in the Rippling Developer Hub — do not revoke the old one yet.
2. Update `RIPPLING_API_TOKEN` in your secrets store.
3. Run the smoke test.
4. Revoke the old token.

## Notes

- Rippling enforces rate limits (~300 requests per 10 seconds per token). The fetchers paginate with a small inter-request delay.
