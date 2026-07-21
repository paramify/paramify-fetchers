# Okta

Okta fetchers pull IAM evidence — phishing-resistant MFA, passwordless authentication, least privilege, just-in-time authorization, account management, authenticator configuration, and more — from the Okta Management API.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `OKTA_API_TOKEN` | Yes | Okta SSWS API token |
| `OKTA_ORG_URL` | Yes | Okta org base URL, no trailing slash (e.g. `https://your-org.okta.com`) |

## Creating an API token

1. Log in to Okta as an admin.
2. Navigate to **Security → API → Tokens**.
3. Click **Create Token** and name it `paramify-evidence-fetchers`.
4. Assign a read-only admin role — the fetchers read users, groups, apps, policies, authenticators, and system logs.
5. Copy the token immediately — it is not shown again.
6. Store it in your secrets manager as `OKTA_API_TOKEN`.

## Required permissions

The token's admin role needs read access to:

- Users and groups (including user factors and assigned roles)
- Applications and app assignments
- Policies (sign-on, MFA enrollment, password) and policy rules
- Authenticators and authenticator methods
- System logs
- API token list

A read-only super admin role covers all of these. A custom admin role scoped to the above resource types is more appropriate for least privilege.

> Some endpoints (authenticators, certain policy types) may require specific Okta SKUs or the OIE platform. If a fetcher returns a 403 or 404 on an endpoint, verify your tenant's features and the token's admin role scope.

## Wiring into a manifest

All Okta fetchers share the same two secrets. Wire them in once per fetcher you add:

```bash
paramify manifest add okta_phishing_resistant_mfa
paramify manifest set-secret okta_phishing_resistant_mfa api_token OKTA_API_TOKEN
paramify manifest set-secret okta_phishing_resistant_mfa org_url OKTA_ORG_URL

paramify manifest add okta_least_privilege
paramify manifest set-secret okta_least_privilege api_token OKTA_API_TOKEN
paramify manifest set-secret okta_least_privilege org_url OKTA_ORG_URL
```

Use `paramify catalog` to see all available Okta fetchers.

## Smoke test

```bash
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "$OKTA_ORG_URL/api/v1/users?limit=1" | python3 -m json.tool | head -20
```

## Rotating the token

1. Create a second token in the Okta admin console — do not revoke the old one yet.
2. Update `OKTA_API_TOKEN` in your secrets store.
3. Run the smoke test to confirm the new token works.
4. Revoke the old token.
