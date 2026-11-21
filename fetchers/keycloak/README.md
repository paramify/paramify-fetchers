# Keycloak fetchers

Read-only evidence from the Keycloak Admin REST API. Every fetcher in this category signs in with the OAuth2
client-credentials grant as a dedicated service-account client, then issues only GET requests under
`/admin/realms/{realm}`. The shared client is `_shared/keycloak_client.py`.

## Setup

1. In the realm to read (or in `master`, then set `auth_realm`), create a confidential OpenID Connect client with
   **Client authentication** and **Service accounts roles** on, and every other flow off.
2. On Keycloak 26.8.2 and later, add the built-in `kc-admin-api` client scope to the client as a **default** scope.
   Keycloak's admin API now requires its audience, and a new client doesn't get it, so without it every call returns 401.
   Don't request the scope in the token call instead: Keycloak 26.8.1 and earlier reject an unknown scope.
3. Give its service account the roles `view-realm`, `view-identity-providers` and `view-events`, and nothing else:
   - for a client in the realm being read, from that realm's `realm-management` client;
   - for a client in `master` (then set `auth_realm: master`), from the `<realm>-realm` client in `master`, such as
     `example-realm-realm`. These are Keycloak's realm-specific admin roles.
   No manage-* role is needed.
4. Set `KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM` (required), optionally `KEYCLOAK_AUTH_REALM`, and the
   `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET` secrets. The fetcher must run from a network that can reach the
   Keycloak admin endpoint.

| Fetcher | Evidence set | Shows |
| --- | --- | --- |
| `realm_security` | `EVD-KEYCLOAK-REALM-SECURITY` | Sessions, lockout, password policy, browser and recovery flows, required actions, federation, event logging |

Client secrets in identity provider configs and bind credentials in user federation configs are never written to
the evidence.
