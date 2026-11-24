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
3. Give its service account the roles `view-realm`, `view-identity-providers`, `view-events`, `view-users` and
   `view-clients`, and nothing else (each fetcher's instructions name the roles it uses):
   - for a client in `master`, from the `<realm>-realm` client in `master`, such as `example-realm-realm`. These are
     Keycloak's realm-specific admin roles. Set `auth_realm: master` when the realm being read is not `master`. To read
     `master` itself, use `master-realm`: `master` has no `realm-management` client. `users_and_roles` does not read
     `master`.
   - for a client in any other realm being read, from that realm's `realm-management` client.
   No manage-* role is needed.
4. Set `KEYCLOAK_BASE_URL`, `KEYCLOAK_REALM` (required), optionally `KEYCLOAK_AUTH_REALM`, and the
   `KEYCLOAK_CLIENT_ID` and `KEYCLOAK_CLIENT_SECRET` secrets. The fetcher must run from a network that can reach the
   Keycloak admin endpoint.

| Fetcher | Evidence set | Shows |
| --- | --- | --- |
| `realm_security` | `EVD-KEYCLOAK-REALM-SECURITY` | Sessions, lockout, password policy, browser and recovery flows, required actions, federation, event logging |
| `admin_events` | `EVD-KEYCLOAK-ADMIN-EVENTS` | Stored sign-in and admin events over a window: sign-ins, lockouts, user, role and client changes. Needs only `view-events` |
| `users_and_roles` | `EVD-KEYCLOAK-USERS-AND-ROLES` | Every user's state, authenticators, groups, effective roles and recent sign-ins; privileged users, missing second factors, inactive accounts |

Client secrets in identity provider configs and bind credentials in user federation configs are never written to
the evidence.
