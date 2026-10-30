# Sophos Central

These fetchers read endpoint protection data from the Sophos Central REST
APIs. All of them only read data.

| Fetcher | What it shows |
|---|---|
| [`sophos_endpoint_protection`](endpoint_protection/) | Per endpoint: services running, tamper protection, Intercept X installed, threat status |
| [`sophos_endpoint_check_in`](endpoint_check_in/) | Per endpoint: hours since the agent last communicated, and online status |
| [`sophos_agent_updates`](agent_updates/) | Per endpoint: days since the agent last updated, and protection package status |
| [`sophos_threat_protection_policies`](threat_protection_policies/) | Per policy: scheduled scan and on-access scanning settings |
| [`sophos_endpoint_inventory`](endpoint_inventory/) | Every endpoint, one inventory record each |

Each fetcher's README has its design card: the question it answers, what it
counts, and what it does not prove.

## What these fetchers cannot show

- **That a scan ran.** The Sophos Central API has no scan history and no
  last-scan time for an endpoint. `sophos_threat_protection_policies` shows
  that scans are configured.
- **Devices without the agent.** Sophos lists only devices that enrolled. To
  show that every in-scope host has the agent, compare the inventory with
  another inventory.

## Create the API credential

A web console login does not work. The fetchers need an API credential, and
only a Super Admin can make one.

1. In Sophos Central, go to **Global Settings > API Credentials Management**.
2. Select **Add Credential**.
3. Enter the name `paramify-fetchers`.
4. Select the role **Service Principal Read-Only**.
5. Copy the client ID and the client secret. Sophos shows the secret only once.

Record the expiry date. Sophos deletes an expired credential and does not
send a warning first. When a credential expires, the fetchers fail with
`auth_failed` and the error says that the credential may be expired.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SOPHOS_CLIENT_ID` | Yes, per target | Client ID of the API credential |
| `SOPHOS_CLIENT_SECRET` | Yes, per target | Client secret of the API credential |
| `SOPHOS_TENANT_ID` | Only for a partner or organization credential | The tenant to read |
| `SOPHOS_AUTH_URL`, `SOPHOS_GLOBAL_URL` | No | Override the Sophos hosts, for a test double only |

The fetchers find the tenant's data region from `whoami`, so you do not set a
region.

## Wire it into a manifest

Each target is one tenant, with its own credential:

```bash
paramify manifest add sophos_endpoint_protection
paramify manifest add-target sophos_endpoint_protection \
  --secret client_id=SOPHOS_CLIENT_ID --secret client_secret=SOPHOS_CLIENT_SECRET
```

For a partner or organization credential, also add `tenant_id=<tenant id>`
to the target. Do the same for each Sophos fetcher.

## Smoke test

```bash
TOKEN=$(curl -s https://id.sophos.com/api/v2/oauth2/token \
  -d grant_type=client_credentials -d scope=token \
  -d client_id="$SOPHOS_CLIENT_ID" -d client_secret="$SOPHOS_CLIENT_SECRET" | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" https://api.central.sophos.com/whoami/v1 | jq '{idType, apiHosts}'
```

`idType` must be `tenant`, `partner` or `organization`.

## Behaviour to know

- Every list call reads every page, and the fetcher compares the count it
  collected with the total that Sophos reports. If they differ, the run fails.
- If Sophos leaves out a fact, the fetcher writes `null`, names the fact in
  the item's `unread_facts`, and exits non-zero. It never writes `false` for a
  value it did not read.
- On HTTP 429 or 5xx, the client retries up to 5 times with exponential
  backoff. Sophos limits each credential to 100 calls a minute.
- No fetcher calls `GET /endpoints/{id}/tamper-protection`. That route
  returns tamper protection passwords.
