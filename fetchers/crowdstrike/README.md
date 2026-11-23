# CrowdStrike Falcon

CrowdStrike fetchers pull managed host inventory, Spotlight vulnerability
findings, detection alerts, prevention policy configuration, the Zero Trust
Assessment audit report, FileVantage file integrity changes, and host firewall
policies and rules from the Falcon OAuth2 REST API.

Two more fetchers feed Paramify pipelines.
[`crowdstrike_host_inventory`](host_inventory/README.md) lists every host for an
inventory pipeline.
[`crowdstrike_spotlight_vulnerability_report`](spotlight_vulnerability_report/README.md)
builds a CSV of every open Spotlight finding for a vulnerability assessment. Its
`Host ID` column equals the inventory's `unique_asset_identifier`, so Paramify
can link each finding to an Inventory item.

All nine fetchers share one API client and one pair of secrets.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `CROWDSTRIKE_CLIENT_ID` | Yes | Falcon API client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | Yes | Falcon API client secret |
| `CROWDSTRIKE_CLOUD_REGION` | No | `us-1` (default), `us-2`, `us-3`, `eu-1`, `us-gov-1`, `us-gov-2` |
| `CROWDSTRIKE_API_BASE_URL` | No | Full API base URL. Overrides the region. |

### Picking the right cloud

Falcon has a different API host per cloud and a token issued for one is not
valid on another. **FedRAMP workloads are normally on GovCloud (`us-gov-1`).**
If you are unsure, the Falcon console URL tells you: `falcon.crowdstrike.com`
is us-1, `falcon.us-2.crowdstrike.com` is us-2, `falcon.laggar.gcw.crowdstrike.com`
is us-gov-1.

| Region | API host |
|---|---|
| `us-1` | `https://api.crowdstrike.com` |
| `us-2` | `https://api.us-2.crowdstrike.com` |
| `us-3` | `https://api.us-3.crowdstrike.com` |
| `eu-1` | `https://api.eu-1.crowdstrike.com` |
| `us-gov-1` | `https://api.laggar.gcw.crowdstrike.com` |
| `us-gov-2` | `https://api.us-gov-2.crowdstrike.mil` |

Hosts are taken from gofalcon's `falcon/cloud.go`, CrowdStrike's own cloud table.
Note `us-gov-2` is `.mil`, not `.com`.

A wrong region shows up as a `401` on the token request, not as a DNS error —
every one of these hosts resolves.

Spelling is forgiving: `us-gov-1`, `usgov1`, `US_GOV_1` and the alias `gov1` all
resolve to the same host, matching what gofalcon accepts. This is deliberate —
the console, the docs and the SDKs each spell GovCloud differently, and the
failure mode of a rejected spelling (an error) is far safer than the
alternative (silently collecting from commercial while believing otherwise).

### Which cloud the evidence came from

Every evidence file carries a `cloud` block:

```json
"cloud": {
  "api_base_url": "https://api.laggar.gcw.crowdstrike.com",
  "cloud_region": "us-gov-1",
  "reported_cloud_region": "us-gov-1"
}
```

`cloud_region` is what the configuration resolved to. `reported_cloud_region` is
what the **tenant itself** said at authentication, from Falcon's `X-CS-Region`
response header — the only one of the two that is not simply a restatement of
the manifest. For a FedRAMP package the distinction matters: it is what lets an
assessor confirm the evidence came from GovCloud rather than the commercial
cloud. When the two disagree the run logs a warning and continues, because the
header is informational and should not fail a collection.

## Creating an API client

Falcon API credentials are OAuth2 client ID/secret pairs scoped per client, not
tied to a user account. Use a dedicated client for evidence collection.

1. Log in to the Falcon console.
2. Navigate to **Support and resources → API clients and keys**.
3. Click **Add new API client**.
4. Name it `paramify-evidence-fetchers` and add a description.
5. Grant **READ** on the scopes below — and nothing else. None of these
   fetchers write.
6. Click **Add**. **The client secret is shown exactly once** — copy it
   immediately into your secrets manager as `CROWDSTRIKE_CLIENT_SECRET`.

## Required scopes

Read-only on all of them. Grant only the scopes for the fetchers you run.

| Scope (READ) | Needed by |
|---|---|
| Hosts | `crowdstrike_hosts`, `crowdstrike_host_inventory` |
| Spotlight vulnerabilities | `crowdstrike_spotlight_vulnerabilities`, `crowdstrike_spotlight_vulnerability_report` |
| Alerts | `crowdstrike_detections` |
| Prevention policies | `crowdstrike_prevention_policies` |
| Zero Trust Assessment | `crowdstrike_zero_trust_assessment` |
| Falcon FileVantage | `crowdstrike_filevantage` |
| Firewall policies | `crowdstrike_firewall_policies` |
| Firewall management | `crowdstrike_firewall_policies` |

Derived from the service collection each endpoint belongs to in falconpy's
`_endpoint/*.py` (field 5 of every operation tuple), which is what the console's
scope names follow. `test_every_called_path_maps_to_a_known_scope` fails if a
fetcher ever reaches a path this table does not cover, so the guide cannot
silently drift from the code.

Scopes are set **when the client is created**; adding one later means editing the
client and, in some tenants, reissuing the secret. Grant all of them up front if
you expect to run all nine — a missing scope surfaces as a `403` at collection
time, which on a time-boxed trial tenant is an expensive way to find out.

`crowdstrike_firewall_policies` is the one fetcher that needs **two** scopes.
Falcon's policy API serves the policy list; everything that decides whether a
policy is actually enforced — `enforce`, `test_mode`, `default_inbound`,
`default_outbound` — is served by the separate firewall management API. A client
granted only "Firewall policies" reads the policies fine and `403`s on exactly
the fields the evidence turns on.

**Spotlight, Zero Trust Assessment and FileVantage are separately licensed Falcon
modules.**
A tenant without the license returns `403` even when the scope is granted. That
is recorded in `api_failures` and exits the fetcher non-zero — a missing module
is a real collection gap, not something to hide. Drop the fetcher from your
manifest if the tenant does not license it.

## Wiring into a manifest

```bash
paramify manifest add crowdstrike_hosts
paramify manifest set-secret crowdstrike_hosts client_id CROWDSTRIKE_CLIENT_ID
paramify manifest set-secret crowdstrike_hosts client_secret CROWDSTRIKE_CLIENT_SECRET
paramify manifest set-config crowdstrike_hosts cloud_region=us-gov-1
```

Repeat for each fetcher, or start from the worked example:
[`examples/crowdstrike_run.yaml`](../../examples/crowdstrike_run.yaml).

**Set the region or base URL as manifest `config`, not as a shell export.** The
runner passes only declared secrets and config to a fetcher and strips
everything else, so an exported `CROWDSTRIKE_API_BASE_URL` is silently dropped
and the fetcher falls back to the commercial `us-1` cloud.

## Smoke test

```bash
# 1. Get a token (note: the token endpoint is form-encoded, not JSON)
TOKEN=$(curl -s -X POST "https://api.crowdstrike.com/oauth2/token" \
  -d "client_id=$CROWDSTRIKE_CLIENT_ID&client_secret=$CROWDSTRIKE_CLIENT_SECRET" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

# 2. Use it
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.crowdstrike.com/devices/queries/devices-scroll/v1?limit=1" \
  | python3 -m json.tool
```

Swap the host for your cloud's. A `403` here with a `message` naming a scope
means the API client is missing that scope.

## Testing without a Falcon tenant

`tools/crowdstrike_mock.py` is a local stand-in for the Falcon API implementing
exactly the endpoints these fetchers call, with response shapes taken from
CrowdStrike's own SDK. It lets the full collect → envelope pipeline be
rehearsed offline:

```bash
python tools/crowdstrike_mock.py --port 8787
# in another shell:
export CROWDSTRIKE_CLIENT_ID=mock-id CROWDSTRIKE_CLIENT_SECRET=mock-secret
paramify run examples/crowdstrike_mock_run.yaml
```

The fixtures are deliberately awkward — a stale host, a sensor in reduced
functionality mode, a policy that is enabled but assigned to no host groups, a
detection-only anti-malware slider — so the summary logic is exercised rather
than just the happy path. Each of those cases caught a real bug.

The same double backs a test suite that needs no credentials, no network and no
running server (it binds an ephemeral port in-process):

```bash
pytest tests/test_crowdstrike_fetchers.py
```

It covers every fetcher end to end, both success and auth-failure paths, both
pagination styles, the summary arithmetic, and the cloud-region mapping.

### Checking field names against CrowdStrike's schema

A test double cannot catch a wrong field name, because it is written from the
same assumption as the fetcher — the two agree with each other and both
disagree with the API. So field names are checked against an independent
source: **gofalcon**, CrowdStrike's official Go SDK, whose model structs are
generated from the same OpenAPI specification that serves the API. Its
`json:"..."` tags are the real wire names.

```bash
python tools/crowdstrike_schema_check.py --refresh   # re-download models
pytest tests/test_crowdstrike_fetchers.py -k vendor_schema
```

`tools/crowdstrike_schema_snapshot.json` is a vendored snapshot of those field
names so CI stays offline. Refresh it when CrowdStrike ships API changes and
review the diff — a field disappearing is a real signal.

This caught a live bug: the Zero Trust Assessment audit endpoint returns a
**map of signal name to score**, not a list of findings with remediation flags.
The fetcher read the latter and produced an empty analysis over a perfectly
valid response — a silent all-clear, which is the worst way for a compliance
fetcher to fail.

### Running against real recorded responses

Stronger still: drive the fetchers over responses CrowdStrike actually
produced. Several organisations that ship CrowdStrike integrations commit real
captures as test data.

```bash
python tools/crowdstrike_corpus.py           # download (gitignored)
python tools/crowdstrike_corpus.py --list    # sources and their licences
pytest tests/test_crowdstrike_real_responses.py -v
```

The corpus is served through the mock's own HTTP layer, so the whole path runs
against real records — OAuth2, pagination, batched entity lookup, summary
maths, envelope. Without the corpus those tests **skip**, so CI stays offline.

Nothing is vendored: the captures stay under their own licences and this repo
carries only URLs.

Two more bugs came out of this, both in `detections` and both invisible against
synthetic fixtures:

- **Severity was discarded on most alerts.** Falcon populates `severity_name`
  on some alerts and only the numeric `severity` (0–100) on others — every EPP
  alert in the captures has `severity: 30` and no name. Bucketing on the label
  alone filed **64% of real alerts as "unknown"**. Now falls back to
  CrowdStrike's documented bands, and never overrides a label Falcon supplied.
- **One tactic counted as two.** Real data contains both `"Credential Access"`
  and `"CredentialAccess"`, so a raw counter reported two tactics at half the
  count each. Bucketing is now punctuation- and case-insensitive, keeping the
  most readable spelling as the label.

Coverage is honest rather than uniform: hosts, Spotlight and detections have
real captures. **Prevention policies and ZTA have none publicly available**, so
they run on fixtures shaped from CrowdStrike's schema and are the two most
worth checking against a live tenant.

### Structural conformance — the check that reaches all five

CrowdStrike's OpenAPI spec is not publicly downloadable (403 without a console
session), but **gofalcon** is generated from it and is public. Its model structs
carry types, enum values and nested structure, not just names:

    // Enum: [Windows Mac Linux]
    PlatformName *string `json:"platform_name"`

`tools/crowdstrike_schema.py` extracts that into `crowdstrike_models.json` (48
models, committed) and validates records against it. Every fixture the test
double serves must be a structurally legal instance of the model CrowdStrike
says that endpoint returns.

```bash
python tools/crowdstrike_schema.py --refresh    # re-extract from gofalcon
python tools/crowdstrike_schema.py --validate   # check the fixtures
```

This is the only check that reaches **prevention policies and ZTA**, which have
no recorded responses anywhere public. It is weaker than real data and much
stronger than a hand-written fixture, which only proves the fixture agrees with
the fetcher written beside it.

**`required` is deliberately not enforced, and that is measured rather than
assumed.** Validating *real* recorded responses against this same schema
produces **626 "required field missing" complaints across 25 real alerts, with
zero type and zero enum errors**. CrowdStrike's spec marks fields required that
real responses routinely omit, so enforcing it would reject genuine Falcon
output. Types and enums, measured the same way, are accurate.
`test_required_flags_are_unreliable_and_we_know_it` pins that finding and will
fail if CrowdStrike ever tightens the API to match the spec.

### Error paths

Retry, rate limiting, unlicensed modules, cursor stalls and token renewal were
all written and none had ever executed — a happy-path double never rate-limits
or revokes a token. `tests/test_crowdstrike_resilience.py` drives each one via
fault injection in the mock:

| Switch | Simulates |
|---|---|
| `CROWDSTRIKE_MOCK_RATE_LIMIT=n` | first *n* calls per path return 429 |
| `CROWDSTRIKE_MOCK_FORBID=/path` | 403 — an unlicensed Spotlight/ZTA module |
| `CROWDSTRIKE_MOCK_ENDLESS=1` | a pagination cursor that never terminates |
| `CROWDSTRIKE_MOCK_PARTIAL_ERRORS=1` | HTTP 200 carrying a populated `errors[]` |

Two bugs came out of it, both of which presented as success:

- **A 200 with `errors[]` was read as a complete result.** Falcon reports
  *partial* results that way, and `raise_for_status()` sees nothing wrong.
- **A repeated pagination cursor returned silently**, making a stalled cursor
  indistinguishable from reaching the end of the data. Normal and anomalous
  termination are now separate paths; the latter records
  `PaginationCursorStalled` and exits non-zero.

### Requests, not just responses

Everything above checks what comes *back*. `tests/test_crowdstrike_requests.py`
checks what goes *out*, because Falcon's handling of a bad request is mostly
silent: an unknown query parameter is **ignored**, so `limit` typo'd means the
default page size and a wrong filter key means no filtering at all.

A recording proxy captures every request each fetcher makes, and each is checked
against gofalcon's `*_parameters.go`: the query parameter names the endpoint
accepts, the documented `limit` range, and — where the docs enumerate them
completely — the legal FQL filter fields.

That last one revises an earlier claim in this file. FQL filters are typed as a
bare string in the SDK, so they had been written off as unverifiable without a
tenant. The *field names* are documented and checkable offline; only the syntax
still is not.

Page sizes matter more than they look: the caps differ per endpoint (10000 for
the device scroll, 5000 for Spotlight, but **1000** for the Zero Trust query),
while each paginator carries one default shared across every endpoint of its
style. Raising a default to suit one endpoint can put another over its cap.

### Pagination at scale

`tests/test_crowdstrike_pagination.py` drives thousands of records through each
paginator and asserts the collection is exact — every record, once, in order —
at sizes chosen either side of a page boundary, plus batch remainders and
duplicate IDs across a boundary.

It also pins one accepted limitation: **offset pagination trusts `total`**, so
an understated total truncates the collection at the next page boundary and
reports success. Ignoring `total` costs an extra request per collection; whether
Falcon's `total` is ever low in practice is a live-tenant question.

## Verification status, precisely

| | hosts | spotlight | detections | prevention | ZTA |
|---|---|---|---|---|---|
| Endpoint path + verb vs SDK | ✅ | ✅ | ✅ | ✅ | ✅ |
| Field names vs vendor schema | ✅ | ✅ | ✅ | ✅ | ✅ |
| Types, enums, nested structure | ✅ | ✅ | ✅ | ✅ | ✅ |
| Query parameters vs SDK | ✅ | ✅ | ✅ | ✅ | ✅ |
| Page size within documented cap | ✅ | ✅ | ✅ | ✅ | ✅ |
| FQL filter fields vs docs | n/a | ✅ | ✗² | n/a | ✗² |
| Parsed real recorded records | ✅ | ✅ | ✅ | ✗ | ✗ |
| Retry / 403 / cursor stall / renewal | ✅ | ✅ | ✅ | ✅ | ✅ |
| Real API envelope shape | ✅¹ | ✅¹ | ✅¹ | ✅¹ | ✅¹ |
| Pagination exact at scale | ✅³ | ✅³ | ✅³ | ✅³ | ✅³ |
| Pagination against real server behaviour | ✗ | ✗ | ✗ | ✗ | ✗ |
| Live tenant | ✗ | ✗ | ✗ | ✗ | ✗ |

¹ Validated against `MsaMetaInfo` / the paging models, not observed. The
recorded captures are individual records, already unwrapped from the envelope,
so no real `resources`/`meta` body was available to check against.

² The docs enumerate the legal filter fields for Spotlight only. Alerts calls
its own set "extensive" and names examples, and the Zero Trust filter is
documented in one line, so both lists are marked incomplete and skipped —
asserting against a partial list would fail correct filters.

³ Against this repo's server double, not CrowdStrike's. What is proven is that
the *client* collects exactly, at scale, across boundaries; whether the server
paginates as documented is the row below.

Two limits worth stating plainly rather than leaving implied:

- **The captures are records, not responses.** They are the input to Elastic's
  ingest pipeline — already unwrapped from the API envelope. So `resources[]`,
  `meta.pagination` and cursor behavior are exercised only against this repo's
  own mock, not against anything CrowdStrike produced.
- **Sample sizes are small** (4 hosts, 8 findings, 25 alerts) and cannot cover
  the full range of enum values or edge states a real estate contains.

Still needing a live tenant: whether the server paginates as documented,
FQL *syntax* acceptance, rate-limit thresholds, GovCloud differences, and what
an unlicensed Spotlight/ZTA module actually returns.

### The `next` vs `after` cursor

Worth knowing before touching `paginate_after`. The cursor is **sent** as
`after` on every endpoint, but comes back under different names:

| Endpoint | Response model | Cursor field |
|---|---|---|
| Spotlight combined | `DomainAPIQueryPagingV1` | `after` |
| Zero Trust queries | `DomainSearchAfterPaging` | **`next`** |

Reading only `after` meant the Zero Trust host query found no cursor, stopped
after one page and reported success — a collection capped at 400 hosts that
looks exactly like a small estate. The client now reads the first string cursor
among `after`, `next`, `offset`, and `offset` is accepted only as a *string*
because the integer-offset endpoints reuse that name for a number.

`DomainSearchAfterPaging` carries both `next` and `offset` and the spec does not
say which is the token to echo back; `next` is taken as the more conventional.
**If Zero Trust host collection ever comes back capped at exactly one page,
check this first.**

## Rotating credentials

1. **Support and resources → API clients and keys**.
2. Select `paramify-evidence-fetchers` → **Edit** → **Reset secret**.
3. Copy the new secret immediately and update `CROWDSTRIKE_CLIENT_SECRET`.
4. Re-run the smoke test.

Resetting the secret invalidates the old one straight away, so rotate during a
window where a failed collection is acceptable.

## Notes

- Falcon bearer tokens last ~30 minutes. The shared client renews automatically
  a minute before expiry, so long collections do not need special handling.
- Falcon rate-limits per API client. All fetchers page with the API's own
  limits and batch entity lookups at 100 IDs per request.
- Alerts are keyed by **composite ID** (`<cid>:ind:<id>`), not the plain
  resource ID used elsewhere in Falcon. The detections fetcher handles this;
  it matters if you hand-craft a filter.
- `crowdstrike_detections` uses the Alerts API (`/alerts/*`), which supersedes
  the legacy `/detects/*` endpoints.
