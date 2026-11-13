# Discovery fetchers

A discovery fetcher answers one question about a platform: **what can these
credentials see?** It lists the groups, campaigns, accounts, projects or
whatever else the platform holds, records whether each kind of thing could be
read, and writes one document. Nothing is uploaded. The document is for the
person deciding which fetchers to run and how to configure them, and today they
answer that from memory or by clicking through the vendor's console.

Discovery is in beta, which is what the `_beta` suffix on each discovery
fetcher's name means: the document shape and the fetchers' coverage may still
change.

```bash
paramify run manifests/knowbe4-discovery.yaml   # → run-<ts>/discovery/knowbe4_discovery_beta.json
```

## Why it is a fetcher kind

Discovery could have been a separate engine with its own auth and dispatch. It
is a fetcher instead (`kind: discovery` in `fetcher.yaml`) because a fetcher
already gets everything enumeration needs:

- secrets resolved from any source, and the cloud credential chains;
- `targets[]` fanout, so discovering twenty AWS accounts is one manifest entry;
- the runner's timeout, subprocess isolation and `$FETCHER_STATUS_FILE`;
- `paramify doctor`, the TUI, and the contract tests.

The runner sends discovery output to `<run>/discovery/`. Neither uploader reads
that directory, which is the whole mechanism that keeps it out of Paramify. The
schema rejects `evidence_set`, `ksis` and `validators` on a discovery fetcher,
because each of them promises an upload or a claim that will never happen.

## The document

Every platform writes the same shape
([`discovery_schema.json`](../framework/schemas/discovery_schema.json)):

```json
{
  "schema_version": "0.1",
  "platform": "knowbe4",
  "identity": "Acme (Diamond)",
  "scope": { "region": "us" },
  "collected_at": "2026-10-07T23:25:56Z",
  "resources": [
    { "type": "group", "status": "ok", "count": 8, "truncated": false,
      "items": [{ "id": "1001", "name": "Engineering", "member_count": 24 }],
      "summary": { "by_status": { "active": 6, "archived": 2 } },
      "source": "GET /v1/groups" },
    { "type": "phishing_campaign", "status": "denied", "count": null, "items": null,
      "reason": "HTTP 403: Forbidden", "source": "GET /v1/phishing/campaigns" }
  ]
}
```

Four rules shape it.

**A type that could not be read is never an empty list.** `status` is `ok`,
`denied` (the credentials may not read it), `not_enabled` (the platform said the
feature is off or unlicensed) or `error` (anything else, throttling included).
`denied` and `error` are gaps: we could not tell. `not_enabled` is an answer,
not a gap: the platform said the feature is off, so there is nothing of that
type. A listing that failed partway is `truncated`, and its count is a
lower bound. "There are none" and "we could not
tell" are different answers, and later features that decide which fetchers apply
to a tenant depend on telling them apart.

**Items identify; they do not describe.** An item is an id, a name and a few
attributes. How something is configured is an evidence fetcher's job, and full
records would make the document large and the tenant data in it larger.

**People are counted, never listed.** Users, enrollments, admins: a resource
about people is `count_only` (`items: null`) with aggregate summaries such as a
count per status. The document says how many, never who.

**A type listed in several places has one entry per place.** AWS lists per
region; Azure lists per subscription. Each entry carries a `scope`
(`{"region": "us-east-2"}`) and its own status, so a type denied in one region
and readable in the rest says exactly that, instead of the whole type reading
as denied or the denied region quietly counting as zero. A type listed once (a
global service, a SaaS tenant) has no `scope`. Each (type, scope) pair appears
once. Totals across scopes count only the scopes that were read, and are a
lower bound when any were not.

Exit codes follow the fetcher contract. An `error` on any type exits 1 with
`partial_failure`, so a scheduled discovery that lost half its answers shows up
red. `denied` is an answer, not a failure, and exits 0. If the credentials
cannot establish identity at all (a key that cannot read its own account), the
run fails before writing anything.

## Reading the output

The document is JSON and is meant to be read as JSON for now: open it, or pipe it
through `jq`. A designed review page is planned; until it ships there is no
`paramify discovery` command.

## Writing one for a new platform

The loop is the same everywhere, so it lives once in
[`fetchers/_lib/discovery.py`](../fetchers/_lib/discovery.py): status mapping,
item projection, summaries, scoped entries, writing the document and choosing
the exit code, plus an `HttpClient` (pacing, 429 retries) for REST APIs. A
platform's `fetcher.py` is a table of `Resource`s plus one `pages` function
that makes the call however the platform needs it:

```python
RESOURCES = [
    Resource("user", "/v1/users", count_only=True, summary=by("status")),
    Resource("group", "/v1/groups",
             fields=["group_type", "status", "member_count"],
             summary=by("status", "group_type")),
    Resource("training_campaign", "/v1/training/campaigns",
             params={"exclude_percentages": "true"}, id="campaign_id",
             fields=["status", "start_date", "end_date"]),
]
```

Two references, deliberately unlike each other:

- [`fetchers/knowbe4/discovery_beta/fetcher.py`](../fetchers/knowbe4/discovery_beta/fetcher.py):
  a SaaS REST API. `HttpClient` plus cursor paging; one tenant, no scopes.
- [`fetchers/aws/discovery_beta/fetcher.py`](../fetchers/aws/discovery_beta/fetcher.py):
  a cloud driven through its CLI. `pages` shells out to `aws` (which pages
  itself) with a JMESPath query that flattens each record to `{id, name, ...}`;
  each `Resource` sets its own `source`; regional types are listed per region
  in parallel and passed to `enumerate_resource(..., scope={"region": r})`, and
  `write()` assembles the document.

For a platform with one call that returns many types (Azure Resource Graph),
make the call once, split the records by type, and give each `Resource` a
`pages` that yields its slice.

Choosing what to list:

- Use the platform's **collection endpoints** only. A per-id detail call adds
  nothing a list does not already return, and costs a request per record.
- Prefer an endpoint that **lists everything in one call** when the platform has
  one (Azure Resource Graph, GCP Cloud Asset Inventory).
- Name each `type` in singular `snake_case` and keep the name stable: later
  features refer to resources by it.
- Mark anything about people `count_only`.
- Raise `CallFailed("not_enabled", ...)` only when the platform actually says a
  feature is off. A guess belongs in `error`.

## KnowBe4 notes

- Every list endpoint pages by cursor: send `cursor=0` first, follow
  `pagination.nextCursor` until it is null. KnowBe4 retires the `page` parameter
  in November 2026.
- `/v1/training/campaigns` returns at most 10 per page unless
  `exclude_percentages=true` is set.
- The limits are four requests a second, a burst of 50 a minute, and about 2,000
  a day. A discovery run makes a few dozen calls.

## AWS notes

- Two layers. **Read directly:** about 75 types, in every enabled region, each
  (type, region) with its own status. The list is set by a rule, not by taste:
  every AWS service an AWS fetcher in this repo reads has at least one type, so
  discovery can always say whether a fetcher applies.
  `test_every_service_an_aws_fetcher_reads_is_discovered` fails when a new
  fetcher reads a service discovery does not cover. **Everything else:** AWS
  Resource Explorer, counted per resource type (it supports 600-odd) in each
  region with an index. A region without an index is `not_enabled` and the
  section says those regions were not searched. Resource Explorer returns at
  most 1,000 resources per search; a capped search is a lower bound.
- Driven through the `aws` CLI, not boto3: the same credential chain, target
  `profile`/`region` handling and `requires` as the other AWS fetchers, and
  nothing new to install. About 1,200 calls, 24 at a time; under a minute on a
  small account.
- A service AWS does not run in a region (CodeArtifact, MemoryDB and others are
  not everywhere) fails with the same "Could not connect to the endpoint URL" as
  a network failure. The fetcher then reads AWS's published availability
  (`/aws/service/global-infrastructure/services/<service>/regions`, a public SSM
  parameter): a region AWS does not list is `not_enabled` ("not offered in
  …"); a region it does list stays an `error`.
- Errors are classified with the same patterns as `fetchers/aws/_shared/aws.sh`:
  a service that was never turned on (`SubscriptionRequiredException`,
  `InvalidAccessException`, `AWSOrganizationsNotInUseException`, …) is
  `not_enabled`; `AccessDenied` and friends, including a service control
  policy's explicit deny, are `denied`; anything else is `error`.
- Each target writes `aws_discovery_beta_<profile|ambient>.json`, so a fanout across
  accounts produces one document per account.
- `regions` in config limits the regions listed; by default every region
  enabled for the account is.

## Not built yet

Discovery deliberately stops at "here is what exists". Each of these reads the
document rather than changing it:

- **Applicability:** which fetchers apply to this tenant, from which resource
  types are non-empty.
- **Config candidates:** offering a `config_schema` field the names it could
  take (the group and campaign titles KnowBe4's fetchers ask for, say), and
  optionally matching them against the field's description.
- **A proposed manifest** built from the above.
- **Drift:** re-running discovery and diffing it against the manifest in use
  ("three new RDS instances that no fetcher collects").
