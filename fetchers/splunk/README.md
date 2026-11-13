# Splunk

Seven fetchers read a Splunk Enterprise deployment's management API (port
8089) with a bearer token. Each answers one question and writes one evidence
set. Every fetcher fans out per deployment: a target is one search head or
standalone instance with its own URL and token.

| Fetcher | Question it answers | Evidence set | KSIs |
|---|---|---|---|
| `splunk_index_retention` | How long is each log kept, and is it tamper-evident? | `EVD-SPLUNK-INDEX-RETENTION` | MLA-OSM |
| `splunk_index_activity` | Is every index still receiving data? | `EVD-SPLUNK-INDEX-ACTIVITY` | MLA-OSM |
| `splunk_log_source_freshness` | Are the hosts and forwarders that send logs still sending? | `EVD-SPLUNK-LOG-SOURCE-FRESHNESS` | MLA-OSM, MLA-LET |
| `splunk_data_inputs` | What is Splunk set up to collect, and what actually arrives? | `EVD-SPLUNK-DATA-INPUTS` | MLA-LET |
| `splunk_alert_rules` | What does Splunk alert on, who hears about it, and did it fire? | `EVD-SPLUNK-ALERT-RULES` | MLA-OSM, MLA-RVL |
| `splunk_alert_delivery` | When an alert fired, did the notification go out? | `EVD-SPLUNK-ALERT-DELIVERY` | MLA-RVL |
| `splunk_role_index_access` | Who can read, or delete, which logs? | `EVD-SPLUNK-ROLE-INDEX-ACCESS` | MLA-ALA |

Each writes `$EVIDENCE_DIR/<fetcher>_<target name>.json`. Start from
`examples/splunk_run.yaml`, which runs all seven against one target.

---

## Setting up access

### Token

Token authentication is off by default in Splunk Enterprise.

1. Sign in to Splunk Web as an admin.
2. Open **Settings → Tokens** and enable token authentication.
3. Create a collection user with the role below.
4. Create a token for that user (**Settings → Tokens → New Token**) with an expiry.
5. Store it in your secrets manager and reference it as the target's `token` secret.

### The collection role

Splunk filters lists by capability and reports the filtered count as the
total, so a token that lacks a capability gets a list that looks complete and
isn't. Every fetcher checks the token's capabilities before collecting and
fails, naming what is missing.

| Fetcher | Capabilities it checks | Index access it needs |
|---|---|---|
| `splunk_index_retention` | `search`, `rest_properties_get` | none beyond `search` |
| `splunk_index_activity` | `search`, `rest_properties_get` | every enabled index |
| `splunk_log_source_freshness` | `search`, `rest_properties_get` | every enabled index |
| `splunk_data_inputs` | `search`, `list_inputs`, `rest_properties_get` | every enabled index |
| `splunk_alert_rules` | `search`, `admin_all_objects` | `_audit`, `_internal` |
| `splunk_alert_delivery` | `search`, `rest_properties_get` | `_internal` |
| `splunk_role_index_access` | `search`, `list_all_roles`, `list_all_users`, `rest_properties_get` | `*` and `_*`, nothing disallowed |

What each kind of token saw on a Splunk Enterprise 10.4.3 instance with 4
users, 26 roles, 176 saved searches and 20 indexes. In every case Splunk
reported the filtered count as `paging.total`:

| Token | Users | Roles | Saved searches | Indexes |
|---|---|---|---|---|
| A role with no capabilities | 1 (itself) | 1 | 127 | 20 |
| Stock `admin` | 4 | 12 | 176 | 20 |
| The role below | 4 | 26 | 176 | 20 |

**Stock `admin` is not enough.** It holds `admin_all_objects`,
`rest_properties_get`, `list_inputs` and `search`, but not `list_all_roles`,
so it cannot see Splunk's 14 internal `_spl_*` roles. `splunk_role_index_access`
refuses it; the other six fetchers run with it. Give the collection user a
custom role, for example in `authorize.conf`:

```ini
[role_paramify_evidence]
importRoles = user
srchIndexesAllowed = *;_*
admin_all_objects = enabled
list_all_roles = enabled
list_all_users = enabled
list_inputs = enabled
rest_properties_get = enabled
```

`admin_all_objects` is the only way to see saved searches that only admin may
read, which includes every Monitoring Console alert on a stock install. It is
a broad grant, so limit the token with an expiry. The fetchers only send read
requests and searches.

Stock `admin` lists every user without `list_all_users`, so that requirement is
stricter than Splunk needs for an admin-derived role. It stays, because a
token without it and without admin rights sees only its own user.

### Targets and settings

| Target field | Env var | Required | Description |
|---|---|---|---|
| `name` | `SPLUNK_TARGET_NAME` | Yes | Label for the deployment; used in the evidence filename. |
| `base_url` | `SPLUNK_BASE_URL` | Yes | Management URL, e.g. `https://splunk.example.com:8089`. Port 8089, not the 8000 web UI. |
| `verify_ssl` | `SPLUNK_VERIFY_SSL` | No | Default `true`. Set `false` only for a self-signed test instance. |
| `ca_bundle` | `SPLUNK_CA_BUNDLE` | No | CA bundle for a certificate from a private CA. Overrides `verify_ssl`. |

The token is a per-target secret, `SPLUNK_TOKEN`. Every evidence file records
`metadata.tls_verified`.

| Setting | Env var | Default | Used by |
|---|---|---|---|
| `max_silence_minutes` | `SPLUNK_MAX_SILENCE_MINUTES` | 60 | index activity, log source freshness, data inputs |
| `forwarder_lookback_days` | `SPLUNK_FORWARDER_LOOKBACK_DAYS` | 30 | log source freshness |
| `lookback_days` | `SPLUNK_ALERT_LOOKBACK_DAYS` | 30 | alert rules |
| `lookback_days` | `SPLUNK_DELIVERY_LOOKBACK_DAYS` | 30 | alert delivery |
| `dormant_days` | `SPLUNK_DORMANT_DAYS` | 90 | role index access |

Every setting a fetcher used is recorded in its `metadata`. The lookbacks read
`_internal`, which keeps 30 days by default.

---

## How a fetcher is built

Every fetcher has the same shape. `index_retention/fetcher.py` is the whole
pattern in 63 lines:

```python
NAME = "splunk_index_retention"
CAPABILITIES = ["search", "rest_properties_get"]

def index_row(entry):                 # one Splunk entry -> one evidence row, field by field
    ...

def collect(client, config):
    entries = client.list_indexes()
    if entries is None:               # the call failed; the client already recorded why
        return None
    rows = [index_row(e) for e in sorted(entries, key=lambda e: e["name"])]
    return {"summary": summarize(rows), "indexes": rows}

if __name__ == "__main__":
    sys.exit(run(NAME, collect, CAPABILITIES))
```

`run()` in `_shared/splunk_client.py` does everything else. It reads the
target, checks capabilities, calls `collect`, writes the evidence file with a
standard `metadata` block, and reports failures to the runner. It also
catches an unexpected response, so a bad day still leaves evidence and a
reason.

The rules:

1. **One question, one fetcher, one evidence set.** If you're describing it
   with "and also", it's two fetchers.
2. **Go through the client.** `get`, `list`, `search` and `list_indexes`
   handle paging, namespaces, retries and Splunk's silent partial answers.
   Never call `requests` yourself.
3. **Prefer configuration endpoints to log searches.** Search `_internal` or
   `_audit` only when the answer exists nowhere else, and keep it to one
   readable query per question.
4. **Return None when a call you need failed.** The evidence then carries no
   records, so nothing can pass on half an answer. A completeness check that
   fails (`client.expect`, the index cross-checks) keeps the records and marks
   the evidence partial.
5. **Build every row field by field.** Never copy Splunk's `content` block. It
   carries password hashes and UI preferences.
6. **Report state, not verdicts.** Fields like `silent`, `stale` and `dormant`
   state facts against a recorded threshold. Pass or fail is the job of
   validators.
7. **Keep instructions to one paragraph, 80 words or fewer.** Put the detailed
   rules here in the README.

### Adding a fetcher

1. Copy `index_retention/` to `fetchers/splunk/<name>/`. Name it
   `splunk_<name>`, with evidence set `EVD-SPLUNK-<NAME>`.
2. Set `CAPABILITIES` to exactly what your endpoints need, and add a row to
   the role table above.
3. Write `index_row`-style row builders, `collect` and a summary.
4. In `fetcher.yaml`, keep the `target_schema` block as it is and add a
   `config_schema` entry for each `CONFIG` setting.
5. In `tests/test_splunk_fetchers.py`, add the fetcher to `FETCHERS` and its
   endpoints to `FakeSplunk`. The shape, complete-run and partial-data tests
   then cover it; add one test for its verdicts.
6. Run `pytest tests/test_splunk_fetchers.py`, `ruff check fetchers/splunk`,
   and `paramify list`, then a real run against a Splunk instance.

---

## What the client guards against

Splunk returns partial data without an error in several ways:

- **`count` defaults to 30.** `list()` reads with `count=0` and must match
  `paging.total`.
- **Knowledge objects are namespaced.** `services/saved/searches` returns
  only the caller's app; read `servicesNS/-/-/`.
- **`data/indexes` omits metric indexes** unless `datatype=all`.
  `list_indexes()` also requires the list to match `indexes.conf` and every
  index the search peers can search.
- **A denied search is empty results plus a WARN.** `search()` fails on any
  WARN or ERROR message.
- **Values mix renderings.** Under `output_mode=json` some fields are native
  booleans and numbers and others strings (`currentDBSizeMB` arrives as
  `"0"`, which is truthy). Read them with `as_bool` and `as_int`.

Transient failures (429, 5xx, a connection that did not open) are retried up
to four times with backoff. TLS failures are not.

## Advanced fetchers

`splunk_alert_delivery` and `splunk_data_inputs` do more than one thing each.
`alert_delivery` reads delivery outcomes from the wording of Splunk's
`sendemail` and `sendmodalert` log lines. `data_inputs` matches REST entries
to `inputs.conf` stanzas through Splunk's URL encoding. Both are proven only
on Splunk Enterprise 10.4.3, so don't copy them as a pattern. Simplify them
against a live instance first.

## Known limitations

- Proven on Splunk Enterprise 10.4.3 standalone only. Distributed deployments
  are untested.
- Splunk Cloud is not yet supported. Its REST API serves the search tier only,
  and officially only access control, knowledge objects, KV store, metrics,
  federated search and search. The index list, `indexes.conf` and data inputs
  that these fetchers read come from Splunk's Admin Config Service on Cloud
  instead.
- An alert that is running while `splunk_alert_delivery` collects can show up
  in `summary.attempts_unmatched`, because Splunk logs the delivery before it
  logs the scheduled run it belongs to. The next collection matches it.
- `splunk_index_activity` fails on a distributed deployment unless the search
  head defines the indexers' indexes.
- `splunk_data_inputs` sees only the queried instance's `inputs.conf`. Inputs
  on forwarders appear only as streams in `received[]`.
- Splunk records nothing after an alert is delivered and keeps no record of
  access reviews. None of this evidence shows that an alert was read or a
  grant was reviewed.
