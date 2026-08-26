# Splunk

Splunk fetchers read configuration from the Splunk **management** REST API and
write it as evidence. Four fetchers:

| Fetcher | Evidences | KSI |
|---|---|---|
| `splunk_indexes` | logs are centrally stored, retained, and cryptographically tamper-evident | MLA-01, SVC-05 |
| `splunk_saved_searches` | log review is scheduled and running | MLA-02 |
| `splunk_fired_alerts` | that review actually produced output | MLA-02 |
| `splunk_users_roles` | who is allowed to read the log data | IAM-05 |

They read in that order deliberately: the store, the review, the output of the
review, and the access control over all of it.

### The namespace rule, for anyone adding a fifth

`/services/<collection>` is scoped to the **caller's app context**.
`/servicesNS/-/-/<collection>` wildcards user and app. For **knowledge
objects** — saved searches, dashboards, lookups, macros, eventtypes, tags,
fired alerts — the difference is enormous: `/services/saved/searches` returned
**11 of 177** on a real instance, silently.

Measured, per collection, on Splunk 10.4.2:

| Collection | `/services/` | `/servicesNS/-/-/` |
|---|---:|---:|
| `saved/searches` | 11 | **177** |
| `data/indexes` | 46 | 46 |
| `authentication/users` | 2 | 2 |
| `authorization/roles` | 10 | 10 |
| `data/inputs/monitor` | 19 | 19 |

System configuration is unaffected; knowledge objects are not. Every fetcher
here uses `/servicesNS/-/-/` regardless, so the question never has to be asked
again.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SPLUNK_TOKEN` | Yes* | Splunk authentication token (a JWT). The credential to use. |
| `SPLUNK_USERNAME` | Yes* | Username, for the session-login fallback |
| `SPLUNK_PASSWORD` | Yes* | Password, for the session-login fallback |
| `SPLUNK_BASE_URL` | No | Management API base URL. Defaults to `https://localhost:8089`. |
| `SPLUNK_CA_BUNDLE` | No | CA bundle that signed the Splunk certificate |
| `SPLUNK_VERIFY_SSL` | No | Set `false` to skip TLS verification |
| `SPLUNK_HTTP_TIMEOUT` | No | Per-request timeout in seconds (default 30) |

\* Either `SPLUNK_TOKEN`, **or** both `SPLUNK_USERNAME` and `SPLUNK_PASSWORD`.
The token wins when both are set.

All three are declared as **optional secrets** (`required: false`), so a manifest
supplies whichever mechanism the deployment uses and the runner injects only
that. Prefer the token: it carries the creating user's roles, can be given an
expiry, and is revocable without changing anyone's password. The
username/password path exists because **token authentication is off by default**
in Splunk Enterprise, so a fresh install cannot use a token until someone enables
it.

## Port 8089, not 8000

The management API is a different listener from the web UI. `https://host:8000`
is the UI and will not answer these calls; the API is on **8089**.

On **Splunk Cloud** the management port is not open by default — it is a
separate hostname (`https://<stack>.splunkcloud.com:8089`) and Splunk support
has to enable access for your IP range. That request is worth making early; it
is not instant.

## Getting a token

Splunk Web → **Settings → Tokens → New Token**. Two things to know:

1. **Token authentication is off by default** in Splunk Enterprise. The same
   page has an *Enable Token Authentication* control, and until it is on, the
   token endpoint is not there. This is the single most likely reason a first
   attempt fails.
2. The token inherits the roles of the user it is created for. Create it for a
   user whose role has the capabilities below and nothing more — a token made
   for `admin` grants everything `admin` can do, including writes this fetcher
   will never make.

### Capabilities needed — none, and that was a surprise

**Measured against a real Splunk Enterprise 10.4.2.** An earlier version of this
file claimed `GET /services/data/indexes` needs `list_indexes` and
`/services/server/info` needs `list_settings`. Neither is true. A purpose-made
role holding none of those capabilities read **all 46 indexes** and the full
server info without complaint.

| Operation | Capability | Verified |
|---|---|---|
| `GET /services/data/indexes` | none beyond authentication | ✅ read with a bare custom role |
| `GET /services/server/info` | none beyond authentication | ✅ same |
| `GET /saved/searches` | none beyond authentication | ✅ same |
| `GET /authentication/users`, `/authorization/roles` | none beyond authentication | ✅ same |
| `GET /alerts/fired_alerts` | none beyond authentication | ✅ same |
| `POST /services/data/indexes` (write) | `indexes_edit` | ✅ 403 without it |
| `GET /services/data/inputs/*` | `list_inputs` | ✅ 403 without it |

So the least-privilege answer is simpler than expected: **a role with no
capabilities at all can produce this evidence.** Create one, assign it to the
token's user, and the token cannot do anything else. Do not hand this a token
made for `admin`.

The last two rows matter for the *next* fetchers — a data-inputs fetcher will
need `list_inputs`, so it hits this where the index one does not.

When a capability genuinely is missing, Splunk answers 403 with the capability
named in the body:

```json
{"messages": [{"type": "ERROR",
  "text": "You (user=evreader) do not have permission to perform this operation (requires capability: list_inputs)."}]}
```

That text is carried through into `api_failures`, so the evidence file tells you
which capability to grant rather than just that something went wrong. (This
wording was guessed when the client was written and turns out to be exact — the
capture is in `tests/fixtures/splunk_real_responses.json`.)

## TLS

Splunk ships a **self-signed** certificate on 8089. Point `SPLUNK_CA_BUNDLE` at
the CA that signed yours; `SPLUNK_VERIFY_SSL=false` is the escape hatch for a
lab or a trial instance.

Whichever way it resolves is recorded in the evidence as
`collection.tls_verified`. Running unverified is common and is not by itself a
finding — but an assessor reading the package should not have to guess whether
the collection authenticated the server it was talking to.

## Two things about this API that bite

**Value types are inconsistent, per field and per rendering.** Under
`output_mode=json` a live 10.4.2 sends:

| Field | Type on the wire |
|---|---|
| `disabled`, `enableDataIntegrityControl` | native JSON `true` / `false` |
| `totalEventCount`, `frozenTimePeriodInSecs`, `maxTotalDataSizeMB` | native `int` |
| `currentDBSizeMB` | **`"1"` — a string** |

The Atom rendering (the default, and what the SDK parses) makes every one of
them a string, which is why Splunk's own integration tests assert
`index["disabled"] == "0"`. In Python `"0"` is truthy, so reading these raw
reports every index disabled and every integrity control enabled — silently,
with `status: success` on top. Everything goes through `as_bool` / `as_int`,
which take both renderings and return `None` for anything unrecognized rather
than guessing.

*This file first claimed everything is a string, inferred from the SDK tests.
Half right. The coercion was correct; the reason was not, and "types vary by
field" is a better argument for coercing than the one it replaced.*

**`count` defaults to 30, not to "all".** Confirmed with 46 indexes present: a
bare request returned 30, `paging.perPage: 30`, `paging.total: 46`. The client
always sets one and pages with `offset` to an empty page — a short page is *not*
the last page. **On a fresh install with 13 indexes this bug is invisible**,
which is why it was worth creating 46 to test.

## What `splunk_indexes` evidences

CR26 **KSI-MLA-OSM** — *"A Security Information and Event Management (SIEM) or
similar system(s) is used and persistently reviewed for centralized,
tamper-resistant logging of events, activities, and changes."*

The index list is close to a restatement of it. The indexes are the centralized
store; `frozenTimePeriodInSecs` says for how long; and
`enableDataIntegrityControl` is the tamper-resistance the indicator names —
with it on, Splunk hashes each bucket's slices at roll time and writes an
`l_Hashes_<bucketID>.dat` beside the data, which `splunk check-integrity`
verifies later.

That last field also reaches **KSI-SVC-VRI** (*"use cryptographic methods to
validate the integrity of machine-based information resources"*), which the
CrowdStrike set could not evidence at all.

Also relevant: **KSI-MLA-RVL** (logs reviewed and audited) and **KSI-CMT-LMC**
(modifications logged and monitored), via `_audit` — Splunk's own audit trail,
which the analysis surfaces on its own rather than as one row of many.

`fetcher.yaml` declares the repo's **pre-CR26 numbered** equivalents
(`KSI-MLA-01`, `KSI-MLA-02`, `KSI-CMT-01`) to stay consistent with the other 137
fetchers. Nothing should be remapped to the CR26 mnemonics until the repo picks
one catalog.

**Not claimed:** that anyone reads the logs. This is the store's configuration,
not evidence of review — a saved-search or alerting fetcher would speak to that,
and it is a separate evidence set.

## Testing without a deployment

`tools/splunk_mock.py` is a stdlib stand-in implementing only the endpoints the
fetchers call. Its fixtures are deliberately awkward — string booleans, an index
that has never received an event, a disabled index that still holds data, and
one whose values are spelled in a way the fetcher does not recognize — so the
summary logic is exercised rather than just the happy path.

```fish
cd ~/code/paramify-fetchers
./.venv/bin/python tools/splunk_mock.py --port 8899   # in one shell
set -x SPLUNK_TOKEN mock-token
./.venv/bin/paramify run examples/splunk_mock_run.yaml
```

Fault injection, matching the CrowdStrike mock: `SPLUNK_MOCK_RATE_LIMIT=n`,
`SPLUNK_MOCK_FORBID=/path`, `SPLUNK_MOCK_MESSAGES=1`, `SPLUNK_MOCK_PAGE_SIZE=n`.
These are read by the mock, so set them in the shell running the *mock*, not in
the fetcher's environment.

### Kill the old mock before starting a new one

`python tools/splunk_mock.py --port 8899` **fails to bind if that port is
already taken, and the process already there keeps serving** — including an
older copy of this file from before your changes. The symptom is a 404 for a
route you just added, or a test asserting values you just corrected, which reads
exactly like a real bug. It cost an hour twice while this category was being
built.

```fish
# kill whatever is on the port first, then start
for pid in (ss -ltnpH | grep :8899 | grep -oP 'pid=\K[0-9]+')
    kill $pid
end
python tools/splunk_mock.py --port 8899
```

`pkill -f splunk_mock` is not a substitute — it matches its own shell wrapper
and kills that instead. The test suite is unaffected either way: it binds an
ephemeral port in-process, which is why this only bites manual runs.

## Validated against a real instance (2026-08-24)

**This has been run against a real Splunk Enterprise 10.4.2** — a local free
install — and `tests/fixtures/splunk_real_responses.json` is the sanitized
capture, replayed by four tests. The fetcher collected all 46 indexes and exited
0. What that changed:

- Every field name it reads exists on a real index record. ✅
- `count` really does default to 30, and the client really does page past it. ✅
- The 403 body and its "requires capability:" wording are exact. ✅
- **Value types are mixed, not all strings.** ❌ → premise corrected above.
- **`list_indexes` does not gate reading indexes.** ❌ → capability table corrected.
- A stock install has data integrity control **off on every index**, `_audit`
  included — so an empty `data_integrity_control_enabled` is the expected
  result on an untuned deployment, not a collection failure.

Still not observed on a real server: a populated `messages[]` on a 200. The
handling is defensive and stays that way.

### Reproducing it

Splunk Enterprise has a free download that runs locally on a trial licence:

```fish
# after installing and starting Splunk locally
set -x SPLUNK_BASE_URL https://localhost:8089
set -x SPLUNK_USERNAME admin
set -x SPLUNK_PASSWORD <the password you set at install>
set -x SPLUNK_VERIFY_SSL false        # stock cert is self-signed
./.venv/bin/python fetchers/splunk/indexes/fetcher.py
```

A fresh install has 13 indexes — `_audit`, `_internal`, `main`, `history`,
`summary`, `splunklogger` (disabled) and seven other internal ones. To exercise
the paging properly you need more than 30, which is a loop of
`POST /services/data/indexes`. To exercise the tamper-evidence claim at all you
need to create one with `enableDataIntegrityControl=1`, because nothing on a
stock install has it.
