# Evidence samples

A sample shows what one fetcher collects, without anyone running it. It is a
`sample.json` file beside the fetcher's `fetcher.yaml`, and it is committed.

Most payloads repeat one record: one entry per EC2 instance, per user, per
subnet. A sample keeps one of those records. It keeps the most filled-in
record, not the first one, and records how many there were and how often each
field had a value. The rest of the payload (summary blocks, single settings)
is kept unchanged.

```console
$ paramify samples show gcp_firewall_rules
gcp_firewall_rules  v0.1.0  live sample, captured 2026-08-17

results.firewall_rules[]  — 7 seen, 1 kept
  action                                   7/7
  allowed                                  6/7
  description                              4/7
  ...
payload:
{ ... }
```

## Commands

| Command | What it does |
|---|---|
| `paramify samples status` | Lists every evidence fetcher and whether it has a sample. UNREVIEWED means nobody has read the sample yet. OLD means it was captured from an earlier fetcher version. |
| `paramify samples show <fetcher>` | Shows the record counts, how often each field was filled in, and the record that was kept. |
| `paramify samples backfill` | Builds samples from past runs under `./evidence` (`--evidence DIR` to change it). Existing samples are kept unless you pass `--force`. |

## The sample file

```json
{
  "sample_schema_version": "1.0",
  "fetcher_name": "aws_sqs_encryption_status",
  "fetcher_version": "0.2.0",
  "source": "live",
  "captured_on": "2026-09-28",
  "reviewed": false,
  "collections": [
    {"path": "results.queues[]", "records": 3,
     "fields": {"name": 3, "url": 3, "encrypted": 3, "kms_master_key_id": 3}}
  ],
  "payload": { "...": "the payload, one record per collection" }
}
```

- `collections` lists every repeated collection: lists of records (`[]`) and
  dicts keyed by data rather than field names, such as `{email: status}` (`{}`).
  Nested counts cover every parent. `results.vaults[].keys[]` counts the keys
  of all vaults, not only the vault that was kept.
- `source` is `live` for a sample captured from a real run. `synthetic` is
  reserved for samples written by hand for fetchers that have no data to
  capture from.
- `fetcher_version` is the version that produced the sample. When it differs
  from the fetcher's current version, the fields may have changed since.

## How backfill picks and cleans a sample

For each fetcher, backfill looks at every past evidence file. It prefers files
that contain records, then files from the current fetcher version, then
successful runs, then the file that shows the most.

Then it replaces identifiers with stable fakes of the same shape. The same
real value always gets the same fake, so re-running backfill gives identical
files.

| What | Becomes |
|---|---|
| Emails | `user1@example.com` (a cloud provider's service account keeps its domain) |
| First, last and full names; `display_name` in a user record | `Person1` |
| Logins (`user_name`, `upn`, `login`, ...) | `user1`, or a fake email |
| 12-digit account ids | `111111111111` |
| UUIDs | `00000000-0000-4000-8000-000000000001` |
| Hex ids of 32 or more characters | zero-padded counters of the same length |
| IPv4 addresses | `10.0.0.n` for private, `203.0.113.n` for public; `0.0.0.0`, loopback and link-local are kept |
| Target and identity values (project, profile, tenant, domain, ...) | `example-project`, `example-profile`, ..., in any case |
| Credential-shaped keys (`*_secret`, `*_token`, `*password`) | `<redacted>` |
| `--scrub WORD` | `example`, in any case |

Identifiers are collected from **every** scanned file, not only the one a
sample comes from. An account id seen in one run is replaced in every other
fetcher's sample too. After cleaning, a leak check looks for every collected
identifier. If one survives (for example, a person's name inside a free-text
note), backfill does not write that sample. It reports the sample as blocked
and exits 1.

## Review before you commit

The rules cannot recognize free text. Descriptions, notes, hostnames and
resource names pass through unchanged. That is why every backfilled sample
starts with `"reviewed": false`. Read the sample, fix anything that should not
be public, and set `"reviewed": true`.

Samples from real tenants need the most care. A client's resource names or a
POA&M description can say more than any identifier does.

## Filling the gaps

`paramify samples status` lists the fetchers that still have no sample. There
are two reasons a fetcher has none:

- **It ran, but the test account has none of that resource.** Create one in a
  sandbox account, run the fetcher, and backfill again.
- **It has never run here.** Capture it the first time it runs for real, with
  `paramify samples backfill --fetcher <name>`.
