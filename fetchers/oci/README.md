# Oracle Cloud Infrastructure

Seventeen evidence fetchers over one OCI tenancy. Each resolves credentials, walks
the compartment tree beneath a chosen root, collects one evidence set, and writes
a JSON file to `$EVIDENCE_DIR`.

| Fetcher | What it answers | KSIs |
|---|---|---|
| `oci_audit_logging_events` | Audit retention, log inventory, which change categories are monitored — and which actually notify a person | MLA-LET, MLA-OSM |
| `oci_bastion_sessions` | Whether administrative access is genuinely just-in-time: session TTL, CIDR allow-list, static jump hosts | IAM-JIT, IAM-ELP |
| `oci_block_volume_encryption` | Whose key encrypts each volume and its backups, and whether the wire is encrypted | SVC-SIN |
| `oci_certificates` | Certificate validity and whether renewal is automated | SVC-VCM, SVC-SIN |
| `oci_cloud_guard_posture` | Whether the tenancy continuously assesses itself, and enforces | CNA-EIS, MLA-EVC |
| `oci_compute_instances` | Instance hardening, boot integrity, and what is reachable from outside | CNA-MAT, SVC-VRI, SVC-SIN |
| `oci_data_service_exposure` | Databases, file systems and integration instances: who can reach the data, whose key encrypts it | SVC-SIN, CNA-MAT, CNA-RNT |
| `oci_dependency_vulnerabilities` | Application Dependency Management audits, and whether findings were fixed or suppressed | SCR-MIT, SCR-MON |
| `oci_dr_plan_executions` | Recovery drills as first-class records, with outcome and measured duration | RPL-TRC, RPL-ABO |
| `oci_iam_password_policy` | Every identity domain's password rules against the CIS thresholds | IAM-APM |
| `oci_iam_policies` | Every policy statement parsed; broad and unguarded grants counted | IAM-ELP, IAM-SNU |
| `oci_iam_users_credentials` | MFA, tenancy administrators, and every standing credential with its age | IAM-APM, IAM-SNU, IAM-ELP |
| `oci_network_exposure` | What the rules allow, and whether anything can actually reach it | CNA-RNT, CNA-MAT, MLA-LET |
| `oci_object_storage_buckets` | Bucket access including pre-authenticated requests, keys, and data logging | SVC-SIN, IAM-ELP, MLA-LET |
| `oci_operator_access_control` | Whether Oracle's own staff need approval to reach Exadata infrastructure, and which requests were let through without a person | IAM-JIT, SCR-MIT |
| `oci_vault_keys` | How each key is held and whether it is actually rotated | SVC-ASM, SVC-SIN |
| `oci_zpr_policies` | Zero Trust Packet Routing: network intent as policy, and how loose it is | CNA-ULN, CNA-RNT |

## Collect with a dedicated read-only user, not the tenancy administrator

This matters more here than it looks. `oci_iam_users_credentials` reports which
tenancy administrators hold API signing keys, and Cloud Guard raises
`USER_HAS_API_KEYS` for the same thing. If you collect as an administrator, the
key these fetchers authenticate with **is itself a finding in the evidence they
produce**. It is also more privilege than they need: every call is a read.

```
# Strictly read-only. Verified: all seventeen collect what a tenancy administrator
# collects, except the audit retention period (see below).
Allow group EvidenceCollectors to inspect all-resources in tenancy
Allow group EvidenceCollectors to read all-resources in tenancy where all {request.permission != 'OBJECT_READ', request.permission != 'SECRET_BUNDLE_READ'}
```

and set `skip_audit_retention: true` (`OCI_SKIP_AUDIT_RETENTION`) on
`oci_audit_logging_events`. To collect retention as well, add

```
Allow group EvidenceCollectors to {AUDIT_CONFIGURATION} in tenancy
```

knowing what it grants — see below.

**Why the `where` clause.** Plain `read all-resources` includes `read objects`
(`GetObject`) and `read secret-bundles` (the secret contents). Tested live: a
collector on the unconditioned statement downloaded an object and read a vault
secret. No fetcher calls either, and with the clause both are denied while every
fetcher's evidence is unchanged.

**`{AUDIT_CONFIGURATION}` is NOT read-only — tested.** The audit retention
period is tenancy-level and no verb on any resource type grants reading it —
`all-resources`, `inspect tenancies` and `read audit-events` each still 404.
Only the named permission does, and the same permission lets the holder
*change* retention: the collector's `UpdateConfiguration` returned 202 (tested
with the value it already had). Scoping it with `where request.operation =
'GetConfiguration'` does not work — Audit then denies the read as well. So a
collector that can report retention can also shorten it to 90 days and lose the
rest of the audit history. Grant it only if that trade is acceptable. Without
it, set `skip_audit_retention`: the call is recorded in
`metadata.skipped_calls`, retention is reported as null with
`audit_retention_skipped_by_configuration: true`, and the run succeeds. Without
the grant AND without the setting, the denied call fails the run, which is what
a missing grant should do.

`read` is needed over `inspect` because several fetchers read resource detail,
not just names — Bastion TTLs, Cloud Guard recipe rules, key rotation settings,
bucket access types. No service-specific `read cloud-guard-family`, `vaults` or
`keys` statement is needed; `all-resources` covers them (verified by removing
them). A missing grant is a 404, not a 403 — see "OCI answers 404 for no
permission" below.

## Authentication — four paths

`_shared/oci_common.load_config()` resolves, in order:

1. **API signing key from the environment.** The deployed path. All five of
   `OCI_TENANCY_OCID`, `OCI_USER_OCID`, `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY`
   and `OCI_REGION` must be set; a partially-set environment falls through to
   the config file and would collect from the wrong tenancy while looking like
   it worked, so it is refused instead.
2. **Instance principal** — a compute instance's own identity. Select with
   `OCI_CLI_AUTH=instance_principal`.
3. **Resource principal** — Functions or OKE workload identity. Selected
   automatically by the presence of `OCI_RESOURCE_PRINCIPAL_VERSION`.
4. **`~/.oci/config`** — local development. `OCI_CONFIG_FILE` relocates it.

`OCI_PRIVATE_KEY` carries the PEM **content**, not a path. That works because
the SDK accepts `key_content` in a config *dict* and explicitly refuses the same
key in a config *file* (`config.CONFIG_FILE_BLACKLISTED_KEYS`), so the runner can
inject the key as a secret with nothing touching disk — and a secret can never be
smuggled in through a file.

### Trap: `OCI_CLI_PROFILE` is read by the CLI and never by the SDK

`oci.config.from_file()` defaults to the literal `DEFAULT` profile and takes the
profile as an argument. Setting the environment variable and expecting the SDK to
honour it silently collects from the wrong profile. `oci_common` reads it
explicitly, so the documented spelling works here.

Verified from the SDK source rather than the docs: the SDK's own variables are
`OCI_CONFIG_FILE`, `OCI_REGION` and the `OCI_RESOURCE_PRINCIPAL_*` family. Every
`OCI_CLI_*` name in Oracle's documentation is CLI-only.

## Configuration

Every fetcher takes these, all optional:

| Variable | Default | Meaning |
|---|---|---|
| `OCI_COMPARTMENT_ID` | tenancy root | Collect from this compartment. Set one target per compartment to fan out. |
| `OCI_INCLUDE_SUBCOMPARTMENTS` | `true` | Walk compartments beneath the root. Off collects the named compartment only. |
| `OCI_ENVIRONMENT` | unset | A label (`prod`, `preprod`) written into the evidence metadata. |
| `OCI_REGION` (target `region`) | the credential's region | Region to collect from. Not on the three IAM fetchers, which are tenancy-wide. |

**One region per run.** Every list call outside IAM answers for a single
region, so a tenancy subscribed to several needs one target per region — the
same shape as the AWS fetchers' `region`. Each evidence file says what it did
not cover: `metadata.regions_subscribed` and `metadata.regions_not_collected`,
so "no public buckets" is never read as more than "none in this region".

Four fetchers are tenancy-scoped whatever compartment a target names, because
the resources are: `oci_iam_users_credentials`, `oci_iam_password_policy`, and
the audit and ZPR configuration halves of their fetchers.

## Traps worth knowing before you debug one

**OCI answers 404 for no permission.** A missing policy statement and a missing
resource look identical, so an unexpected 404 is usually a policy gap. The
failure lands in `metadata.api_failures` with the operation named.

**Subtree compartment listing only works from the tenancy root.**
`compartment_id_in_subtree=True` is a 400 from any child compartment
(`compartmentId must be tenancy ocid`). `walk_compartments()` uses the one-call
subtree listing from the root and walks breadth-first by hand below it, so a
target scoped to a child compartment still collects.

**IAM is eventually consistent, and slow.** A just-created compartment 404s from
other services for roughly a minute. A fetcher pointed at a brand-new
compartment records that as a collection failure, which is correct but
surprising.

**A resource and the things it depends on can sit in different compartments.**
A subnet, its route table, the gateway that route targets, its security lists
and the log group holding its flow log may each live in a different compartment,
and landing zones put logs in a separate security compartment on purpose. The
fetchers gather across the whole walked scope before joining, so this is handled
inside one target. Across targets it is not: a fanout target scoped to an
application compartment cannot see a log group in a logging compartment, and
will report that subnet's flow log, or that bucket's access log, as absent. Point
a target at a common parent for `oci_network_exposure` and
`oci_object_storage_buckets`.

**The IAM API sees one identity domain.** `identity.list_users` answers for
the Default domain only; a user in any other domain is simply absent, with the
run exiting 0. `oci_iam_users_credentials` walks every domain and reads the
others through their SCIM endpoints (verified against a second, staged domain).
One SCIM trap: `attributes=` *replaces* the default attribute set rather than
adding to it, so asking for `groups` that way returns users without `active`.
Missing state reads as UNKNOWN and is counted in `users_with_unknown_state`,
never as inactive.

**One failing call can fail its neighbours.** The SDK's default circuit breaker
opens after ten failures on a client — one call exhausting its retries on a 500
is enough — and for 30 seconds every call on that client fails at once with
`CircuitBreakerError`, the original status inside its message. The run exits 1
either way; expect several failures in the ledger where one call was the cause.
It stays on: without it, an outage retries each call for up to ten minutes.

**Summary and detail disagree about which fields exist, in both directions.**
Bastion's TTL and allow-list are only on `get_bastion`; a certificate's whole
validity window is only on the *list* summary and absent from `get_certificate`.
Both are pinned in `tests/test_oci_model_shapes.py`, which asserts facts about
Oracle's models rather than about this code.

## Testing without a tenancy

`tests/test_oci_fetchers.py` runs all seventeen as subprocesses against recorded
HTTP responses — no credentials, no network, about 11 seconds. Recording happens
at the HTTP layer and replays through the real SDK, so deserialization, enum
validation, pagination and the SDK's error classes all still run.

```
python tools/oci_capture.py                # re-record every cassette (needs a tenancy)
python tools/oci_capture.py vault_keys     # or just one
pytest tests/test_oci_fetchers.py tests/test_oci_cross_check.py
```

Re-record after changing which calls a fetcher makes: an unmatched request
raises rather than returning an empty body, so drift fails the suite instead of
quietly collecting nothing.

`tools/oci_fault_sweep.py` replays every recorded call once as each of a 401,
404, 429, 500 and a connect timeout — about 1,800 runs, two minutes on twelve
cores — and fails if any run exits 0 without recording the call, or tolerates
one that is evidence rather than context. Run it after changing how a fetcher
handles errors.

`tests/test_oci_pagination.py` replays every cassette a second time with each
multi-item list re-served one item per page (`opc-next-page` for OCI's APIs,
`startIndex` for SCIM) and requires identical evidence. The trial tenancy's
lists nearly all fit on one page, so without it a call that read only the first
page would pass everything else and truncate a real estate.

`tests/test_oci_missing_fields.py` covers the other half: a field Oracle's models
mark optional, left out of a real recorded response, must never make the
evidence read better — a missing console-capability block must not drop a user
from the MFA finding, and a missing `isEnabled` must not hide an internet
gateway's SSH exposure. Missing reads as Oracle's default when that is the
conservative answer, and is otherwise counted as unknown beside the finding.
The cases were found by nulling every field of every cassette in turn.

Note for anyone reaching for an HTTP mocking library: **the SDK vendors its own
copy of requests** at `oci._vendor.requests`, so `responses`, `requests-mock` and
`vcrpy` all patch a module the SDK never calls.

### Checking field names against Oracle's own models

`tools/oci_schema_check.py` AST-walks each record function for `.get("field")`
and checks the name against the `swagger_types` of the SDK model that function
normalizes, then flags any nested object read in a boolean context. The `oci`
package is already a declared dependency, so there is nothing to download and no
snapshot to drift.

```
python tools/oci_schema_check.py    # exits non-zero on a finding
```

A companion test fails if a record function is not registered, so the check
cannot pass by having nothing left to check.

### Cross-checking against Oracle's own detector

`tests/test_oci_cross_check.py` asserts that what these fetchers report agrees,
name for name, with the problems Cloud Guard raised on the same tenancy — the
public bucket, the user without MFA, the administrator's API keys, the weak
password policy, the unattached volume, the VNIC with no NSG, the internet
gateway. Activity problems like INTERNET_GATEWAY_CREATED name the user who
acted, not the resource, so those are checked by direction rather than name,
and the recording replaces that person's name. No other category
in this repo has an independent detector to check itself against.

## Verification status, precisely

**Verified against a live tenancy** (Always Free, us-phoenix-1): all seventeen run
green — zero API failures, zero partial failures — scoped to the tenancy root
and to a child compartment, deterministic across runs, and exiting non-zero with
`code=auth_failed` on bad credentials. Every judgement has a mutation proven to
fail its test. All nineteen claimed KSI IDs exist in the live FedRAMP catalog.

**Verified as a restricted user**: all seventeen run under the two-statement
policy above with evidence identical to an administrator's apart from the
deliberately skipped retention period; object and secret contents denied. With
`{AUDIT_CONFIGURATION}` added, identical outright.

**Not verified**: scale, and multi-region. A trial tenancy has one region and a
handful of resources. Pagination is exercised on every list call by re-paging
the recorded responses, not against thousands of real records. Full Stack DR
pairs protection groups across two regions and the trial tenancy has one, so
`oci_dr_plan_executions` is verified against Oracle's models and empty
responses only, as its module docstring says. The same holds for
`oci_operator_access_control`: Operator and Delegate Access Control govern
Exadata resources, which no trial tenancy can create, so its request shapes are
live-verified and its record fields are checked against the SDK models.

Application Dependency Management IS verified live, against three real Maven
audits (Log4Shell, Text4Shell, a vulnerable jackson-databind): one plain, one
with an exclusion that hides a finding but not the headline, and one whose CVSS
ceiling lowers the headline from CRITICAL to MEDIUM. Note that Oracle's
`is_success` means "passed the team's own thresholds", not "the scan ran":
completion is read from the audit's lifecycle state, and the threshold result
is reported separately.
