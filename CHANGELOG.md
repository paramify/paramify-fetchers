# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) applied
to the contract (see [`docs/versioning.md`](docs/versioning.md)). "The contract"
is the public API surface — the `fetcher.yaml` / category / manifest / envelope
schemas and the `paramify` CLI — not the internal code.

## [Unreleased]

### Added

- **A central `validators/` registry.** A validator is now a first-class,
  deduplicated object — one file at `validators/<category>/<key>.yaml`, checked
  against the new `framework/schemas/validator_schema.json`. It carries the
  Paramify fields as native YAML and owns its side of the fetcher link through an
  `evidence_sets` list of `reference_id`s, so a validator that applies to four
  fetchers is one file naming four sets rather than four copies drifting apart.
  A fetcher's validators are the reverse lookup on its `evidence_set.reference_id`.
  See [`docs/validators_design.md`](docs/validators_design.md).
- **Validator sync** — `paramify validators sync` and `paramify upload
  --with-validators` (engine in `uploaders/paramify_validators/`). Pushes registry
  validators to Paramify (`POST /validators`) and CONNECTs each to its evidence
  sets. The validators shipped here are templates that customers tune in their own
  instance, so the sync is **create-or-skip**: an existing validator is never
  modified unless `--update` is passed, association happens on create only, and
  `--dry-run` previews without writing. The per-instance Paramify id is resolved
  at sync time and cached in a gitignored `.paramify/` lock — never written back
  to the shared registry.

### Changed

- **Validator authoring: guards are written positively, and collection health is
  its own validator.** `validationRules[].disposition` is accepted and then
  discarded by the REST API, so a rule authored in the negative `ERROR` form
  degrades into a contradictory pass-requirement and the validator can never
  pass — measured returning FAIL on every input, including compliant evidence.
  Collection health now lives once in `validators/common/collection_succeeded.yaml`
  (listing every evidence set that wants it) with plain PASS rules; compliance
  validators no longer carry an `exit_code` anchor, so their capture groups start
  at 1. Migration when the API honours `disposition` is an inversion of two rules
  in that single file.
- **Every validator opens with a presence rule, and count-based validators get an
  `integrity` partner.** A `MATCH_GROUP` comparison over a regex that did not
  match evaluates true, and a count-of-violations rule reads a renamed upstream
  key as zero violations — both silent false passes. `role` gains a third value,
  `integrity`, for the validator that proves the counted field was present.
  `validators/aws/alb_encryption_in_transit.yaml` is reshaped accordingly; in its
  previous form it returned PASS on drifted evidence where 1 of 4 load balancers
  was encrypted.
- The `suggest-validator` skill now authors validators into `validators/` rather
  than only proposing a regex, and verifies them against compliant,
  non-compliant, and **unreadable** evidence.

### Deprecated

- The inline `validators` block on `fetcher.yaml`. Nothing in the framework reads
  it and only `gitlab/significant_change_notifications` still carries one; it stays
  in the schema, marked deprecated, so that fetcher's data remains shape-checked
  until it migrates to the registry. New validators belong in `validators/`.

## [0.5.1-beta] - 2026-09-02

### Fixed

- **An AWS failure now says *why*, not just which call broke.** 0.5.0-beta got
  all 80 AWS fetchers reporting through `$FETCHER_STATUS_FILE`, but 250 of their
  CLI calls ran as `aws ... 2>/dev/null` and the matching log line recorded only
  a label. Of 310 failure records, 8 carried the AWS error text and **302 carried
  none** — so expired credentials, a missing IAM permission and throttling all
  arrived looking identical, while being three unrelated fixes. All 80 also
  passed a hardcoded `partial_failure`, so `metadata.error_code` carried no
  information for the largest category in the repo.

  Both are fixed. `metadata.error` now carries the AWS error text behind the
  calls that failed, and `metadata.error_code` is derived from it:

  ```json
  {
    "error": "2 AWS API failure(s); first: aws sts get-caller-identity failed; aws ec2 describe-security-groups (list) failed (exit=254) -- aws: [ERROR]: An error occurred (InvalidClientTokenId) ... The security token included in the request is invalid. | aws: [ERROR]: An error occurred (AuthFailure) ... AWS was not able to validate the provided access credentials",
    "code": "auth_failed"
  }
  ```

  That `code` is what the not-enabled classification work and the
  deleted-mid-scan decision were both waiting on.

  **No call site was rewritten.** `aws` in
  [`fetchers/aws/_shared/aws.sh`](fetchers/aws/_shared/aws.sh) is now a shell
  function shadowing the CLI, so all 250 calls keep their exact text — including
  `2>/dev/null` — and still have their stderr captured. stdout, stderr and the
  exit code reach the caller unchanged, so the `2>"$_ERR"` + `grep` pattern the
  not-enabled check depends on still works, synchronously. The one constraint
  this adds: a fetcher must reach the CLI as plain `aws`, never `command aws` or
  an absolute path, or its calls go unclassified. A test enforces that.

  Classification is regex over botocore's wording, which is the only signal a
  CLI-based fetcher has — the SDK-based categories read a typed exception
  instead. A future AWS rewording can therefore downgrade a code to
  `partial_failure`; that is the safe direction, and
  `tests/test_aws_failure_classification.py` pins the current wordings verbatim.

- **A not-enabled service still exits 0.** The wrapper captures the
  `SubscriptionRequiredException` stderr like any other, so this was the
  regression risk worth naming: had it been recorded as a failure, every account
  without Macie, Inspector, or Shield would have started reporting a spurious
  `partial_failure`. `aws_service_unavailable` is still checked first and
  short-circuits, verified end-to-end and pinned by a test.

- **Failure reasons read correctly again.** The separator was built with
  `tr '\n' '; '`, and `tr` maps one character to one character — so it emitted
  `;` with no space and left a trailing one before the `(+N more)` suffix.

### Changed

- **Two Azure SDK pins widened**, and CI can now tell whether that is safe.
  `azure-mgmt-network` moves from `<32` to `<33` and
  `azure-mgmt-recoveryservicesbackup` from `<11` to `<12`, in both
  `pyproject.toml` and `requirements.txt`. Anyone installing `.[azure]` gets the
  new majors.

  The reason this is worth an entry: **CI installed `.[dev]` and `.[dev,tui]` but
  never `.[azure]`, so no test in the suite had ever imported an Azure SDK.**
  Every `azure-mgmt` major that has broken this category broke it silently —
  wrong or empty evidence rather than an exception — which meant a dependency PR
  widening an Azure pin went green on evidence that proved nothing about Azure.
  One did
  exactly that: it relaxed the load-bearing `azure-mgmt-monitor<7` and passed all
  twelve checks, while 7.0.0 removes the `diagnostic_settings` operation group
  that three fetchers read.

  A new `azure-sdk (surface)` job is now the only one that installs the Azure
  extra, and it pins the surface in the shapes a major bump actually takes it
  away: relocated client imports, vanished operation groups, vanished methods,
  and the model-field renames that produce wrong rather than empty evidence — 56
  checks across all 27 Azure fetchers. It asserts the extra really resolved
  before running, because the module opens with `pytest.importorskip` and a
  failed install would otherwise skip and report green. `azure-mgmt-monitor`
  majors are held back until the operation group returns; a test fails when it
  does, so the pin and the hold get lifted together instead of going stale.

- **The container base image moves to Python 3.14** (`deploy/Dockerfile`:
  `python:3.12-slim` → `python:3.14-slim`), and **CI now tests on 3.14** as well
  as 3.10–3.13. The interpreter the Dockerfile and the dev environments actually
  run was previously the one nothing gated.

- **Corrected the 0.5.0-beta entry below.** It said `metadata.error` "now carries
  the actual cause", and illustrated it with a report rich in AWS error text.
  That example came from one of the 8 call sites that captured stderr, out of
  310 — it was not representative, and for AWS the accurate claim at 0.5.0-beta
  was that the report *names the call that failed*. The entry now says so, and
  this release is what makes the original claim true.

## [0.5.0-beta] - 2026-09-02

### Added

- **CrowdStrike Falcon fetcher set** — seven fetchers and a fourteenth
  category, contributed by [@StewartClaw](https://github.com/StewartClaw):
  managed host inventory, Spotlight vulnerabilities, detections, prevention
  policies, Zero Trust Assessment, FileVantage file integrity, and host firewall
  policies and rules. All seven share one OAuth2 client
  ([`_shared/falcon_client.py`](fetchers/crowdstrike/_shared/falcon_client.py))
  that handles token refresh, cursor and offset pagination, and the
  `Retry-After` contract on 429s. **Commercial and GovCloud both supported** —
  `cloud_region` selects a commercial region or `us-gov-1` / `us-gov-2`, and the
  client follows the region-discovery redirect Falcon's auth endpoint issues
  when the host is wrong.

  Built without a Falcon tenant, so correctness is pinned to CrowdStrike's
  published API models rather than to hand-written fixtures:
  `tools/crowdstrike_schema.py` derives the request/response shapes,
  `tools/crowdstrike_schema_check.py` fails
  when a fetcher reads a field the published model does not define,
  `tools/crowdstrike_usage_check.py` fails when a declared API scope isn't
  exercised (and the reverse), and `examples/crowdstrike_mock_run.yaml` runs the
  whole set against a schema-derived local double — no tenant, no credentials, no
  network egress. That covers the documented contract, not a live tenant's
  responses; **prevention policies and Zero Trust Assessment are the two worth
  re-checking against a real tenant**, as no public response samples exist for
  either.

- **[`docs/ksi_mapping.md`](docs/ksi_mapping.md)** — the full fetcher ↔ KSI
  mapping, readable in both directions, with FedRAMP's verbatim statements and
  NIST control crosswalk, and the open gaps called out as fetcher backlog.
  Generated by `tools/gen_ksi_mapping.py`; the generator is idempotent, so CI can
  fail on a diff to keep it honest.

- **Issue-report fetchers (`kind: issue_report`).** A second collection kind for
  the file a scanner already produces — a Nessus export, a Wiz findings CSV —
  rather than a JSON payload asserting a configuration state. The runner writes
  those files unmodified to `<run>/issue-reports/` (no envelope: Paramify's
  intake parser reads the vendor's own structure), records identity in a sidecar
  index, and a new uploader (`paramify issues upload`) posts each file to
  `POST /assessment/{assessmentId}/intake`. The assessment is chosen by name
  (`paramify assessments list` / `select`), the same way `paramify programs
  target` picks a program UUID without anyone typing one. Start from
  [`fetchers/_template_issue_report/`](fetchers/_template_issue_report/) and
  [`docs/issue_report_fetchers.md`](docs/issue_report_fetchers.md). Written
  against Paramify REST API v0 spec 0.6.0
  ([API documentation](https://app.paramify.com/api/documentation/)).

### Changed

- **A failed fetcher now tells you *why*, in every category.** Paramify used to
  show whoever was triaging `Encountered 3 API failures during collection` — a
  count, with no hint of which call broke. Two causes, one root: **103 fetchers
  across seven categories** (`aws` 80, `okta` 8, `knowbe4` 4, `k8s` 3,
  `paramify` 3, `rippling` 3, `checkov` 2) never wrote `$FETCHER_STATUS_FILE`,
  so the runner fell back to the tail of stderr and `metadata.error` carried
  whatever the fetcher happened to log last; and the detail was being collected
  and then thrown away — every AWS fetcher recorded its causes into a temp
  failure log whose only reader, across all 80, was `wc -l`, and the exit trap
  deleted it.

  `metadata.error` now names the call that failed — for AWS that is the call
  label, not yet the AWS error text behind it (corrected in 0.5.1-beta above) —
  and `metadata.error_code` is one of seven closed values (`auth_failed`,
  `not_authorized`, `target_unreachable`, `rate_limited`, `bad_config`,
  `partial_failure`, `internal_error`). Forcing a
  credential failure on `aws_guard_duty_findings` reported
  `Encountered 2 API failures during collection` before. It now reports:

  ```json
  {
    "error": "2 AWS API failure(s); first: aws sts get-caller-identity failed;aws guardduty list-detectors failed (exit=254): aws: [ERROR]: An error occurred (UnrecognizedClientException) when calling the ListDetectors operation: The security token included in the request is invalid.",
    "code": "partial_failure"
  }
  ```

  **228 non-zero exit paths across the tree, 0 unreported.** Note that the AWS
  family reports `partial_failure` uniformly — it counts and quotes the calls
  that broke rather than classifying *why*. Distinguishing `auth_failed` from
  `rate_limited` from `not_authorized` there needs per-call classification and is
  follow-up work; the reason text is what carries that information today.

  **For fetcher authors this is a contract change.** Reporting a failure is no
  longer something you hand-roll: there is now exactly one helper per runtime —
  [`fetchers/_lib/status.sh`](fetchers/_lib/status.sh) and
  [`fetchers/_lib/fetcher_status.py`](fetchers/_lib/fetcher_status.py), both
  named `report_failure` — and
  [`docs/fetcher_contract.md`](docs/fetcher_contract.md) mandates it. It logs
  *and* reports, so it is the whole failure path; logging inside the helper is
  what guarantees the reason is the last line on stderr, which is what the
  fallback reads. The same nine-line status write previously existed as **27
  copies under two names** (`report_failure` and `write_status`) — 22 in
  individual fetchers, three in category-shared modules, and one in each
  scaffolding template — because the porting playbook printed those nine lines
  and told authors to paste them. The playbook and both templates now import the
  helper instead. A category-shared module may
  re-export it and must not reimplement it, which is how all 80 AWS fetchers
  were wired without a single per-file `source` line.

  **One known regression:** `crowdstrike` fetchers no longer set
  `metadata.error_code`. They passed their own strings (`collection_error`, a raw
  HTTP status) which the shared helper drops as outside the closed set. The error
  *text* is intact, and mapping those onto the seven real codes is a judgement
  call left to its own change.

- **Every fetcher's `ksis` re-keyed to the FedRAMP Consolidated Rules for 2026.**
  FedRAMP replaced the numeric Phase One indicators (release 25.05C, 52 of them)
  with mnemonic ones (version 2026.07.14.01, 46 of them) — `KSI-CNA-01` is now
  `KSI-CNA-RNT`. Every id changed, so every mapping in the repo did too. Beyond
  the re-key: `TPR` was deleted and `SCR` (Supply Chain Risk) added, `INR` became
  Incident Response, `SVC-SIN` absorbed both in-transit and at-rest encryption,
  `IAM-APM` absorbed both phishing-resistant MFA and passwordless, immutable
  infrastructure moved from `CNA` to `CMT`, and vulnerability management left
  `MLA` entirely.

  **No action required for existing manifests or evidence sets.** Manifests
  select fetchers by name (`use: <fetcher>`) and never referenced KSIs; no
  fetcher was renamed. `evidence_set.reference_id` is unchanged on all 176
  fetchers, so the uploader's get-or-create resolves to the same evidence sets —
  no duplicates, no re-linking. `ksis` is not carried in the envelope and is
  never transmitted to Paramify; it is repo-side reporting metadata read by
  `paramify ksi`.

  What does change: `paramify ksi` output, and the KSI ids shown in fetcher
  descriptions. Evidence sets created from now on drop the `(KSI-XXX-NN)` suffix
  from their display name — the uploader never renames, so sets that already
  exist in a tenant keep the name they were created with.

  Mappings are now documented as **suggested / related** rather than assertions
  that a fetcher satisfies an indicator on its own. Four indicators are left
  uncovered on purpose (`SVC-VCM`, `MLA-ALA`, `RPL-TRC`, `SCR-MIT`): the evidence
  does not exist yet, and an honest gap beats a mapping that has to be defended.
  Coverage is 32/36 config-evidenceable indicators.

- **Dropped "20x" from our own KSI labels** in `paramify ksi`, the fetcher
  schema, and fetcher descriptions. The reference file now carries the exact
  release string, so it is the single source of truth for which release we
  measure against. FedRAMP 20x program deliverables (the VER reports) keep the
  name.

### Deprecated

- **`write_status` in `azure_common` and `gcp_common`** is now an alias for the
  shared `report_failure`. The 46 Azure and GCP call sites still using it keep
  working and are unchanged here; they log twice as a result (their own
  `logger.error` plus the helper's), which is cosmetic in the run log and does
  not affect what Paramify receives. Renaming those call sites and dropping the
  alias is one later pass, because the static conformance scan has to stop
  crediting the old name at the same moment the call sites change.

### Fixed

- **TUI**: arrow keys now work where the layout implies they should. `left` /
  `right` move along a button row — Textual's `Button` binds only `enter`, so
  every Yes/No and Save/Cancel dialog *read* as a left-right choice while
  answering to neither, leaving `tab` as the only way across. `up` / `down`
  typed into a filter box now walk the list it filters without taking focus out
  of the box, so you can keep narrowing while you move.

  Both are bound on the container rather than on the widgets, which is what
  keeps them safe: a key bubbles up from whatever has focus, so anything that
  already owns it keeps it. An `Input`'s `left` / `right` still moves its text
  cursor; a `Tree`'s and an `OptionList`'s `up` / `down` still move their own.
  Affects the confirm, form, and picker dialogs, the catalog filter, and the
  Manifest and Paramify action rows.

- **MySQL RDS instances were reported as not enforcing TLS even when they were.**
  `rds.force_ssl` is a PostgreSQL and SQL Server parameter; MySQL uses
  `require_secure_transport`. `aws_component_ssl_enforcement_status` and
  `aws_rds_tls_configuration` only read the former, so every MySQL instance came
  back as unenforced regardless of its actual configuration. Both now accept
  either parameter, matching `ON` / `1` / `true` case-insensitively. Contributed
  by [@jazzl0ver](https://github.com/jazzl0ver).

  **The evidence payload grows** (additively): `rds_tls_configuration` gains
  `require_secure_transport`, `require_secure_transport_source`, and a derived
  `ssl_enforced` per parameter group, plus two summary counters. `ssl_enforced`
  is the either-parameter roll-up and is the field to standardize on downstream;
  `force_ssl` is still emitted alongside it. **Any validator matching on the old
  shape is worth re-checking.** Not yet exercised against a live MySQL instance —
  the parameter names follow the AWS documentation.

- **`aws_fsx_encryption_status` over-counted its own failures.** It appended raw
  multi-line stderr to the failure log that the failure count is a `wc -l` of, so
  a run with 2 failures reported 3. The stderr is now flattened to one line per
  failure.

- **One unreadable KMS key no longer fails the whole collection.**
  `aws_kms_key_rotation` exited non-zero when it could not read a single key's
  rotation status — an AWS-managed key such as `alias/aws/acm`, or a customer key
  whose policy scopes out the collecting role. The per-key `AccessDenied` was
  already handled, but every failure landed in one bucket that was checked as
  "any failure at all", so one unreadable key out of forty failed a run whose
  evidence was otherwise complete.

  An unreadable key now stays in the payload carrying the reason AWS gave
  (`rotation_status: "unreadable"`, `collection_error: "AccessDeniedException on
  GetKeyRotationStatus"`), and the run succeeds. This follows the contract's own
  guidance that a reader of the evidence file should be able to see the
  collection was incomplete; the exit code stays the only failure signal.

  Two payload changes come with it. `rotation_enabled` is now `null` for a key
  that could not be read — it was `false`, which asserted "not rotated" about a
  key nobody had read and dragged `rotation_percentage` down with it. And that
  percentage is now taken over the keys actually read, with
  `readable_keys` / `unreadable_keys` added to the summary beside `total_keys`.
  A validator keying on the old shape should be checked. This is payload, not
  contract, so no bump ([`docs/versioning.md`](docs/versioning.md)).

  Collection still fails where the evidence would be empty or wrong: the caller
  identity, `kms list-keys`, or **every** key being unreadable — that last guard
  is new, so a broken identity cannot report "0 of 0 keys rotated" as a clean
  run. Reported by [@jazzl0ver](https://github.com/jazzl0ver) (#44, fixed in #46).

- **EBS encryption-by-default was reported as disabled on accounts where it is
  enabled.** `aws_block_storage_encryption_status` read the setting with
  `--output text`, which renders the API's boolean as `True`, and compared it to
  a lowercase `"true"` that could never match. Any control keyed on
  `encryption_enabled_by_default` read as unimplemented on a correctly
  configured account — a false negative in the evidence, not a display quirk.

  This was the only site with the problem: it is the one place in the repo that
  reads a boolean through `--query … --output text` and compares it to a
  lowercase literal. Fixed by [@jazzl0ver](https://github.com/jazzl0ver) (#47).

- **`docs/porting_playbook.md` no longer tells you to derive `reference_id` from
  a KSI id.** It offered `reference_id: <stable id, e.g. KSI-IAM-01>` as the
  example, which is precisely the advice that cannot survive a renumbering —
  and FedRAMP just renumbered everything. `reference_id` is the immutable key
  the uploader get-or-creates on; changing it orphans the evidence set in every
  tenant.

- **README's category table** listed GitLab as 3 fetchers; it has 4
  (`significant_change_notifications` was missing).

- **`paramify programs target` no longer misses the manifest it should edit.**
  Its `-f/--file` defaulted to the literal `manifest.yaml` resolved against the
  *current directory*, and `read_manifest()` reads a missing file as an empty
  manifest — so running it from a subdirectory, or passing a bare name whose file
  lives under `manifests/`, silently found nothing and reported "No manifest
  entry takes a program as a target", blaming the contents for a path that
  wasn't there. Worse, the write then created a second manifest at that wrong
  path. Now: omitting `-f` offers the discovered manifests as a numbered pick
  list (annotated with how many entries take a program, since names carry no
  convention to guess from) and uses a lone candidate outright, naming it; `-f`
  accepts a bare name or stem, resolved against `manifests/` and the repo root
  so it works from anywhere in the tree; and a `-f` that resolves to nothing is
  an error that writes no file. Under `--json` (or any non-tty) several
  candidates is an error listing them rather than a guess. Other `manifest`
  subcommands still default to `./manifest.yaml`.

## [0.4.0-beta] - 2026-08-18

### Breaking

- **KnowBe4 group- and campaign-scoped fetchers now require config.** The group
  and campaign names these three fetchers match on were hardcoded to one tenant
  (see *Fixed* below); they now come from `config_schema` and are **required**, so
  a manifest that ran them before will now fail `paramify validate` — and the run
  — until the values are wired:

  | Fetcher | New required config |
  |---|---|
  | `knowbe4_high_risk_training` | `high_risk_groups`, `role_specific_campaigns` |
  | `knowbe4_developer_specific_training` | `developer_groups`, `developer_campaigns` |
  | `knowbe4_security_awareness_training` | `security_awareness_campaigns` |

  Each takes a comma-separated list of names exactly as they read in your tenant,
  set with `paramify manifest set-config <fetcher> <key>=<value>` or through the
  matching `KNOWBE4_*` env var. `retraining_interval_days` was added at the same
  time but defaults to 365 and needs nothing. `paramify doctor <manifest>` names
  any that are still missing.
- **KnowBe4 evidence changed shape.** A metric the fetcher could not measure is
  now `null` rather than `0`, and `training_module_summary` for an empty tenant is
  `{}` rather than `null`; a new `results.config_resolution` block records what was
  requested, what matched, and what the tenant actually has. **Re-check any
  validator or query that asserts on those fields** — one written against
  `"completion_rate": 0` will no longer match, which is the point: `0` used to mean
  both "measured, and it is zero" and "could not measure", and only the first of
  those is a finding.

### Added

- **Azure — 27 fetchers (new category).** Identity and access (Entra ID MFA,
  privileged roles, conditional access), compute and AKS posture, storage and
  database encryption at rest, Key Vault, App Service, monitoring and backup.
  Python against the official `azure-mgmt-*` SDKs — no `az` CLI at runtime — and
  authentication is `DefaultAzureCredential`, so a managed identity, a service
  principal or a cached `az login` all work and none of them is a key file.
  Fanned out per subscription. Installs with `pip install -e '.[azure]'` (23
  packages), deliberately **not** folded into `[all]`: it is heavier than
  everything else here combined and only matters if you run Azure. Majors are
  pinned, because six breaking changes across `azure-mgmt` majors each produced
  wrong or empty evidence rather than an error. Credential setup, and the
  tenant-vs-subscription scoping that the Entra fetchers need, are documented in
  the six themed example manifests
  ([`examples/azure_identity_and_access.yaml`](examples/azure_identity_and_access.yaml)
  and siblings); the category has no `README.md` of its own yet.
- **GCP — 19 fetchers (new category).** Compute and GKE posture, IAM and service
  accounts, KMS, Cloud Storage and Cloud SQL encryption at rest, BigQuery, logging
  and monitoring, DNS. Python against the official `google-cloud-*` clients, no
  `gcloud` at runtime, authenticating through Application Default Credentials —
  again no key file. Fanned out per project; a target that omits `project` collects
  from the ADC default ("collect where deployed"). `pip install -e '.[gcp]'` (12
  packages), also out of `[all]`. Credential setup in
  [`fetchers/gcp/README.md`](fetchers/gcp/README.md).
- **Paramify — 3 FedRAMP 20x VER report fetchers (new category).** Accepted
  Vulnerability Info (VER-RPT-AVI), the Vulnerability Detail Report, and the
  historical VER-activity snapshot, generated from Paramify issue data and fanned
  out per program. Shared logic lives in `fetchers/paramify/_shared/ver_common.py`.
  Report-period and workspace-wide knobs (`cert_package_uri`, `api_base_url`,
  `http_timeout`) are category config under `platforms.paramify.config` rather than
  per-target secrets, so one value per workspace is set once.
- **Optional secrets — `required: false` on a declared secret.** The ambient
  identity case: aws, azure, gcp and k8s all authenticate through a credential
  chain whose preferred links (an instance role, EKS IRSA or Pod Identity, a
  managed identity, workload identity, SSO, a cached CLI login) hand over no
  secret at all, while the same chain also accepts static keys. Every declared
  secret used to be mandatory, so those keys could not be declared without
  breaking the deployments that supply none — which meant `paramify describe` and
  the TUI reported that an AWS fetcher needed no credentials whatsoever. They are
  now declared and marked optional: advertised, resolvable from a `${env:...}` ref
  like any other secret (so the runner masks them out of captured output), and
  simply not injected when a manifest omits them.
- **Category-level `secrets:`** in `fetchers/_categories/<name>.yaml` — credentials
  shared by every fetcher in a category, declared once instead of repeated. Azure's
  service principal is three env vars used identically by all 27 of its fetchers.
  A per-fetcher secret of the same name still wins, mirroring how `config_schema`
  already merges; `contract.effective_secrets()` is the one place both the
  describe/TUI surface and the runner resolve through, so what is advertised and
  what is demanded cannot drift apart. `secrets[].description` was added alongside,
  and is what explains *why* an optional credential is optional.
- **`$FETCHER_STATUS_FILE` — an explicit channel for why a collection failed.**
  A fetcher that fails writes `{"error": "...", "code": "..."}` there and the runner
  puts it in the envelope as `metadata.error` / `metadata.error_code` (a new
  optional envelope field; the envelope stays additive, so `schema_version` is
  still 1.0). Previously `metadata.error` was the tail of stderr, which assumes the
  last thing a fetcher logged is why it failed — false for the 16 fetchers whose
  final line is "Evidence saved to …", so a failed collection reported a success
  message as its failure reason. The stderr tail remains the fallback, so nothing
  had to migrate. Paramify surfaces that field to whoever is triaging. (#24)
- `paramify programs` — a new command group over the Paramify workspace.
  `programs list` shows each program's readable name next to its project UUID;
  `programs target` selects programs (interactively, by name/id, or `--all`) and
  writes them as fanout targets, filling in the shared config they need. The API
  identifies programs by UUID while people know them by name; this closes that
  gap without anyone copying a UUID by hand. The shared values (`--cert-uri`,
  `--report-from`) are shown on every interactive run with what the manifest
  holds today as the prompt default and a note of where it comes from: enter
  keeps it and writes nothing, typing over it updates the category value. So the
  same command adds a program and rolls the report window forward, and neither
  requires opening the manifest to see what the next run will carry. Entries that
  resolve to different values get no default — either one offered as *the* answer
  would misreport the other.
- `program_name` — an optional target field on the Paramify VER fetchers. The
  fetcher uses it for its evidence filename and the uploader for the artifact
  title, so per-program artifacts read as `… - Alpha Cloud Services` rather than
  a bare UUID. A UUID prefix stays in the filename because program names are not
  guaranteed unique.
- **`requires:` on a category** — `fetchers/_categories/<name>.yaml` gains a
  `requires:` block naming the external binaries and the pip distributions its
  fetchers need, and `paramify doctor` checks them. With a manifest it checks only
  the categories that manifest actually uses, so a GitLab-only run is never told
  to install the aws CLI or 23 Azure SDKs. Version pins stay in
  `requirements.txt`, which remains the single source of truth for versions; a
  category file names only which distributions are its own. The declarations are
  themselves tested (`tests/test_category_requires.py`): an import or a
  shelled-out binary that nothing declares fails the suite, because doctor's
  report is only as good as what the category files say.
- **`paramify doctor --probe`** — authenticates against each cloud category
  (`aws`, `k8s`, `azure`, `gcp`) and reports which identity answered: caller ARN
  and account, Azure principal and subscriptions, GCP account and project.
  Without it doctor can only see whether variables are *set*, which is nearly
  meaningless for credential chains whose preferred links — IRSA, workload
  identity, managed identity, a cached CLI login — set no variable at all, so
  doctor reported a clean bill of health and the run failed on auth. It also
  answers "as whom", the more common silent failure: credentials that work but
  point at the wrong account produce a successful run full of empty evidence.
  Opt-in because it is the only part of doctor that touches the network, each
  probe runs in a subprocess under a hard timeout, and a failed probe is reported
  without failing the command.
- **`paramify doctor --require-upload`** — makes a missing API token count toward
  the exit code. Upload readiness (token presence and the destination URL) is
  always reported; gating is opt-in because collecting evidence without uploading
  it is a legitimate workflow that should not fail a preflight.
- **`paramify upload` asks for the API token** when none is set and it is safe to
  ask — a real terminal at both ends, no CI, not `--json`. Reaching the upload
  step means the collection is already paid for, and this is a failure a person
  can fix on the spot rather than by re-running the whole thing. The value is used
  for that run and written nowhere; persisting a credential is the user's call, so
  it prints how instead of guessing at a file. `paramify run` says the same thing
  up front, advisory only, so you learn it in the first second rather than the
  last.

### Changed

- **`paramify describe` shows each field's env var and description.** Both schemas
  said a field's `description` was shown there; it was not, so the two things
  needed to wire a field into a manifest — the env var it arrives in, and what it
  is for — were only readable by opening `fetcher.yaml`. It is also the only place
  an optional secret explains why it is optional.
- **`paramify evidence` and the TUI's evidence viewer print what the tenant wrote.**
  Both rendered their JSON with the default `ensure_ascii`, so an em dash in a
  failure reason came back as `\u2014` and any accented name was unreadable and
  unsearchable. The files on disk are unchanged.
- **The README's demo GIFs were re-recorded**, and there are four now: a run and the
  evidence it wrote, building a manifest and preflighting it with `doctor`, the
  catalog and a fetcher's contract, and the TUI. The old three were rendered the day
  before the TUI's design language changed and two weeks before its Paramify tab was
  rebuilt, and predate azure/gcp/paramify entirely — `tui.gif` showed an application
  that no longer exists. They now also show the CLI's color. The recordings are made
  against a larger set of synthetic fetchers than the repo ships, so a run of your
  own is shorter than the one on film; what the frames show of the runner, the
  envelope and each command's output is what you get.
- **gitlab, knowbe4, okta and sentinelone categories now have a `description`.**
  Four of thirteen listed as a bare name in `paramify catalog`, which is the one
  place someone browsing decides whether a category is what they want.
- The `tui` extra pins `textual>=8,<9` (was `>=1.0,<2.0`). The old range was not
  what anyone ran, and focus / `Input` behaviour differs enough across those lines
  that the TUI is not the same app on 1.x. `tests/test_tui_keys.py` (new) drives
  the real app through Textual's pilot to hold the key-and-focus contract: what
  each tab focuses, that the globals survive a repeat tab press, and that enter
  reaches an action wherever the footer says it does.
- **TUI**: the footer hint bar lists `esc` (the only way out of a focused text
  field back to the shortcut keys — an `Input` consumes every printable key) and
  the Run tab shows `enter/ctrl+r`, since focus opens on the ▶ Run button and
  `enter` presses it.
- Each VER report's `_summary` now carries a `collection` block (status + the
  API-failure ledger). `/issues` is the only call these fetchers make, so a
  failure yields empty report arrays; without this a failed report was
  indistinguishable from a genuinely clean one to anything reading the payload.
- The uploader prefers a target's `program_name` over its opaque id when titling
  an artifact. Fetchers whose id is already readable are unaffected.
- **Every timestamp in a VER report is now emitted in one format** — UTC, second
  precision, literal `Z` (`2026-07-30T09:00:00Z`). Values from the Paramify API
  (`detectedAt`, `evaluationCompletedAt`, the `dueDate` quoted in an overdue
  explanation) were previously passed through with the API's millisecond
  precision, so a single document mixed notations; they are normalized on the way
  in, and non-UTC offsets are converted rather than preserved. A `report_from` /
  `report_to` given as a bare date is expanded, with a date-only end reported as
  that day's last second (`2026-06-30` → `2026-06-30T23:59:59Z`) to match the
  window actually collected.
- **`paramify doctor` preflights the manifest, not just the environment.** It now
  runs the same validation `paramify validate` does, so it cannot pass a manifest
  the runner will refuse: a misspelled `use:`, a missing required config key, a
  `supports_targets` fetcher with no `targets[]`, or a declared secret the
  manifest never mapped. Scanning env-var references could not see any of those —
  a secret that was never mapped leaves nothing to scan, so it read as a clean
  bill of health and failed at run time. A manifest that cannot be parsed is now
  reported as a finding rather than raising a YAML traceback out of the CLI, and a
  valid one says so out loud, since silence on validity reads as "not checked".
- **Doctor checks secret *values*, not just that the variable exists.** A
  whitespace-only value counts as missing: it reads as set to a presence check and
  then fails at the API, with the variable visibly present so nothing looks wrong.
  Values shaped like copy-paste artifacts — surrounding quotes, a trailing newline
  from `$(cat file)`, a `*_URL` / `*_URI` / `*_ENDPOINT` with no scheme — are
  reported as warnings that never affect the exit code, because a legitimate value
  can look odd and a preflight that cries wolf stops being read.
- **The Paramify API token and base URL resolve in one place**
  (`framework/paramify_auth.py`), which both uploaders and doctor read, so the
  answer to "which token, which workspace" cannot differ between the preflight and
  the upload. The destination is labelled production / stage / self-hosted and
  shown as loudly as the token: pointing at stage when you meant production does
  not error, the upload just succeeds into the wrong workspace.

### Fixed

- **`paramify validate` no longer demands credentials the runner does not need.**
  An optional secret could not pass validation: the runner skips one a manifest
  omits, but validate demanded every declared secret regardless — so as soon as the
  aws, azure and k8s categories declared their static keys (above), every manifest
  naming one of their fetchers would have failed preflight while running perfectly
  well. Validate also read a fetcher's own `secrets` rather than
  `effective_secrets`, so a category-declared credential was not checked at all and
  a manifest genuinely missing a required one passed validate and died in the run.
  Both halves are the same fix: resolve secrets the way the runner does, then skip
  the optional ones. No existing manifest newly fails — every category-level secret
  shipped today is optional.
- **KnowBe4**: the three group- and campaign-scoped fetchers no longer report an
  unresolved config as a failing control. The group and campaign titles they match
  on were hardcoded to one tenant, so pointed anywhere else they emitted
  `completion_rate: 0` and exited 0 — byte-identical to a tenant where the campaign
  resolved and genuinely nobody had trained. Two very different states, one output,
  and no assertion could tell them apart. The names now come from `config_schema`
  (`high_risk_groups`, `role_specific_campaigns`, `developer_groups`,
  `developer_campaigns`, `security_awareness_campaigns`, plus
  `retraining_interval_days`), and a name that matches nothing in the tenant is
  **not** a fetcher failure — one typo must not turn a whole nightly run red. The
  fetcher exits 0 and reports every metric it could not measure as `null`, never
  `0`, alongside a `results.config_resolution` block naming what was requested,
  what matched, and what the tenant actually has. `null` means "not measured"; `0`
  still means "measured, and it is zero", so a genuine 0% remains a real finding.
  A config key that is never wired at all is caught pre-flight by
  `paramify validate`, since these are `required`.
- **KnowBe4**: names are matched exactly rather than as substrings. A group
  configured as `IT` previously also swept in `AUDIT` and `Legal-IT`, inflating the
  high-risk population.
- **KnowBe4**: config values reach `jq` as data (`--args` / `$ARGS.positional`)
  instead of being spliced into the filter text. A campaign title containing a
  quote or backslash produced a jq compile error before; making the titles
  customer-supplied would have turned that into a routine failure.
- **KnowBe4**: all four fetchers assemble their evidence in one `jq` pass. Each
  record was previously appended by re-running `jq` over the growing output file,
  which was quadratic — 1500 enrollments took 69s and 3000 took over 120s, so a
  mid-size tenant blew the runner's 600s cap. 3000 enrollments now completes in
  about 3s. `training_module_summary` for an empty tenant is `{}` rather than
  `null`.
- **KnowBe4**: a response that is not a JSON array (an error body returned with
  HTTP 200) is recorded as a failure instead of being treated as a page. Pagination
  previously looped forever on such a body, bounded only by the runner's timeout.
  Pagination also stops at a 1000-page cap, and `printf '%s'` replaces `echo` on
  every API response so a backslash in a title survives a non-bash shell.
- **TUI**: pressing the number of the tab you are already on no longer clears
  focus. Assigning `TabbedContent.active` the value it already holds fires no
  `TabActivated`, so nothing re-homed focus after it was cleared — and because a
  page's bindings only resolve while focus is inside that page, every page
  shortcut (`a`/`e`/`x`, `ctrl+r`, `j`/`k`, the arrows) silently went dead until
  you pressed escape or a different tab.
- **TUI**: `ctrl+p` on the Paramify tab runs Preview instead of opening Textual's
  command palette, which claims that key as a *priority* binding — checked ahead
  of the focused widget, so the page's own binding could never fire. `p` now does
  it too, mirroring the Manifest tab's preview key.
- **TUI**: `enter` does what the footer promises on the two tables where it did
  nothing at all — on a run it drills into that run's evidence files (where enter
  opens one), and on a manifest row it opens the entry editor.
- **TUI**: editing the manifest's output dir no longer loses the path. Textual
  selects an `Input`'s value on focus, so the first keystroke replaced the whole
  path; and an edit never submitted with `enter` was silently reverted by the next
  rebuild. Focus no longer selects the value, and leaving the field commits it.
- **TUI**: `enter` in a confirmation dialog now means No. Yes is composed first,
  so it took the default focus — on the dialogs that delete a manifest file,
  remove an entry, and upload to Paramify. `y` still confirms.
- **TUI**: config set at the category level showed as unset on every entry that
  inherited it — the manifest screen read only the entry's own `config` block and
  had no notion of `platforms.<category>.config`. Both the detail pane and the
  summary count now render `api.effective_config()`, the same merge the runner
  performs, and show which layer each value came from.
- **Paramify VER fetchers**: a pending or rejected `RISK_ADJUSTMENT` no longer
  reports `finalDisposition: "Partially Mitigated"` — mitigation now requires an
  accepted deviation, not an unapproved request.
- An issue carrying neither `poamId` nor `id` no longer raises `KeyError` and
  kills the whole report.
- `PARAMIFY_HTTP_TIMEOUT` is parsed at call time and falls back to the default on
  a malformed value, instead of aborting the run with a bare `ValueError` at
  import.
- A timestamped `report_to` no longer over-includes up to a day beyond the
  declared reporting period.
- `PARAMIFY_REPORT_TO` is now declared, so it can actually be set through a
  manifest (the runner passes only declared env vars).

## [0.3.1-beta] - 2026-07-28

### Changed

- Run manifests are no longer gitignored, and the repo no longer tracks a file at
  `./manifest.yaml`. The manifest that used to sit there ships as
  `example_manifest.yaml` instead. Manifests describe which evidence you collect,
  so teams under a compliance program generally want them in version control —
  they hold no secret values, since `${env:VAR}` resolves from the environment at
  run time. Previously `/manifest.yaml` and `/manifests/` were listed in
  `.gitignore` *and* a `manifest.yaml` was tracked; because ignore rules don't
  apply to already-tracked files, that entry had no effect and edits to the
  shipped manifest were staged by default, conflicting on every upgrade.
  **If you were relying on the tracked `manifest.yaml`,** copy
  `example_manifest.yaml` to `manifest.yaml`, or pass `--manifest` explicitly.
  `paramify manifest init` and the `manifests/` picker convention are unchanged.

### Added

- [`docs/private_mirror_workflow.md`](docs/private_mirror_workflow.md) — keeping a
  private copy of this repo that still receives upstream releases, for teams whose
  fetcher work can't be public.

## [0.3.0-beta] - 2026-07-23

### Added

- 13 Datadog fetchers (new category): Cloud SIEM detection rules & signals, SIEM
  operational configuration, log pipelines / indexes / archives, host & container
  inventory, agent check results, the APM service catalog, and incident records with
  timelines. Credential setup in [`fetchers/datadog/README.md`](fetchers/datadog/README.md).
- `paramify scripts sync` — push each fetcher's entry script (`fetcher.py` /
  `fetcher.sh`) to Paramify and CONNECT it to that fetcher's evidence set, so the
  tenant records *how* each piece of evidence is generated. A provisioning step
  separate from `paramify upload`: it reconciles the tenant to the repo GitOps-style
  (marker-keyed identity in the script description, `fetcher.yaml` `version` as the
  update signal, a sha256 drift guard). **Scoped to a manifest by default** — it
  provisions scripts only for the fetchers you collect, mirroring how `upload` is
  run-scoped — with `--all` to push the whole catalog, plus `--dry-run` / `--force` /
  `--reassociate` / `--json`. Backed by the `uploaders/paramify_scripts/` uploader.
  Only `SCRIPT` associations are automated; control / solution-capability / validator
  linkage stays Paramify-side.
- [`docs/uploader_design.md`](docs/uploader_design.md) — a dedicated uploader design
  doc covering both built uploaders and the shared evidence-set identity model, and
  a README section + docs-table entries pointing to it.

### Changed

- **TUI Paramify tab redesigned** into stacked *evidence upload* and *scripts sync*
  panels. Scripts sync gained a **Preview** action that runs a read-only dry-run and
  surfaces the per-fetcher plan (create / update / drift / noop) in a table — flagging
  which drifted scripts `--force` would push — and syncs the active manifest's fetchers.

### Fixed

- TUI: page keyboard shortcuts (`ctrl+r` / `ctrl+u` / `ctrl+s`) now fire regardless of
  which control is focused, and default focus lands in the active pane on mount, on tab
  switches (mouse clicks included), and after `escape` — previously they worked only
  right after a number-key tab switch.
- TUI: the *Add fetchers* picker no longer drops a category once all its fetchers are in
  the manifest; already-added fetchers show greyed-out and non-selectable, so a
  fully-added category (e.g. `datadog`) stays visible.
- TUI: the Paramify action row (Preview / Sync Scripts / force / reassociate) now uses
  uniform control sizes instead of content-sized widths and mismatched heights.

## [0.2.1-beta] - 2026-07-10

### Changed

- The `deploy/` bundle is now **Docker-only** (Dockerfile + compose + cron) — a
  smaller, less prescriptive deployment footprint for public use.

### Removed

- The Kubernetes deployment manifests and the multi-account hub-and-spoke
  Terraform (`deploy/k8s/`). The Kubernetes *fetchers* (`fetchers/k8s/`) are
  unaffected.

### Fixed

- The containerized deploy no longer defaults evidence uploads to Paramify
  staging; it uses production (`app.paramify.com`), matching the uploader's own
  default.

## [0.2.0-beta] - 2026-07-10

First public release — a beta / pre-release. Pre-1.0, so the contract may still
change before 1.0 (see [`docs/versioning.md`](docs/versioning.md)).

### Added

- Fetcher framework: the `paramify` CLI (list · catalog · describe · manifests ·
  validate · run · runs · evidence · upload · manifest builder) plus the
  `paramify tui` front-end, both talking only to `framework.api`.
- `paramify doctor` — a preflight that checks the Python version, the external
  CLIs each category needs on `PATH`, and (given a manifest) whether its secret
  env vars are set.
- 108 fetchers across 8 categories (aws 79, okta 8, sentinelone 5, knowbe4 4,
  gitlab 3, k8s 3, rippling 3, checkov 2). The AWS category collects where
  deployed via the ambient credential chain, with optional per-target
  profile/region fanout.
- Evidence envelope (`{schema_version, metadata, payload}`, `schema_version`
  `1.0`) wrapped around every fetcher output by the runner.
- Paramify evidence uploader (`uploaders/paramify_evidence/`).
- A containerized deployment bundle (`deploy/`) — a Docker image + compose that
  runs the collector on a schedule and uploads, with secrets injected at run time
  (environment or AWS Secrets Manager).
- A credential-free demo (`demo_hello` fetcher + `examples/demo.yaml`) that emits
  synthetic evidence, so the whole collect → envelope pipeline runs with no cloud
  account.
- KSI metadata: an optional `ksis` array on `fetcher.yaml`, mappings populated
  for 89 fetchers, and `paramify ksi` — a FedRAMP 20x KSI coverage view over
  `api.ksi_coverage()`.
- Optional `validators` metadata on `fetcher.yaml` (regex checks over the
  evidence payload).
- Versioning & contract policy ([`docs/versioning.md`](docs/versioning.md)), this
  changelog, and the manual release runbook
  ([`docs/releasing.md`](docs/releasing.md)).

### Changed

- Licensed under GPL-3.0-only.
- Documentation rewritten for public consumption; the README leads with the TUI,
  then the AI-agent path, then the CLI.
- TUI restyled — border titles, status pills, denser controls, and hatched empty
  states.

[Unreleased]: https://github.com/paramify/paramify-fetchers/compare/v0.5.1-beta...HEAD
[0.5.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.5.0-beta...v0.5.1-beta
[0.5.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.4.0-beta...v0.5.0-beta
[0.4.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.3.1-beta...v0.4.0-beta
[0.3.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.3.0-beta...v0.3.1-beta
[0.3.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.2.1-beta...v0.3.0-beta
[0.2.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.2.0-beta...v0.2.1-beta
[0.2.0-beta]: https://github.com/paramify/paramify-fetchers/releases/tag/v0.2.0-beta
