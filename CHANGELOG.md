# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/) applied
to the contract (see [`docs/versioning_guide.md`](docs/versioning_guide.md)). "The contract"
is the public API surface — the `fetcher.yaml` / category / manifest / envelope
schemas and the `paramify` CLI — not the internal code.

## [Unreleased]

### Added

- **`azure_devops_identities`** (`EVD-AZURE-DEVOPS-IDENTITIES`): who can sign in to
  an Azure DevOps organization and who holds its administrative groups. It records:
  - every user, service principal and service identity, with access level,
    origin, member or guest type, date added and last access (from user
    entitlements);
  - every group with its direct members, and each identity's direct and
    inherited groups;
  - the effective members of Project Collection Administrators, Project
    Collection Service Accounts, Project Collection Build Administrators and each
    project's Project, Build, Release and Endpoint Administrators, with the path
    of nested groups to each and whether it is held only through an Entra group;
  - users inactive past `AZURE_DEVOPS_INACTIVE_DAYS` (default 90), counting a
    never-used account from the day it was added, and people deleted in Entra ID
    who are still in the organization.

  Azure DevOps memberships never expire; `entra_groups_granting_privilege` names
  the Entra groups to check for PIM. A summary field whose read failed is null,
  not 0 or empty. Read-only PAT scopes: Graph and Member Entitlement Management;
  or an Entra identity that is an organization member.
- **`azure_entra_groups`** (`EVD-AZURE-ENTRA-GROUPS`) — every Entra ID group with
  its members and owners, its kind, whether it can hold directory roles, and
  whether membership is set by a rule (dynamic, with paused rules flagged), by hand
  or synced from on-premises. Summarizes role-assignable groups without an owner or
  with guests, groups without an owner or with only disabled owners, and groups
  holding guests, disabled users, nested groups or service principals. Members and
  owners past `$expand`'s 20-item limit are read from beta, since v1.0 leaves out
  service principals. Groups whose owners Graph doesn't return (synced,
  distribution, mail-enabled security) are left out of the owner figures, a
  hidden-membership group with no visible members reads unknown, and a partial
  group list nulls every count. Needs GroupMember.Read.All (or Directory.Read.All);
  User.Read.All, Member.Read.Hidden and Application.Read.All are optional, and
  without User.Read.All the guest, disabled-user and disabled-owner figures read
  null.
- **Oracle Cloud Infrastructure category** (`fetchers/oci/`, fifteen
  fetchers, `pip install -e '.[oci]'`). Authenticates with an API signing key
  the runner injects as a secret (`OCI_PRIVATE_KEY` carries the PEM content,
  never a path), or with an instance or resource principal where deployed;
  walks the compartment tree beneath a chosen root; one evidence set per
  fetcher. `oci_dependency_vulnerabilities` closes KSI-SCR-MIT, which no other
  category evidences: Application Dependency Management audits and what their
  ignore lists hide. The rest cover certificate renewal automation, Bastion
  just-in-time access, Cloud Guard, Zero Trust Packet Routing, IAM
  users/credentials/policies/password rules, Vault keys, volume and bucket
  encryption, network reachability, instance hardening, audit/logging/events
  and managed data services. Ships with 33 validators, recorded-response tests
  that replay through the real SDK (`tests/test_oci_*`), a schema check against
  the SDK's generated models (`tools/oci_schema_check.py`), a fault sweep
  (`tools/oci_fault_sweep.py`) and a read-only collector policy in
  `fetchers/oci/README.md`. Contributed by Stewart Clawson
  (paramify/paramify-fetchers#87).
- **A shared engine for ServiceNow Scripted REST endpoints.**
  `fetchers/servicenow/_shared/scripted_rest.py` does the request, the retries,
  the response checks and the write for every ServiceNow fetcher. A fetcher now
  only declares its endpoint: the URL variable, the watermark parameter, and,
  for an endpoint that pages, the page size and where the records are. Paging
  by limit and offset is new. The fetcher README tells you how to add an
  endpoint.
- **`servicenow_cases` and `servicenow_changes` have `evidence_set` blocks**
  (`EVD-SERVICENOW-CASES`, `EVD-SERVICENOW-CHANGES`). Before, `paramify upload`
  skipped their evidence and counted it as an error.

- **Evidence samples for 84 fetchers.** Each one is a `sample.json` beside the
  fetcher's `fetcher.yaml`. A sample shows one sanitized record from a live run
  in a test account, for AWS, Azure, GCP and the demo fetchers. Use
  `paramify samples show <fetcher>` to read one. No sample is reviewed yet, and
  12 come from an earlier fetcher version. `paramify samples status` marks both.
  See [`docs/evidence_samples.md`](docs/evidence_samples.md).
- **Shell tab completion.** `paramify --install-completion` installs completion
  for commands and options. `paramify samples show <Tab>` completes the names of
  the fetchers that have a sample. See
  [`docs/cli_guide.md`](docs/cli_guide.md#tab-completion).
- **Scope exclusions for Azure fetchers.** A shared helper,
  `fetchers/azure/_shared/scope_exclusions.py`, takes case-insensitive glob
  patterns (comma- or space-separated) and answers whether a name is excluded and
  by which pattern. A fetcher that adopts it reads them from its
  `scope_exclusions` config field, and its evidence keeps every excluded item in
  `results.excluded` with the pattern that matched (or the reason it followed),
  echoes the patterns, lists the ones that matched nothing, counts each excluded
  kind, and counts what stayed in scope (`in_scope_hosts` and the like), so a
  check can require more than 0 and catch a pattern such as `*` that takes out
  everything. Every verdict, count and percentage covers only what remains in
  scope. With no patterns set the output is unchanged apart from those empty,
  zero or total fields. Adopted by:
  - `azure_front_door_origins` 0.5.0: custom-domain and endpoint host names, and
    route names through a `route:` prefix (`route:qa-*`, or `route: qa-*`); a
    bare pattern never matches a route's name, and any other prefix fails the
    run. A route is out of scope when a `route:` pattern
    matches it or every host it serves is out, an origin group when every route
    reaching it is, and a production app when only out-of-scope groups reach it,
    so multi-region redundancy is judged on the core domains. Access restrictions
    are read only for apps an in-scope group reaches.
  - `azure_front_door_tls` 0.3.0 and `azure_front_door_waf_coverage` 0.3.0:
    the same matching. TLS also leaves out certificate secrets that only
    out-of-scope domains use, and WAF coverage the host-routes of an out-of-scope
    route. Both fetcher.yaml texts move to the new description format.
  - `azure_dns_configuration` 0.4.0: public record-set names, relative (in every
    zone) or FQDN. A prefixed pattern fails the run.
- **A string config field can be a `${env:VAR}` reference.** The runner
  resolves it the way it resolves a secret. An unset or empty variable gives way
  to the next value down (platform config, then the default; an error for a
  required field with neither) and leaves one run note per entry naming every
  unset variable; a malformed reference is an error. String config fields only,
  not targets: the runner refuses a reference on an integer or boolean field,
  and `manifest set-config`, `set-platform-config`, `add-target` and
  `set-target` refuse one on a typed config field or any target field (a
  target's secrets still take references), as does `validate` for a hand-edited
  one. Only the fetcher's own fields and the issue-report keys are resolved; a key
  only a sibling fetcher declares passes through untouched. A reference must be
  the whole value, and it can't read a variable whose name looks like a
  credential's (`_TOKEN`, `_SECRET`, `_API_KEY`, `_PAT` and the like) or one that
  holds a secret: any fetcher's or category's declared secret, or any variable a
  `secrets:` reference in the manifest reads. The runner and `validate` refuse
  all of these without resolving them, naming the variable; the `manifest`
  commands refuse a partial reference or a credential-like name, and the
  `validate` they run after saving reports the rest. The value an allowed
  reference reads is masked out of the fetcher's captured output and the run
  metadata like a secret. `effective_config`, and so the TUI, shows a reference
  as written, never its value, with whether it is set; the TUI and shared config
  checks compare what it reads, and `validate` names an issue-report reference
  unset in its shell.

### Changed

- **`azure_app_service_configuration` 0.3.0: cipher suites, basic-auth publishing, Key Vault
  references and runtime end of support.** Each web app now reports its minimum TLS cipher
  suite and the suites still allowed (whether CBC or static-RSA suites remain), the SCM site's
  minimum TLS version, whether basic-auth publishing is allowed on the SCM and FTP endpoints,
  which app settings and connection strings are Key Vault references and whether each
  resolves, and whether each declared runtime is past end of support, joined to App
  Service's own runtime stack list. All Reader GETs; no setting value is read. Existing
  fields are unchanged. Also maps to KSI-SVC-VCM (client certificate mode and managed
  identity).
  - **Opt-in literal-secret scan.** With `scan_literal_secrets` on (off by default), it
    reads app settings and connection strings through config/list, which needs
    `Microsoft.Web/sites/config/list/action`, and lists the names of those holding a
    literal secret instead of a Key Vault or App Configuration reference, each with the
    reason (`credential_in_value` or `secret_like_name`). Values are classified in memory
    and never written. A 403 reads `not_authorized` for that app and a ReadOnly lock's 409
    reads `not_read`; neither is a collection failure. When apps exist but none could be
    scanned, the secret counts are null rather than 0. The same read supplies a Windows
    app's Node version (`WEBSITE_NODE_DEFAULT_VERSION`, matched to the Node stack only and
    written only when it is a version number) to runtime support; without it, a Windows
    app on the default .NET Framework v4.0 reads as unknown rather than supported.
    Production sites only; deployment slots are not read.
- **`azure_front_door_origins` 0.5.0: Kudu and silent regions.** An app whose
  Kudu (scm) site has its own access restrictions
  (`scmIpSecurityRestrictionsUseMain` off) that let every public caller in is no
  longer `locked_to_front_door`: the gap is `scm_public_access_unrestricted`,
  counted in `serving_app_service_origins_scm_public_access_unrestricted`, and
  each record lists the Kudu rules. `all_regions_healthy_last_hour` is null when
  a region with an enabled origin has no value for the last hour (false still
  wins when a region is known to be unhealthy), so a region that went silent no
  longer reads as healthy. Custom domains are now always read, for
  `in_scope_hosts`.
- **`azure_front_door_origins` 0.3.0: live origin health and traffic per region.**
  Hourly Azure Monitor metrics for each profile over `metrics_lookback_days`
  (default 7, at most 30): `OriginHealthPercentage` (average and minimum) by origin
  and group, and `OriginRequestCount` by origin, matched to origins by host name or
  origin host header. `origin_health` rolls them up per group and region: health,
  healthy hours (measured against the share of probes the group's load-balancing
  settings require), requests and request share, whether every region was healthy
  in the profile's newest hour with health data and serving in its newest hour
  with requests (taken separately, since ingestion lags per profile and per
  metric; a group silent that hour reads as not serving, and an hour older than
  the window's last 3 leaves both unknown), and `traffic_shifts`, each hour the
  set of serving regions changed. Adds KSI-RPL-TRC. `production_tag` moves from `config_schema`
  to `target_schema`, so each subscription target sets its own tag (same
  `AZURE_PRODUCTION_APP_TAG` variable). Existing fields are unchanged.
- **`azure_front_door_origins` 0.2.0: App Service origin lockdown and regional
  twins.** Each origin that is an App Service app or slot (by its azureOrigin, its
  private-link target, or the app whose host name it uses) is listed in
  `app_service_origins` with the app's access restrictions, its
  `publicNetworkAccess`, its plan's capacity and zone redundancy, and
  `locked_to_front_door`: public access is off, or the only public allow rules are
  `AzureFrontDoor.Backend` rules whose `X-Azure-FDID` value is the profile's own
  `frontDoorId` (read with `profiles.get`), or that of another profile in the
  subscription that also serves the app (listed in `fronting_front_door_ids`).
  `lockdown_gaps` names what fails; the id of a profile that doesn't serve the app
  is `other_front_door_id_allowed` (listed in `other_front_door_ids_allowed`),
  since that profile may not have the serving profile's WAF. Resource Graph lookups page
  in a stable order and fail on a truncated result or a repeated skip token. Every app in the subscription (narrowed by the
  new optional `production_tag`) is listed in `production_apps`, flagged when no
  serving origin group reaches it, when no enabled origin in another region of its
  group is its twin, or when the twin's plan has fewer instances. Existing fields
  are unchanged; `profiles` gain `front_door_id`.
- **`azure_dns_configuration` 0.2.0: public record sets.** Each public zone now
  lists `record_sets` (`record_sets.list_all_by_dns_zone`): name, FQDN, type, TTL,
  `targets` (the A, AAAA, CNAME, MX, TXT, NS, PTR, SRV, CAA or SOA values) and
  the alias target resource with its type. Each A, AAAA or CNAME record gets a
  `failover_method`: `front_door` or `traffic_manager` (an alias to one, or a CNAME
  to its `azurefd.net` / `trafficmanager.net` / `usgovtrafficmanager.net` host),
  `cdn`, or `record_update` (a fixed target, so failing over means changing the
  record within its TTL). A record that points at another record set in the zone
  (an alias, or a CNAME to a name in the zone) takes that record set's method, one
  link deep, and names it in `same_zone_target` when the zone holds a record set
  of that name and type (a name in a delegated child zone isn't a link). Dangling
  aliases and CNAMEs to deleted hosts aren't detected. New summary fields count record sets by type,
  aliases, empty endpoint records and endpoints by failover method; zones whose
  record sets can't be read are null and fail the run. Adds KSI-CNA-MAT,
  KSI-RPL-ABO and KSI-RPL-TRC. Existing fields and keys are unchanged.

### Fixed

- **`servicenow_cases` and `servicenow_changes` no longer report a failed
  collection as a success.** A 200 response that is not JSON, for example a
  single sign-on or instance hibernation page, and a response whose
  `result.status` is not `success` now fail the run, and no evidence is
  written. Before, the fetcher saved the response and exited 0.
- **The ServiceNow fetchers give the correct failure code.** HTTP 429 is
  `rate_limited`, 5xx is `target_unreachable`, and other 4xx are `bad_config`.
  Before, all of them were `partial_failure`. A redirect is not followed. It
  fails the run with `bad_config`. A URL that is not `https://` is refused,
  because basic auth sends the password with each request. HTTP 429 and 5xx
  responses are retried.

- **`azure_private_dns_zone_configuration` matches a record's IP only in the
  networks its zone resolves for** (0.1.0 → 0.2.0). An IP was matched against
  every private endpoint, NIC and load balancer in the tenant, so a stale record
  at a common address such as 10.0.0.4 read as backed, `ip_mismatch` or
  `platform_managed` when an unrelated VNet used the same address. Each IP is
  now matched only within the zone's linked VNets and the VNets peered with
  them, so an endpoint in a spoke peered with the hub the zone is linked to
  still backs it. A peering counts from either side, so this holds even when
  the credential cannot read the hub: the readable spokes whose own peering
  points at it are found with a separate query. A zone with no links reads as
  `unverified`, not backed. A linked VNet the credential cannot read stays in
  scope: a visible endpoint NIC in it still backs the record, but an IP nothing
  visible holds there is `unverified`. An IP the network match reads `stale`,
  `unverified` or `unknown` is also backed when an Approved endpoint whose NIC
  holds the record's IPs registers it through the endpoint's own private DNS
  zone group: this exact zone, this FQDN, exactly these IPs. That proof never
  overrules an `ip_mismatch`, `endpoint_not_approved` or `platform_managed`
  found in the zone's own VNets. The zone groups are read per endpoint with
  `private_dns_zone_groups.list` (Reader covers it); a failed read is recorded,
  leaves only that proof unknown (`zone_group_backed: null`) and never backs a
  record or reads it stale. The new `backed_by` names the proof (`network`,
  `zone_group` or both). Only one peering hop is followed, so in these layouts
  only hand-made records (no zone group) move from backed to `unverified`:
  Virtual WAN (spokes two hops apart through the hub), spoke to spoke through a
  hub, and Azure Virtual Network Manager mesh (no peering objects). Where
  address spaces overlap, the verdict no longer depends on which VNet sorts
  first: an IP that falls in more than one of the zone's VNets with different
  verdicts is `unverified`. The new per-record `ip_address_networks` names the
  VNets each IP was matched in, `[]` when none, `null` when a lookup it depends
  on failed. VNets are read by id (linked, then peered) instead of every VNet in
  the tenant, and a failed lookup chunk leaves only its own VNets unknown (the
  links to them and the records of zones that resolve for them), not the whole
  run. Key Vault records in Azure Government and Azure China
  (`privatelink.vaultcore.usgovcloudapi.net`, `privatelink.vaultcore.azure.cn`)
  now match their endpoints' `vault.usgovcloudapi.net` and `vault.azure.cn`
  names instead of reading `ip_mismatch`. Status counts move, so **re-check any
  validator or query that asserts on `private_endpoint_status`,
  `ip_address_statuses`, `backed_by` or the `privatelink_records_*` summary
  counts.**
- **The private DNS zone and private endpoint fetchers' expanding queries
  parse.** Four Resource Graph queries put `mv-expand`'s row limit before the
  expanded column (`mv-expand limit 2000 x = ...`), which Resource Graph
  rejects with `ParserFailure`. The private endpoint, other NIC and load
  balancer IP lookups in `azure_private_dns_zone_configuration` therefore always
  failed, every privatelink A record read `unknown` and the run exited 1. The
  subnet lookup in `azure_private_endpoint_configuration` also always failed,
  so every endpoint's subnet read `unknown`. The limit now follows the column
  (`mv-expand x = ... limit 2000`).
- **`azure_private_endpoint_configuration` reports unread IPs as unknown**
  (0.1.0 → 0.1.1). When an endpoint's network interface was not read,
  `private_ip_addresses` was `[]`, reading as "no IPs". It is now `null`. A
  failed lookup is also recorded in `metadata.api_failures`; a NIC that Resource
  Graph simply did not return (indexing lag, or a scope the credential cannot
  read) gives `null` with no failure entry. **Re-check any validator or query
  that expects `private_ip_addresses` to be a list.**

### Changed

- **`azure_sentinel_incidents` 0.2.0: response timeline, monthly metrics, rules
  and entities.** Besides the latest SecurityIncident row per incident, which
  still gives close times and now tasks, the fetcher reads every update row in
  the lookback. Each incident gains:
  - `acknowledged_time_utc` and `hours_to_acknowledge`: the first update by a
    person that moves it to Active or Closed or gives it an owner or a different
    one (by object id when both updates have one, so a renamed owner isn't a
    different one), up to its first close, so a reopen never counts and removing an owner
    doesn't either; a person creating it already Active or owned acknowledges
    it at creation. Updates with no modifier, and those by automation rules,
    playbooks, alert grouping, Fusion, incident creation or the Defender XDR
    sync, don't count. Microsoft doesn't document what a person's update writes
    as the modifier, so any other modifier counts as a person, an unlisted
    system included. Known only when the creation row was read; a later row
    missing doesn't undo one already found.
  - `status_changes`, `owner_changes` and `severity_changes` (time, from, to and
    who made it), and `tasks` with status and completion time. Owners compare
    by object id when both updates have one, so a rename isn't an owner change,
    and an owner known only by object id is named by it. Times are each
    update's LastModifiedTime, and rows written at the same instant always sort
    alike.
  - `hours_to_detect` (first activity to creation), `comments_count`,
    `classification_comment` and `related_analytic_rule_ids`.
  - the `entities` on its alerts, as kind and identifier, from SecurityAlert
    joined on the incident's alert ids: up to 25 of each kind, processes as image
    name and process id, URLs as scheme and host only. Entities read
    as `null` when the alerts can't be read.
  - `provider_incident_id` and `provider_incident_url`: for an incident synced
    from Defender XDR, its id and link there; Microsoft Graph alerts give the same
    id as `incidentId`.
  - `owner_object_id` and `owner_email`, beside the existing owner names. An
    owner known only by email or object id is still an owner, in
    `history_complete`, `open_new_unowned_history_incomplete` and the backlog
    by owner.
  - `history_complete`: whether every update was read: the incident was created
    inside the history read, which starts at the lookback or SecurityIncident's
    retention, whichever is later; its creation row was read; and a row tied for
    the latest time read matches its current status, severity and owner (by
    object id when both sides have one, else by name) and, if its
    `lastModifiedTimeUtc` is within the last hour, is that recent. One already
    acknowledged before its oldest update read has no acknowledgement time rather
    than a late one. `updates_read` counts the update rows read for it.

  Each workspace gains `monthly`: per calendar month of the lookback, MTTD by
  month created, MTTA by month acknowledged and MTTR by month closed over the
  in-scope incidents, and the open backlog at month end by severity and owner
  over every incident, which is `null` for month ends older than
  SecurityIncident's retention; its `updates_retained` is true when the whole
  month is inside the history read. An older incident closed in the lookback leaves
  the backlog without counting in that month's MTTR, so monthly MTTR may read
  low. It also gains `recurring_titles`, `recurrence_by_title` and
  `recurrence_by_rule` (two or more incidents created in the lookback),
  `open_unacknowledged` (open, every update read, and no person has acknowledged
  it), `open_new_unowned_history_incomplete` (open, still New with no owner, and
  not every update read, so never counted in `open_unacknowledged`), and
  `mttd_hours`, `mtta_hours` and `mttr_hours`. When the update history can't be
  read, the timeline fields, `monthly`, `acknowledged_incidents` and
  `open_unacknowledged` are `null` rather than empty. When close times can't be
  read, `close_time_status` is `unknown` and the close-time counts are `null`,
  rather than every closed incident counting as missing. A SecurityIncident
  table the query can't find, in a workspace that lists an incident over an hour
  old, is hidden by table-level access: the run records an access failure and
  exits 1, and close times and history are unknown. In a workspace that lists
  none, or only incidents under an hour old that may not be ingested yet, it
  reads as empty, with a note. SecurityAlert is treated the same way when an
  incident over an hour old has alerts. SecurityAlert is cut to the incidents'
  alert ids before it is aggregated and joined, and a query whose result is too
  large for one response (over 64 MB or 500,000 rows) is read again in halves
  of the incidents, down to 64 shares, rather than failing the run.
  The summary's counts, existing ones included, are `null` when any workspace's
  incident list failed, the workspace list or a check for Sentinel failed, or a
  workspace named in `SENTINEL_WORKSPACES` wasn't found, and the counts that
  can be unknown are `null` when any workspace's value is; with no Sentinel
  workspace found they are 0.
  Each workspace also gains `limitations`: in a workspace connected to Defender
  XDR, analysts usually work incidents in the Defender portal and
  SecurityIncident shows mostly the XDR sync's updates, so those incidents read
  as not acknowledged and an open one can count in `open_unacknowledged`; their
  acknowledgement times would need Defender XDR's incident activity history,
  which neither SecurityIncident nor Graph's `security/incidents` (its current
  state and comments, but not when an incident was first activated or assigned)
  provides.
  Other existing fields are unchanged; KSI-PIY-RES is not mapped, since it isn't
  evidenceable.

## [0.6.0-beta] - 2026-10-23

### Breaking

- **Python 3.11 is now the minimum version.** Python 3.10 reached end of life
  in October 2026 and gets no more security fixes. `requires-python` is now
  `>=3.11`, so `pip install` refuses a 3.10 interpreter. `paramify doctor` also
  reports 3.10 as too old. To upgrade, make a new virtual environment on Python
  3.11 or later and install again. The ruff and mypy targets move to 3.11 too.
- **`paramify issues upload` sends reports into Paramify pipelines.** The API
  key needs new permissions, and each issue-report entry must now set
  `close_cycle` (next entry). The command no longer calls
  `POST /assessment/{id}/intake`. Per assessment it
  uploads each report bare to `POST /pipelines/{id}/intake`, then queues one
  `POST /pipelines/{id}/process` naming exactly those artifacts, then waits for
  the job and prints its counts (created, updated, seen-closed, auto-closed). The
  call is `PROCESS_CLOSE` only when the assessment's `close_cycle` is `after_run`
  and every target bound to it in the run succeeded and uploaded; otherwise
  `PROCESS`, with the reason the close was skipped. The pipeline puts an upload
  on its oldest open cycle, so `effectiveDate` no longer routes it. The API key
  needs `PIPELINE_INTAKE`, plus `PIPELINE_PROCESS`, plus `PIPELINE_CLOSE` to
  close. A job that fails, is blocked behind a failed job, or outlasts
  `--wait-timeout` (default 900 s) fails the command; `--no-wait` queues and
  exits. The intake log now also records each job, so a re-run processes files
  an interrupted run uploaded but never processed, and waits on a job it left
  running. The TUI's issue-report panel shows the planned operation per
  assessment and warns in the confirm when a run will close a cycle.
- **Every issue-report entry must set `close_cycle`.** It is a reserved config
  key, `after_run` or `never`, with no default. Until an entry sets it, the
  uploader holds back that entry's reports. Closing a cycle auto-closes every
  open issue the cycle never saw, so it states how the customer fills the
  assessment's cycles: one report per cycle closes after each complete run;
  several files per cycle close only when the last is in. `paramify assessments
  select` asks for it (or takes `--close-cycle`), and so does the TUI's
  assessment picker. `paramify validate` reports an entry without one, reading
  entry and `platforms.<category>` config the way the runner does.
- **A manifest path or name that does not exist is now an error.** Every
  command resolves a manifest name the same way: as typed, then under
  `manifests/`, then with `.yaml`. A name that matches nothing exits 1. Before,
  some commands read it as an empty manifest, `-f demo` could create `./demo`,
  and `doctor` passed. `paramify validate demo` now works.
- **A malformed `${env:...}` reference is now an error.** A reference must name
  an upper-case variable, such as `${env:OKTA_API_TOKEN}`. A reference that does
  not match, such as a lower-case name, now fails the schema check and secret
  resolution. Before, the runner passed it through as the literal secret value.
- **A target's `profile` outranks static AWS keys in the environment.** When a
  target sets `profile`, the runner removes `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` for that invocation and logs a
  note. Before, keys in the environment silently won over the profile. A profile
  that uses `credential_source = Environment` no longer works, because those
  keys are gone when it runs. Categories can declare `auth.selector_env` and
  `auth.credential_env` to describe the same rule for other clouds.
- **The Okta account allowlists are configuration, not code.**
  `okta_iam_core.py` carried a hardcoded list of one service account and two named
  people's email addresses, used to seed service-account and Super Admin detection
  for a single tenant. Both lists now come from config and default to empty:
  `OKTA_KNOWN_SERVICE_ACCOUNTS` on `okta/non_user_accounts_authentication` and
  `OKTA_KNOWN_SUPER_ADMINS` on `okta/least_privilege`, each declared in that
  fetcher's `config_schema` and accepting a comma- or newline-separated list of
  logins/emails. No behaviour change for a tenant that sets them; every other
  tenant now gets only the name-independent detection methods (userType, API token
  ownership, OAuth client assignment, group membership, assigned admin roles),
  which is what it should always have been.
- **`write_status` is gone from `azure_common` and `gcp_common`.** It was an
  alias of `report_failure`, kept for older fetchers. A custom fetcher that
  imports it must import `report_failure` instead.

### Security

- **Jira fetchers** (`jira_site_inventory`, `jira_remediation_items`,
  `jira_audit_records`, `jira_access_roles`): `JIRA_BASE_URL` must now be a Jira
  Cloud site (`https://<site>.atlassian.net`, or the Government Cloud domain) or
  the API gateway for a scoped token (`https://api.atlassian.com/ex/jira/<cloudId>`).
  Any other host, a userinfo part, a query, a fragment or a port is refused before
  the token is sent, and the error no longer echoes the value. HTTP redirects are
  no longer followed; a 3xx answer is a `bad_config` failure. The README documents
  a read-only scoped token for the admin collector.
- **`jira_remediation_items`, `jira_audit_records`, `jira_access_roles`**: hitting a
  collection cap now fails the run with `partial_failure`, and every evidence file
  carries `metadata.complete` and `metadata.incomplete_reason`.
  `jira_audit_records` no longer reports `records_truncated: false` when records
  past the cap were dropped.
- **`jira_change_requests`, `jira_incident_postmortems`**: a configured field name
  that matches no Jira field, or several, now fails the run as `partial_failure`
  instead of silently skipping the checks that need it. Ambiguous names list their
  matching ids in `metadata.field_candidates`.
- **`jira_change_requests`, `jira_incident_postmortems`** (review of PR #174): a
  check whose field role is turned off no longer produces its finding on every
  ticket; `metadata.checks_disabled` lists the findings that cannot be produced,
  and a setting that depends on a turned-off field (required severities, required
  phases, category targets, report window, or no approval source at all) is
  refused as `bad_config`. A failed `issue/bulkfetch` marks its keys as not
  visible (`postmortem_not_visible`, `action_items_not_visible`) instead of
  reporting the post-mortem or action items as absent. The deployment time of a
  reopened change is its first move into the done status, so a late approval is
  still caught. A role may be pinned to several `customfield_` ids for
  team-managed projects; changelog reads with more than 10 field ids are made in
  groups instead of being cut to 10. Pinned ids are checked against the site's
  field list, a value that is neither a name, an id nor a list of ids is
  `bad_config`, the deployment time of a change is its first entry into any
  done-category status (read from `GET /rest/api/3/status`), and turning off
  `change_type` while change types are pre-approved is refused.
- **All Jira fetchers**: `metadata.partial_failure` now follows
  `metadata.complete` (a hit cap or an unresolved field is partial, not only a
  failed call). HTTP 429 and 5xx are retried with `Retry-After` or backoff, and a
  request that still gets no answer after the first success is one failed call
  rather than the end of the run. `jira_site_inventory` (0.1.1) uses the shared
  client instead of its own drifted copy.
- **`jira_access_roles`**: reads only the project roles named in a privileged
  grant (`JIRA_ACCESS_ALL_ROLES=true` reads every role), lists grants to holder
  types it cannot resolve (`reporter`, `assignee`, custom fields) as
  `unresolved_privileged_grants`, tolerates a product the site does not have in
  the `group/bulk` fallback, and states that organization admins are not included.
- **`jira_audit_records`**: sensitive changes are matched by key words in the
  category name with `summary.unclassified_categories` for what matched nothing
  (Atlassian does not publish the category list); changed values are kept only
  for sensitive records, shortened and markup-escaped; fewer records than the
  server's `total` is reported as partial.
- **`jira_access_roles`**: reading no admin group at all is a recorded failure,
  never an empty result. **`jira_site_inventory`**: a bad token is `auth_failed`
  again (the credential is checked on `/myself` before the anonymous
  `serverInfo`), and hitting the issue cap now fails the run as partial like the
  other Jira fetchers.
- **All Jira fetchers** (second review): summary counts are `null`, not `0`, for
  a section whose fetch failed or did not finish, so an assessor never reads a
  refused call as "none found". A date-only approval date is compared with the
  deployment at day granularity (same day is unknown, never a finding), and a
  date-only detected or reported time is `report_time_not_measurable` instead of
  a false `reported_late`. `jira_remediation_items` measures a done ticket with
  no `resolutiondate` from its status history and counts
  `closed_without_close_time`. `jira_change_requests` claims only KSI-CMT-LMC
  (CNA-RNT and CNA-ULN dropped). `search_issues` stops on a repeated page token.
- **All Jira fetchers** (third round, from an adversarial review of the second):
  a check that could not run because a read failed is listed per ticket under
  `unknown`, never under `findings` (`approval_unknown` when a status-based
  approval's history read failed; `phases_unknown`, `postmortem_not_visible`,
  `action_items_not_visible`; a remediation ticket's `closed_at_source:
  unknown`), and `bulk_changelogs` now says which issues' history it failed to
  read. A capped search, a stopped collection (an unexpected response shape)
  and, in `jira_access_roles`, a failed role, role-index, admin-group listing or
  membership read null the summary section they belong to and no other.
  `summary.action_items` is null when any post-mortem or action item was not
  read. Changelog times are rendered in the ticket's own UTC offset before they
  are compared with a date-only field (bulkfetch gives epoch milliseconds, which
  is UTC), so a closure at 20:00 local on the due day is no longer "after the due
  date". `is_date_only` requires a parseable date, so `10/05/2026` is
  unparseable, not unmeasurable. `jira_remediation_items`, `jira_audit_records`
  and `jira_site_inventory` now survive an unexpected response shape
  (`internal_error` with the evidence written) like the other three, and
  `jira_site_inventory` nulls its project or issue counts when that read failed
  or the issue search hit its cap. History times follow the collector's IANA
  timezone from `/myself` (DST included), not a fixed offset; a done
  remediation ticket's close time is its last entry into the done category by
  status id (`GET /rest/api/3/status`, so `jira_remediation_items` now needs
  `read:status:jira` with a scoped token), with `reopened` recorded; summary
  `changes_approval_unknown` names deployed changes whose approval could not be
  read; `jira_access_roles` marks a group whose membership read failed with
  `membership_complete: false` and null counts instead of "0 members". A done
  remediation ticket whose close time cannot be taken from the history (an
  unparseable time, or the status catalog unread) has `closed_at_source:
  unknown` rather than a guessed date; an open ticket closed once before is
  `reopened`.
- **`jira_site_inventory` scopes documented**: the README scope table had no row
  for it. Found on the first scoped-token run: `GET /rest/api/3/priority/search`
  needs `read:priority:jira`, which the other Jira fetchers do not use.
- **`jira_site_inventory` behaviour change** (from the base URL allowlist above):
  `JIRA_BASE_URL` now accepts `https://<site>.atlassian.net`,
  `https://<site>.jira.com`, the Government Cloud domain and the scoped-token
  gateway, and nothing else. A URL with a path, query, port or userinfo, which the
  old client passed through to `requests`, is now refused as `bad_config`.

### Added

- **`cornerstone` category** with four KSI-CED-RAT fetchers over Cornerstone's
  Reporting API (read-only OData views, OAuth 2.0 client credentials):
  `cornerstone_security_awareness_training`, `cornerstone_role_based_training`,
  `cornerstone_secure_development_training` and
  `cornerstone_incident_response_training`. Each resolves the configured courses
  in `vw_rpt_training`, reads every registration from `vw_rpt_transcript`, and
  reports per user (numeric Cornerstone id only) the latest status, last
  completion and whether it is inside the retraining interval, plus each
  course's version and last content change. The awareness fetcher can take a
  `vw_rpt_user` population filter so never-assigned users count as
  `not_assigned`. Every view read is counted first and checked for
  completeness; an unresolved course name reports null metrics and exits 0.
  The portal URL must be one label under `csod.com`, redirects are refused, and
  nextLinks are followed only on the same host under the views root. Covered
  offline by `tests/test_cornerstone_fetchers.py`; not yet run against a live
  portal. Review (PR #175): the user population filter is shared by all four
  fetchers with a per-fetcher override and, without one, the completion rate is
  null and the run is `partial_or_empty`; failed attempts (`user_lo_pass` false)
  and configured withdrawn/failed status ids never count as completed;
  exemptions age like completions; an overdue assignment overrides an older
  completion; `A|B` names alternatives for one course; GUIDs compare
  case-insensitively and rows read but unattributed fail the run; a URL the
  client refuses is a recorded failure, not a crash; paging and throttle
  settings are declared on the category; rows with no user id are excluded and
  counted; all course names resolve in one chunked catalog query; a token
  refresh after a 401 no longer consumes a retry attempt.


- **CI runs the tests on Python 3.15.** The test matrix is now 3.11 to 3.15.
  The 3.10 row is gone.
- **`azure_devops_audit_streams`** (`EVD-AZURE-DEVOPS-AUDIT-STREAMS`): whether an
  Azure DevOps organization exports its audit log, which it otherwise keeps for
  90 days. Records:
  - whether auditing is on, from the Log Audit Events policy when the token can
    read it, otherwise from the audit log: its newest change to that policy, else
    its newest event (a scoped PAT gets 401 on the policy, and the run notes it;
    signed in with Entra instead, the fetcher reads the policy itself);
  - every audit stream's target, status, reason and last update;
  - the newest audit event, not counting the fetcher's own reads of the log.

  For an Azure Monitor Logs stream it counts this organization's
  `AzureDevOpsAuditing` rows in the workspace over the window, and `missing_rows`
  flags an enabled stream that delivered nothing while the organization was
  active. The organization is matched on organization-level events and rows
  only: project-level rows carry the project's id, so they are counted apart
  rather than as other organizations, and a stream is only expected to have
  delivered events newer than itself. Stream tokens and keys are never written.
- **`azure_devops_pipelines`** (`EVD-AZURE-DEVOPS-PIPELINES`): the first Azure DevOps
  fetcher, one target per organization, signed in with a PAT (`AZURE_DEVOPS_PAT`)
  or, when none is set, the ambient Entra identity (az login, managed or workload
  identity, or a service principal added to the organization). Each YAML
  pipeline's final YAML comes from a preview run pinned to the default branch's
  head commit, so templates are expanded and nothing is queued. If the preview is
  refused, the file is read at that commit instead. `yaml_commit` and
  `yaml_sha256` let an assessor fetch the same YAML and re-check it. Steps are
  sorted into test, security scan, IaC validation, infrastructure and application
  deploy, signing, signature verification and SBOM. `tests_gate_deploys` reports
  whether a failing test would stop every deploy, following `continueOnError`,
  conditions such as `always()` and `succeededOrFailed()`, and stage and job
  `dependsOn`; `ungated_deploys` names the rest and why. The fetcher also collects:
  - completed runs and published test runs over the lookback; test runs are queried
    in 7-day slices, the most the API allows, and `not_passed_tests` comes from the
    totals, so triaging failures doesn't change it;
  - each environment's approvals, branch control, required-template and
    artifact-evaluation checks, as configured at collection time;
  - every deployment in the window, joined to its run's branch, commit and test
    results;
  - each repository's default-branch policies. `requires_review` doesn't count the
    author's own vote, and `self_approval_satisfies_review` flags policies the
    author can satisfy alone;
  - the project's pipeline settings;
  - a count of classic release pipelines and their deployments in the window.

  `summary.not_collected` lists what is out of scope: approval decisions, policy
  bypass permissions, and the content of classic pipelines. Signing steps are
  framed as supporting evidence for KSI-SVC-VRI. A failed call names the PAT scope
  it needs. With a PAT, environments need Environment (Read & manage), because
  Azure DevOps has no read-only scope for them; an Entra identity needs only read
  access, such as project Readers. The shared client
  (`fetchers/azure/_shared/devops_rest.py`) handles PAT or Entra sign-in
  (`metadata.auth_mode`) and continuation paging, and records the identity it
  collected as (`metadata.collecting_identity`, from `_apis/connectionData`) for
  every Azure DevOps fetcher. It sends credentials only to the host it paged from
  and never follows a redirect, and it keeps the TF/VS error code on every
  failure.
- **A ServiceNow category with two fetchers.** `servicenow_cases` collects
  compliance review cases, and `servicenow_changes` collects ITSM change records.
  Both use a bearer token (`SERVICENOW_API_TOKEN`) and take an instance URL for
  each target. An optional last-run watermark limits a pull to new records.
  Leave it unset for the first pull.
- **Four Azure Front Door fetchers.** `azure_front_door_waf_policies`,
  `azure_front_door_waf_coverage`, `azure_front_door_tls` and
  `azure_front_door_origins` read Front Door Standard and Premium profiles.
  Classic Front Door and classic CDN profiles are counted as skipped. All four
  need only Reader access and run against each subscription. The `azure` extra
  adds `azure-mgmt-frontdoor` and `azure-mgmt-cdn`.
- **`azure_defender_assessments`** collects each Defender for Cloud assessment
  for each resource, with its severity, status and resource id. Severity comes
  from the assessment itself in Resource Graph, and falls back to the
  subscription's metadata catalogue. Each record has a `severity_source`, and
  the summary counts the records whose severity came from the catalogue or is
  unknown. A failed Resource Graph query is a collection failure (exit 1). A
  subscription where `Microsoft.Security` is not registered is recorded as
  `not_registered`, not as a failure.
- **`paramify capabilities list|show` and `paramify artifacts list|pull`.** These
  read a workspace's solution capabilities and their narratives, and download
  the artifacts of an evidence set. `pull` reports whether each artifact has an
  envelope.
- **`paramify validators check`** — runs the behaviour cases in
  `validators/_cases/` through the real ECMAScript engine
  (`framework/validator_eval/`, evaluated under `node` because Paramify's engine
  is JavaScript and Python `re` cannot compile `(?<name>...)` at all). A case
  file pins what a validator must return for a given artifact; a set-level file
  combines every validator on an evidence set the way Paramify does
  (ERROR > FAIL > PASS), which is the only way to prove an `integrity` validator
  covers its partner — a violation-counting validator passes its own drifted
  artifact, because zero matches is its pass condition. Reports vacuous passes
  (a PASS reached with a rule that read nothing) and names validators with no
  cases. Deliberately not a CI gate: the cases are an authoring aid, and
  legitimate evidence-shape changes should not block a merge.
- **An `onboard-platform` skill** integrates a platform that has no fetchers
  yet. It researches the API, sets up a sandbox with real data, plans a set of
  fetchers and builds each one.
- **Illustrated guides** for the architecture, run manifest, fetcher contract,
  authoring, envelope, config injection, validators, uploader, pipelines,
  inventory and issue-report fetchers, KSI mapping, platform onboarding, private
  mirror, versioning and releasing.
- **`azure_app_service_backups`** (`EVD-AZURE-APPSVC-BACKUPS`, KSI-RPL-ABO). For
  each App Service web app, whether it is actually
  being backed up, judged from its restore points: automatic backups plus
  successful custom backups.
  - **Observed backups.** It reports `latest_restore_point_age_hours` at run time
    and `largest_restore_point_gap_hours` inside `restore_point_window_hours`
    (default 48). `backed_up` is true only when the newest restore point is inside
    that window. `effective_backup_interval_hours` is the observed interval, and
    `configured_backup_interval_hours` is kept separate.
  - **Recovery point objective.** Set the optional `recovery_point_objective_hours`
    and each app reports `meets_recovery_point_objective`.
  - **Custom backups.** It also reports each app's custom backup configuration and
    history, and restores made from custom backups within
    `restore_test_window_days`.
  - **Backup storage.** It reports the region, replication and version immutability
    of the storage accounts custom backups go to.
  - **Exclusions.** Function apps and deployment slots are listed in
    `results.exclusions` with counts and the reason.
  - **Permissions.** Reader is enough. The custom configuration needs the opt-in
    `Microsoft.Web/sites/config/list/action`. Without it the configuration is
    recorded as `not_authorized` (unknown), not as a collection failure.
  - **Checks and limits.** The web app list is checked against Azure Resource
    Graph, and `results.limitations` states what the evidence does not cover. SAS
    tokens and database connection strings are never written.
  - **Shared module.** `_shared/app_service.py` now holds the web-app client and
    kind filter that `azure_app_service_configuration` also uses.
- **`checkov_bicep`** (`EVD-CHECKOV-BICEP`) runs `checkov --framework bicep,arm`
  over a cloned repo, typically one hosted in Azure DevOps, using a PAT with
  Code (Read). It records Bicep and ARM checks together, each tagged with its
  framework, with per-framework counts.

  A scan that checked nothing never reads as clean. These cases exit non-zero:
  - no `.bicep` files and no ARM `deploymentTemplate` JSON (`no_files`; counts
    are null, not 0)
  - files present but checkov ran zero checks (`no_checks`), e.g. resources
    declared only through `br/public:avm` registry modules
  - files checkov could not parse (`partial`; each is listed, and can be
    excluded with `skip_paths` once reviewed)

  The `org@` prefix of an Azure DevOps clone URL is dropped, and `clone_token`
  is optional, so public repos can be scanned.

  `source_type: tfvc` reads Azure DevOps TFVC, which `git clone` cannot fetch.
  It looks up the project's newest changeset (or the one named in
  `tfvc_version`), then downloads `tfvc_path` at that changeset as one zip
  through the TFVC items API, using a `tfvc_token` PAT with Code (Read). The
  evidence records `source_type` and, in `metadata`, the path, `changeset` and
  `changeset_date`, where a git source records its branch and commit. Git stays
  the default. As in `checkov_terraform` 0.2.0, failed checks on
  `skip_resources` matches move to `skipped_checks`, the effective skip lists
  are recorded in `metadata`, `use_default_skip_checks` can drop the shipped
  defaults, and `metadata.branch` names the branch actually scanned.
- **`web_vulnerability_disclosure`** (`EVD-WEB-VULNERABILITY-DISCLOSURE`), the
  second `web` fetcher. Given a site or a security.txt URL, it fetches
  `/.well-known/security.txt` and records it verbatim, with its fields parsed per
  RFC 9116 and whether it carries an OpenPGP cleartext signature (not verified).
  It then follows each `Policy:` link and extracts its text as `web_page_text`
  does, and each https `Encryption:` link, where an ASCII-armored public key is
  read with the standard library (fingerprint, creation, expiry, user IDs,
  subkeys). Fixed fields come first for validators: `expires_in_days`,
  `canonical_matches_url`, `contact_emails_in_key`,
  `key_expires_after_security_txt`, `policies_all_ok` and `policy_placeholders`
  (`[X]`-style blanks left in the policy). Missing REQUIRED fields, a wrong
  content type and broken linked pages are recorded as findings. The run fails
  only when security.txt itself cannot be collected or parsed. Tested with the
  security.txt and key Paramify publishes, served locally; the key's facts match
  `gpg --show-keys`. Also run live against paramify.com. Linked URLs and their
  redirects may only reach public addresses; a link to a private, loopback or
  link-local address is recorded as `blocked_address`. No KSI mapping.
- **A `zendesk` category and its first fetcher, `zendesk_help_center_section`**
  (`EVD-ZENDESK-HELP-CENTER-SECTION`). Given a Help Center section URL, it lists
  the section's articles through the Help Center API as an anonymous user, so
  only public articles count. It follows `next_page` to the end and fails the
  run when the collected number differs from the API's `count` or any API call
  fails. Each article keeps Zendesk's own fields and body HTML, plus plain
  text, a text hash, any "Last updated" date in the text, and an anonymous GET
  of its page recording whether it was sent to a sign-in page or met a
  Cloudflare bot challenge (a challenge leaves `all_articles_public` null,
  since public access could not be checked). Fixed fields
  come first: article count, newest and oldest `updated_at`,
  `days_since_last_update`, `all_articles_public`, and two Paramify-specific
  keyword heuristics for a Secure Configuration Guide
  (`mentions_top_level_admin`, `scg_terms`) that show keyword presence, not
  adequate guidance, plus `all_user_segments_everyone` (no article is
  restricted to a user segment). An empty section is recorded, not failed.
  Run live against support.paramify.com's Recommended Secure Configuration
  section (4 articles, matching the API's `count`). There, Cloudflare
  challenged every anonymous article-page GET, so `all_articles_public`
  read null. No KSI mapping. The README's supported services grid lists
  Zendesk, using the Simple Icons `zendesk` mark (CC0) in light and dark
  variants (`fetchers/logos/zendesk.svg` and `zendesk-dark.svg`).
- **A `web` category and its first fetcher, `web_page_text`**
  (`EVD-WEB-PAGE-TEXT`). It fetches one public URL per target, with no
  credential, and records the text the page served. For HTML that is the
  visible text, one line per block element, with script, style and head
  dropped and navigation and footer kept. For JSON it is the parsed document
  plus the body verbatim, and plain text is kept as served. Fixed fields come
  first so a validator's first match lands on them: the final URL and each
  redirect, the HTTP status and content type, the `<title>`, a `last_updated`
  date copied verbatim from the first "Last updated" or "Effective date" line
  (or the line after a bare label, as www.paramify.com lays it out),
  the text length, the body's `sha256`, and `text_sha256` of the extracted text,
  which is the stable change signal because markup and per-request tokens do
  not move it. The run fails on a network or TLS
  error, any status other than 200, more than 5 redirects, a body over 5 MB, an
  unsupported content type, JSON that does not parse, or a page with no text,
  which is how a page rendered by JavaScript shows up. The evidence shows what
  the URL served when it was collected, not which version of a document is in
  force. HTML parsing uses the standard library, so there is no new
  dependency; the HTML-to-text and date capture live in `fetchers/_lib/html_text.py`
  for any category to import. Tested with synthetic fixtures. Run live only against GitHub
  pages, because www.paramify.com was not reachable from the test environment.
  No KSI mapping. The README's supported services grid lists Web, with a globe
  icon drawn for this repo (`fetchers/logos/web.svg` and `web-dark.svg`).
- **`jira_change_requests`** (`EVD-JIRA-CHANGE-REQUESTS`): change, internal
  connection and exception tickets with CCB approver and time, deployment time,
  test and security review results, watcher and comment counts, status and field
  history, and per-ticket findings (deployed without approval, approved after
  deployment, failed tests, missing security review, exceptions open past expiry
  or overdue for review). Field names are configurable and resolved by name.
- **`jira_incident_postmortems`** (`EVD-JIRA-INCIDENT-POSTMORTEMS`): incidents with
  severity, category, minutes from detection to report against a reporting window
  and per-category targets, phase history, linked post-mortems and their action
  items, with findings for late reports, missing post-mortems and unassigned or
  overdue action items.
- **`jira_remediation_items`** (`EVD-JIRA-REMEDIATION-ITEMS`): the Jira tickets a
  required JQL (`JIRA_REMEDIATION_JQL`) selects as findings, each with owner, due
  date, overdue flag and full status history from `POST /rest/api/3/changelog/bulkfetch`,
  plus open, closed, overdue, unassigned and days-to-close rollups. Browse Projects only.
- **`jira_audit_records`** (`EVD-JIRA-AUDIT-RECORDS`): the Jira site audit log over a
  lookback window (`GET /rest/api/3/auditing/record`) with actor, time, source address
  and changed values, and a rollup of permission, user, group, workflow and scheme
  changes. Needs the Administer Jira global permission.
- **`jira_access_roles`** (`EVD-JIRA-ACCESS-ROLES`): Jira site-admin and admin groups
  and their members, product access roles, and per project the privileged permission
  grants, project role members and the resolved privileged users, flagging privileged
  grants made to everyone. Needs the Administer Jira global permission.

- **`azure_vnet_egress_routing`** (`EVD-AZURE-VNET-EGRESS`) — where each subnet's
  and network interface's Internet-bound traffic goes, as `egress_path`: an
  appliance, a black hole, a gateway, a NAT gateway, or Azure's implicit default
  outbound access (`default_outbound_access_effective` reads an unset subnet flag
  as on). A default route split into halves (`0.0.0.0/1` + `128.0.0.0/1`) counts as
  the default, and on a subnet whose default goes to an appliance or gateway every
  route straight to the Internet is listed in `internet_bypass_routes`. An
  appliance next hop is resolved to what holds it (`appliance_owner`): an Azure
  Firewall, an IP-forwarding NIC, or something outside the subscription.
  Subnets connected to a Virtual WAN hub with routing intent resolve to the hub's
  firewall when the connection propagates the default route. Each subnet also lists
  its own and its peers' address ranges that are not forced through the appliance.
  Every route table says whether a subnet uses it, and every Azure Firewall carries
  its tier, policy, effective threat-intelligence mode (the strictest along the
  policy's parent chain) and the subnets routed through it. A spoke VNet is
  recognised from its own peerings even when its hub is in a separate connectivity
  subscription. The hub is then looked for in up to 50 other subscriptions the
  credential can read (`VIRTUAL_HUB_SEARCH_MAX_SUBSCRIPTIONS`), keeping only that
  hub's connections to this subscription's spokes; a spoke still not found reads
  `virtual_hub_unresolved`, not `default_outbound`. Load balancer outbound rules are
  not evaluated. Configured routes only:
  effective routes need an action Reader does not have. Tested read-only against a
  production subscription, where every count matched Resource Graph.
- **`azure_ddos_protection`** (`EVD-AZURE-DDOS`) — every public IP, what holds it,
  its virtual network and its `effective_protection`: `network_protection` (a DDoS
  plan on the VNet), `ip_protection`, `none`, `disabled`, `not_supported` (NAT
  gateway IPs, which DDoS Protection cannot cover), or `unknown` where the VNet
  cannot be resolved. A public load balancer frontend takes its backend pools' VNet.
  Also every DDoS
  protection plan and the VNets that use it. Virtual WAN hub firewall addresses are
  not public IP resources and are not listed.

- **Four Azure fetchers: flow logs, AI services, managed identities and API
  Management**, read-only on the built-in Reader role. `azure_network_flow_logs`
  reports every Network Watcher and flow log (target, retention, storage
  destination, Traffic Analytics) and works out which virtual networks and
  subnets have their traffic logged, counting subnets with workloads apart from
  empty ones and those Azure allows no NSG on; legacy NSG flow logs are marked,
  since Microsoft retires them in September 2027. A flow log with no retention
  policy keeps records indefinitely, and a filtered VNet flow log is not full
  coverage. `azure_ai_services_configuration`
  reports each Azure AI services account (Foundry, OpenAI, Language, Speech,
  Document Intelligence) and AI Search service: network exposure, whether API
  keys still work, customer-managed keys, managed identity and whether audit
  logs are exported; every model deployment with its publisher, where it may
  process data (global, data zone or regional) and its content filter and
  Prompt Shields protection, judged on the four harm categories because
  Microsoft's own default annotates some filters rather than blocking them;
  custom filter policies weaker than the default; and every Foundry connection
  agents use, with whether it holds a stored secret. `azure_managed_identity_configuration` reports every user-
  and system-assigned identity with what it is attached to, its federated
  credentials (GitHub subject breadth, flexible matching expressions,
  audiences), its Microsoft Graph application permissions, and its role
  assignments judged by what each role's permissions allow (full control,
  granting access, reading keys, full data access) rather than by name.
  `azure_api_management_configuration` reports each API Management service's
  network exposure, legacy TLS and every switchable cipher (unset switches
  follow Azure's documented defaults, which leave the CBC and RSA-key-exchange
  suites on), whether legacy management API versions are blocked, certificate
  expiry, developer portal sign-up, its subscriptions including the built-in
  all-access one, which security policies apply at global, product, API and
  operation level, how each API is protected, its backends and whether gateway
  logs are exported; policy XML, named-value contents and subscription keys are
  never written to the evidence. Adds
  azure-mgmt-cognitiveservices, azure-mgmt-msi and azure-mgmt-apimanagement.
- **Three Azure fetchers: AI hubs, container workloads and the data tier**,
  read-only on the built-in Reader role. `azure_ai_hub_configuration` reports
  each AI hub, AI project and Machine Learning workspace: network exposure,
  managed virtual network isolation and outbound rules, high business impact,
  customer-managed keys, whether system datastores are reached with the storage
  key or an identity, every datastore's credential type, every model endpoint's
  authentication mode and public access, compute public IPs and SSH, diagnostic
  log export, and every connection with whether it holds a stored secret. It
  reads ARM JSON because the Machine Learning SDK predates hubs.
  `azure_container_workloads_configuration` reports Container Apps environments
  (internal-only or public, mTLS and peer traffic encryption, log destination),
  apps and jobs (secrets stored in the app rather than Key Vault, password-based
  registry pulls, plain environment variables with secret-looking names,
  internet-facing ingress and whether Easy Auth stops an unauthenticated caller
  (AllowAnonymous does not), images running a
  mutable tag rather than pinned by digest) and Container Instances
  container groups (public IP, VNet placement, registry credentials, Azure
  Files volumes, logging). `azure_data_services_configuration` reports MongoDB
  vCore clusters (firewall rules judged on how many addresses they admit
  together, native versus Entra authentication,
  high availability), Data Explorer clusters (open allow-lists, trust of any
  external tenant, purge rights, callout policies, principal assignments) and
  Event Hubs namespaces (minimum TLS, network rules, shared keys with Manage
  rights while local auth is on at namespace and hub level, geo-replication,
  event hub retention and capture), each with customer-managed keys and audit
  log export. ARM JSON is read through the shared `arm_rest` client and log export
  through `_shared/diagnostics.py`. New shared modules: `foundry_connections.py`
  (connection auth types, also used by `azure_ai_services_configuration`) and
  `ip_ranges.py` (firewall-range width). Adds
  azure-mgmt-appcontainers, azure-mgmt-containerinstance, azure-mgmt-mongocluster,
  azure-mgmt-kusto and azure-mgmt-eventhub.

- **Default custom tags on everything the uploaders create.** Every evidence
  set, script and validator that `paramify upload`, `paramify scripts sync`
  and `paramify validators sync` create or maintain now carries two custom
  tags: a provenance tag, `Automated by Paramify Fetchers`, and a service tag
  from the category's new `display_name` (`AWS`, `Okta`, `SentinelOne`).
  Tags are added on every run and never removed, so a user's own tags on
  those resources are left alone and resources from earlier runs are
  backfilled. Both are `upload.yaml` knobs under `tags:` — rename the
  provenance string, drop either tag, or set `tags: false` for none. To
  switch the feature off without touching a file, set
  `PARAMIFY_CUSTOM_TAGS=off` in the environment, or pass `--no-tags` to any
  of the three commands for one run; the Done block says which switch is in
  effect. A token without the custom-tags permission gets one warning and
  the stage proceeds untagged. Every category file now declares a `display_name`; the category
  schema gains the optional field. `paramify validators sync` reads the
  repo's `upload.yaml` by default, as the other two stages already did.

- **`azure_redis_cache_configuration`**, for classic Azure Cache for Redis
  (`Microsoft.Cache/redis`), the sibling of `azure_managed_redis_configuration`.
  Per cache it reports the minimum TLS version and whether the non-TLS port is
  enabled, whether authentication is required at all, whether access keys are
  disabled so only Entra ID can be used, public network access, private
  endpoints, VNet injection and firewall rules, judged on the distinct addresses
  all rules admit together so a split or near-total range is visible. For an assessor it also reports who holds Entra data-access
  policies, whether connection and Entra sign-in audit logs reach a destination
  (through a new shared `_shared/diagnostics.py`), the maintenance window, and
  replication, zone redundancy (including Azure's Automatic zonal allocation),
  geo-replication and persistence, and its summary names the
  caches behind each failed expectation. `list_keys` is never called and
  the projection is an allow-list, so access keys and the storage connection
  strings in the cache's Redis configuration never reach the evidence. A cache
  without `minimumTlsVersion` accepts TLS 1.0 and is not counted as TLS-only, and
  any per-cache read that fails is recorded as unknown. Adds `azure-mgmt-redis`.
  Verified against a live subscription.

- **A third fetcher kind, `kind: inventory`**, for fetchers that list every
  asset of a kind for Paramify's Inventory. An inventory is evidence with a
  record contract: the payload holds `data`, one record per asset each with a
  unique `unique_asset_identifier`, and `records_included`. The record fields
  are each fetcher's own. It needs an `evidence_set` and goes to it through
  `paramify upload`, where an inventory pipeline attached to the set builds
  Inventory items. A pipeline reads the file as the whole estate, so the
  runner checks every inventory output when it envelopes it and records the
  verdict in `metadata.inventory`, and the uploader does not send one that is
  incomplete: a failed run, a contract break, withheld records, or no records
  at all. The TUI lists inventories in their own section. Start from
  `fetchers/_template_inventory/`; see `docs/inventory_fetchers_guide.md`.

- **Two Azure fetchers for private connectivity**, read-only on the built-in
  Reader role. `azure_private_endpoint_configuration` reports each private
  endpoint's connection status (Approved, Pending, Rejected or Disconnected),
  subnet, private IPs and private DNS zone groups, and for its target resource
  whether it still exists and whether public network access is disabled. An App
  Service slot is checked on the slot, not its parent site. Per endpoint subnet
  it reports whether the subnet's NSG and route table apply to endpoint traffic,
  which Azure does only when the subnet's endpoint network policies are on.
  `azure_private_dns_zone_configuration` reports each private DNS zone's virtual
  network links and record sets, and checks every IP of each `privatelink` A
  record against the private endpoints that hold it: backed, ip_mismatch, stale
  or unverified, with a record that has a dead IP next to a live one reported as
  partially backed. The match is on the record's own name, because a public name
  derived from the zone is wrong for Key Vault and AKS. Zone names that exist
  more than once are found across every subscription the credential can read.
  Both record whether Microsoft.Network is registered. A failed lookup is
  reported as unknown, never as deleted or stale, and a resource whose
  subscription or resource group the credential cannot read is reported as not
  visible rather than deleted. Shared Resource Graph paging and the readable-scope
  check live in `_shared/azure_common.py`.

- **Four Azure fetchers for the network edge and cache tier**, read-only on
  the built-in Reader role. `azure_managed_redis_configuration` reports each
  Azure Managed Redis cluster's minimum TLS version, public network access and
  private endpoints, and per database the client protocol (Encrypted or
  Plaintext) and whether access-key authentication is disabled. Classic Azure
  Cache for Redis is not read. `azure_dns_configuration` reports each public
  zone's DNSSEC state and signing keys, and each private zone with its virtual
  network links. The DNS SDK has no DNSSEC operation, so it is read with a
  direct ARM call, and a 404 "DNSSEC is not enabled" counts as unsigned rather
  than as a failed collection. `azure_vpn_gateway_configuration` reports VPN
  gateways, the IKE version, status and IPsec policy of each connection, and
  point-to-site protocols and sign-in types. A connection with no custom policy
  is reported against Azure's default, whose IKEv2 main mode uses DH Group 2, so
  the default does not read as free of weak algorithms. Point-to-site counts only
  when a client address pool exists, because the list call returns a placeholder
  on gateways that never set it up.
  `azure_virtual_wan_configuration` reports Virtual WANs, whether hubs are
  secured by a firewall, and the IKE version on each site link, along with
  vWAN VPN sites, point-to-site gateways and server configurations. The DNS,
  VPN and Virtual WAN fetchers record whether Microsoft.Network is registered,
  so zero resources can be told apart from a provider that is off. A read that
  fails (a Redis cluster's databases, a zone's DNSSEC config) or an IKE protocol
  Azure leaves empty is recorded as null and counted as unknown, never as
  compliant, unsigned or IKEv1. Both VPN
  fetchers keep an allow-list of fields, because Azure returns site-link
  pre-shared keys in plain text to Reader; no key reaches the evidence.
  Verified against a live subscription.

- **Evidence samples: one record per fetcher, captured once.** A fetcher can
  now carry a `sample.json` beside its `fetcher.yaml` that shows what it
  collects without anyone running it. Where the payload repeats a record (one
  entry per instance, user or subnet), the sample keeps the most filled-in
  one, with how many were seen and how often each field was filled in. New
  commands: `paramify samples status`, `paramify samples show <fetcher>` and
  `paramify samples backfill`, which builds samples from past runs under
  `./evidence`. Backfill replaces emails, person names, logins, account ids,
  UUIDs, long hex ids, IP addresses and target values with stable fakes of the
  same shape, and does not write a sample in which any identifier from any
  scanned file survives. Free text is not rewritten, so a backfilled sample
  starts `"reviewed": false` and needs a person to read it before it is
  committed. See
  [`docs/evidence_samples.md`](docs/evidence_samples.md).

- **Discovery fetchers (`kind: discovery`)**, a fourth collection kind that
  lists what a platform's credentials can see instead of collecting evidence.
  The runner writes their output to `<run>/discovery/`, which neither uploader
  reads. Every platform writes the same JSON document
  (`framework/schemas/discovery_schema.json`). Each resource type says whether
  it could be read (`ok`, `denied`, `not_enabled`, `error`, or `truncated` with
  a lower-bound count), so a type that could not be read never looks like one
  with nothing in it. Records about people are counted, never listed. The
  shared engine in `fetchers/_lib/discovery.py` handles paging, retries and the
  document, so a platform's fetcher is a table of resources plus its paging. The
  first is `knowbe4_discovery_beta`: account, groups, training campaigns, modules,
  policies, phishing campaigns and tests, and user and enrollment counts. It
  pages by cursor, since KnowBe4 retires the `page` parameter in November 2026.
  The second is `aws_discovery_beta`: about 75 resource types, at least one for every
  AWS service an AWS fetcher reads (a test keeps that true), listed in every
  enabled region through the aws CLI, plus a count per resource type from AWS
  Resource Explorer wherever it has an index, with each (type, region) pair carrying
  its own status so a region denied by a service control policy never reads as
  empty. One document per target account. See `docs/discovery.md`.
- **A Wiz category with twelve fetchers**, for Wiz commercial and Wiz for
  Government, sharing one GraphQL client and one service account. Eleven are
  evidence fetchers: `wiz_scan_coverage`, `wiz_posture_issues`,
  `wiz_infrastructure_vulnerabilities`, `wiz_container_vulnerabilities`,
  `wiz_cloud_configuration_posture`, `wiz_host_configuration_posture`,
  `wiz_threat_detections`, `wiz_file_integrity_monitoring`,
  `wiz_attack_surface_findings`, `wiz_code_findings` and
  `wiz_tenant_security_settings`. The last five read Wiz modules a tenant may
  not have; each checks the tenant's schema at run time, selects only the
  fields that exist, and lists the missing ones in the evidence. A missing
  scope or licence fails the collection rather than reading as no findings.
  The twelfth, `wiz_stig_compliance_report`, is an issue report: one CSV row per
  STIG control, rule and resource for one enabled Wiz framework, for a
  CONFIGURATION assessment's pipeline. Wiz's own compliance CSV exists only as
  a saved report, and creating or rerunning one is a write, so the rows are
  built from GraphQL queries instead, in a fixed column set and sorted order so
  the same Wiz state gives the same file. Every result is reported, not just
  PASS and FAIL, so a check that moves to ERROR is not read as fixed. Any Wiz
  error, Wiz's 10,000-row cap, an empty result, a disabled framework, or a
  finding Wiz returns without its control mapping fails the run with no file
  written.
  None of the twelve writes to Wiz: the client refuses to send a mutation.
- **Two more Wiz issue reports, `wiz_issues_report` and
  `wiz_vulnerability_findings`**, on the same read-only client and config
  names. `wiz_issues_report` sends Wiz's own Issues CSV to a CONFIGURATION
  assessment. The report is created once in Wiz and scheduled there; the
  fetcher finds it by `report_id` or exact `report_name`, and downloads its
  last run only if that run completed within `max_report_age_hours` (default
  26). It never creates, edits or reruns a report, so the service account
  needs `read:reports` and nothing that writes. `wiz_vulnerability_findings`
  pages through every vulnerability finding and writes the legacy Paramify
  column layout for a VULNERABILITY assessment, with an optional `project_id`
  filter. Both export everything on every run (no delta mode, since a delta
  processed with a cycle close resolves every issue it leaves out), and any
  read failure, an empty export (unless `allow_empty`), or an interrupted
  download fails the run with no file written. See
  `docs/wiz_pipeline_fetchers.md`.
- **`paramify issues upload` names the cycle an upload landed on**, and warns
  when newer cycles exist. Uploads land on the assessment's oldest open cycle,
  so an old cycle left open takes every new scan while the newer cycles show
  nothing. The TUI's Paramify tab shows the same warning. An HTTP 409 now
  quotes Paramify's reason instead of assuming no cycle is in progress, since
  work aimed at a cycle other than the in-progress one is refused the same way.
- **The issues uploader only reads reports inside the run's `issue-reports/`.**
  A report path in `_issue_reports.json` that resolves outside it, or a report
  that is a symlink, is refused and nothing is read, so an edited index cannot
  send another file to Paramify as a scan report.
- **`_issue_reports.json` is written atomically, and a corrupt one never closes
  a cycle.** An index that cannot be read is kept beside the new one as
  `_issue_reports.json.corrupt`, and the new index is marked `cannot_close`:
  the uploader processes that run's reports but does not close the cycle,
  because the index can no longer show that every target succeeded. The TUI's
  Run tab shows why a fetcher failed next to its status, and focus returns to
  the Paramify tab when a send finishes, so its keys work without pressing 5
  again.
- **Evidence sets carry a collection frequency.** `evidence_set.frequency` in
  `fetcher.yaml` takes Paramify's evidence frequency values (`DAILY`,
  `THREE_DAY`, `WEEKLY`, `BIWEEKLY`, `MONTHLY`, `QUARTERLY`, `BIANNUAL`,
  `ANNUAL`, `NOT_SET`) and defaults to `THREE_DAY`, so every fetcher has one
  without a change to its file. The runner copies it into the envelope's
  `metadata.evidence_set`, and both uploaders send it when they create a set.
  Sets that already exist keep the frequency they have. The uploader config can
  override it per fetcher, like `name` and `instructions`.
- **`docs/pipelines_guide.md`: sending scan reports from the TUI**, step by step
  with three recordings. It covers a manifest for the scanners, pointing each
  fetcher at an assessment and choosing its close policy, running and sending
  from the Paramify tab, and jobs and manual closes. It explains how cycles
  work, lists what each error means, and maps every step to its command.
- **`paramify issues jobs` and `paramify issues close`.** `jobs` lists an
  assessment's pipeline jobs and retries or cancels one (`--retry`, `--cancel`);
  a failed job blocks every job queued behind it on the same assessment until
  one of those happens, and nothing does it automatically. `close` closes an
  assessment's current cycle on its own, after confirmation, for assessments
  whose cycle is filled by several runs, and prints how many open issues the
  close auto-closed.
  The TUI's Paramify tab has both: `j` lists jobs and retries or cancels one,
  `C` closes one of the manifest's assessments' cycles behind a warning. The
  reports themselves are sent with `i`, which replaces `ctrl+i` (most terminals
  send the same byte for ctrl+i and Tab, so it never fired). The run console
  says when a run left issue reports to send, and the assessment picker no
  longer blocks the app while it lists the workspace's assessments.
- **Issue-report invocations in the sidecar.** `_issue_reports.json` (schema
  1.1) gains `invocations`: one entry per issue-report invocation, including a
  failed one that wrote no file and an entry that raised before running. Before
  this, a failed target that wrote nothing left no trace, and a run missing one
  framework's report looked complete.
- **A Splunk category with seven fetchers**, one Splunk Enterprise deployment per
  target, each with its own management URL (port 8089) and bearer token.
  `splunk_index_retention` (retention, archive-or-delete on freeze, data
  integrity control), `splunk_index_activity`, `splunk_log_source_freshness`,
  `splunk_data_inputs`, `splunk_alert_rules` (Splunk Web's own alert definition,
  with run and fire history from `_internal` and `_audit`),
  `splunk_alert_delivery` and `splunk_role_index_access` (effective index access
  after inheritance and denials, delete rights, dormant accounts). This closes
  KSI-MLA-ALA. Every fetcher is a `collect(client, config)` function handed to a
  shared `run()`, which checks the token's capabilities first and fails the
  collection, rather than publishing a partial list, when Splunk returns less
  than everything: a `count` cut short of `paging.total`, a search answered with
  a warning, or an index list that disagrees with `indexes.conf` and the search
  peers. Tested against Splunk Enterprise 10.4.3, where a role with no
  capabilities saw 1 of 4 users and 127 of 176 saved searches, and stock `admin`
  12 of 26 roles, each time with a `paging.total` that agreed. The collection role
  is in `fetchers/splunk/README.md`. Splunk Cloud is not yet supported.

- **A Better Stack category and its first fetcher** —
  `betterstack_public_status_page`, which GETs a public status page's own
  `/index.json` and records it as evidence. No credential: a Better Stack status
  page publishes that document to anyone who can reach the page, so the fetcher
  sends nothing and the category declares no secrets. The response is kept
  verbatim — `data` and `included` exactly as the page returns them, nothing
  removed, renamed, recomputed or flattened — alongside the URL actually
  fetched and a collection timestamp. The one field added to it,
  `lowest_reported_availability`, is a selection rather than a calculation: it
  names the component reporting the lowest availability and copies that value
  out of the response unchanged, so the evidence carries the same figure the
  status page UI shows (0.999915 reads there as "99.991% uptime"). It exists
  because a Paramify `MATCH_GROUP` rule reads one capture group while the
  number of components varies per page — naming the weakest component gives
  such a rule one field to compare that still speaks for the whole page. Ties
  break on the lowest resource id so an unchanged page selects the same
  component every run, and the field is omitted rather than invented when no
  component reports a numeric availability. Completeness is enforced rather
  than assumed: every id named under `data.relationships` and every status
  update a report references must be present in `included`, and a shortfall
  fails the collection instead of producing a populated-looking partial
  payload, as do a non-200, a body that is not JSON, and a body that is not a
  status page document. The fetcher fans out per status page and is generic —
  it knows nothing about any particular page — and `fetcher.yaml`'s
  `evidence_set.instructions` states plainly what the evidence cannot show:
  that Better Stack's `availability` counts hard downtime only, with degraded
  and maintenance periods excluded from it, and that `/index.json` carries no
  monitor configuration and so proves nothing about check frequency, what is
  actually probed, or monitoring regions.
- **A validator for the Better Stack status page set**
  (`validators/betterstack/`, with behaviour cases under `validators/_cases/`).
  One `configuration` check: a `MATCH_GROUP` rule comparing a component's
  reported `availability` against a 0.999 baseline, anchored on the shape of a
  status_page_resource rather than on any component's name, so it holds for any
  customer's page. Collection health stays where it belongs, in the shared
  `validators/common/collection_succeeded.yaml`, which the set is listed on.
- **`azure_app_service_plans`** — every App Service plan with its SKU name and
  tier, instance count (`sku.capacity`), zone redundancy and scaling settings,
  plus the web apps and function apps running on it (joined by
  `server_farm_id`). App Service availability is a property of the plan, not the
  app, so nothing in the existing Azure evidence showed whether an app survives
  losing an instance or a zone. The summary counts zone-redundant plans,
  multi-instance plans, single-instance plans, and plans on a no-SLA tier (Free,
  Shared); consumption and elastic plans are flagged `platform_scaled`, since
  their capacity is not a fixed instance count. Reader-only; evidence set
  `EVD-AZURE-APPSVC-PLANS`.

- **`azure_defender_regulatory_compliance`** (`EVD-AZURE-DEFENDER-REG-COMPLIANCE`)
  — Defender for Cloud's regulatory compliance grading, nested standard → control
  → assessment with passed / failed / skipped counts at each level, and headline
  keys for the Microsoft cloud security benchmark (`mcsb_failed_controls`,
  `mcsb_failed_control_names`, ...). `azure_defender_assessments` has the same
  results flat, one row per resource and check; this groups them by benchmark
  control. A subscription with Microsoft.Security unregistered, or with no
  Standard-tier Defender plan (the service refuses regulatory compliance on the
  free tier), reports it as `regulatory_compliance_status` and exits 0.

- **`azure_policy_compliance`** (`EVD-AZURE-POLICY-COMPLIANCE`) — what the assigned
  Azure Policies found, where `azure_policy_assignments` only says what is
  assigned. From `azure-mgmt-policyinsights` (a new pinned dependency of the
  `azure` extra): the subscription-wide and per-assignment counts of
  non-compliant resources and policies from `policy_states` summarize, a bounded
  list of the non-compliant (resource, policy) records
  (`max_non_compliant_resources`, default 1000, with a truncation flag), and the
  remediation tasks with their deployment counts. The evaluation window the
  service applied is recorded, and `resources_evaluated` tells "nothing
  non-compliant" from "nothing evaluated".

- **A Jira category, and its first fetcher: `jira_site_inventory`.** One
  evidence set covering a Jira Cloud site end to end: deployment info, every
  project the account can browse (type, lead, issue types, issue count), the
  issue types, priorities and statuses in use, Jira Service Management service
  desks where the site has JSM, and every issue updated in the lookback window
  (90 days, or an explicit `jql`) with rollups by project, type, status and
  priority, time to resolution, and separate change and incident counts.
  Account email + API token, declared once on the category; no Jira admin
  needed. See [`fetchers/jira/README.md`](fetchers/jira/README.md).
- **A fanout target editor in the TUI** (`t` on the Manifest tab). A fanout
  fetcher runs once per target, so its targets are the run plan — but the page
  showed only how many there were, and there was no way to change one: fixing a
  typo'd account id meant removing the target and retyping every field. `t` now
  opens the fetcher's targets as a table, with `a` add, `e` edit, and `x` remove
  on the highlighted row. Fields come from the fetcher's `target_schema`, so the
  form is whatever that fetcher actually takes, per-target secrets included.
- **`paramify manifest set-target <fetcher> <index> k=v …`** — the CLI half of
  the editor. A replace rather than a merge, so a field cleared in the form is
  actually cleared; the target's per-target secrets are preserved unless
  `--secret` is passed.
- **Upload artifacts through the evidence set's channel.** Where a set has one,
  the uploader now sends `channelId` with the artifact: an artifact uploaded
  outside a configured channel does not count toward validation on the solution
  capability. No configuration — a set with a channel uses it, a set with none
  uploads unchanneled exactly as before. A set with more than one channel errors
  that file rather than guessing, until the rules for choosing exist. The channel
  is recorded per file in `upload_log.json`, since the API does not report it back
  on an artifact. See [`docs/uploader_guide.md`](docs/uploader_guide.md).
- **A default uploader config at `./upload.yaml`.** Every upload stage falls back
  to it when no `--config` is given, which is how the TUI — which passes no path —
  reaches base_url and the per-fetcher overrides at all. Both front-ends now name
  the config in use before a batch runs.
- **A central `validators/` registry.** A validator is now a first-class,
  deduplicated object — one file at `validators/<category>/<key>.yaml`, checked
  against the new `framework/schemas/validator_schema.json`. It carries the
  Paramify fields as native YAML and owns its side of the fetcher link through an
  `evidence_sets` list of `reference_id`s, so a validator that applies to four
  fetchers is one file naming four sets rather than four copies drifting apart.
  A fetcher's validators are the reverse lookup on its `evidence_set.reference_id`.
  See [`docs/validators_guide.md`](docs/validators_guide.md).
- **Validator sync** — `paramify validators sync` and `paramify upload
  --with-validators` (engine in `uploaders/paramify_validators/`). Pushes registry
  validators to Paramify (`POST /validators`) and CONNECTs each to its evidence
  sets. The validators shipped here are templates that customers tune in their own
  instance, so the sync is **create-or-skip**: an existing validator is never
  modified unless `--update` is passed, association happens on create only, and
  `--dry-run` previews without writing. The per-instance Paramify id is resolved
  at sync time and cached in a gitignored `.paramify/` lock — never written back
  to the shared registry.
- **`azure_entra_service_principals`**, the tenant's non-user accounts. The
  Azure category saw app registrations but not service principals, so a managed
  identity, a principal for another tenant's app, or a secret held directly on a
  service principal was invisible. Every service principal is now reported with
  its type, its owner (Microsoft first-party, this tenant, or another tenant) and
  every credential it can present, including federated identity credentials on
  this tenant's applications. The summary counts managed-identity, federated,
  certificate-based and secret-based principals, and credentials that are
  expired, expire within 30 days, or never expire. It makes two paged Graph reads
  per tenant, never one per principal, and needs `Application.Read.All`.
- **`azure_entra_authentication_policy`** shows which sign-in methods the tenant
  allows. `azure_entra_mfa_status` shows what users have registered, but not
  whether the tenant still accepts SMS alongside the FIDO2 keys they registered.
  Every method in the authentication methods policy is reported with its state,
  targets and settings. SMS and Voice are flagged weak, and FIDO2 (passkeys
  included) and X.509 certificates phishing-resistant. The fetcher also reports
  the registration campaign, the policy's migration state (legacy MFA/SSPR
  policies still apply until it completes), security defaults, and Entra password
  protection (custom banned-password list, smart lockout). It reports the Entra
  ID licence tier too, because a custom banned-password list is only enforced
  with P1. Needs `Policy.Read.All` and `Directory.Read.All`. An `az login`
  session cannot read the methods policy, because the Azure CLI's client is not
  pre-authorized for `Policy.Read.All`.
- **`azure_resource_inventory`** — an automatically generated inventory of every
  resource in the subscription, from one Azure Resource Graph query over the
  `Resources` table: id, name, type, location, resource group, tags, SKU, kind and
  provisioning state, with counts by type and by location and the number of
  untagged resources. The per-service fetchers each see only their own resource
  types, so nothing listed the subscription as a whole. The query is paged to the
  end; a truncated result, or a page count that disagrees with Resource Graph's own
  total, is a collection failure rather than a shorter inventory. Adds the
  `azure-mgmt-resourcegraph` dependency to the `azure` extra.
- **`azure_log_analytics_workspaces`** — every Log Analytics workspace with its
  SKU, workspace retention, daily ingestion cap, public network access for
  ingestion and query, access control mode
  (`enableLogAccessUsingOnlyResourcePermissions`), and whether shared-key auth is
  disabled. Per-table retention is summarized as counts by plan and retention
  plus the minimum across tables, with only the tables that override the
  workspace default, or are custom, listed by name — a workspace carries several
  hundred built-in tables. Also the workspace's data export rules and whether
  Microsoft Sentinel is onboarded (the SecurityInsights solution is enabled).
  Nothing in the Azure category recorded where logs are kept or for how long.
  Adds the `azure-mgmt-loganalytics` dependency to the `azure` extra.
- **Seven Microsoft Sentinel and Log Analytics log-integrity fetchers.** Per
  Sentinel workspace (`SENTINEL_WORKSPACES`, or every onboarded workspace in the
  subscription): `azure_sentinel_data_sources` (connectors, plus which tables
  and alert products actually ingested in the window),
  `azure_sentinel_analytics_rules`, `azure_sentinel_incidents` (status,
  classification, time to close) and `azure_sentinel_automation_rules`. Per Log
  Analytics workspace, Sentinel or not: `azure_log_analytics_query_audit`
  (whether queries are audited, and weekly human vs app query counts) and
  `azure_log_analytics_deletion_rights` (who, active or PIM-eligible, can purge
  or delete log data, delete the workspace or shorten its retention, and
  whether through a wildcard role). Per subscription:
  `azure_log_storage_immutability` (immutability policy, legal hold and soft
  delete on the containers Azure Monitor writes logs to; only a Locked policy or
  a legal hold counts as protected). They share `_shared/azure_rest`, which
  calls ARM, Graph and the Log Analytics query API directly, since the only
  stable Sentinel SDK pins a 2021 API version, and retries throttling and
  transient server errors, honouring Retry-After. Analytics rules are listed at
  the stable and the preview API and merged, since NRT rules exist only in
  preview. Data older than a table's retention is reported as not retained,
  never as missing.

- **Three Azure SQL Managed Instance fetchers.** Nothing in the Azure category
  covered Managed Instance, which has its own API surface apart from SQL
  Database. All three are Reader-only and fan out per subscription.
  - `azure_sql_managed_instance_backups` (`EVD-AZURE-SQLMI-BACKUPS`): short- and
    long-term retention for each database, the instance's backup storage
    redundancy (requested vs current, so a pending change shows), compute zone
    redundancy, and the instance failover groups with their failover policy and
    instance pairs. Azure lists a failover group once from each region it spans,
    each with its own resource id; the fetcher merges them into one record.
  - `azure_sql_managed_instance_configuration` (`EVD-AZURE-SQLMI-CONFIG`): the
    public data endpoint, proxy override, minimum TLS version, private endpoint
    connections, the Entra admin and Entra-only authentication, and whether a
    diagnostic setting exports `SQLSecurityAuditEvents`. That shows the audit
    route only; whether a server audit is on is set in T-SQL, which no ARM call
    can read.
  - `azure_sql_managed_instance_encryption` (`EVD-AZURE-SQLMI-ENCRYPTION`): the
    TDE protector (service-managed or Key Vault key, auto-rotation) and TDE
    state for each database.

  Any system database the API lists is flagged and left out of every count. A
  failed call leaves every flag and total derived from it null rather than
  false or 0, so an unanswered call never reads as "off".

- **`azure_resource_diagnostic_settings`** (`EVD-AZURE-RESOURCE-DIAG-SETTINGS`)
  — resource-level logging across the whole subscription. `azure_diagnostic_settings`
  reads only the subscription's activity log export, and the per-service fetchers
  only their own types, so nothing showed which resources' logs go nowhere. Every
  resource Resource Graph lists, plus the blob, file, queue and table services
  each storage account's kind has, is checked for the log categories its type emits and the
  diagnostic settings that export them: `has_enabled_log_setting`,
  `destination_types`, `sends_to_log_analytics`, `uncaptured_log_categories` and
  `captures_all_audit_categories`. The summary gives log-setting and Log
  Analytics coverage of the log-emitting resources, with the uncovered ones
  counted by type; metrics-only and unsupported types are outside the
  denominator. A row count that disagrees with Resource Graph's total, or any
  read error other than an unsupported type or a since-deleted resource, fails
  the run. One `ResourceTypeNotSupported` answer covers the rest of that type.
  Reader-only; about 14 resources a second, timeout 3600s.
- **`azure_alert_rules`** (`EVD-AZURE-ALERT-RULES`) — every metric alert, log
  search alert and smart detector rule, resolved through its action groups to
  the receivers it notifies and checked against alert processing rules that
  suppress or add notifications. A processing rule scoped narrower than the
  alert is a partial match. Per rule: `routes_to_enabled_receiver`,
  `routes_to_person` (email, SMS, voice, app push, ARM role or ITSM; webhooks,
  Logic Apps, Functions, runbooks and Event Hubs may or may not reach anyone),
  `suppressed` and `reaches_human`, each true, false or null when unknown. The
  summary counts unknown verdicts apart rather than as "no". Read through raw ARM REST, since `azure-mgmt-monitor` 6.x drops
  `nextLink` on metric alerts and action groups and reads log alerts in the 2018
  schema. Reader-only.
- **`azure_change_provenance`** (`EVD-AZURE-CHANGE-PROVENANCE`) — every
  control-plane change in the subscription over Resource Graph's 14 days of change
  history, attributed by correlationId to the ARM deployment that made it, to a
  configured pipeline identity, or to a direct edit. A deployment a person ran,
  from the CLI or through the Portal's create wizards, is `manual_deployment` and
  does not count as a redeployment. Changes Azure records with no caller take the
  origin of the nearest named change to the same resource, then of a deployment
  whose run and outputs cover them, and are otherwise `platform` or
  `unattributed`. The summary gives `percent_redeployed`, a
  `percent_redeployed_conservative` that counts unattributed changes against it,
  direct edits by client, caller and resource type, and the direct changes in
  resource groups deleted since, whose deployment history went with them.
  Reader-only. Maps to `KSI-CMT-RMV`.
- **`azure_residual_resources`** (`EVD-AZURE-RESIDUAL-RESOURCES`) — leftovers in
  the subscription: unattached disks, NICs, NSGs, public IPs and NAT gateways,
  disconnected private endpoints, private DNS zones linked to no network, App
  Service plans hosting nothing, empty resource groups, user-assigned identities
  with no attachment, role or federated credential, stopped or long-untouched
  deployment slots, and role assignments whose principal Entra ID no longer has.
  Cross-tenant `ForeignGroup` principals are never reported deleted, and the run
  fails rather than guess when Microsoft Graph is signed in to a tenant other than
  the subscription's. Needs Reader, plus Microsoft Graph `Directory.Read.All`
  (admin-consented) when it runs as a service principal. Maps to `KSI-SVC-PRR`.
- **Three Azure Application Gateway fetchers.** All three are Reader-only and
  fan out per subscription. They share `_shared/app_gateway.py`, which fails
  the run when `list_all` returns a different number of gateways than Resource
  Graph counts. Resource Graph can lag behind `list_all`, so a mismatch is
  counted once more after 30 seconds before the run fails.
  - `azure_app_gateway_tls_listeners` (`EVD-AZURE-APPGW-TLS-LISTENERS`): every
    L7 and L4 listener, with its protocol, a public or private frontend,
    whether a plain-HTTP listener only redirects to HTTPS, and the effective
    minimum TLS version along with where it comes from. The source is the SSL
    profile, then the gateway's `sslPolicy`, then the default predefined policy.
    An L4 Tcp listener always counts as plaintext, even when TLS passes through
    it to the backend.
  - `azure_app_gateway_backend_tls` (`EVD-AZURE-APPGW-BACKEND-TLS`): every
    backend setting, with its protocol, whether the certificate chain and SNI
    are validated, its trusted roots and its probe protocol, plus which rules
    use it. Only settings that are in use count towards the totals.
  - `azure_app_gateway_waf` (`EVD-AZURE-APPGW-WAF`): the WAF that applies to
    each HTTP(S) listener. A path rule's policy overrides the listener's, which
    overrides the gateway's, which overrides the legacy configuration. The
    fetcher reports whether that WAF is enabled in Prevention mode, and each
    policy's disabled managed rules, exclusions and rate-limit rules. A policy
    in another subscription is read with a direct GET. If the identity is
    refused (401 or 403) or the policy no longer exists (404), the policy is
    recorded as unreadable, the listener's result is null rather than
    "enforcing", and the run does not fail. Any other error does fail it.

  These fetchers were run against a live subscription with one gateway. SSL
  profiles, attached WAF policies and L4 listeners have not yet been
  exercised against live data. `tests/test_azure_app_gateway_verdicts.py`
  covers those paths against modelled gateways.

### Changed

- **New evidence sets start their collection schedule on the day they are
  created.** Both uploaders (`paramify_evidence` and `paramify_scripts`) now send
  `startDate` (today, `YYYY-MM-DD`) alongside `frequency` when they create an
  evidence set, so the TUI and `paramify upload` no longer leave it unset.
  Existing sets are reused unchanged.
- **`aws_config_conformance_packs` maps rules to FedRAMP Low and Moderate and
  to NIST 800-53 Rev. 5 controls** (0.1.0 → 0.5.0). Deployed rule names change on
  each redeploy, so each one now resolves to its stable source identifier. The
  raw AWS response stays in the evidence. Adds Moderate pack support and a
  control-to-rule view.
- **`aws_detect_new_aws_resource` finds rules and topics with other names, and
  accepts event-driven rules** (0.1.0 → 0.2.0). New optional `rule_name` and
  `topic_name` target fields keep the old defaults. Event-pattern rules no
  longer fail the polling-interval check. Adds `validation_results.rule_checks`.
- **Azure SDK dependencies.** `azure-mgmt-resource-policy` moves from 1.0.0b3 to
  1.0.0, and `azure-mgmt-network` stays below 34. The `azure` extra adds
  `azure-mgmt-redisenterprise`, `azure-mgmt-dns`, `azure-mgmt-privatedns` and
  `azure-mgmt-resource-deployments`.
- **`azure_policy_compliance` 0.2.0: what was evaluated, whether remediation took,
  and what keeps coming back.**
  - Each listed non-compliant state now carries `evaluation_details`: the
    expressions Azure Policy evaluated, with field path, operator, actual value and
    target value, plus any ifNotExists lookup.
  - The service returns these only per resource, so they are read for at most
    `max_evaluation_detail_resources` (default 100) of the listed resources. The
    resources with the most listed states are read first.
  - `evaluation_details_status` gives the reason a state has no details. It is
    `collected` only when Azure returned an evaluated expression or an ifNotExists
    lookup; a state returned without either is `not_returned`, as Resource Provider
    mode policies (`Microsoft.KeyVault.Data` and the like) always are. A state the
    resource's query did not return at all is `not_in_detail_result`. A
    per-resource read that Azure refuses (a 403, or an AuthorizationFailed error
    code, which Policy Insights has returned with a 409) is retried once, 5 s
    later. A run makes at most 3 retries, and none after a retry is refused again,
    since the refusal is then systematic. Still refused, that resource's states
    are `not_authorized`, with the error code and refused action (never the
    principal) in `evaluation_details_reason`, and it is counted in
    `evaluation_details_not_authorized_resources`. It does not fail the run, since
    the details only enrich the states; any other error on that read, a 404 or a
    5xx included, still does.
    `evaluation_details_truncated` says when not every listed resource was read.
  - Each remediation task's per-resource deployments (status, error, times) are
    listed in `remediation_deployments`, up to `max_remediation_deployments`
    (default 1000), and each is checked against its resource's latest compliance
    state, with `current_state_evaluated_at` and `reevaluated_since_deployment`.
    The states are read only for the remediated resources. New summary keys count
    remediated resources (`remediated_resources_listed`) and those now compliant,
    now non-compliant, and whose succeeded remediation is now non-compliant. These
    count each resource once, and its latest deployment decides; tasks re-run on
    one resource add deployments, not resources. The non-compliant counts include
    resources that were fixed and later drifted back; `non_compliance_recurrence`
    shows the drift when that pair was read. `now_compliant` is null when the state
    was evaluated before the deployment last changed, and that deployment counts as
    `remediated_resources_not_yet_reevaluated` instead. When either time is
    missing, `now_compliant` comes from the state. Azure deletes a task 60 days
    after its last change, so this covers about the last 60 days at most.
  - From 30 days of history, the summary counts (resource, policy) pairs
    non-compliant throughout and pairs non-compliant only some of the time.
    `history_truncated` is also set when fewer groups come back than the service
    counts. When the history read fails, `history_collected` is false and these
    counts are null rather than 0.
  - For up to `max_recurrence_pairs` (default 100) of the part-time ones,
    `non_compliance_recurrence` counts the separate non-compliant episodes and how
    many times the pair fell back out of compliance. `recurring_non_compliant_pairs`
    counts pairs with more than one episode.
  - Every bounded list has a truncation flag; a limit of 0 skips that list and
    leaves its flag false. Existing fields are unchanged. Still Reader-only. Also
    mapped to `KSI-SVC-EIS`.
  - `runtime.timeout` is 3600 seconds: the added queries run serially, and a
    production run took about 8 minutes, near the runner's 600-second default.
- **`azure_network_security_groups` 0.3.0: east-west segmentation.** Each workload
  subnet now says which other subnets in its VNet can reach it on every port
  (`east_west_segmentation`: `segmented`, `partial`, `unsegmented`, `undetermined`
  or `no_peer_subnets`, with the subnets named on each side). Both subnets' NSGs
  are walked in priority order, default rules included, so a VNet relying on the
  platform's AllowVnetInBound reads `unsegmented`. An allow scoped to an
  application security group, or an NSG in another subscription, gives
  `undetermined` rather than a guess. A rule's port ranges are merged, so a deny
  split across `0-1023` and `1024-65535` covers every port. Platform subnets are left out. Subnets gain
  `address_prefixes` and `platform_subnet`, and rules gain their application
  security group ids. NIC-level NSGs, traffic within a subnet and peered VNets are
  not considered.
- **The TUI keeps evidence and scan reports apart.** The catalog and the
  add-fetcher picker group by kind first (**Evidence**, **Scan reports**) and
  platform second, so a platform that ships both, like Wiz, no longer lists
  them in one folder. Highlighting a section heading explains what that kind
  is and how it is sent. A fetcher's contract states its kind and where its
  output goes: the evidence set, or for a scan report the type of assessment it
  needs, its format, and how it is sent. The manifest table replaces the `mode`
  column (the `targets` column already shows `—` for a fetcher that runs once)
  with `kind`, and adds a last `sends to` column: the evidence set, or the
  assessment and close policy, or `no assessment — press A`. The manifest's
  detail pane shows the same. The TUI now says "scan report" wherever it said
  "issue report"; `kind: issue_report` in `fetcher.yaml` is unchanged. The
  catalog descriptor (`paramify catalog --json`) gains an `evidence_set` block
  and `issue_report.format`.
- **TUI fixes found while recording that walkthrough.** On a manifest with no
  evidence and no scripts, nothing on the Paramify tab held focus, so its keys
  did nothing. Enter in a picker's filter box now takes the highlighted option.
  The confirm dialog wraps long messages instead of cutting them off, which had
  hidden the auto-close warning. The jobs list shows each job's assessment by
  name and its error. A queued or running job is marked as waiting, not failed.
- **`paramify upload` and `paramify issues upload` pick the newest run of
  their own kind** when no run is named, not simply the newest run: evidence
  and pipeline manifests usually share an output directory, and each command
  used to pick up the other's run (`issues upload` then failed with "this run
  collected no issue reports" while the scan run sat beside it). Both take
  `-f MANIFEST` to use only that manifest's runs, reading its output directory
  when `--output-dir` is not given. The standalone uploaders and each panel of
  the TUI's Paramify tab choose the same way; the TUI scopes to the active
  manifest's runs once it has any.
- **AWS fetchers finish in large accounts** (67 fetchers, minor version
  bumps). Many made several AWS CLI calls, and started several `jq` processes,
  per resource, so an account with thousands of snapshots, roles or security
  groups ran past the runner's 600-second timeout. They now read each resource
  type with one paginated or batch call where AWS offers one, and build their
  records in a single `jq` pass. Measured against an account with 2,925 EBS
  snapshots, 912 IAM roles, 1,003 customer-managed policies and 1,009 security
  groups: `ebs_snapshot_status`, `iam_roles`, `iam_policies` and
  `security_groups` each timed out before and now finish in 2–26 seconds with
  2–4 calls, and every fetcher that finished before and after produced
  byte-identical evidence. Fetchers with no bulk form of their per-item call
  (S3 bucket settings, SQS queue attributes, KMS key details) still make one
  call per item, but no longer start a process or rewrite the output per item.
  The evidence-set instructions in each `fetcher.yaml` now list the commands
  the fetcher actually runs.

- **`azure_network_security_groups` shows outbound posture and NIC coverage**
  (0.1.0 → 0.2.0). Only an NSG's custom rules were read, so the platform's
  default AllowInternetOutBound — which permits all Internet egress unless a
  custom rule overrides it — never appeared, and every NSG looked like it said
  nothing about outbound traffic. Each NSG now also carries its
  `default_security_rules`, and the summary adds outbound counts, including
  `unrestricted_internet_outbound_groups` (rules evaluated in priority order).
  Network interfaces are now listed too, with the NSG on the NIC or inherited
  from its subnet; `nics_without_any_nsg` counts the ones with neither, which
  subnet coverage alone could not show. Rules gain `priority` and destination
  address fields. Existing fields and summary keys are unchanged.

- **`azure_app_service_configuration` shows access restrictions and diagnostic
  settings** (0.1.0 → 0.2.0). The access-restriction rules for the main site and
  the SCM (deployment) site were already returned by the per-app configuration
  call but dropped from the evidence, so nothing showed whether an app accepts
  traffic from anywhere. Each app's `configuration` now carries both rule lists,
  their default actions, `scm_ip_security_restrictions_use_main`, and an
  evaluated `main_site_allows_all_traffic` / `scm_site_allows_all_traffic`; the
  summary counts the apps where either site lets every caller through. Each app
  also gains `monitor_diagnostic_settings` (one `diagnostic_settings.list` per
  app, still Reader-only), counted as `apps_with_diagnostic_settings` and
  `apps_with_enabled_logs`. Existing fields and summary keys are unchanged.

- **`azure_rbac_role_assignments` 0.2.0 collects resource-group and resource-level
  grants.** The fetcher listed with `atScope()`, which returns only assignments at
  the subscription scope and above, so a role granted on one resource group or one
  resource — a Contributor on a single Key Vault, a data role on a storage account —
  never reached the evidence. A second, unfiltered listing now fills
  `results.role_assignments_below_subscription` (the unfiltered result minus the
  `atScope()` set, same record shape), with new `below_subscription_*` and
  `all_scopes_*` summary keys, including `all_scopes_assignments_by_scope_level`.
  Every existing key is still computed over the subscription-and-above set and
  means what it did. Also mapped to `KSI-CNA-DFP`, `KSI-IAM-JIT` and
  `KSI-MLA-ALA`.
- **`azure_policy_assignments` 0.2.0 resolves each assignment's policy effect.**
  `enforced` only ever meant enforcementMode Default, so an enforced assignment of
  an audit-only initiative read the same as one that denies. Each assignment now
  carries `policy_effects` — the effect of its definition, or of every member of
  its initiative, with `[parameters('effect')]`-style effects followed through the
  assignment's parameter value, then the initiative's default, then the
  definition's default, and the source of each recorded — plus `effect_class`
  (`enforcing` / `audit_only` / `disabled` / `unresolved`) and `actually_enforces`
  (an enforcing effect — deny, denyAction, modify, deployIfNotExists, append — under
  enforcementMode Default). New summary keys: `actually_enforcing_assignments`,
  `audit_effect_only_assignments`, `assignments_by_effect_class`,
  `member_policy_effect_counts` and others; the existing `audit_only_assignments`
  still means DoNotEnforce. Also mapped to `KSI-CNA-IBP` and `KSI-MLA-EVC`.
- **`azure_key_vault_configuration` 0.2.0 records each vault's audit logging.**
  A vault's data-plane operations — who read or changed which key, secret or
  certificate — are logged only if a diagnostic setting exports the `AuditEvent`
  category, and the evidence did not say whether one did. Each vault now carries
  its diagnostic settings, `audit_logging_enabled` (true when a setting with a
  destination exports `AuditEvent` directly or through the `audit` / `allLogs`
  group), and the destinations the audit events reach. The summary adds
  `vaults_with_audit_logging`, `vaults_without_audit_logging`,
  `vaults_audit_logging_unknown` (the read failed — neither logged nor unlogged)
  and `audit_logging_percentage`. Existing fields are unchanged. The fetcher now
  also maps to `KSI-MLA-LET`, and to `KSI-CNA-MAT`, `KSI-CNA-RNT` and
  `KSI-SVC-SIN`, which its network and SKU fields already evidenced.
- **`azure_activity_log_alerts` 0.2.0 says whether an alert reaches a person.**
  A rule with an action group counted as monitoring even when the group was
  disabled, had no enabled receiver, or an alert processing rule removed its
  notifications. Each rule now carries `resolved_action_groups` (enabled state
  and enabled receivers; webhook host only, phone numbers masked),
  `routes_to_enabled_receiver`, `routes_to_person`, `suppressed` and
  `reaches_human`, decided as in `azure_alert_rules` (true, false, or null when
  unknown), from raw ARM reads of action groups and processing rules. A second
  map, `change_operation_coverage`, covers App Service create / update,
  configuration, deployment and slot swap, at site and slot level, counting
  only alerts that reach a person (null where only one that might covers it);
  `monitored_operation_coverage_reaching_human` does the same for the existing
  map. `action_groups` and `monitored_operation_coverage` are
  unchanged.
- **`azure_resource_inventory` 0.2.0 shows each resource's Defender and Policy
  coverage.** Two more Resource Graph queries read Defender for Cloud assessments
  (`SecurityResources`) and Azure Policy states (`PolicyResources`). They are joined
  to the inventory by resource id in the fetcher, because Resource Graph allows one
  cross-table join per query and pages `summarize` only to its first page. Each
  resource gains `defender_assessments`, `defender_unhealthy`,
  `defender_unhealthy_high_severity` (High or Critical), `policy_evaluations` and
  `policy_non_compliant`; a result on a child resource, such as a subnet, counts for
  the inventoried parent. Only Healthy and Unhealthy assessments count:
  NotApplicable ones did not happen (off by policy, for instance) and are counted
  apart, in `defender_not_applicable` and `defender_not_applicable_total`; an
  assessment with a missing or unexpected status counts in neither, but in
  `defender_unknown_status_total`. The
  summary lists `resources_without_defender_assessment`
  and `resources_without_policy_evaluation`. A resource counts there only when the
  service covers another resource of its type in the subscription. Types it covers
  on no resource are listed apart, with counts, in `types_without_defender_assessment`
  and `types_without_policy_evaluation`, so a type Defender has no recommendations
  for is not a gap. `all_assessable_resources_assessed_by_defender` and
  `all_evaluable_resources_evaluated_by_policy` are false when the service covers
  nothing at all, and on an empty inventory, which is what Resource Graph returns
  to a caller without Reader. `defender_coverage_collected` and
  `policy_coverage_collected` say whether each coverage query was read to the end. Also new: coverage percentages, unhealthy High/Critical and
  non-compliant counts on inventoried resources, and
  `resources_covered_by_neither_by_type` (uncovered resources of every type, gaps
  and never-covered types alike). Assessments and policy states about anything not
  inventoried (the subscription, resource groups, deleted resources) are counted
  apart, with `defender_unhealthy_outside_inventory`,
  `defender_unhealthy_high_severity_outside_inventory`,
  `defender_unhealthy_without_severity_outside_inventory` and
  `policy_non_compliant_outside_inventory`, so the inventoried counts plus these add
  up to the totals; many High recommendations (owner MFA, Defender plans) are about
  the subscription itself. Assessments of AWS, GCP or on-premises machines (a
  `resourceDetails` source other than Azure) always count outside, by source.
  `results.coverage_queries` gives each query's page count, reported total and
  `outside_inventory_by_target`, the same counts for those results by the type of
  what they target (never its name). Every
  query is paged to the end; a coverage query that fails or comes back truncated
  is a collection failure, and that service's counts stay null rather than reading
  as uncovered. Also mapped to `KSI-MLA-EVC`, `KSI-CNA-EIS` and `KSI-SVC-EIS`.
  Existing fields and summary keys are unchanged.
- **`azure_defender_plans` 0.2.0 records each plan's sub-plan, enablement time
  and inheritance.** Each plan now carries `sub_plan` (Servers `P1` / `P2`,
  `DefenderForStorageV2`, `PerKeyVault`, …), `enablement_time` (the last time it
  was set to Standard; `null` when Azure does not report it, which can be the case
  for every plan, so `enabled_plan_enablement_times` can be all `null` and is not a
  reliable signal for a validator), `resources_coverage_status`, `enforce`,
  `deprecated` and `replaced_by`, and `inherited` / `inherited_from` with
  `inherited_from_scope` (`management_group`, `subscription`, `resource_group` or
  `resource`), all from the same `pricings.list` call. Azure documents inheritance as reported for
  resource-level pricing only, so at subscription scope it reads `null` and
  `plans_reporting_inheritance` says whether any plan reported it. New summary
  keys: `enabled_plans`, `enabled_plan_sub_plans`, `enabled_plan_enablement_times`,
  `enabled_plans_not_fully_covered` (an enabled plan with no coverage status is
  listed as `unknown`, so it never reads as covered), `plans_not_enabled`
  (deprecated plans left out), `deprecated_plans`, `deprecated_plans_enabled`,
  `enforced_plans`, `inherited_plans` and `plans_inherited_from_management_group`.
  The summary does
  not judge which plans a system needs. Existing fields and summary keys are
  unchanged.
- **`azure_diagnostic_settings` also maps to `KSI-MLA-OSM`**, which its
  subscription activity-log export already evidenced.
- **`KSI-SVC-PRR` counts as config-evidenceable.** Its residual elements are a
  state of the environment a fetcher can show, so `framework/reference/ksis.yaml`
  marks it evidenceable and `docs/ksi_mapping.md` lists it as covered by
  `azure_residual_resources`: 35 of 37 evidenceable indicators.
- **The TUI saves manifest edits as they are made.** Adding a fetcher, editing an
  entry, adding / editing / removing a target, picking an assessment, removing an
  entry, and changing the output dir all write the file immediately. Edits used
  to live in memory until `s`, with nothing on screen to say the file and the
  view had diverged — so quitting, or not knowing the key, discarded the work.
  `s` still saves on demand, which is also how a write that failed is retried: a
  save that cannot happen reports why and keeps the edit rather than losing it
  along with the file write.

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
- **The `suggest-validator` skill writes validators.** It now authors them into
  `validators/` rather than only proposing a regex, and verifies them against compliant,
  non-compliant, and **unreadable** evidence.

### Deprecated

- The inline `validators` block on `fetcher.yaml`. Nothing in the framework reads
  it and only `gitlab/significant_change_notifications` still carries one; it stays
  in the schema, marked deprecated, so that fetcher's data remains shape-checked
  until it migrates to the registry. New validators belong in `validators/`.

### Removed

- **The docs the illustrated guides replaced.** `docs/design.md`,
  `authoring_a_fetcher.md`, `config_injection_design.md`, `envelope_design.md`,
  `fetcher_contract.md`, `inventory_fetchers.md`, `issue_report_fetchers.md`,
  `pipelines.md`, `platform_onboarding.md`, `private_mirror_workflow.md`,
  `releasing.md`, `run_manifest_reference.md`, `uploader_design.md`,
  `validators_design.md` and `versioning.md` are gone. Links now point at the
  guides (`design.md`'s at `architecture_guide.md`); the onboarding source lists
  keep pinned copies.

### Fixed

- **Azure management calls go to the credential's cloud.** Every
  management-plane Azure fetcher sent its requests to commercial Azure, so a US
  Government, Germany or China subscription failed with `SubscriptionNotFound`.
  The management endpoint now follows `AZURE_AUTHORITY_HOST`, as the Entra
  fetchers already did.
- **An optional secret that cannot be resolved falls back to ambient identity.**
  The TUI wires optional secrets to default environment variables. When such a
  variable was unset, the entry failed before it ran (exit 255), even with a
  task role or workload identity present.
- **Four run-path failures that exited 0.** An unquoted YAML date in a target
  stopped the run. The timeout now stops the whole process group, so a hung
  `aws` or `curl` call cannot outlast it. Quitting the TUI during a run no
  longer marks the running fetcher failed. `guard_duty`, `guard_duty_findings`
  and `global_accelerator_ha` now record a service that is not enabled instead
  of failing.
- **`checkov_bicep` passes its list settings to checkov intact** (0.2.0 →
  0.2.1). `checks`, `skip_checks`, `skip_paths` and `skip_resources` take
  entries separated by commas or newlines, each trimmed. `checks` and
  `skip_checks` also take spaces and tabs, since check ids never contain them,
  and `_shared/skip-checks.default.txt` is read the same way, with `#`
  starting a comment anywhere on a line. Configured values reach checkov as
  `--flag=value`. Before:
  - a `skip_paths` entry with a space (`My Templates/legacy`) became two skip
    paths, and each piece could skip folders it was not meant to;
  - a `skip_paths` entry with `*` or `?` was expanded against the files in the
    fetcher's working directory, so `*.json` could reach checkov as
    `--skip-path report.json`;
  - `checks` failed the run if it had a space after a comma
    (`CKV_AZURE_3, CKV_AZURE_44`), ids separated only by spaces, or one id
    per line;
  - `skip_checks` failed the run if its ids were separated only by spaces,
    and read only its first line, so checks listed below it still ran;
  - a line of `_shared/skip-checks.default.txt` holding several ids or a
    trailing `#` comment failed the run;
  - `skip_resources` patterns on separate lines became one pattern that
    matched nothing;
  - a `skip_paths` or `repo_id` value starting with `-` was read as an option,
    and the run failed.

  `skip_paths` entries are Python regular expressions, which is how checkov
  reads them: it searches each file's path for every entry, so `.`, `*`, `?`,
  `+`, `(`, `)`, `[` and `]` need a backslash to match literally. They are
  not globs. An entry that is not a valid regular expression, such as
  `*.json`, now fails the run with `bad_config` naming it, before anything
  is fetched; checkov's Bicep scan crashed on one. The check needs `python3`
  on PATH, which the checkov category now declares.

  `metadata.skip_paths` now holds the entries checkov was given as
  `--skip-path` values. It used to disagree in three cases:
  - a path with a space was one entry, while checkov got two;
  - a `*` pattern was listed as written, while checkov got the files it
    matched;
  - entries on separate lines with no comma between them were one entry,
    while checkov got one per line.

  New `metadata.checks` lists the `checks` allowlist, so a restricted scan no
  longer reads as a full one. It is empty when every check ran.
- **`azure_policy_assignments` recognises the `AuditAction` effect** (0.2.0 →
  0.3.0). An assignment whose effect resolved to `AuditAction`, the audit
  counterpart of `DenyAction`, was reported as `unresolved` with no reason and
  raised `unresolved_effect_assignments`. It now resolves to `auditAction`, an
  audit-only effect. `mutate` and `addToNetworkGroup` (both in Microsoft's
  effects reference) and `enforceSetting` (used by built-in definitions) now
  resolve as enforcing effects. Every assignment's `policy_effects.effect_counts`
  and the summary's `member_policy_effect_counts` therefore gain four keys,
  zero unless used: `auditAction`, `mutate`, `addToNetworkGroup` and
  `enforceSetting`. Any other unrecognised value is still unresolved, but its
  `reason` now names the value (`unknown effect value 'X'`). Two new summary
  keys count unresolved member policies: `unresolved_member_policies`, and
  `unresolved_member_policies_not_enforced` for those in any assignment whose
  enforcementMode is not Default. Members of an initiative whose definition
  can't be read aren't counted; that assignment shows only in
  `unresolved_effect_assignments`. The per-assignment fields are unchanged: a
  partly resolved DoNotEnforce initiative is still classed by its resolved
  members, so its `effect_class` can read `audit_only` and
  `enforcing_effects_not_enforced` false. The new summary keys are where that
  gap shows.
- **`azure_entra_authentication_policy` counts X.509 as phishing-resistant only
  when it is multi-factor** (0.1.0 → 0.2.0). An enabled X.509 certificate method
  was always listed in `phishing_resistant_methods_enabled`, even with its default
  authentication mode set to `x509CertificateSingleFactor`, which does not satisfy
  MFA by itself. It now counts only when the default mode is
  `x509CertificateMultiFactor`; a new summary field,
  `x509_certificate_multi_factor`, reports the mode (`null` when it is not
  reported).
- **`azure_entra_mfa_status` finds every admin** (0.1.0 → 0.2.0). Admin status
  came only from the registration report's `isAdmin` flag, which exists only on
  users with a registration row, so an admin who had registered nothing was
  counted as a non-admin and `admin_mfa_coverage_percentage` was overstated.
  Admins are now the holders of privileged directory roles (the same list
  `azure_entra_privileged_roles` uses), directly or through a role-assignable
  group, plus anyone the report flags. Each user carries
  `privileged_directory_roles` and `is_admin_in_registration_report`; the summary
  adds `admin_users_without_mfa`, `admin_users_without_registration_details` and
  `admin_role_membership_readable`. The fetcher now reads `GET /directoryRoles`,
  the members of each privileged role and the transitive members of any group
  holding one: covered by `Directory.Read.All`, which the Entra fetchers already
  document (or `RoleManagement.Read.Directory` + `GroupMember.Read.All`). If that
  read is denied the run fails and the admin figures read `null`.
- **Checkov evidence no longer overstates pass rates** (`checkov_terraform` and
  `checkov_kubernetes` 0.1.0 → 0.2.0). `skip_resources` deleted failed checks on
  matching resources, so they left `total_checks` and raised
  `aggregate_percentage`; they are now moved to `skipped_checks` (marked
  `SKIPPED`, with the matching pattern in `suppress_comment`) and counted in
  `summary.skipped_by_resource_filter`. An empty pattern from a trailing comma
  no longer matches every resource. The 17 checks in
  `skip-checks-k8s.default.txt`, among them `CKV_K8S_20` and `CKV_K8S_31`, were
  always skipped and left no trace in the evidence. The effective skip list is
  now recorded in `metadata.skip_checks`, and the new `use_default_skip_checks`
  knob (default `true`, so results are unchanged) set to `false` lets
  `skip_checks` replace the defaults. When the requested branch could not be
  cloned, the scan fell back to the default branch but `metadata.branch` still
  named the requested one. `metadata.branch` now names the branch actually
  scanned, with `requested_branch` and `branch_fallback` beside it.
- **`gcp_cloud_sql_encryption_status` reads point-in-time recovery per engine**
  (0.1.0 → 0.1.1). The fetcher took the first non-null of
  `pointInTimeRecoveryEnabled` and `binaryLogEnabled`, so a MySQL instance with
  the binary log on (MySQL's PITR switch) and the generic toggle at `false`
  read as having no PITR. MySQL now reads `binaryLogEnabled` and PostgreSQL /
  SQL Server read `pointInTimeRecoveryEnabled`, the same rule
  `gcp_cloud_sql_backup_configuration` uses. Each record adds the two raw flags
  (`pitr_toggle_enabled`, `binary_log_enabled`) and the summary adds
  `point_in_time_recovery_instances`.
- **`gcp_compute_instance_configuration` counts OS Login 2FA only where OS
  Login is on** (0.1.0 → 0.1.1). `enable-oslogin-2fa` does nothing without
  `enable-oslogin`, but `os_login_2fa_enabled` (per instance and per project)
  and the `os_login_2fa_instances` / `project_os_login_2fa_enabled` summary
  fields reported the flag alone. They now report effective 2FA (OS Login on
  and the 2FA flag on, each resolved instance-first). The raw flag is kept as
  `os_login_2fa_configured`.
- **`gcp_gke_cluster_configuration` recognises Binary Authorization set by
  evaluation mode** (0.1.0 → 0.1.1). `binary_authorization_enabled` read only
  the deprecated `enabled` flag, so a cluster enforcing with
  `PROJECT_SINGLETON_POLICY_ENFORCE` read as off and was left out of
  `binary_authorization_clusters`. Any mode other than `DISABLED` now counts as
  enabled. The legacy flag decides only when no mode is set, since the API
  ignores it otherwise. It is kept as `binary_authorization_legacy_enabled`.
- **Every uploader reads "already exists" / "already connected" the same way.**
  The API refuses a repeat evidence-set create or a repeat CONNECT instead of
  ignoring it, and each uploader held its own test for that refusal: the scripts
  uploader treated a repeat CONNECT as success, the validator syncer failed on
  it, and the evidence-set fallbacks recognised the refusal only as an HTTP 400.
  API spec 0.9.2 permits the same refusal as a 409 Conflict on every operation,
  which the 400-only tests would have missed. One shared rule
  (`framework/paramify_responses.py`) now accepts 400 or 409 when the message
  names the duplicate, and nothing else, so re-running any stage stays
  idempotent on either code. The validator syncer also resolves its token like
  the other uploaders (`PARAMIFY_UPLOAD_API_TOKEN`, falling back to
  `PARAMIFY_API_TOKEN`) and reports a failed evidence-set lookup as its own
  error rather than a bare HTTP exception.
- **`aws_security_groups` shows all-traffic and IPv6 rules** (0.2.0 → 0.3.0).
  A rule with no port range — protocol `-1`, "All traffic" — was dropped from
  the evidence, so an inbound all-traffic rule from `0.0.0.0/0` and every
  default allow-all egress rule were invisible. Such rules are now kept, with
  `FromPort` and `ToPort` set to `null`. IPv6 ranges were never read, so a rule
  open only to `::/0` looked closed; each rule now carries `IPv6CIDRs` (IPv6
  ranges joined with `", "`) after `CIDRs`. Existing keys and their order are
  unchanged.

- **`aws_iam_mfa_status` reports FIDO security keys as `fido`** (0.1.0 →
  0.2.0). Every device whose serial is an ARN was typed `virtual`, so a FIDO/U2F
  security key (`arn:aws:iam::<account>:u2f/...`), the phishing-resistant
  factor, read as an authenticator app. `Type` is now `fido` for a `:u2f/`
  serial, `virtual` for a `:mfa/` serial, `hardware` for a bare serial (a
  hardware TOTP token) and `unknown` for any other shape.

- **`aws_iam_policies` lists permissions-boundary use apart from attachments**
  (0.2.0 → 0.3.0). `AttachedUsers` and `AttachedRoles` also named the users and
  roles that use the policy only as their permissions boundary, which grants
  nothing. They now hold attachments only, and two new keys after
  `AttachedRoles`, `BoundaryUsers` and `BoundaryRoles`, name the users and roles
  that use it as their boundary. Existing keys and their order are unchanged.

- **`aws_security_groups` shows rules that reference security groups and
  prefix lists** (0.3.0 → 0.4.0). Only IP ranges were read, so a rule whose
  source (outbound: destination) is another security group or a managed prefix
  list came out with empty CIDRs and no source, as if it allowed nothing. Each
  rule now ends with `SecurityGroupIds` and `PrefixListIds`, joined with `", "`
  like `CIDRs`; a group owned by another account is written
  `<account-id>/<group-id>`. Each group record also gains `GroupName` and
  `VpcId` after `Rules`. Keys are only appended.

- **`aws_network_firewall_rules` counts Suricata and domain-list rules**
  (0.1.0 → 0.2.0). `StatefulRuleCount` read only `StatefulRules`, so a stateful
  rule group written as a Suricata rules string or a domain list reported 0.
  A rules string now counts its lines that are not blank or `#` comments
  (backslash-continued lines count once); a domain list counts its domains
  (`Targets`), not the rules AWS generates per target type. A new
  `StatefulRuleSource` key names which of the three was counted.

- **`aws_auto_scaling_high_availability` lists each group's instances.** A
  query error left `Instances` empty for every Auto Scaling group.

- **`aws_organizations_scp` keeps the organization record when one SCP cannot
  be read.** A single unparseable policy used to drop the whole organization
  from the evidence.

- **AWS failure reports name the fetcher** instead of `aws__shared`, and an
  expired `aws login` session is reported as expired credentials.

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
  [`docs/issue_report_fetchers.md`](https://github.com/paramify/paramify-fetchers/blob/v0.5.0-beta/docs/issue_report_fetchers.md). Written
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
  [`docs/fetcher_contract.md`](https://github.com/paramify/paramify-fetchers/blob/v0.5.0-beta/docs/fetcher_contract.md) mandates it. It logs
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
  contract, so no bump ([`docs/versioning.md`](https://github.com/paramify/paramify-fetchers/blob/v0.5.0-beta/docs/versioning.md)).

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

- [`docs/private_mirror_workflow.md`](https://github.com/paramify/paramify-fetchers/blob/v0.3.1-beta/docs/private_mirror_workflow.md) — keeping a
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
- [`docs/uploader_design.md`](https://github.com/paramify/paramify-fetchers/blob/v0.3.0-beta/docs/uploader_design.md) — a dedicated uploader design
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
change before 1.0 (see [`docs/versioning.md`](https://github.com/paramify/paramify-fetchers/blob/v0.2.0-beta/docs/versioning.md)).

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
- Versioning & contract policy ([`docs/versioning.md`](https://github.com/paramify/paramify-fetchers/blob/v0.2.0-beta/docs/versioning.md)), this
  changelog, and the manual release runbook
  ([`docs/releasing.md`](https://github.com/paramify/paramify-fetchers/blob/v0.2.0-beta/docs/releasing.md)).

### Changed

- Licensed under GPL-3.0-only.
- Documentation rewritten for public consumption; the README leads with the TUI,
  then the AI-agent path, then the CLI.
- TUI restyled — border titles, status pills, denser controls, and hatched empty
  states.

[Unreleased]: https://github.com/paramify/paramify-fetchers/compare/v0.6.0-beta...HEAD
[0.6.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.5.1-beta...v0.6.0-beta
[0.5.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.5.0-beta...v0.5.1-beta
[0.5.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.4.0-beta...v0.5.0-beta
[0.4.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.3.1-beta...v0.4.0-beta
[0.3.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.3.0-beta...v0.3.1-beta
[0.3.0-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.2.1-beta...v0.3.0-beta
[0.2.1-beta]: https://github.com/paramify/paramify-fetchers/compare/v0.2.0-beta...v0.2.1-beta
[0.2.0-beta]: https://github.com/paramify/paramify-fetchers/releases/tag/v0.2.0-beta
