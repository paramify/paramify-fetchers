# GitHub

GitHub fetchers collect change-management, supply-chain and code-security
evidence from the GitHub API: what protects each default branch, how changes
actually merged, how GitHub Actions is locked down, whether releases can be
verified, what was deployed to production and under which controls, the three
alert streams (Dependabot, code scanning, secret scanning), vulnerability
disclosure, organization security settings, who has access, credentials that are
not a person, the audit log, FedRAMP significant change notifications, and an
inventory of every repository for Paramify's Inventory.
Every fetcher runs once per **organization**; add a target per
organization, each with its own token and API host.

| Fetcher | Evidence | KSIs |
|---|---|---|
| `github_branch_protection` | Rules GitHub enforces on each default branch (rulesets + classic protection), rulesets that exist but enforce nothing, bypass lists | CMT-VTD, CMT-LMC, SVC-VRI |
| `github_pull_request_checks` | Merged PRs in a window with approvals (bots marked) and check outcomes (required vs optional), and direct pushes | CMT-LMC, CMT-VTD |
| `github_dependabot_alerts` | Every Dependabot alert with age, time to fix, CISA KEV membership, and whether the repository is really being scanned | SCR-MON, SVC-EIS |
| `github_code_scanning_alerts` | Whether each default branch is analysed, by which tools, how recently; every alert | SVC-EIS, MLA-EVC |
| `github_secret_scanning` | Scanning and push protection per repository, every alert (never the secret), push-protection bypasses | SVC-ASM |
| `github_org_security_settings` | Two-factor requirement and members without it, member defaults, Actions token rights, security configuration coverage | IAM-APM, IAM-ELP, CNA-EIS |
| `github_access_review` | Owners, members, outside collaborators, invitations, teams and their repository grants, repository admins | IAM-ELP, IAM-AAM |
| `github_non_user_credentials` | Deploy keys, installed apps, fine-grained tokens, Actions secrets by age, webhook TLS and signing | IAM-SNU, SVC-ASM |
| `github_repository_inventory` | **Inventory** (`kind: inventory`): one record per repository with visibility, state, security features and custom property values; all or nothing | PIY-GIV |
| `github_actions_security` | Allowed actions and SHA pinning policy, the workflow token's default, fork PR approval, self-hosted runners, and what each workflow file does (unpinned actions, permissions blocks, privileged triggers checking out PR code, untrusted input in scripts, OIDC) | SCR-MIT, CMT-VTD, IAM-SNU, CNA-MAT |
| `github_release_integrity` | Build provenance on each release asset (by digest), immutable releases, release tags locked by tag rulesets | SVC-VRI, SCR-MIT |
| `github_deployment_controls` | Environments' reviewers, self-review, wait timers, branch policies and admin bypass; production deployments in a window with commit, creator and whether Actions made them | CMT-RMV, CMT-VTD, CMT-LMC |
| `github_vulnerability_disclosure` | Private vulnerability reporting, security policy, repository security advisories with state and age | PIY-RVD |
| `github_significant_change_notifications` | FedRAMP SCN objects from pull requests flagged as significant changes, schema-validated and checked against SCN-CSO-INF | CMT-LMC |
| `github_audit_log` | Audit log event counts and every access, protection and control change in a window (**Enterprise Cloud only**) | MLA-LET, MLA-OSM, IAM-SUS |

## Target

| Field | Env | Required | Notes |
|---|---|---|---|
| `org` | `GITHUB_ORG` | yes | Organization login, as in `github.com/<org>` |
| `api_url` | `GITHUB_API_URL` | no | `https://api.github.com` (default), `https://api.<sub>.ghe.com` (GHE.com), `https://<host>/api/v3` (GitHub Enterprise Server) |
| `repositories` | `GITHUB_REPOSITORIES` | no | Comma-separated names; unset collects every repository the token can see |
| `include_archived` | `GITHUB_INCLUDE_ARCHIVED` | no | Default `false`. Set it `true` on the inventory's target: an archived repository is still an asset |
| secret `token` | `GITHUB_TOKEN` | yes | Per target |

## Creating the token

Use a **fine-grained personal access token** (or a GitHub App installation
token) whose **resource owner is the organization**, with read-only
permissions. GitHub names the permission an endpoint needs in its
`X-Accepted-GitHub-Permissions` header; every collection failure quotes it, so
a missing grant is reported as e.g. `(needs: administration=read)`.

1. Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate new token.
2. **Resource owner:** the organization. **Repository access:** All repositories.
3. Grant **Read-only** for the permissions below, then approve the token under
   the organization's *Personal access tokens → Pending requests* if the
   organization requires approval.

| Permission (token page) | API name, as quoted in failures | Needed by |
|---|---|---|
| Metadata (repository) | `metadata` | all |
| Administration (repository) | `administration` | branch_protection (also rule-suite bypasses), pull_request_checks (required checks), dependabot_alerts (security updates), code_scanning_alerts (default setup), secret_scanning (settings), non_user_credentials (deploy keys), actions_security (Actions policy, runners), release_integrity (immutable releases) |
| Contents (repository) | `contents` | pull_request_checks (commits), dependabot_alerts (dependency graph), actions_security (workflow files), branch_protection (CODEOWNERS errors) |
| Pull requests (repository) | `pull_requests` | pull_request_checks, significant_change_notifications |
| Actions (repository) | `actions` | deployment_controls (environments) |
| Deployments (repository) | `deployments` | deployment_controls |
| Attestations (repository) | `attestations` | release_integrity |
| Repository security advisories (repository) | `repository_advisories` | vulnerability_disclosure. **Without it GitHub lists published advisories only, with no error**: drafts and private reports disappear and nothing says so |
| Commit statuses (repository) | `statuses` | pull_request_checks |
| Dependabot alerts (repository) | `vulnerability_alerts` | dependabot_alerts |
| Code scanning alerts (repository) | `security_events` | code_scanning_alerts |
| Secret scanning alerts (repository) | `secret_scanning_alerts` | secret_scanning |
| Secrets (repository) | `secrets` | non_user_credentials |
| Webhooks (repository) | `repository_hooks` | non_user_credentials |
| Administration (organization) | `organization_administration` | org_security_settings, non_user_credentials (installations), actions_security (Actions policy), release_integrity (immutable releases), audit_log |
| Members (organization) | `members` | access_review, org_security_settings |
| Secrets (organization) | `organization_secrets` | non_user_credentials |
| Webhooks (organization) | `organization_hooks` | non_user_credentials |
| Personal access tokens (organization) | `organization_personal_access_tokens` | non_user_credentials, **GitHub App tokens only**: the token page offers no such permission, and GitHub answers a personal token with 403 whatever it holds. Run with a personal token, `fine_grained_tokens` is `null` and the metadata says why |
| Custom properties (organization) | `organization_custom_properties` | repository_inventory (or set `include_custom_properties: false`) |
| Self-hosted runners (organization) | `organization_self_hosted_runners` | actions_security (or set `include_self_hosted_runners: false`) |
| Custom organization roles (organization) | `organization_custom_org_roles` | access_review (or set `include_organization_roles: false`) |

Measured: a token holding exactly these permissions, read-only, produced
the same evidence as one holding every permission, for all fifteen fetchers.

Two settings are visible only to an **organization owner**: the two-factor
requirement and the list of members without two-factor. Collected by a
non-owner they are `null`, never `false`.

A **GitHub App installation token** holding the same read-only permissions
produced the same evidence as a personal token for all fifteen, with two
differences, both measured: it can list the organization's fine-grained
tokens, and GitHub does not show it who may bypass a ruleset, so those
rulesets appear in `bypass_actors_unreadable` rather than as bypass-free.

## Wiring into a manifest

See [`examples/github_run.yaml`](../../examples/github_run.yaml): one target
shared by every fetcher through a YAML anchor, with `token:
${env:GITHUB_TOKEN}`.

## Smoke test

```bash
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" \
  "${GITHUB_API_URL:-https://api.github.com}/orgs/$GITHUB_ORG/repos?per_page=1" \
  | python3 -m json.tool | head -20
```

A `[]` means the token sees no repositories: check its resource owner and
repository access.

## Rotating the token

1. Create a second token with the same permissions — do not revoke the old one yet.
2. Update the env var in your secrets store.
3. Run the smoke test.
4. Revoke the old token.

## What the client guards against

Each of these was measured against a live organization or public
repositories; each returns well-formed, misleading data without an error.

- **Lists default to 30 items.** Every list asks for 100 and follows `Link:
  rel="next"`, for page-number and cursor endpoints alike, and fails on a
  repeated page or the page cap rather than stopping short.
- **"Off" and "forbidden" share status codes.** `404 Branch not protected`,
  `403 Dependabot alerts are disabled`, `404 Secret scanning is disabled`,
  `404 no analysis found` and `403 Upgrade to GitHub Team` describe the
  target. `404 Not Found` and `403 Resource not accessible` describe the
  token. The client tells them apart by message: the first set is evidence,
  the second a collection failure.
- **A token restricted to some repositories lists only those.** The listing is
  compared with the organization's own repository count.
- **Unreadable is not absent.** Where a token cannot read something that
  could disprove a verdict, the verdict is `null`, never `false`.
- **GraphQL fails with a 200.** Errors arrive in an `errors` list beside
  partial `data`; any error fails the collection. A heavy page times out
  (502) rather than erroring, so the page size halves, down to 5, instead of
  retrying the same page. The client sends GraphQL queries only and refuses a
  `mutation` before it leaves the process; every other call is a GET. The
  token is sent only to the configured API host: a next-page link anywhere
  else fails the collection.

## What the fetchers guard against

- **A ruleset can exist and enforce nothing** (`disabled` or `evaluate`).
  Protection is read from the rules GitHub reports *enforced* on the branch
  (`rules/branches/{branch}`), and rulesets that are defined but not enforced
  are listed separately. Ruleset patterns are matched the way GitHub matches
  them, which is Ruby's `File.fnmatch` with `FNM_PATHNAME`: `*`, `?` and
  `[...]` stop at `/`, and `**/` crosses it only when `**` is a whole segment,
  so `refs/heads/**/*` matches `main` and `a/b/c` while `refs/heads/**` matches
  `main` but not `feature/x`. Measured on a live repository, then fuzzed
  against Ruby on 6 million patterns with no disagreement. A pattern the
  matcher cannot read leaves the ruleset's coverage unknown, never guessed.
- **A bot can satisfy a required review.** When the organization lets Actions
  approve pull requests, a `github-actions[bot]` approval meets a ruleset's
  `required_approving_review_count`. Approvals are reported with `bot`, and the
  organization flag in `org_security_settings`.
- **The same check runs twice** (on `push` and `pull_request`); outcomes are
  grouped by check name, latest run wins.
- **Dependabot can be on and blind.** The dependency graph parses manifests
  only on a push, so alerts can read as enabled while the graph holds nothing.
  `dependency_graph_packages` is reported beside `alerts_enabled`.
- **The organization alert lists omit repositories with the feature off**, so
  alerts are read per repository.
- **A push-protection bypass resolves its own alert.** Open secret alerts can be
  zero while a secret was pushed past protection; bypasses are listed apart.
- **A security configuration can be defined and attached to nothing.** Coverage
  is read from each configuration's attached repositories.
- **Required code-owner review can require nothing.** With no CODEOWNERS file, or
  lines GitHub cannot parse, no owner is asked. `branch_protection` reads
  GitHub's own parse (`codeowners/errors`) wherever the review is required.
- **A workflow setting is not what runs.** `actions_security` reads every
  workflow file on the default branch (GraphQL, ten repositories a query) and
  parses it: a reference is pinned only to a full 40-character commit SHA; a
  `pull_request_target` or `workflow_run` workflow that checks out the pull
  request's code, by the checkout action or `gh pr checkout`/`git fetch pull/`,
  runs an outsider's code with secrets; event fields an outsider writes
  (titles, bodies, branch names) inside a `run:` script are an injection.
  YAML 1.1 reads a bare `on:` key as `true`, which the parser allows for.
  Checked against an independent reading of 537 workflow files from 15 large
  public repositories with no disagreement.
- **An immutable release is attested by GitHub itself.** That release
  attestation says what was released, not how it was built, so
  `release_integrity` asks only for build provenance (`predicate_type=provenance`).
  Large Sigstore bundles are served from blob storage and are not fetched; an
  inline statement is checked to name the asset's digest. Signatures are not
  verified; `gh attestation verify` does that.
- **An environment's branch policy does not bind the API.** A deployment created
  through the REST API to a branch the environment refuses succeeds (measured);
  only workflow jobs are held to it. `deployment_controls` reports which
  production deployments GitHub Actions did not make, and whether each deployed
  commit is in the default branch's history, by commit rather than ref: a
  deployment may name a bare commit (Vercel does), and a squash-merged pull
  request's own commits never reach the default branch.
- **GitHub's commit comparison calls a commit that does not exist identical.**
  Each comparison is paired with an object lookup; a missing commit is unknown.
- **Draft advisories vanish without the permission.** See the permission table;
  GitHub also hides an advisory's `created_at` from non-maintainers, so time to
  resolution is `null` there.

## Not visible to these fetchers

- **Review or merge gates enforced outside GitHub** (a bot merge queue such as
  Prow, or comment-driven approval) do not appear as reviews or rules; such a
  repository reads as unreviewed and unprotected. `pull_request_checks`
  reports who merged each pull request (`merged_by`, `merged_by_bot`) and its
  labels, so a reviewer can tell kubernetes' Prow merges (a bot, after `lgtm`
  and `approved` labels) from a person merging their own change.
- **The audit log** is GitHub Enterprise Cloud only; `audit_log` fails with
  that reason on a Free or Team organization, before any call. It is built
  against GitHub's Enterprise Cloud API description and has not yet been run
  against a live audit log.
- **A private vulnerability report could not be staged**: GitHub refuses one
  from an administrator of the repository. Reports are covered by unit tests
  on the documented shape.
- **Required checks are as of collection time.** A pull request merged before a
  requirement changed is judged against today's requirement.

## Cost and run time

Fetchers call the API one request at a time, as GitHub asks of integrations.
`pull_request_checks` reads pull requests (with reviews, labels and checks) and
commits over GraphQL: measured, about 2 points per 50 pull requests and 1 per
50 commits, from GraphQL's own hourly budget. REST would cost three calls per
pull request and one per commit, about 8,400 for 30 days of microsoft/vscode.
A pull request whose reviews (more than 50) or checks (more than 100) overflow
one page is read over REST. Measured: 30 days of microsoft/vscode (1,809
merged pull requests, about 2,500 commits) in 14 minutes; 3 days (247 pull
requests) in 4 REST calls and 14 GraphQL queries. The run fails as
truncated, never partial, beyond `max_pull_requests` or `max_commits`.
`dependabot_alerts` downloads CISA's KEV catalog once per run; set `check_kev:
false` where `cisa.gov` is unreachable.
`actions_security` reads workflow files ten repositories to a GraphQL query and
makes two to four REST calls per repository. `release_integrity` makes one call
per release asset, `deployment_controls` one per production deployment plus a
GraphQL query per twenty deployed commits, and `audit_log` one per hundred
events.

## Significant change notifications

`github_significant_change_notifications` is the GitHub side of
`gitlab_significant_change_notifications`. Both use one parser and FedRAMP
schema validator (`fetchers/_lib/fedramp_scn.py`), so one template yields the
same notification on both platforms. Install its template,
[`significant_change.md`](../gitlab/significant_change_notifications/templates/significant_change.md),
as `.github/pull_request_template.md` (or under `.github/PULL_REQUEST_TEMPLATE/`).
A pull request is flagged by ticking `Significant Change — SCN required`, or by
`marker_label`. Set `cert_package_uri` (shared with the paramify VER fetchers) or
`fedramp_cert_package_uri`. Scan `state: open` for transformative changes, which
need notice before they ship. The GitLab fetcher's README describes the parsing.
