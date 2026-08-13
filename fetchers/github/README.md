# GitHub

GitHub fetchers pull source-control and CI/CD configuration evidence from the
GitHub REST API. All three are **read-only** and run once per **organization** —
the runner fans out across the organizations listed as targets in the manifest.

Transport is `requests` against `api.github.com` (or your GitHub Enterprise
Server). **No new dependency:** `requests` is already in the top-level
`requirements.txt`, and this category deliberately does not use PyGithub.

| Fetcher | Evidence | GitHub REST endpoints |
|---|---|---|
| `github_repository_branch_protection` | Per-repo default-branch protection: required PR reviews + approval count, status checks, enforce-admins, signed commits, force-push/deletion, linear history, conversation resolution; plus private/archived, secret scanning, push protection, Dependabot alerts | `/orgs/{org}/repos`, `/repos/{o}/{r}`, `/repos/{o}/{r}/branches/{b}/protection`, `…/protection/required_signatures`, `/repos/{o}/{r}/dependabot/alerts` |
| `github_organization_security_settings` | Org posture: 2FA requirement, default (base) repository permission, member + outside-collaborator counts, repo creation/deletion + private-fork policy, SAML SSO state, code-security defaults for new repos | `/orgs/{org}`, `/orgs/{org}/members`, `/orgs/{org}/outside_collaborators`, `/orgs/{org}/credential-authorizations` |
| `github_actions_workflow_config` | Actions supply chain: allowed-actions policy, workflow PR approval, default `GITHUB_TOKEN` permission (read vs write), self-hosted runners + runner groups, Actions secret **names and counts only** | `/orgs/{org}/actions/permissions[/selected-actions|/workflow]`, `/orgs/{org}/actions/{runners,runner-groups,secrets}`, and the `/repos/{o}/{r}/actions/…` equivalents |

## The one thing to get right

**"Is the branch protected?" is not the control.** A repository can have branch
protection enabled while requiring zero approving reviews, permitting force
pushes, and exempting administrators — a validator asserting `protected: true`
waves that through. What actually varies, and what these fetchers capture, is the
*content* of the rule: `approval_count`, `enforce_admins`,
`required_status_checks`, `require_signed_commits`, `allow_force_pushes`.

Three distinctions the evidence keeps deliberately separate, because collapsing
them either fabricates or hides a finding:

| State | Means | Written as |
|---|---|---|
| `protection_state: "protected"` | A rule exists; its fields say what it requires | booleans as configured |
| `protection_state: "unprotected"` | The endpoint returned 404 — no rule at all | positives `false`, `allow_force_pushes`/`allow_deletions` `true` |
| `protection_state: "unknown"` | The call failed; we cannot know | every field `null`, run exits non-zero |

The same rule applies to org settings and repo security features: a field the
token cannot see is `null` with a `*_visible: false` flag beside it, **never**
`false`. Reporting "not visible" as "disabled" would invent a finding out of a
permissions gap.

## Organization is required

Unlike the `aws` / `azure` / `gcp` categories there is no ambient identity to
fall back on. A GitHub token can see several organizations plus personal
repositories, and the API resolves no "current org", so `organization` is a
**required** target field. Inferring it from whatever the token can reach would
mean the evidence set's contents change the day someone's token gains access to
another org.

## Prerequisites: a read-only token

Two token types work, both read-only. A **fine-grained PAT** scoped to the
organization is preferred.

1. **Fine-grained PAT** — GitHub → *Settings → Developer settings → Personal
   access tokens → Fine-grained tokens → Generate new token*. Set **Resource
   owner** to your organization, an expiry aligned with your rotation policy, and:

   | Permission | Level | Needed for |
   |---|---|---|
   | Repository → Metadata | Read | repo list, default branch |
   | Repository → Administration | Read | branch protection, `security_and_analysis`, repo Actions settings |
   | Repository → Secrets | Read | repo Actions secret names |
   | Repository → Dependabot alerts | Read | Dependabot alert status |
   | Organization → Administration | Read | org settings, 2FA requirement, Actions policy |
   | Organization → Members | Read | member / outside-collaborator counts |
   | Organization → Self-hosted runners | Read | runners and runner groups |
   | Organization → Secrets | Read | org Actions secret names |

2. **GitHub App installation token** (`ghs_…`) with the same read-only
   permissions. Hand over the **already-exchanged installation token** — the
   fetchers never mint one, because minting needs the App private key and that
   stays outside this repo. Installation tokens expire after an hour, so resolve
   them at run time from your secret store.

Classic PATs (`read:org`, `repo`) work but grant far more than is needed.

> A missing permission surfaces as an API failure and a non-zero exit, with the
> reason in the run's `metadata.error`. It is never silently recorded as
> "disabled" — see the table above.

## Wiring into a manifest

The token is declared as one secret per fetcher (not per target), so every
organization in a single entry is read with the **same** token. For
organizations with separate credentials, use one manifest per organization.

```bash
paramify manifest add github_repository_branch_protection
paramify manifest set-secret github_repository_branch_protection github_token=GITHUB_TOKEN
paramify manifest add-target github_repository_branch_protection organization=my-org
paramify validate manifest.yaml
paramify run manifest.yaml
```

A ready-to-edit manifest for all three fetchers is at
[`examples/github_scm_controls.yaml`](../../examples/github_scm_controls.yaml).

## Environment variables

| Variable | Required | Purpose | Declared in |
|---|---|---|---|
| `GITHUB_TOKEN` | Yes | Read-only PAT or App installation token | `secrets[].github_token` |
| `GITHUB_ORG` | Yes | Organization login to collect from (`GITHUB_ORGANIZATION` also accepted) | `target_schema.organization` |
| `GITHUB_API_URL` | No | API root; defaults to `https://api.github.com`. GHES: `https://ghe.example.com/api/v3` | category `passthrough_env` |
| `GITHUB_HTTP_TIMEOUT` | No | Per-request timeout in seconds (default 30) | category `passthrough_env` |
| `GITHUB_MAX_REPOSITORIES` | No | Cap repositories examined (0 = all) | `config_schema.max_repositories` |
| `GITHUB_INCLUDE_REPOSITORY_SETTINGS` | No | Actions fetcher: collect per-repo settings too (default true) | `config_schema.include_repository_settings` |
| `EVIDENCE_DIR` | — | Output directory (defaults to `./evidence`) | runner-set |
| `FETCHER_STATUS_FILE` | — | Where a failing run writes its reason | runner-set |

## Smoke test

```bash
curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
     -H "Accept: application/vnd.github+json" \
     -H "X-GitHub-Api-Version: 2022-11-28" \
     "${GITHUB_API_URL:-https://api.github.com}/orgs/$GITHUB_ORG" \
  | python3 -m json.tool | head -20
```

`two_factor_requirement_enabled` present in that output means the token has the
organization admin read the fetchers need; absent means it does not.

## Rotating the token

1. Create a second token — do not revoke the old one yet.
2. Update the value in your secrets store.
3. Run the smoke test.
4. Revoke the old token.

## Output & failure semantics

- One envelope per target (`aggregation: per_target`); the filename carries a
  sanitized organization login.
- Output is **deterministic** — records are sorted by a stable identifier and the
  JSON is written with sorted keys, so re-runs are byte-stable and regex
  validators stay quiet.
- **Partial failure never looks like success.** Any failed API call lands in
  `payload.metadata.api_failures`, sets `payload.metadata.partial_failure: true`,
  and exits non-zero. One inaccessible repository of fifty does not silently
  exit 0.
- On a non-zero exit each fetcher writes `{"error": …, "code": …}` to
  `$FETCHER_STATUS_FILE` so the reported failure reason is the real one rather
  than the tail of stderr. `code` is one of `auth_failed`, `not_authorized`,
  `target_unreachable`, `rate_limited`, `bad_config`, `partial_failure`,
  `internal_error`. With the env var unset this is a silent no-op.
- **Rate limits are reported, never slept through.** The contract forbids retry
  logic, so a 403/429 carrying rate-limit headers exits with `rate_limited` and
  the seconds until reset. A 403 *without* those headers is a permission problem
  and reports `not_authorized` — the two need different fixes.
- Pagination is handled internally by following the `Link: …; rel="next"` header.

## Secret values are never collected

The Actions fetcher records secret **names**, timestamps and visibility. GitHub
exposes no API that returns a secret value, and the fetcher additionally projects
each entry through an explicit field allowlist, so a future API change cannot
leak one into an evidence file. The resolved `GITHUB_TOKEN` is also registered
with a redaction filter, so it cannot appear in a recorded error message or the
status file.

## Request volume

The org-level fetchers are a handful of calls. The two repository-walking
fetchers scale with repository count:

| Fetcher | Requests |
|---|---|
| `github_organization_security_settings` | ~5 + member/collaborator pagination |
| `github_repository_branch_protection` | 1 + up to 3 per non-archived repo |
| `github_actions_workflow_config` | ~6 + up to 4 per non-archived repo |

Archived repositories are skipped (read-only, and out of the coverage
denominator). For a very large org, bound the run with `max_repositories` — when
it truncates, `summary.repositories_truncated` is `true` so a subset never reads
as complete — or set `include_repository_settings: false` for an org-only Actions
run. A fine-grained PAT gets 5,000 requests/hour.

## Provenance

Field projections for the repository and organization fetchers are ported from
[Prowler](https://github.com/prowler-cloud/prowler) (Apache-2.0, `master`):
`providers/github/services/repository/repository_service.py` (the `Repo` /
`Branch` models and its 18 checks) and
`providers/github/services/organization/organization_service.py` (the `Org` model
and its 5 checks). The "404 means unprotected / any other error means unknown"
split is Prowler's, kept so the two tools agree on what "unprotected" means.

Prowler's third GitHub service, `githubactions_service.py`, is **not** a
configuration model: it shells out to the `zizmor` binary and wraps per-workflow-
file static-analysis findings. That is a different kind of evidence and would add
a non-Python dependency, so `github_actions_workflow_config` carries over the
intent (Actions as the supply-chain attack surface) while taking its field
projection from GitHub's Actions REST API.

## Notes

- No validators ship with these fetchers yet — the validator registry is
  unmerged. `summary.protected_default_branch_percentage`,
  `summary.two_factor_required_for_all_members` and
  `summary.default_workflow_permissions` are the fields to write them against.
- SAML SSO **enforcement** (as opposed to "configured") is only visible via
  GraphQL; the REST-only signal is reported as `configured` / `not_configured` /
  `not_visible` rather than guessed at.
- GitLab fetchers are a separate category with their own token — see
  [`../gitlab/README.md`](../gitlab/README.md).
