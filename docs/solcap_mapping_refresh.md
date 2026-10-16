# Refreshing the solution capability mapping

`mappings/solution_capabilities.yaml` says which solution capabilities each
fetcher's evidence speaks to. It is generated from the "20x Mapping" tab of the
fetcher-to-solution-capability mapping sheet, and the sheet is the source of
truth: fix a mapping there, never in the YAML.

`.github/workflows/solcap-mapping-refresh.yml` re-imports the tab every Monday
(and on demand) and proposes the result as a single rolling pull request,
`bot/solcap-mapping-refresh`. Nothing reaches `main` until a person merges it.
When the sheet hasn't changed, no PR is opened.

## What the PR tells you

The PR body is the importer's report:

- **Changes**: mappings added, removed, and whose KSIs moved.
- **Sheet problems**: rows that look wrong, with their sheet row numbers. None
  of them stop the import; fix them in the sheet and the next refresh picks the
  fix up.

| Problem | Meaning |
|---|---|
| Not a library id | `Sol Cap ID` isn't `RS-nn-nn-nn`, so it can never match a workspace capability by id |
| One id, several names / One name, several ids | the same capability is spelled two ways |
| Platform disagrees with the fetcher | the row's `Platform` names a different fetcher category than the fetcher's own (e.g. "Azure" on a GCP fetcher). Free-text values that name no category ("S3", "AWS IAM") are not flagged |
| Fetcher not in this repo | the rows are left out of the YAML; a typo, a renamed fetcher, or one not built yet |
| No Sol Cap ID | the mapping can only be name-matched, which always needs a person's approval |
| Duplicate rows | the same fetcher × capability × KSI appears twice |

Merging the PR pairs nothing. The mapping is a suggestion list read while a
validator is authored: which capabilities a validator for that fetcher's
evidence could prove.

## Running it by hand

Export the tab as CSV (File → Download → Comma-separated values, with the
"20x Mapping" tab selected), then:

```bash
python tools/import_solcap_mapping.py ~/Downloads/20x-mapping.csv --report report.md
python tools/import_solcap_mapping.py ~/Downloads/20x-mapping.csv --check   # exit 1 if it would change
```

## One-time setup

The job reads the sheet with no stored key. GitHub's OIDC token is exchanged
through Google Workload Identity Federation for a five-minute token of a service
account whose only access is **Viewer** on that one sheet. The identity pool
accepts tokens from this repository's `main` branch only, so a workflow on a
pull request branch cannot mint one.

Pick a Google Cloud project to hold the service account and the pool:

```bash
PROJECT_ID=<project>
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
REPO=paramify/paramify-fetchers
REPO_ID=$(gh api "repos/$REPO" --jq .id)

gcloud services enable sheets.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
  --project "$PROJECT_ID"

# The reader. It gets no project roles at all; its only access is the sheet share below.
gcloud iam service-accounts create solcap-sheet-reader --project "$PROJECT_ID" \
  --display-name "Reads the solcap mapping sheet (GitHub Actions)"
SA="solcap-sheet-reader@$PROJECT_ID.iam.gserviceaccount.com"

# The pool and its GitHub provider, pinned to this repo (by its numeric id, which
# survives a rename) and to main.
gcloud iam workload-identity-pools create github --project "$PROJECT_ID" \
  --location global --display-name "GitHub Actions"
gcloud iam workload-identity-pools providers create-oidc paramify-fetchers --project "$PROJECT_ID" \
  --location global --workload-identity-pool github \
  --issuer-uri https://token.actions.githubusercontent.com \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_id=assertion.repository_id,attribute.ref=assertion.ref" \
  --attribute-condition "assertion.repository_id == '$REPO_ID' && assertion.ref == 'refs/heads/main'"

# Let workflows from this repo act as the reader.
gcloud iam service-accounts add-iam-policy-binding "$SA" --project "$PROJECT_ID" \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/attribute.repository_id/$REPO_ID"
```

Then:

1. **Share the sheet** with `$SA` as **Viewer** (Share → add the email; there's
   no inbox, so untick "Notify").
2. **Add the repository secrets.** The workflow logs are public, so these are
   secrets rather than variables:

   ```bash
   gh secret set SOLCAP_WIF_PROVIDER --repo "$REPO" \
     --body "projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github/providers/paramify-fetchers"
   gh secret set SOLCAP_SHEET_READER --repo "$REPO" --body "$SA"
   gh secret set SOLCAP_SHEET_ID  --repo "$REPO" --body "<id from the sheet URL: /d/<id>/edit>"
   gh secret set SOLCAP_SHEET_GID --repo "$REPO" --body "<the tab's gid from its URL: #gid=<gid>>"
   ```

   The gid, not the tab name, picks the tab, so renaming the tab doesn't break
   the job.
3. **Let the job open pull requests.** Either
   - turn on *Settings → Actions → General → Allow GitHub Actions to create and
     approve pull requests*. A PR opened this way does **not** trigger CI, so the
     workflow runs the mapping tests itself; to run full CI on the PR, close and
     reopen it. Or
   - add a `SOLCAP_PR_TOKEN` secret (a GitHub App installation token or a
     fine-grained token with *Contents* and *Pull requests* write on this repo).
     PRs it opens run CI normally.
4. **Try it:** `gh workflow run solcap-mapping-refresh.yml --repo "$REPO"`, then
   check the run summary (it carries the same report as the PR body).
