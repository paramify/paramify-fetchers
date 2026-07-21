# GitLab

GitLab fetchers pull CI/CD pipeline configuration, merge request summaries, and project summaries from the GitLab REST API. Each fetcher runs once per project — the runner fans out across the projects listed as targets in the manifest.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `GITLAB_API_TOKEN` | Yes | GitLab project access token (per target) |
| `GITLAB_URL` | Yes | GitLab instance base URL, no trailing slash |
| `GITLAB_PROJECT_ID` | Yes | Project path or numeric ID (e.g. `group/project`) |
| `GITLAB_BRANCH` | No | Branch/ref to use (default `main`) |

## Creating a token (recommended: Project Access Token)

A project-scoped token is preferred over a personal access token — it limits the credential to the specific project being scanned.

1. Open your GitLab project.
2. Navigate to **Settings → Access Tokens**.
3. Click **Add new token** and name it `paramify-evidence-fetchers`.
4. Set an expiration date aligned with your rotation policy.
5. Select scopes: **`read_api`** (add **`read_repository`** if your GitLab instance requires it for file/tree endpoints).
6. Set the role to **Reporter** or higher (read-only access is sufficient).
7. Copy the token immediately — it is not shown again.

For a personal access token (if project tokens are unavailable): **Profile → Access Tokens → Add new token**, with the same scopes.

## Required permissions

- **Scopes:** `read_api`, `read_repository`
- **Project role:** Reporter or higher

## Wiring into a manifest

GitLab fetchers are fanout — each target is one project. Use `add-target` once per project. The API token is declared `per_target` in the fetcher schema, so each target can use a different token:

```bash
paramify manifest add gitlab_ci_cd_pipeline_config

# First project
paramify manifest add-target gitlab_ci_cd_pipeline_config \
  project_id=group/change-management \
  url=https://gitlab.example.com \
  --secret api_token=GITLAB_TOKEN_1

# Second project (can use a different token, or the same one)
paramify manifest add-target gitlab_ci_cd_pipeline_config \
  project_id=group/terraform \
  url=https://gitlab.example.com \
  branch=main \
  --secret api_token=GITLAB_TOKEN_2
```

If all projects share one token, point every target at the same env var name.

## Smoke test

```bash
curl -s -H "PRIVATE-TOKEN: $GITLAB_API_TOKEN" \
  "$GITLAB_URL/api/v4/projects/$(python3 -c 'import os,urllib.parse; print(urllib.parse.quote(os.environ["GITLAB_PROJECT_ID"],safe=""))')" \
  | python3 -m json.tool | head -20
```

## Rotating the token

1. Create a second token — do not revoke the old one yet.
2. Update the env var in your secrets store.
3. Run the smoke test.
4. Revoke the old token.

## Notes

- GitLab fetchers paginate via `per_page` + `page` and make multiple requests for large projects or MR sets.
- Checkov fetchers use a separate token (`GIT_CLONE_TOKEN`) for git clone access — see [`../checkov/README.md`](../checkov/README.md).
