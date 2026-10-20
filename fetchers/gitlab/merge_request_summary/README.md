# gitlab_merge_request_summary

Pulls recent merge requests for a GitLab project with approval, discussion, and timing metadata. Evidence for change-management compliance (KSI-CMT-LMC).

## Fanout-capable

Single-target per invocation; runner fans out across multiple projects via `supports_targets: true`. See [`docs/run_manifest_guide.md`](../../../docs/run_manifest_guide.md#3-fan-out-with-targets) for the manifest shape.

## Required env vars

| Var | Source |
|-----|--------|
| `GITLAB_URL` | `target_schema.url` |
| `GITLAB_API_TOKEN` | per-target secret |
| `GITLAB_PROJECT_ID` | `target_schema.project_id` |
| `GITLAB_MR_STATE` | `target_schema.state` (default `merged`) |
| `GITLAB_MR_DAYS_BACK` | `target_schema.days_back` (default `30`) |
| `GITLAB_MR_MAX_RESULTS` | `target_schema.max_results` (default `50`) |
| `EVIDENCE_DIR` | runner-set |

## Output

`<EVIDENCE_DIR>/gitlab_merge_request_summary_<sanitized_project_id>.json`

## Exit codes

- `0` — success
- `1` — required env var missing, or API error
