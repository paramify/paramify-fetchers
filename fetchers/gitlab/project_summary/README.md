# gitlab_project_summary

Inventories configuration files (Terraform, Dockerfiles, YAML configs, etc.) in a GitLab project repository. Evidence of information resource inventory (KSI-PIY-GIV).

## Fanout-capable

Single-target per invocation; runner fans out across multiple projects via `supports_targets: true`. See [`docs/run_manifest_guide.md`](../../../docs/run_manifest_guide.md#3-fan-out-with-targets) for the manifest shape.

## Required env vars

| Var | Source |
|-----|--------|
| `GITLAB_URL` | `target_schema.url` |
| `GITLAB_API_TOKEN` | per-target secret |
| `GITLAB_PROJECT_ID` | `target_schema.project_id` |
| `GITLAB_FILE_PATTERNS` | `target_schema.file_patterns` (optional; comma-separated list of extensions/filenames; defaults to compliance-relevant set) |
| `EVIDENCE_DIR` | runner-set |

## Output

`<EVIDENCE_DIR>/gitlab_project_summary_<sanitized_project_id>.json`

## Exit codes

- `0` — success
- `1` — required env var missing, or API error
