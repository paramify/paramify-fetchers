# <fetcher_name>

<One sentence: what evidence this collects and from where.>

## What it speaks to

<Which KSI / control / capability this evidence supports.
Compliance mapping is a Paramify-side configuration concern, not a fetcher
concern. This section is informational, not authoritative.>

## Required env vars

| Var | Purpose |
|-----|---------|
| `<UPPER_SNAKE_ENV_VAR>` | <what it's for> |
| `EVIDENCE_DIR` | Output directory (defaults to `./evidence`) |

## How to run

The fetcher reads secrets from `os.environ`. Any mechanism that populates the
process environment works — `.env`, `export`, AWS Secrets Manager, HashiCorp
Vault, K8s secret env mounts, CI provider secret blocks, etc. All are equally
supported; `.env` is not privileged.

```bash
# From repo root, with required env vars set in the environment:
python fetchers/<category>/<short_name>/fetcher.py
```

## Output

Writes `<category>_<short_name>.json` to `EVIDENCE_DIR`.

## Known v0.x interim behavior

- Reads env vars directly via `os.getenv` (replaced by the framework's secret resolver later).
- Reads `EVIDENCE_DIR` from env (replaced by the runner passing an output path later).
