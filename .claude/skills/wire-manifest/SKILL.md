---
name: wire-manifest
description: >
  Check a manifest against a fetcher's contract and wire it up to run — add a
  fetcher to the manifest, diagnose why a fetcher won't run, or fill in the
  secrets/config/targets a fetcher needs. Use when the user just made a fetcher
  and wants to add it, asks "why won't my fetcher run", or wants to verify their
  manifest can run a specific fetcher. Reads the manifest, diffs it against the
  fetcher's contract, and emits the exact `paramify manifest` commands
  to close the gaps.
---

# Wire a Manifest

This skill takes one fetcher + one manifest and answers "what's missing to run
this?", then wires it up. It is the interactive layer over the runner's
`describe` / `validate` / `manifest` commands — lean on those, don't reimplement
their checks.

**Golden rules**
- The manifest's `run.fetchers:` list IS the "what to run" decision. A fetcher
  that exists on disk but isn't in the manifest **never runs**. Presence is the
  first thing to check.
- Edit via the `paramify manifest` subcommands, never hand-edit YAML —
  they coerce field types and re-validate on write. Hand-editing is a fallback,
  not the path.
- Secrets are wired as `${env:VAR_NAME}` refs — you set the **env var name**,
  never the secret value. `validate` checks the ref is present in the manifest;
  it does **not** check the env var is set in the shell — that's a separate step
  this skill adds.
- A clean `validate` means the manifest is **structurally runnable**, not that
  credentials are valid or the collected data is correct.

---

## Phase 0 — Identify the fetcher and the manifest

1. **Which fetcher?** The one the user just made, or a name they give. If unsure,
   `paramify list` shows discovered fetchers.

2. **Which manifest?** Default `./manifest.yaml` (the runner's default; override
   with `-f`). If it doesn't exist yet:
   ```bash
   paramify manifest init   # writes manifest.yaml with output_dir
   ```

3. **Confirm the fetcher is discoverable** before touching the manifest:
   ```bash
   paramify describe <fetcher> --json
   ```
   If `describe` errors with "unknown fetcher", the problem is **discovery, not
   the manifest** — wrong directory, a `_`-prefixed dir, or a schema-invalid
   `fetcher.yaml`. Stop and route to `create-fetcher` / fix the fetcher first.

---

## Phase 1 — Read the contract and the current state

- **Contract** — from `describe <fetcher> --json`: required vs optional
  `secrets`, `config`, `target_schema`, and the `supports_targets` flag (fanout
  or single). Note which secrets are `per_target`.
- **Current manifest** — `paramify manifest show --json`
  (or read the file). Determine:
  - Is the fetcher present in `run.fetchers:` at all?
  - What `secrets` / `config` / `targets` are already wired on its entry?
  - For platform-wide config: is it under `run.platforms.<category>`?

---

## Phase 2 — Diagnose the gaps

1. **Run the authoritative check:**
   ```bash
   paramify validate <manifest> --json
   ```
   `validate` reports the structural gaps for entries **that are present**:
   unknown fetcher, fanout/target mismatch (targets on a single fetcher or none
   on a fanout one), missing required config (platform or per-fetcher), and
   missing secrets including per-target ones. Treat its `errors[]` as the gap list.

2. **Presence gap (validate can't see this):** if the fetcher is **absent** from
   `run.fetchers:`, `validate` says nothing about it — it only checks entries
   that exist. So an absent fetcher = a `manifest add` is needed, even on a clean
   `validate`. Check presence yourself in Phase 1.

3. **Env-var gap (validate can't see this either):** `validate` confirms a
   secret has a `${env:VAR}` ref, not that `VAR` is exported. Best-effort, check
   each referenced var is set (presence only — never print values):
   ```bash
   # for each VAR referenced as ${env:VAR} on this fetcher's entry/targets:
   [ -n "${VAR:-}" ] && echo "VAR set" || echo "VAR MISSING — set before run"
   ```
   Report missing vars as a pre-run warning, not a manifest edit.

---

## Phase 3 — Produce the fix

Build the exact command sequence from the gaps. Map each gap to one command:

| Gap | Command |
|-----|---------|
| Fetcher absent | `manifest add <fetcher>` |
| Missing secret | `manifest set-secret <fetcher> <secret_name> <ENV_VAR>` |
| Missing per-fetcher config | `manifest set-config <fetcher> key=value` |
| Missing platform config | `manifest set-platform-config <category> key=value` |
| Fanout needs targets | `manifest add-target <fetcher> field=val ... --secret name=ENV_VAR` |
| Ambient-cred var stripped | `manifest set-passthrough <category> VAR [VAR ...]` |
| Programs needed as targets | `programs target [fetcher ...]` |
| Issue report has no `assessment_id` | `assessments select <fetcher>` |

All prefixed with `paramify`.

The last two reach the Paramify API (`PARAMIFY_API_TOKEN`, read scope) because
both wire in a UUID the operator knows only by name. Use them rather than
`set-config assessment_id=<uuid>` or a hand-written target: they compose the same
mutators, and they validate the UUID exists while it is still cheap to fix.
`assessments select` also filters the choices to the assessment type the fetcher
declares, which `set-config` cannot do.

The manifest is the **user's file** — before editing it, show the planned
commands and ask whether to run them or just hand them over. Default to showing
first when several edits are involved.

---

## Phase 4 — Verify (STOP on any failure)

1. **Clean validate:**
   ```bash
   paramify validate <manifest>
   # expect: "OK  manifest valid; N fetcher entries"
   ```
2. **Hand back the run command** and state the boundary plainly: a clean
   `validate` means the wiring is correct, **not** that credentials work or the
   data is right — that's the user's real run to confirm. Remind them the
   `${env:VAR}` vars must be set in the shell first (Phase 2 step 3).
   ```bash
   paramify run <manifest>
   ```
   If the fetcher is `kind: issue_report`, also remind them that `paramify run`
   only collects: intake is `paramify issues upload` after the run, and a
   missing `assessment_id` is `paramify assessments select <fetcher>` first.

---

## Anti-patterns

- Hand-editing the manifest YAML when a `manifest` subcommand does it (and
  re-validates).
- Putting a **secret value** in the manifest instead of a `${env:VAR}` ref.
- Assuming a fetcher runs because the directory exists — it must be in
  `run.fetchers:`.
- Treating a clean `validate` as proof the creds work or the env vars are set.
- Adding `targets:` to a single-target fetcher, or omitting them for a fanout one
  (`validate` flags both — let it).
