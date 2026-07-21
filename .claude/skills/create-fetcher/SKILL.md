---
name: create-fetcher
description: >
  Create a new Paramify evidence fetcher, or port an existing one from
  another source. Use when the user wants to add a fetcher,
  integrate a new tool or data source (aws, azure, okta, gitlab, k8s, …),
  or scaffold a fetcher for a category. Runs a short interview, scaffolds to
  the v0.x contract, and verifies the wiring via the runner.
---

# Create a Fetcher

This skill walks you through building one Paramify evidence fetcher end to end:
route (port vs new) → orient → interview → build → verify. It is the
interactive layer over the canonical docs — read those for detail, don't
restate them here.

**Golden rules**
- One fetcher = one evidence set. Directory is `fetchers/<category>/<short_name>/`;
  the `name:` field is the globally-unique `<category>_<short_name>`.
- The fetcher writes a **raw evidence dict** to `EVIDENCE_DIR`. The runner wraps
  it in the envelope — do NOT emit `metadata`+`payload` yourself.
- Every env var the fetcher reads must be declared as a `secret` OR a
  config/target field, or the runner strips it.
- Version is `0.1.0`. Directories starting with `_` are skipped by discovery.

---

## Phase 0 — Route: port or net-new

1. Ask the user: **what tool/data source, and what evidence** should this collect?
   Derive `<category>` (source-system family, e.g. `aws`) and `<short_name>`
   (evidence type, e.g. `iam_roles`). Both lowercase, underscore-separated.

2. **Collision check** — if the directory already exists, stop and ask the user
   whether to overwrite, rename, or resume-edit:
   ```bash
   test -d fetchers/<category>/<short_name> && echo "EXISTS — ask user" || echo "free"
   ```

3. **Decide port vs new.** Ask: "Do you already have a working script that
   collects this evidence (in another repo, a local file, etc.)?"
   - **Yes → PORT.** Follow `docs/porting_playbook.md` step by step
     (it has its own verify gates and anti-patterns). Stop using this file.
   - **No → NET-NEW.** Continue below.

---

## Phase 1 — Orient

Read these before building (skim, don't summarize back):
- `docs/authoring_a_fetcher.md` — the net-new authoring guide. This is the
  canonical reference for the rest of this skill; lean on it, don't restate it.
- `framework/schemas/fetcher_schema.json` — the enforced schema (required:
  name, version, description, runtime, output, secrets).
- The closest **reference fetcher** to mirror — pick from the list in
  `docs/authoring_a_fetcher.md` §"Reference fetchers" (single vs. fanout ×
  bash vs. Python), so the skill never drifts from the maintained set.

---

## Phase 2 — Interview

**Infer what you can; ask only what's genuinely ambiguous.** Keep it short.

**Infer silently, then show for confirmation:**
- `runtime` — **bash** (`<cli> … | jq`) if the tool ships a first-class CLI
  (aws, az, kubectl, gcloud); **python** if it needs an SDK/REST client,
  pagination, or non-trivial parsing (okta, gitlab, rippling).
- `description` and `evidence_set.instructions` — from the user's goal + the
  exact API/CLI calls the fetcher will make.
- `category` — from the tool name.

**Ask the user (batch into ONE `AskUserQuestion`, ≤3 questions):**
1. **Auth model** — a long-lived token/key the fetcher reads from env (→ one
   `secrets[]` entry per var), OR an ambient cloud credential chain like
   `aws`/`az` login (→ `secrets: []`, and the identity vars go in the category's
   `auth.passthrough_env`)?
2. **Fanout** — one account/tenant (single), or run once per target — per
   project/region/subscription (→ `supports_targets: true`, `target_schema`,
   `aggregation: per_target`)?
3. **Evidence set** — `reference_id` (stable key, e.g. `EVD-AZURE-STORAGE-ENC`)
   and display `name`.

**Only if it comes up — don't ask proactively:**
- Non-secret knobs/filters → `config_schema` field with an `env` (the runner
  injects it), e.g. `BUCKETS_TO_INCLUDE`.
- First fetcher in a new category → Phase 3 does per-category setup.
- A long scanner → `runtime.timeout` (default 600s).

**Do NOT offer** `depends_on`/comparators (schema has it but the runner has no
consumer yet — it won't run), or `controls`/`validation_rules`/`tags` (schema
rejects them).

**Checkpoint:** print the resolved spec — name, runtime, `secrets[]`, fanout +
`target_schema`, `evidence_set`, and how a failed run is detected — and get a
single confirmation before building.

---

## Phase 3 — Build

1. **New category?** Create `fetchers/_categories/<category>.yaml` (description;
   `auth.passthrough_env` for ambient-credential tools; shared `config_schema`).
   If multiple fetchers will share code, make `fetchers/<category>/_shared/`.
   Add new Python deps to top-level `requirements.txt`.

2. **Scaffold:** `cp -r fetchers/_template fetchers/<category>/<short_name>`.
   Lean ports ship just `fetcher.yaml` + the entry script — drop the template's
   README/tests/schemas unless you're adding real content.

3. **Write `fetcher.yaml`** to the schema. Use the auth/fanout decisions from
   Phase 2. Include the `evidence_set` block.

4. **Write the entry script** following `docs/authoring_a_fetcher.md`
   §`fetcher.py` / §`fetcher.sh` (which link onward to the canonical skeleton).
   Keep status output to one `logger.info`/`log_info` "Evidence saved to …"
   line on success. Mirror the reference fetcher's shape.

5. **Wire failure → exit code** per `docs/authoring_a_fetcher.md` §"Detecting
   collection failures": track collection failures, exit non-zero if any
   occurred (Python: an `api_failures` list; bash: a temp-file counter).

6. If bash: `chmod +x fetchers/<category>/<short_name>/fetcher.sh`.

---

## Phase 4 — Verify (STOP on any failure)

The skill verifies **wiring**, not data — it can't hit the user's real tenant.

1. **Schema-valid + discovered:**
   ```bash
   paramify list   # your fetcher appears, right [fanout]/[single]
   ```
2. **Entry script loads:**
   ```bash
   bash -n fetchers/<category>/<short_name>/fetcher.sh           # bash
   # or, python:
   .venv/bin/python -c "import importlib.util as u; s=u.spec_from_file_location('c','fetchers/<category>/<short_name>/fetcher.py'); m=u.module_from_spec(s); s.loader.exec_module(m); print('OK')"
   ```
3. **Fake-cred smoke test** — proves the env path is intact:
   ```bash
   <ENV_VARS>=fake EVIDENCE_DIR=/tmp/paramify-verify \
     <bash fetcher.sh | .venv/bin/python fetcher.py>
   echo "exit: $?"
   ```
   - **PASS:** exits **non-zero** with a network-layer error (DNS/connection/401),
     and a valid JSON file was still written.
   - **FAIL:** exit 0 (failure detection is broken — fix step 5), or
     `ModuleNotFoundError` / "missing required env var" before real work begins
     (fix imports or the declared env var names).

4. **Hand back the real-tenant command** for the user to run with real creds,
   and say plainly: a green smoke test means the wiring is correct, not that it
   collects correct data — that's the user's real-tenant run to confirm. Once
   that run produces real evidence, the `suggest-validator` skill can read it and
   propose a regex validator for the field that proves the control.

5. **Wire it into a manifest.** A fetcher on disk does not run until it's in a
   manifest's `run.fetchers:`. To add it and fill in the secrets/config/targets
   it needs, use the `wire-manifest` skill (or, quickly:
   `paramify manifest add <fetcher>` then `validate`).

---

## Anti-patterns

Full list in `docs/authoring_a_fetcher.md` §"What you don't need to do". The
ones that bite most often:

- Directory `<category>_<short_name>/` → use `<short_name>/` only.
- `version: 1.0.0` → `0.1.0` for pre-contract fetchers.
- Emitting an envelope (`metadata`+`payload`) → write a raw evidence dict; the
  runner wraps it.
- `print(...)` status chatter → one `logger.info` on success.
- A CLI arg parser for `--output-dir`/`--profile`/`--region` → read everything
  from env.
- Forgetting `chmod +x` on a bash entry script.
