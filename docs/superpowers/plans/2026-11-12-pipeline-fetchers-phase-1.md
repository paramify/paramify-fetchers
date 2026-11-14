# Pipeline Fetchers, Phase 1 (Inventory) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An inventory sent by `paramify upload` builds Paramify Inventory, or the upload says why it did not, and a new pipeline fetcher needs only a `pipeline:` block and its records.

**Architecture:** A `pipeline:` block in `fetcher.yaml` is parsed into `Fetcher.pipeline` and recorded by the runner as `metadata.pipeline`. The sync engine's desired step carries it onto `EntryDesired.pipeline`, and the delivery provider applies the pipeline rules on top of #301's routing: always a batch, never direct when batches exist, warn on `MANUAL`, refuse a set with validators, always send the envelope. `paramify validate`, a new `paramify preset` command and the TUI read the same block.

**Tech Stack:** Python 3, jsonschema (Draft 2020-12), Typer CLI, Textual TUI, pytest (+ syrupy snapshots for the TUI).

**Spec:** `docs/pipeline_fetchers_design.md` (§3–§5, §8–§10). Phase 2 (§6) and Phase 3 (§7) are out of scope.

## Global Constraints

- Ordinary evidence (an entry with no `pipeline`) routes exactly as on `main`. Every existing test in `tests/test_provider_delivery_*.py`, `tests/test_cli_upload_plan.py` and `tests/test_api_upload_engine.py` passes unchanged.
- `pipeline.type` enum: `inventory`, `vulnerability`, `configuration`. `kind: inventory` requires the block with `type: inventory`. `kind: evidence` (or no kind) and `kind: discovery` refuse it. `kind: issue_report` allows it (optional) with `type` `vulnerability` or `configuration`.
- `id_scheme` pattern: `^[a-z0-9]+(-[a-z0-9]+)*$`. `asset_id_field` is allowed only when `type` is not `inventory`. `preset` is refused by the schema.
- The inventory data path is always `payload.data`; the unique ID is always `unique_asset_identifier`. Neither is declared.
- A pipeline file is never sent direct while the workspace has batches. With no artifact request it goes in an evidence-level batch (`no_request` default `evidence` for pipeline entries).
- A pipeline file is always sent as the envelope, whatever `artifact_payload` says.
- The uploader never changes an evidence set's approval rule and never removes validators.
- Run `ruff check framework/` and `pytest -q` before each commit. TUI snapshot changes are updated with `pytest tests/test_tui_*.py --snapshot-update` and reviewed in the diff.
- Each task adds its own entry under `## [Unreleased]` in `CHANGELOG.md`.

## Review Focus

1. **A run collected before this change** has `metadata.inventory` but no `metadata.pipeline`. It must still be treated as a pipeline entry (`{"type": "inventory"}`). Test: Task 3, `test_old_inventory_run_is_a_pipeline_entry`.
2. **`artifact_payload: payload` with an inventory.** The bytes sent *and* the bytes the WAF scan reads must both be the envelope. Test: Task 4, `test_pipeline_file_is_sent_and_scanned_as_the_envelope`.
3. **An evidence set the uploader creates in this run** (`obs.evidence is None`) with `approval: MANUAL` in the manifest. No observed set exists, but the plan must still warn. Test: Task 3, `test_manual_approval_on_a_new_set_warns`.
4. **A pipeline entry whose every file is skipped** (an incomplete inventory) on a set that has validators. It must be a `noop` (nothing to send), not a validators refusal. Test: Task 3, `test_incomplete_inventory_on_a_set_with_validators_is_noop`.
5. **An evidence-set response without a `validators` key** (an older API, or the fake). It must parse as no validators, not crash. Test: Task 3, `test_evidence_without_validators_key_parses_empty`.

---

### Task 1: The `pipeline:` contract

**Files:**
- Modify: `framework/schemas/fetcher_schema.json` (add `properties.pipeline` and three `allOf` rules)
- Modify: `framework/contract.py` (add `Pipeline`, `Fetcher.pipeline`, `Fetcher.is_pipeline`)
- Modify: `framework/config_loader.py:129-180` (parse the block)
- Modify: `framework/api.py:_fetcher_descriptor` (add `d["pipeline"]`)
- Modify: `framework/envelope.py:build_metadata` (add `meta["pipeline"]`)
- Modify: `fetchers/github/repository_inventory/fetcher.yaml`, `fetchers/sophos/endpoint_inventory/fetcher.yaml`, `fetchers/_template_inventory/fetcher.yaml`
- Test: `tests/test_pipeline_contract.py` (new)

**Interfaces:**
- Produces: `framework.contract.Pipeline(type: str, id_scheme: str, asset_id_field: Optional[str] = None)` (a dataclass); `Fetcher.pipeline: Optional[Pipeline] = None`; `Fetcher.is_pipeline -> bool`; `framework.contract.pipeline_dict(p: Pipeline) -> Dict[str, str]` (keys `type`, `id_scheme`, and `asset_id_field` only when set), used by the descriptor and the envelope; `metadata["pipeline"]` and `descriptor["pipeline"]` both equal `pipeline_dict(fetcher.pipeline)`.

- [ ] **Step 1: Write the failing tests** in `tests/test_pipeline_contract.py`. Reuse the `_doc()` / `_schema_errors()` helpers pattern from `tests/test_inventory.py:44-61` (copy them; give `_doc` a default `pipeline={"type": "inventory", "id_scheme": "x-id"}`).

```python
def test_inventory_requires_the_pipeline_block():
    assert _schema_errors(_doc(pipeline=None))

def test_inventory_pipeline_type_must_be_inventory():
    assert _schema_errors(_doc(pipeline={"type": "vulnerability", "id_scheme": "x-id"}))

def test_evidence_fetcher_refuses_a_pipeline_block():
    assert _schema_errors(_doc(kind="evidence"))

def test_preset_is_refused_for_now():
    errs = _schema_errors(_doc(pipeline={"type": "inventory", "id_scheme": "x-id", "preset": "p"}))
    assert any("preset" in str(e.path) or "preset" in e.message for e in errs)

def test_id_scheme_is_kebab_case():
    assert _schema_errors(_doc(pipeline={"type": "inventory", "id_scheme": "Wiz ID"}))

def test_asset_id_field_is_refused_on_an_inventory():
    assert _schema_errors(_doc(pipeline={"type": "inventory", "id_scheme": "x-id", "asset_id_field": "c"}))

def test_issue_report_may_declare_a_vulnerability_pipeline():
    doc = _doc(kind="issue_report", evidence_set=None, output={"type": "csv", "path": "x.csv"},
               issue_report={"assessment_type": "VULNERABILITY"},
               pipeline={"type": "vulnerability", "id_scheme": "wiz-resource-id", "asset_id_field": "Resource ID"})
    assert not _schema_errors(doc)

def test_loader_parses_the_block_and_envelope_records_it(tmp_path):
    f = _parse_fetcher(_doc(), tmp_path)          # framework.config_loader._parse_fetcher(data, path)
    assert f.is_pipeline and f.pipeline == Pipeline("inventory", "x-id")
    # build an InvocationResult the way tests/test_envelope.py does (exit_code=0, no outputs)
    meta = build_metadata(result, f, "R1")
    assert meta["pipeline"] == {"type": "inventory", "id_scheme": "x-id"}

def test_every_inventory_fetcher_in_the_repo_declares_a_pipeline():
    fetchers = discover_fetchers(REPO_ROOT)
    assert all(f.is_pipeline for f in fetchers.values() if f.is_inventory)
```

- [ ] **Step 2: Run them and see them fail.** `pytest tests/test_pipeline_contract.py -v`. Expected: the schema tests fail (no `pipeline` property), and the loader test fails with an `ImportError` on `Pipeline`.

- [ ] **Step 3: Implement.**
  - Schema: `properties.pipeline` is an object with `additionalProperties: false`, required `["type", "id_scheme"]`, the properties from Global Constraints, and `"preset": {"not": {}, "description": "Reserved: a preset reference once the Paramify API can create presets. Not supported yet."}`. Add `allOf` rules: inventory requires `pipeline` with `type` const `inventory` and no `asset_id_field`; for a kind that is not `inventory`/`issue_report`, `not: {required: [pipeline]}`; for issue_report, `pipeline.type` is in `[vulnerability, configuration]`. Each rule gets a `$comment` in the style of the existing ones.
  - Loader: build `Pipeline` from `data.get("pipeline")` like `evidence_set`, and pass `pipeline=` to `Fetcher(...)`.
  - The descriptor and `build_metadata` add `pipeline_dict(...)` when `fetcher.pipeline` is set.
  - The three yaml files: `pipeline: {type: inventory, id_scheme: github-repository-url}` / `sophos-endpoint-id` / `<category>-<id>` (the template, with a comment pointing to `docs/pipeline_fetchers_guide.md`). Bump `version:` minor on the two real fetchers.

- [ ] **Step 4: Run the tests and see them pass.** `pytest tests/test_pipeline_contract.py tests/test_inventory.py tests/test_contract*.py -q`, then `pytest -q`. Expected: all pass.

- [ ] **Step 5: Commit.** `git commit -m "feat(contract): add the pipeline: block for fetchers that feed a Paramify pipeline"`

---

### Task 2: `asset_type` in the inventory record

**Files:**
- Modify: `framework/schemas/inventory_schema.json` (`items.required` gains `asset_type`, `minLength: 1`, a description naming the parent component)
- Modify: `framework/inventory.py:check` (add `by_asset_type`)
- Modify: `fetchers/_template_inventory/fetcher.py` (the template record writes `asset_type`)
- Test: `tests/test_inventory.py`

**Interfaces:**
- Produces: `metadata.inventory.by_asset_type: Dict[str, int]` (sorted by count, descending, then name), present only when the payload holds the contract. Task 6 reads it.

- [ ] **Step 1: Write the failing tests.**

```python
def test_a_record_without_asset_type_breaks_the_contract():
    p = {"records_included": True, "data": [{"unique_asset_identifier": "a"}]}
    assert any("asset_type" in s for s in payload_problems(p))

def test_the_verdict_counts_records_by_asset_type():
    data = [{"unique_asset_identifier": str(i), "asset_type": t} for i, t in enumerate(["server", "endpoint", "endpoint"])]
    block = check({"records_included": True, "data": data}, 0)
    assert block["by_asset_type"] == {"endpoint": 2, "server": 1}
    assert list(block["by_asset_type"]) == ["endpoint", "server"]
```

Update every existing fixture record in `tests/test_inventory.py` (and any other test that builds inventory records: `grep -rln unique_asset_identifier tests`) to include `asset_type`.

- [ ] **Step 2: Run them and see them fail.** `pytest tests/test_inventory.py -v`. Expected: the 2 new tests fail.

- [ ] **Step 3: Implement** the schema change and `by_asset_type` in `check()` (computed only when `payload_problems` is empty).

- [ ] **Step 4: Run the tests and see them pass.** `pytest -q`. Expected: all pass, including `tests/test_github_fetchers.py` and `tests/test_sophos_fetchers.py` (both fetchers already write `asset_type`).

- [ ] **Step 5: Commit.** `git commit -m "feat(inventory): require asset_type on each record and count records by it"`

---

### Task 3: Plan-side delivery rules for pipeline entries

**Files:**
- Modify: `framework/paramify/resources.py` (`EvidenceSet.validators`, `_evidence`)
- Modify: `framework/sync/providers/desired.py` (`EntryDesired.pipeline`, `DeliveryFile.pipeline`, the `no_request` default)
- Modify: `framework/sync/providers/delivery_routing.py` (`pipeline_refusal`)
- Modify: `framework/sync/providers/delivery.py` (`_plan_entry`: refusal, warnings, summary suffix)
- Modify: `tests/paramify_fake.py` (`add_evidence(..., validators=())`)
- Test: `tests/test_provider_delivery_diff.py`, `tests/test_paramify_resources.py`

**Interfaces:**
- Consumes: `metadata["pipeline"]` (Task 1).
- Produces:
  - `EvidenceSet.validators: Tuple[str, ...] = ()`: the names (else ids) of the set's paired validators, from the response's `validators` list. A missing key gives `()`.
  - `EntryDesired.pipeline: Optional[Dict[str, Any]] = None` and `DeliveryFile.pipeline: bool = False`.
  - `desired.pipeline_of(metadata: Dict) -> Optional[Dict[str, Any]]`: `metadata["pipeline"]`, else `{"type": "inventory"}` when `metadata["inventory"]` is a dict, else `None`.
  - `desired.DEFAULT_PIPELINE_NO_REQUEST = "evidence"`.
  - `delivery_routing.pipeline_refusal(entry: EntryDesired) -> Optional[Refusal]`.
  - Constants in `delivery.py`: `PIPELINE_DIRECT`, `PIPELINE_BATCHES_OFF`, `PIPELINE_MANUAL`, `PIPELINE_VALIDATORS` (exact copy below).

- [ ] **Step 1: Write the failing tests** in `tests/test_provider_delivery_diff.py`. Extend the `entry()` helper with `pipeline=None` and `approval="SUBMISSION_WITH_PASSING_VALIDATORS"` keyword arguments.

```python
INV = {"type": "inventory", "id_scheme": "x-id"}

def test_pipeline_entry_with_no_request_goes_in_an_evidence_batch(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel(), requests=(), current=()))
    assert a.verb == "deliver" and a.payload["target"] == "EVIDENCE"

def test_pipeline_entry_refuses_delivery_direct(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, delivery="direct"), observed(ev_with_channel()))
    assert a.verb == "refuse" and "never goes direct" in a.summary

def test_pipeline_entry_refuses_no_request_direct(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="direct"), observed(ev_with_channel(), requests=(), current=()))
    assert a.verb == "refuse"

def test_pipeline_entry_goes_direct_with_a_note_when_batches_are_off(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel()), BATCHES_OFF)
    assert a.payload["target"] == DIRECT and any("no batches" in w for w in a.warnings)

def test_manual_set_warns(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel(approval="MANUAL")))
    assert a.verb == "deliver" and any("approves MANUAL" in w for w in a.warnings)

def test_manual_approval_on_a_new_set_warns(tmp_path):            # Review Focus 3
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence", approval="MANUAL"), observed(None))
    assert any("approves MANUAL" in w for w in a.warnings)

def test_set_with_validators_refuses(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel(validators=("VAL-1",))))
    assert a.verb == "refuse" and "VAL-1" in a.summary and "never approve" in a.summary

def test_incomplete_inventory_on_a_set_with_validators_is_noop(tmp_path):  # Review Focus 4
    skipped = write_file(tmp_path, "a.json", key="aws_x", skip_reason="incomplete inventory not sent: x")
    a = plan_one(entry(tmp_path, pipeline=INV, files=(skipped,)), observed(ev_with_channel(validators=("VAL-1",))))
    assert a.verb == "noop"

def test_deliver_summary_says_the_pipeline_runs(tmp_path):
    a = plan_one(entry(tmp_path, pipeline=INV, no_request="evidence"), observed(ev_with_channel()))
    assert a.summary.endswith("approves on submit → pipeline runs")

def test_ordinary_evidence_with_no_request_still_goes_direct(tmp_path):
    a = plan_one(entry(tmp_path, no_request="direct"), observed(ev_with_channel(), requests=(), current=()))
    assert a.payload["target"] == DIRECT
```

Add `ev_with_channel(approval="SUBMISSION", validators=())` next to the existing fixtures if no equivalent exists, and let `write_file` take `skip_reason`. In `desired` tests (the file that covers `desired_from_run`, else `tests/test_sync_desired.py`):

```python
def test_old_inventory_run_is_a_pipeline_entry():                   # Review Focus 1
    assert pipeline_of({"inventory": {"complete": True}}) == {"type": "inventory"}
    assert pipeline_of({"pipeline": INV, "inventory": {}}) == INV
    assert pipeline_of({}) is None

def test_pipeline_entry_defaults_no_request_to_evidence(tmp_path):
    # a run dir with one enveloped inventory file and no manifest no_request
    [e] = desired_from_run(run_dir, {})
    assert e.pipeline == INV and e.no_request == "evidence"
```

In `tests/test_paramify_resources.py`:

```python
def test_evidence_without_validators_key_parses_empty():          # Review Focus 5
    assert _evidence({"id": "e", "referenceId": "R", "channels": []}).validators == ()

def test_evidence_validators_are_named():
    ev = _evidence({"id": "e", "referenceId": "R", "validators": [{"id": "v1", "name": "VAL-1"}, {"id": "v2"}]})
    assert ev.validators == ("VAL-1", "v2")
```

- [ ] **Step 2: Run them and see them fail.** `pytest tests/test_provider_delivery_diff.py tests/test_sync_desired.py tests/test_paramify_resources.py -q`. Expected: the new tests fail.

- [ ] **Step 3: Implement.**
  - `desired_from_run`: `pipeline = pipeline_of(md)`. `no_request = cfg.get("no_request") or (DEFAULT_PIPELINE_NO_REQUEST if pipeline else DEFAULT_NO_REQUEST)`. Set `DeliveryFile.pipeline=bool(pipeline_of(metadata))`.
  - `pipeline_refusal`: when `entry.pipeline` and (`entry.delivery == "direct"` or `entry.no_request == "direct"`), return `Refusal(PIPELINE_DIRECT, "remove delivery: direct and no_request: direct from this entry")`.
  - In `_plan_entry`, after the `if not files:` block and before routing: return the `pipeline_refusal` as a `refuse` action; then, when `obs.evidence` has validators, refuse with `PIPELINE_VALIDATORS` and fix `f"remove the validators from {e.reference_id} in the app"`. Add the warnings: `PIPELINE_BATCHES_OFF` when `direct == BATCHES_OFF`; `PIPELINE_MANUAL` when the observed set's approval, or (no set yet) `e.approval`, is `MANUAL`. Append `" · approves on submit → pipeline runs"` to a `deliver` summary when the approval is not `MANUAL` and the target is a batch.
  - `_direct_reason` must return `None` for `delivery: direct` on a pipeline entry, so the refusal (not a direct send) decides.
  - The copy:

```python
PIPELINE_DIRECT = "a pipeline file never goes direct: a direct upload is stored but builds nothing"
PIPELINE_BATCHES_OFF = "this workspace has no batches, so the pipeline file goes direct, the pre-batch way"
PIPELINE_MANUAL = "{ref} approves MANUAL; the {type} pipeline waits for someone to approve the batch"
PIPELINE_VALIDATORS = "{ref} has {n} validator(s) ({names}); its batches will never approve"
```

- [ ] **Step 4: Run the tests and see them pass.** `pytest -q`. Expected: all pass, with no existing delivery test changed.

- [ ] **Step 5: Commit.** `git commit -m "feat(upload): route pipeline files to a batch, never direct, and refuse sets with validators"`

---

### Task 4: Apply-side: envelope always, and results that say whether the pipeline runs

**Files:**
- Modify: `framework/sync/providers/delivery.py` (`_content`, `_scan`, `_Delivered`, the post-submit message)
- Test: `tests/test_provider_delivery_apply.py`, `tests/test_cli_upload_plan.py`

**Interfaces:**
- Consumes: `DeliveryFile.pipeline`, `EntryDesired.pipeline` (Task 3).
- Produces: the entry result JSON gains `"pipeline": {"type": str, "approved": bool}` when the entry is a pipeline entry (absent otherwise). `_Delivered.pipeline_type: Optional[str] = None`.

- [ ] **Step 1: Write the failing tests** with the existing `Harness` and `FakeParamify`.

```python
def test_pipeline_file_is_sent_and_scanned_as_the_envelope(tmp_path):   # Review Focus 2
    # harness with upload_cfg {"artifact_payload": "payload"} and one inventory file
    sent = fake.uploaded_bytes("inv.json")
    assert json.loads(sent).keys() == {"schema_version", "metadata", "payload"}
    # and the WAF scan saw the envelope: patch waf.scan to record its content, assert it is the envelope

def test_approved_pipeline_batch_says_the_pipeline_runs(tmp_path):
    outcome = ...  # apply one inventory entry on a SUBMISSION set
    assert "APPROVED: pipeline runs now; check Monitoring → Inventory" in outcome.detail
    assert outcome.result["pipeline"] == {"type": "inventory", "approved": True}

def test_submitted_pipeline_batch_is_not_success(tmp_path):
    # set approval MANUAL
    assert "SUBMITTED: waiting for approval; the pipeline has not run" in outcome.detail
    assert outcome.result["pipeline"]["approved"] is False

def test_ordinary_entry_result_has_no_pipeline_key(tmp_path):
    assert "pipeline" not in outcome.result
```

Use whatever accessor the harness already has for uploaded bytes and outcome details (see `Harness` at `tests/test_provider_delivery_apply.py:41`). Add `uploaded_bytes(name)` to `FakeParamify` if none exists.

Also add a CLI golden case in `tests/test_cli_upload_plan.py`: `--plan --json` on an inventory run carries the `approves on submit → pipeline runs` summary.

- [ ] **Step 2: Run them and see them fail.** `pytest tests/test_provider_delivery_apply.py tests/test_cli_upload_plan.py -q`. Expected: the new tests fail.

- [ ] **Step 3: Implement.**
  - `_plan_entry` puts `"pipeline": e.pipeline` in the action payload. `_started(p, mode)` sets `_Delivered.pipeline_type = (p.get("pipeline") or {}).get("type")`, so both the batch and the direct path carry it.
  - `_content(path, mode)` takes the mode explicitly, and callers pass `"envelope" if f.pipeline else self._payload_mode`. The `_waf_hits` cache key uses that same mode.
  - `_Delivered.result()` adds the `pipeline` key when `pipeline_type` is set, with `approved = (status == "APPROVED")`.
  - In the post-submit message (the `elif run.status == "SUBMITTED"` branch, `delivery.py` ~l.706): for a pipeline entry, `SUBMITTED` gives `"SUBMITTED: waiting for approval; the pipeline has not run"` (keep the validators-failed variant first), and `APPROVED` gives `"APPROVED: pipeline runs now; check {where}"`, where `where` is `Monitoring → Inventory` for `inventory` and `Monitoring → Issues` otherwise.

- [ ] **Step 4: Run the tests and see them pass.** `pytest -q`. Expected: all pass.

- [ ] **Step 5: Commit.** `git commit -m "feat(upload): always send pipeline files as the envelope and report whether the pipeline runs"`

---

### Task 5: `paramify validate` rules and the validator registry

**Files:**
- Modify: `framework/validators.py` (`pipeline_reference_ids`, `pipeline_conflicts`, and `manifest_reference_ids` skips pipeline sets)
- Modify: `framework/api.py` (`validate`, `validate_notes`)
- Modify: `uploaders/paramify_validators/syncer.py:collect_validators` (drop pipeline sets from explicit `reference_ids`)
- Test: `tests/test_validators_registry.py`, `tests/test_cli.py` (or the existing `api.validate` test file: `grep -ln "def test.*validate" tests`)

**Interfaces:**
- Consumes: `Fetcher.is_pipeline` (Task 1).
- Produces: `pipeline_reference_ids(fetchers: Dict[str, Fetcher]) -> Set[str]`; `pipeline_conflicts(validators: Iterable[Validator], fetchers: Dict[str, Fetcher]) -> List[str]`, one message per (validator, pipeline set).

- [ ] **Step 1: Write the failing tests.** Test helpers: `fake_inventory_fetcher(ref)` returns `_parse_fetcher(...)` of an inventory doc whose `evidence_set.reference_id` is `ref` (see Task 1); `manifest_using(name)` is `{"run": {"output_dir": "./evidence", "fetchers": [{"use": name}]}}`; `manifest_with(use=, paramify=)` is the same with `"paramify": paramify` on the entry and the fetcher's required secrets/config filled with placeholder `${env:X}` refs so that only the new rule can fail.

```python
def test_no_registry_validator_targets_a_pipeline_set():
    assert pipeline_conflicts(discover_validators(REPO_ROOT).values(), discover_fetchers(REPO_ROOT)) == []

def test_a_validator_on_a_pipeline_set_is_a_conflict():
    v = Validator(key="k", name="K", type="AUTOMATED", statement="s", evidence_sets=["EVD-X-INVENTORY"])
    [msg] = pipeline_conflicts([v], {"x_inventory": fake_inventory_fetcher("EVD-X-INVENTORY")})
    assert "k" in msg and "EVD-X-INVENTORY" in msg and "never approve" in msg

def test_manifest_scope_leaves_out_pipeline_sets():
    assert "EVD-X-INVENTORY" not in manifest_reference_ids(manifest_using("x_inventory"), fetchers)

def test_validate_refuses_direct_delivery_on_a_pipeline_entry(tmp_path):
    errs = api.validate(manifest_with(use="github_repository_inventory", paramify={"delivery": "direct"}), REPO_ROOT)
    assert any("never goes direct" in e for e in errs)

def test_validate_refuses_no_request_direct_on_a_pipeline_entry(tmp_path):
    errs = api.validate(manifest_with(use="github_repository_inventory", paramify={"no_request": "direct"}), REPO_ROOT)
    assert any("never goes direct" in e for e in errs)

def test_validate_notes_manual_approval_on_a_pipeline_entry(tmp_path):
    notes = api.validate_notes(manifest_with(use="github_repository_inventory", paramify={"approval": "MANUAL"}), REPO_ROOT)
    assert any("MANUAL" in n and "waits" in n for n in notes)
```

- [ ] **Step 2: Run them and see them fail.** Expected: `ImportError` on `pipeline_conflicts`, and the validate tests fail.

- [ ] **Step 3: Implement.** `api.validate` uses `manifest_loader.resolved_paramify(parsed, entry)` for each pipeline entry and adds `f"{key}: {setting}: direct is not allowed on a pipeline fetcher; {PIPELINE_DIRECT}"` (import the constant from Task 3). It adds `pipeline_conflicts(select_validators(registry, manifest_reference_ids_including_pipeline), fetchers)` as errors; give `manifest_reference_ids` a keyword `include_pipeline: bool = False` so validate can see them. `validate_notes` adds `f"{key}: approval MANUAL on a pipeline fetcher; the pipeline waits for someone to approve each batch"`. `collect_validators` subtracts `pipeline_reference_ids(discover_fetchers(root))` from an explicit `reference_ids`.

- [ ] **Step 4: Run the tests and see them pass.** `pytest -q`. Expected: all pass.

- [ ] **Step 5: Commit.** `git commit -m "feat(validate): keep validators and direct delivery off pipeline evidence sets"`

---

### Task 6: `paramify preset <fetcher>`

**Files:**
- Modify: `framework/api.py` (`preset_sheet`, `newest_run_with`)
- Modify: `framework/cli.py` (a `preset` command next to `evidence`)
- Test: `tests/test_preset.py` (new), plus a golden case in `tools/cli_goldens.py` / `tests/goldens/cli/preset.txt`

**Interfaces:**
- Consumes: `Fetcher.pipeline`, `metadata.inventory.by_asset_type` (Tasks 1–2).
- Produces:
  - `api.newest_run_with(output_dir: Path, filename: str) -> Optional[Path]`: the newest `run-*` directory under `output_dir` holding `filename`.
  - `api.preset_sheet(root: Path, name: str, output_dir: Optional[Path] = None) -> Dict[str, Any]`: keys `fetcher`, `type`, `evidence_set` (reference_id or None), `sample` (path str or None), `data_path` (`"payload.data"` for inventory, else None), `unique_id` (`"unique_asset_identifier"` for inventory, else None), `id_scheme`, `asset_id_field`, `asset_types` (dict or None), `linked` (sorted names of other pipeline fetchers with the same `id_scheme`). It raises `ValueError(f"{name} is not a pipeline fetcher")` when there is no block, and `KeyError` when the fetcher is unknown.
  - `api.render_preset_sheet(sheet: Dict[str, Any]) -> str`: the text layout of spec §5. The TUI (Task 7) uses it too.

- [ ] **Step 1: Write the failing tests.**

```python
def test_sheet_for_an_inventory_with_a_run(tmp_path):
    # tmp output dir with run-2026-11-12T00-00-00Z/sophos_endpoint_inventory.json, an envelope whose
    # metadata.inventory.by_asset_type == {"endpoint": 412, "server": 37}
    s = api.preset_sheet(REPO_ROOT, "sophos_endpoint_inventory", output_dir=tmp_path)
    assert s["data_path"] == "payload.data" and s["unique_id"] == "unique_asset_identifier"
    assert s["id_scheme"] == "sophos-endpoint-id" and s["asset_types"] == {"endpoint": 412, "server": 37}
    assert s["sample"].endswith("sophos_endpoint_inventory.json")
    text = api.render_preset_sheet(s)
    assert "attach it to this set, not a new one" in text and "endpoint 412 · server 37" in text

def test_sheet_without_a_run_says_what_needs_one(tmp_path):
    s = api.preset_sheet(REPO_ROOT, "sophos_endpoint_inventory", output_dir=tmp_path)
    assert s["sample"] is None and s["asset_types"] is None
    assert "run the fetcher first" in api.render_preset_sheet(s)

def test_non_pipeline_fetcher_is_refused():
    with pytest.raises(ValueError, match="not a pipeline fetcher"):
        api.preset_sheet(REPO_ROOT, "aws_acm_certificate_status")   # an ordinary evidence fetcher

def test_cli_preset_json(tmp_path):
    r = runner.invoke(app, ["preset", "sophos_endpoint_inventory", "--json", "--output-dir", str(tmp_path)])
    assert r.exit_code == 0 and json.loads(r.stdout)["id_scheme"] == "sophos-endpoint-id"
```

- [ ] **Step 2: Run them and see them fail.** `pytest tests/test_preset.py -v`. Expected: `AttributeError` on `preset_sheet`.

- [ ] **Step 3: Implement.** CLI options: `--json`, `-f/--manifest` (the output directory comes from the manifest's `run.output_dir`), `--output-dir` (overrides `-f`; default `<root>/evidence`). An unknown fetcher exits 2 with the closest names; a non-pipeline fetcher exits 1 with the `ValueError` message. Register the command in the CLI help group with `evidence`. Add the golden.

- [ ] **Step 4: Run the tests and see them pass.** `pytest -q`. Expected: all pass, and `python tools/cli_goldens.py --check` (or the repo's golden check) is clean.

- [ ] **Step 5: Commit.** `git commit -m "feat(cli): add paramify preset, the settings to enter for a pipeline's preset"`

---

### Task 7: TUI

**Files:**
- Modify: `framework/tui/render.py:destination_cell` (` · pipeline` suffix)
- Modify: `framework/tui/screens/manifest.py` (`P` binding and hint; the `paramify` form for pipeline entries; the detail pane)
- Modify: `framework/tui/screens/upload.py` (an unapproved pipeline result in `palette.WARN`)
- Test: `tests/test_tui_kinds.py` or a new `tests/test_tui_pipeline_entries.py`; snapshots in `tests/__snapshots__/`

**Interfaces:**
- Consumes: `descriptor["pipeline"]` (Task 1), `api.preset_sheet` / `api.render_preset_sheet` (Task 6), `result["pipeline"]["approved"]` (Task 4).

- [ ] **Step 1: Write the failing tests.**

```python
def test_destination_cell_marks_a_pipeline_set():
    d = {"kind": "inventory", "evidence_set": {"reference_id": "EVD-X"}, "pipeline": {"type": "inventory", "id_scheme": "x"}}
    assert destination_cell(d, None).plain.endswith(" · pipeline")

async def test_entry_form_hides_direct_settings_for_a_pipeline_entry(pilot_with_manifest_using("sophos_endpoint_inventory")):
    # press e on the row; the FormModal's paramify group has keys {"stack", "approval"} only
    ...

async def test_P_opens_the_preset_sheet(...):
    # press P on an inventory row; a PreviewModal titled "preset: sophos_endpoint_inventory" shows render_preset_sheet text

async def test_P_on_an_evidence_row_notifies_instead(...):
    # press P on an ordinary evidence row; a notify "… is not a pipeline fetcher" and no modal
```

Follow the pilot helpers already used in `tests/test_tui_e2e.py` / `tests/test_tui_pipeline.py`.

- [ ] **Step 2: Run them and see them fail.** `pytest tests/test_tui_pipeline_entries.py -v`. Expected: the new tests fail.

- [ ] **Step 3: Implement.**
  - `Binding("P", "preset_sheet", "Preset")` and `("P", "preset")` in `HINTS`.
  - `action_preset_sheet` opens `PreviewModal(render_preset_sheet(sheet), title=f"preset: {use}")`. Let `PreviewModal` take a close key list so `P` closes it too.
  - In `action_edit_entry`, when `d.get("pipeline")`, `paramify_specs` drops `no_request` and `delivery`, and the `approval` help reads `"pipeline files always go in a batch; MANUAL waits for a person"`.
  - The detail pane shows `pipeline: <type> · <id_scheme>`.
  - In the upload panel, an entry result whose `pipeline.approved` is false renders in `palette.WARN`.

- [ ] **Step 4: Run the tests and see them pass.** `pytest tests/test_tui_*.py --snapshot-update`, review the snapshot diffs (only the manifest table's "sends to" column, the hints row, and the new modal should change), then `pytest -q`.

- [ ] **Step 5: Commit.** `git commit -m "feat(tui): show pipeline entries, hide direct settings, and add the preset sheet on P"`

---

### Task 8: Docs

**Files:**
- Create: `docs/pipeline_fetchers_guide.md`
- Modify: `docs/inventory_fetchers_guide.md` (step 4 and troubleshooting), `docs/uploader_guide.md` ("When a batch cannot be used"), `fetchers/_template_inventory/README.md`, `docs/README.md` (link the guide), `docs/pipeline_fetchers_design.md` (Status: Phase 1 built)

- [ ] **Step 1: Write `docs/pipeline_fetchers_guide.md`.** Cover: what a pipeline fetcher is (one paragraph); the `pipeline:` block, with the table from spec §3; the inventory record rules (`unique_asset_identifier`, `asset_type`, flat fields for mapping); what the uploader does for you (batch, approval, no validators), in five bullets; and **the ID scheme list** as a table (`scheme | ID format | fetchers`) seeded with `github-repository-url` and `sophos-endpoint-id`, plus `aws-arn`, `azure-resource-id`, `wiz-resource-id` and `hostname` marked "no fetcher yet".
- [ ] **Step 2: Rewrite inventory guide step 4** as the meeting's order of operations: run `paramify preset <fetcher>`; build the inventory preset with those values (unique ID and parent component are both required); attach it to *the fetcher's* set, not a new one; leave the set's approval automatic and add no validators; upload, and the uploader makes the batch. Add troubleshooting rows for `never goes direct`, `approves MANUAL`, `has N validator(s)`, and "uploaded, but Inventory is empty" (check the set has the pipeline attached and the batch is APPROVED).
- [ ] **Step 3: Check the links.** Run the repo's link check if one exists (`grep -rn "linkcheck\|check_links" tools tests | head`), else `pytest -q -k link`.
- [ ] **Step 4: Commit.** `git commit -m "docs: pipeline fetchers guide and the inventory order of operations"`

---

### Task 9: Live checks (needs a person and API tokens)

Not code. Run each on **stage and production** with the branch installed, and record the result in `docs/pipeline_fetchers_design.md` §8 (date, workspace, result).

- [ ] **Check 1:** an inventory set with a channel and no request. `paramify upload` makes an ad hoc batch → `APPROVED` → Inventory has the records.
- [ ] **Check 2:** a workspace with batches off. The upload goes direct with the note → does Inventory build? If not, change the batches-off row in Task 3 to a refusal (a new task).
- [ ] **Check 3:** a preset that maps a nested record field (`tags.env`). If it can't be mapped, add a rule to `framework/inventory.py` that refuses a record whose fields hold objects without a flat copy (a new task), and update the guide.
- [ ] **Check 4:** a `MANUAL` set. `--plan` warns, the result is `SUBMITTED: waiting for approval…`, and Inventory stays empty until a person approves.
- [ ] **Commit** the §8 results: `git commit -m "docs: record the pipeline fetchers live checks"`
