"""Facade for the fetcher framework — one source of truth for every front-end.

The unified `paramify` CLI (driven by humans and AIs) and the `paramify tui`
call ONLY this module. They never re-implement discovery, validation, manifest
editing, or execution; they differ only in how they render the JSON-able values
these functions return.

Design constraints (see docs/config_injection_design.md, CLAUDE.md):
- The editable artifact is the manifest (customer-side values). Declarations
  (fetcher.yaml, fetchers/_categories/*.yaml) are read-only — they generate the
  form via catalog(); we never write into fetchers/.
- Secrets are references, never values. set_secret() writes ${env:VAR}; the form
  collects WHICH env var holds a secret, not the credential itself.

The in-memory manifest exchanged with callers is the raw dict ({"run": {...}}),
the same shape as the on-disk YAML and the manifest schema. Manifest is only
materialized internally (parse_manifest) for semantic validation and execution.
"""

import importlib.util
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from framework.config_loader import discover_fetchers, discover_platforms
from framework.contract import ConfigField, Secret, TargetField
from framework.envelope import is_enveloped, wrap_outputs
from framework.runner import manifest_loader

_STDERR_TAIL_CHARS = 4000


# --------------------------------------------------------------------------- #
# Repo discovery
# --------------------------------------------------------------------------- #

def find_repo_root(start: Optional[Path] = None) -> Path:
    """Locate the repo root by walking up for sibling fetchers/ + framework/ dirs."""
    cur = (start or Path.cwd()).resolve()
    for parent in [cur, *cur.parents]:
        if (parent / "fetchers").is_dir() and (parent / "framework").is_dir():
            return parent
    raise RuntimeError(
        "Could not locate repo root (looking for sibling fetchers/ and framework/ dirs)"
    )


# --------------------------------------------------------------------------- #
# Catalog — discover + group + describe (powers the UI form and `catalog --json`)
# --------------------------------------------------------------------------- #

def _config_descriptor(f: ConfigField) -> dict:
    return {
        "name": f.name,
        "kind": "config",
        "type": f.type,
        "required": f.required,
        "default": f.default,
        "description": f.description,
        "env": f.env,
    }


def _secret_descriptor(s: Secret) -> dict:
    return {
        "name": s.name,
        "kind": "secret",
        "type": "string",
        "required": True,
        "default": None,
        "description": None,
        "env": s.env,
        "per_target": s.per_target,
    }


def _target_descriptor(f: TargetField) -> dict:
    return {
        "name": f.name,
        "kind": "target_field",
        "type": f.type,
        "required": f.required,
        "default": f.default,
        "description": f.description,
        "env": f.env,
    }


def _fetcher_descriptor(f) -> dict:
    return {
        "name": f.name,
        "version": f.version,
        "description": f.description,
        "category": f.category,
        "supports_targets": f.supports_targets,
        "config": [_config_descriptor(c) for c in f.config_schema.values()],
        "secrets": [_secret_descriptor(s) for s in f.secrets],
        "target_schema": [_target_descriptor(t) for t in f.target_schema.values()],
    }


def catalog(root: Path) -> dict:
    """Discover all fetchers, group them by category, and describe every editable
    field. This single structure is both the UI form schema and the AI-readable
    `catalog --json` output."""
    fetchers = discover_fetchers(root)
    platforms = discover_platforms(root)

    by_category: Dict[str, List[Any]] = {}
    for f in fetchers.values():
        by_category.setdefault(f.category or "_uncategorized", []).append(f)

    categories = []
    for name in sorted(by_category):
        spec = platforms.get(name)
        platform_block = None
        if spec is not None:
            platform_block = {
                "config": [_config_descriptor(c) for c in spec.config_schema.values()],
                "passthrough_env": list(spec.passthrough_env),
            }
        categories.append({
            "name": name,
            "description": spec.description if spec else None,
            "platform": platform_block,
            "fetchers": [
                _fetcher_descriptor(f)
                for f in sorted(by_category[name], key=lambda x: x.name)
            ],
        })

    return {"categories": categories, "fetcher_count": len(fetchers)}


# --------------------------------------------------------------------------- #
# KSI coverage — join fetcher `ksis` against the FedRAMP 20x reference
# --------------------------------------------------------------------------- #

def _load_ksi_reference(root: Path) -> dict:
    """Load the canonical FedRAMP 20x KSI reference (the coverage denominator)."""
    return yaml.safe_load((root / "framework" / "reference" / "ksis.yaml").read_text())


def ksi_coverage(root: Path) -> dict:
    """Coverage of the FedRAMP 20x KSIs by discovered fetchers.

    Joins each fetcher's `ksis` against framework/reference/ksis.yaml and returns
    one presentation-agnostic model — per-KSI status (covered/gap/organizational),
    per-family rollups, and a summary. The CLI, `--json`, and TUI all render this.

    status: `covered` if any fetcher maps to it; else `gap` when it's
    config-evidenceable; else `organizational` (evidenced by HR/training/manual,
    not cloud config). coverage_pct is over the config-evidenceable set only.
    """
    ref = _load_ksi_reference(root)
    fetchers = discover_fetchers(root)

    by_ksi: Dict[str, List[str]] = {}
    for f in fetchers.values():
        for k in getattr(f, "ksis", None) or []:
            by_ksi.setdefault(k, []).append(f.name)
    for names in by_ksi.values():
        names.sort()

    families = ref.get("families", {})
    ref_ksis = ref.get("ksis", [])
    ref_ids = {k["id"] for k in ref_ksis}

    ksi_entries = []
    for k in ref_ksis:
        fetchers_for = by_ksi.get(k["id"], [])
        evidenceable = bool(k.get("evidenceable", True))
        status = "covered" if fetchers_for else ("gap" if evidenceable else "organizational")
        ksi_entries.append({
            "id": k["id"],
            "family": k.get("family"),
            "statement": k.get("statement"),
            "evidenceable": evidenceable,
            "status": status,
            "fetchers": fetchers_for,
        })

    fam_rollup = []
    for fam, fam_name in families.items():
        members = [e for e in ksi_entries if e["family"] == fam]
        evi = [e for e in members if e["evidenceable"]]
        fam_rollup.append({
            "family": fam,
            "name": fam_name,
            "total": len(members),
            "evidenceable": len(evi),
            "covered": len([e for e in evi if e["fetchers"]]),
            "gaps": [e["id"] for e in evi if not e["fetchers"]],
        })

    evi_all = [e for e in ksi_entries if e["evidenceable"]]
    covered_all = [e for e in evi_all if e["fetchers"]]
    gaps_all = [e for e in evi_all if not e["fetchers"]]
    organizational = [e for e in ksi_entries if not e["evidenceable"]]
    unknown = sorted(k for k in by_ksi if k not in ref_ids)

    return {
        "release": ref.get("release"),
        "summary": {
            "total": len(ksi_entries),
            "evidenceable": len(evi_all),
            "covered": len(covered_all),
            "gaps": len(gaps_all),
            "organizational": len(organizational),
            "coverage_pct": round(100 * len(covered_all) / len(evi_all), 1) if evi_all else 0.0,
        },
        "families": fam_rollup,
        "ksis": ksi_entries,
        "unknown_ksis": [{"id": k, "fetchers": by_ksi[k]} for k in unknown],
    }


# --------------------------------------------------------------------------- #
# Doctor — preflight environment check
# --------------------------------------------------------------------------- #

# External CLIs a category's fetchers shell out to. Categories not listed here
# are pure-Python/HTTP fetchers that need no external tool. (AWS fetcher.sh files
# declare "Required tools: aws, jq"; k8s uses kubectl; checkov clones + scans.)
CATEGORY_TOOLS = {
    "aws": ["aws", "jq"],
    "k8s": ["kubectl"],
    "checkov": ["checkov", "git"],
}

_ENV_REF = re.compile(r"\$\{env:([^}]+)\}")


def doctor(root: Path, manifest_path: Optional[Path] = None) -> dict:
    """Preflight check for running fetchers here.

    Reports the Python version, whether the external CLIs the relevant categories
    need are on PATH, and — if a manifest is given — which secret env vars it
    references are actually set. Presentation-agnostic; the CLI and TUI render
    this one model. `ok` is a go/no-go: Python must clear the floor, and when a
    manifest is supplied its categories' tools must be present and its secret env
    vars set. Without a manifest, missing tools are informational (you may run
    only some categories), so `ok` reflects the Python check alone.
    """
    py = sys.version_info
    python = {
        "version": f"{py.major}.{py.minor}.{py.micro}",
        "required": "3.10",
        "ok": (py.major, py.minor) >= (3, 10),
    }

    fetchers = discover_fetchers(root)
    categories = sorted({f.category for f in fetchers.values() if f.category})
    tools_required = manifest_path is not None

    manifest_report = None
    if manifest_path is not None:
        data = read_manifest(manifest_path)
        entries = (data.get("run") or {}).get("fetchers") or []
        used_cats = sorted({
            c for c in (
                fetchers[e["use"]].category
                for e in entries
                if e.get("use") in fetchers
            )
            if c
        })
        if used_cats:
            categories = used_cats

        fetcher_reports = []
        manifest_ok = True
        for e in entries:
            refs: set = set()
            for v in (e.get("secrets") or {}).values():
                refs |= set(_ENV_REF.findall(str(v)))
            for t in e.get("targets") or []:
                for v in (t.get("secrets") or {}).values():
                    refs |= set(_ENV_REF.findall(str(v)))
            missing = sorted(r for r in refs if not os.environ.get(r))
            manifest_ok = manifest_ok and not missing
            fetcher_reports.append({
                "use": e.get("use"),
                "env_refs": sorted(refs),
                "missing": missing,
                "ok": not missing,
            })
        manifest_report = {
            "path": str(manifest_path),
            "fetchers": fetcher_reports,
            "ok": manifest_ok,
        }

    seen: set = set()
    tools = []
    for cat in categories:
        for tool in CATEGORY_TOOLS.get(cat, []):
            if tool in seen:
                continue
            seen.add(tool)
            resolved = shutil.which(tool)
            tools.append({
                "name": tool,
                "categories": [c for c in categories if tool in CATEGORY_TOOLS.get(c, [])],
                "present": resolved is not None,
                "path": resolved,
            })
    tools.sort(key=lambda t: str(t["name"]))

    ok = python["ok"]
    if tools_required:
        tools_ok = all(t["present"] for t in tools)
        ok = ok and tools_ok and (manifest_report["ok"] if manifest_report else True)

    return {
        "python": python,
        "categories": categories,
        "tools": tools,
        "tools_required": tools_required,
        "manifest": manifest_report,
        "ok": ok,
    }


# --------------------------------------------------------------------------- #
# Manifest read / write
# --------------------------------------------------------------------------- #

def read_manifest(path: Path) -> dict:
    """Read a manifest YAML into its raw dict. Returns an empty manifest if the
    file is missing or blank. Raises yaml.YAMLError on malformed YAML."""
    p = Path(path)
    if not p.exists():
        return init_manifest()
    data = yaml.safe_load(p.read_text())
    return data if isinstance(data, dict) else init_manifest()


def dump_manifest(manifest: dict, path: Path, root: Path) -> None:
    """Write a manifest dict to YAML. Refuses to write a structurally invalid
    (schema-invalid) manifest; semantic gaps (e.g. a not-yet-filled secret) are
    allowed so work-in-progress can be saved."""
    errs = manifest_loader.schema_errors(manifest, root)
    if errs:
        raise ValueError("refusing to write schema-invalid manifest:\n  " + "\n  ".join(errs))
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.safe_dump(manifest, sort_keys=False, default_flow_style=False))


# --------------------------------------------------------------------------- #
# Manifest mutation helpers (back the AI `manifest` subcommands and the UI PUT)
# All operate in place on the raw dict and return it for chaining.
# --------------------------------------------------------------------------- #

def init_manifest(output_dir: str = "./evidence") -> dict:
    return {"run": {"output_dir": output_dir, "fetchers": []}}


def _run(m: dict) -> dict:
    return m.setdefault("run", {})


def _entries(m: dict) -> list:
    return _run(m).setdefault("fetchers", [])


def _find_entry(m: dict, use: str) -> Optional[dict]:
    return next((e for e in _entries(m) if e.get("use") == use), None)


def _ensure_entry(m: dict, use: str) -> dict:
    entry = _find_entry(m, use)
    if entry is None:
        entry = {"use": use}
        _entries(m).append(entry)
    return entry


def set_output_dir(m: dict, output_dir: str) -> dict:
    _run(m)["output_dir"] = output_dir
    return m


def add_entry(m: dict, use: str) -> dict:
    if _find_entry(m, use) is None:
        _entries(m).append({"use": use})
    return m


def remove_entry(m: dict, use: str) -> dict:
    run = _run(m)
    run["fetchers"] = [e for e in _entries(m) if e.get("use") != use]
    return m


def set_fetcher_config(m: dict, use: str, key: str, value: Any) -> dict:
    _ensure_entry(m, use).setdefault("config", {})[key] = value
    return m


def set_secret(m: dict, use: str, name: str, env_var: str) -> dict:
    """Set a (non-per-target) secret reference for a fetcher entry. Stores a
    ${env:VAR} reference — never the secret value."""
    _ensure_entry(m, use).setdefault("secrets", {})[name] = f"${{env:{env_var}}}"
    return m


def add_target(
    m: dict, use: str, values: Dict[str, Any], secret_env: Optional[Dict[str, str]] = None
) -> dict:
    """Append a fanout target. secret_env maps per_target secret name -> ENV_VAR;
    each is stored as a ${env:VAR} reference."""
    entry = _ensure_entry(m, use)
    target = dict(values)
    if secret_env:
        target["secrets"] = {n: f"${{env:{v}}}" for n, v in secret_env.items()}
    entry.setdefault("targets", []).append(target)
    return m


def remove_target(m: dict, use: str, index: int) -> dict:
    """Remove the fanout target at `index` from a fetcher entry. No-op if the
    entry or index does not exist."""
    entry = _find_entry(m, use)
    if entry is not None:
        targets = entry.get("targets") or []
        if 0 <= index < len(targets):
            del targets[index]
    return m


def _platform(m: dict, category: str) -> dict:
    return _run(m).setdefault("platforms", {}).setdefault(category, {})


def set_platform_config(m: dict, category: str, key: str, value: Any) -> dict:
    _platform(m, category).setdefault("config", {})[key] = value
    return m


def set_passthrough_env(m: dict, category: str, env_vars: List[str]) -> dict:
    _platform(m, category).setdefault("auth", {})["passthrough_env"] = list(env_vars)
    return m


# --------------------------------------------------------------------------- #
# Validation — schema + semantic, returns readable error strings (never raises
# on a merely-incomplete manifest)
# --------------------------------------------------------------------------- #

def validate(manifest: dict, root: Path, fetchers=None, platforms=None) -> List[str]:
    """Validate a manifest dict against the schema and the discovered fetchers.

    Returns a list of human-readable error strings (empty == valid+runnable).
    Mirrors the checks the runner enforces before executing. `fetchers`/`platforms`
    may be passed pre-discovered (e.g. when validating many manifests in a loop)
    to avoid re-scanning the fetcher tree each call.
    """
    errors = manifest_loader.schema_errors(manifest, root)
    if errors:
        return errors  # can't do semantic checks on a structurally-broken manifest

    if fetchers is None:
        fetchers = discover_fetchers(root)
    if platforms is None:
        platforms = discover_platforms(root)
    parsed = manifest_loader.parse_manifest(manifest)

    for i, entry in enumerate(parsed.entries):
        if entry.use not in fetchers:
            errors.append(f"entry[{i}] uses unknown fetcher: {entry.use}")
            continue
        fetcher = fetchers[entry.use]

        if fetcher.supports_targets and not entry.targets:
            # No targets[] is valid when every target field is optional — the runner
            # does one ambient run ("collect where deployed"). Only an error if a
            # target field is actually required.
            if any(f.required for f in fetcher.target_schema.values()):
                errors.append(
                    f"{entry.use}: supports_targets but no targets[] in manifest "
                    f"(a required target field has no value)"
                )
        if not fetcher.supports_targets and entry.targets:
            errors.append(f"{entry.use}: does not support targets but manifest has targets[]")

        spec = platforms.get(fetcher.category)
        platform_cfg = parsed.platforms.get(fetcher.category)
        combined = {}
        if spec:
            combined.update(spec.config_schema)
        combined.update(fetcher.config_schema)
        for name, fdef in combined.items():
            if not fdef.required or fdef.default is not None:
                continue
            in_platform = platform_cfg and name in platform_cfg.config
            in_entry = name in entry.config
            if not (in_platform or in_entry):
                errors.append(
                    f"{entry.use}: required config '{name}' not set "
                    f"(platforms.{fetcher.category}.config or fetcher config)"
                )

        for secret in fetcher.secrets:
            if secret.per_target:
                for j, t in enumerate(entry.targets):
                    if secret.name not in t.secrets:
                        errors.append(
                            f"{entry.use} target[{j}] missing per_target secret '{secret.name}'"
                        )
            else:
                if secret.name not in entry.secrets:
                    errors.append(f"{entry.use}: missing secret '{secret.name}'")

    return errors


# --------------------------------------------------------------------------- #
# Run — the orchestration loop, with an optional event callback for streaming
# --------------------------------------------------------------------------- #

def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _invocation_record(r) -> dict:
    record = {
        "fetcher_name": r.fetcher_name,
        "fetcher_version": r.fetcher_version,
        "target": r.target,
        "started_at": r.started_at,
        "completed_at": r.completed_at,
        "duration_sec": r.duration_sec,
        "exit_code": r.exit_code,
        "outputs": r.outputs,
    }
    if r.exit_code != 0 and r.stderr:
        record["stderr_tail"] = r.stderr[-_STDERR_TAIL_CHARS:]
    return record


def _manifest_id(path, root: Path) -> str:
    """Stable identity for a manifest in run metadata: its path relative to the
    repo root (so attribution survives the repo moving), absolute otherwise."""
    p = Path(path).resolve()
    try:
        return str(p.relative_to(Path(root).resolve()))
    except ValueError:
        return str(p)


def run(
    manifest: dict,
    root: Path,
    on_event: Optional[Callable[[dict], None]] = None,
    manifest_path: Optional[Path] = None,
) -> dict:
    """Execute a manifest. Wraps each output in the evidence envelope and writes
    _run_metadata.json (unchanged from the original CLI run). Fires on_event for
    run_start / fetcher_start / fetcher_skip / log_line / fetcher_result /
    fetcher_error / run_complete so a UI can stream live progress.

    Pass manifest_path so the run metadata records which manifest produced the
    run — that attribution powers each manifest's last_run in list_manifests().

    Returns a summary dict. Raises ValueError if the manifest is schema-invalid.
    """
    from framework.runner.executor import run_entry  # lazy: avoid import cycle

    errs = manifest_loader.schema_errors(manifest, root)
    if errs:
        raise ValueError("manifest schema invalid:\n  " + "\n  ".join(errs))

    fetchers = discover_fetchers(root)
    platforms = discover_platforms(root)
    parsed = manifest_loader.parse_manifest(manifest)

    def emit(event: dict) -> None:
        if on_event is not None:
            on_event(event)

    run_id = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    run_dir = parsed.output_dir.resolve() / f"run-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    emit({
        "event": "run_start",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "fetchers": [e.use for e in parsed.entries],
    })

    all_results = []
    overall_ok = True
    started_at = _iso_now()

    for entry in parsed.entries:
        if entry.use not in fetchers:
            emit({"event": "fetcher_skip", "fetcher": entry.use, "reason": "not discovered"})
            overall_ok = False
            continue
        fetcher = fetchers[entry.use]
        # An ambient run (supports_targets, no targets[]) is a single invocation.
        n_targets = len(entry.targets) if (fetcher.supports_targets and entry.targets) else 1
        emit({
            "event": "fetcher_start",
            "fetcher": entry.use,
            "targets": n_targets,
            "fanout": fetcher.supports_targets,
        })

        def on_line(line: str, _use=entry.use) -> None:
            emit({"event": "log_line", "fetcher": _use, "line": line})

        try:
            results = run_entry(
                fetcher,
                entry,
                run_dir,
                platforms.get(fetcher.category or ""),
                parsed.platforms.get(fetcher.category or ""),
                on_line=on_line,
            )
        except (RuntimeError, ValueError) as e:
            emit({"event": "fetcher_error", "fetcher": entry.use, "error": str(e)})
            overall_ok = False
            continue

        for r in results:
            wrap_outputs(r, fetcher, run_id, run_dir)
            if r.exit_code != 0:
                overall_ok = False
            emit({
                "event": "fetcher_result",
                "fetcher": entry.use,
                "exit_code": r.exit_code,
                "duration_sec": r.duration_sec,
                "target": r.target,
                "outputs": r.outputs,
            })
        all_results.extend(results)

    completed_at = _iso_now()
    metadata = {
        "run_id": run_id,
        "manifest": _manifest_id(manifest_path, root) if manifest_path else None,
        "started_at": started_at,
        "completed_at": completed_at,
        "invocations": [_invocation_record(r) for r in all_results],
    }
    metadata_path = run_dir / "_run_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str))

    summary = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "metadata_path": str(metadata_path),
        "ok": overall_ok,
        "started_at": started_at,
        "completed_at": completed_at,
        "invocations": metadata["invocations"],
    }
    emit({"event": "run_complete", **summary})
    return summary


# --------------------------------------------------------------------------- #
# Upload — Paramify evidence uploader facade (powers CLI + TUI)
# --------------------------------------------------------------------------- #

def _load_paramify_uploader(root: Path):
    """Load the source-tree uploader without requiring uploaders/ to be packaged."""
    path = Path(root) / "uploaders" / "paramify_evidence" / "uploader.py"
    if not path.exists():
        raise RuntimeError(f"Paramify evidence uploader not found at {path}")
    spec = importlib.util.spec_from_file_location("paramify_evidence_uploader", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load Paramify evidence uploader from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def upload_preflight(
    run_dir,
    root: Path,
    config_path: Optional[Path] = None,
    *,
    dry_run: bool = False,
) -> dict:
    """Inspect upload readiness without making Paramify API calls."""
    uploader = _load_paramify_uploader(root)
    uploader.load_dotenv()
    config = uploader.load_config(str(config_path)) if config_path else {}
    paramify_cfg = config.get("paramify") or {}
    base_url = (
        paramify_cfg.get("base_url")
        or os.environ.get("PARAMIFY_API_BASE_URL")
        or uploader.DEFAULT_BASE_URL
    )

    run_path = Path(run_dir)
    errors: List[str] = []
    file_count = 0
    if not run_path.is_dir():
        errors.append(f"No run directory to upload: {run_path}")
    else:
        file_count = sum(1 for _ in uploader.iter_evidence_files(run_path))
        if file_count == 0:
            errors.append(f"No evidence files found in {run_path}")

    url_error = uploader._base_url_error(base_url)
    if url_error:
        errors.append(url_error)

    token_present = bool(os.environ.get("PARAMIFY_UPLOAD_API_TOKEN"))
    if not token_present and not dry_run:
        errors.append("PARAMIFY_UPLOAD_API_TOKEN is not set")

    return {
        "ok": not errors,
        "run_dir": str(run_path),
        "base_url": base_url,
        "file_count": file_count,
        "token_present": token_present,
        "dry_run": dry_run,
        "errors": errors,
    }


def upload_run(
    run_dir,
    root: Path,
    config_path: Optional[Path] = None,
    *,
    dry_run: bool = False,
    on_event: Optional[Callable[[dict], None]] = None,
) -> dict:
    """Upload one run directory to Paramify.

    Fires upload_start / upload_file / upload_complete so front-ends can render
    progress. Raises ValueError for setup errors; returns the uploader summary
    for completed batches, even when some files failed.
    """
    uploader = _load_paramify_uploader(root)
    config = uploader.load_config(str(config_path)) if config_path else {}
    return uploader.upload_run(
        Path(run_dir),
        config=config,
        dry_run=dry_run,
        on_event=on_event,
    )


# --------------------------------------------------------------------------- #
# Evidence — read produced run outputs (powers the TUI evidence browser)
# --------------------------------------------------------------------------- #

def _run_summary(run_dir: Path) -> dict:
    """Summarize one run-* directory from its _run_metadata.json + output files."""
    started = completed = manifest_src = None
    invocations: list = []
    meta_path = run_dir / "_run_metadata.json"
    complete = meta_path.exists()
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            started = meta.get("started_at")
            completed = meta.get("completed_at")
            manifest_src = meta.get("manifest")
            invocations = meta.get("invocations") or []
        except (OSError, json.JSONDecodeError):
            pass

    files: list = []
    seen = set()
    for inv in invocations:
        for name in inv.get("outputs") or []:
            seen.add(name)
            files.append({
                "name": name,
                "path": str(run_dir / name),
                "fetcher": inv.get("fetcher_name"),
                "target": inv.get("target"),
                "exit_code": inv.get("exit_code"),
            })
    # Any JSON outputs not recorded in the metadata (e.g. legacy/direct runs).
    for p in sorted(run_dir.glob("*.json")):
        if p.name == "_run_metadata.json" or p.name in seen:
            continue
        files.append({"name": p.name, "path": str(p), "fetcher": None, "target": None, "exit_code": None})
    files.sort(key=lambda f: f["name"])

    name = run_dir.name
    return {
        "run_id": name[len("run-"):] if name.startswith("run-") else name,
        "dir": str(run_dir),
        "manifest": manifest_src,  # _manifest_id of the producing manifest; None = unattributed
        "started_at": started,
        "completed_at": completed,
        "complete": complete,  # False = no _run_metadata.json (run aborted before finishing)
        "ok": sum(1 for i in invocations if i.get("exit_code") == 0),
        "fail": sum(1 for i in invocations if i.get("exit_code") not in (0, None)),
        "files": files,
    }


def list_runs(output_dir) -> List[dict]:
    """List runs under output_dir, newest first. Each entry summarizes one run-*
    directory (run_id, timing, complete flag, ok/fail counts, and a per-output-file
    list joined with its invocation record). Returns [] if the dir is missing.

    A run-* dir with neither metadata nor output files (an aborted run that wrote
    nothing) is skipped so it doesn't masquerade as a clean empty run; a dir with
    files but no metadata is kept but flagged complete=False."""
    base = Path(output_dir).expanduser()
    if not base.is_absolute():
        base = Path.cwd() / base
    base = base.resolve()
    if not base.is_dir():
        return []
    runs = []
    for d in sorted(base.glob("run-*"), reverse=True):
        if not d.is_dir():
            continue
        summary = _run_summary(d)
        if not summary["complete"] and not summary["files"]:
            continue  # pure ghost: nothing was written
        runs.append(summary)
    return runs


def read_evidence(path) -> dict:
    """Read one evidence JSON file, normalized. Splits the standard envelope
    (schema_version/metadata/payload); a raw (un-enveloped) file comes back with
    metadata={} and the whole object as payload. Raises ValueError if unreadable."""
    p = Path(path)
    try:
        raw = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read evidence file {p}: {e}")
    if is_enveloped(raw):
        return {
            "enveloped": True,
            "schema_version": raw.get("schema_version"),
            "metadata": raw.get("metadata") or {},
            "payload": raw.get("payload"),
        }
    return {"enveloped": False, "schema_version": None, "metadata": {}, "payload": raw}


# --------------------------------------------------------------------------- #
# Manifests — discover selectable run manifests (powers the welcome screen)
# --------------------------------------------------------------------------- #

def _manifest_summary(path: Path, root: Path, fetchers=None, platforms=None) -> Optional[dict]:
    """Summarize a manifest file, or return None if it isn't a run manifest
    (its top level must be a mapping with a `run` key)."""
    summary = {
        "name": path.name,
        "path": str(path),
        "fetcher_count": 0,
        "issues": None,          # None = couldn't validate; else int error count
        "runnable": False,
        "last_run": None,
        "last_result": None,
        "readable": True,
    }
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        summary["readable"] = False
        return summary
    if not isinstance(raw, dict) or "run" not in raw:
        return None  # a stray / non-manifest YAML file — don't offer it as a manifest
    run = raw.get("run") or {}
    summary["fetcher_count"] = len(run.get("fetchers") or [])
    try:
        errors = validate(raw, root, fetchers, platforms)
        summary["issues"] = len(errors)
        summary["runnable"] = not errors
    except Exception:
        pass
    try:
        # last_run: the newest run in the manifest's output_dir that THIS
        # manifest produced (run metadata records its _manifest_id). Runs
        # without attribution — predating that field, or another manifest
        # sharing the output_dir — don't count, so a manifest stays "never
        # run" until it is run again.
        mid = _manifest_id(path, root)
        runs = [r for r in list_runs(run.get("output_dir") or "./evidence")
                if r.get("manifest") == mid]
        if runs:
            last = runs[0]
            total = last["ok"] + last["fail"]
            summary["last_run"] = last["run_id"]
            summary["last_result"] = f"{last['ok']}/{total} ok" if total else None
    except Exception:
        pass
    return summary


def list_manifests(root) -> List[dict]:
    """Discover selectable run manifests: <root>/manifests/*.yaml, plus a legacy
    <root>/manifest.yaml if present (listed first). Each is summarized with its
    fetcher count, validity (issues), and last-run info for the welcome picker.
    Non-manifest YAML files (no top-level `run`) are skipped."""
    root = Path(root)
    paths: List[Path] = []
    mdir = root / "manifests"
    if mdir.is_dir():
        paths += sorted(mdir.glob("*.yaml"))
    legacy = root / "manifest.yaml"
    if legacy.exists() and legacy.resolve() not in {p.resolve() for p in paths}:
        paths.insert(0, legacy)
    if not paths:
        return []
    # Discover the fetcher tree once and reuse it across every manifest's
    # validate() — otherwise the welcome screen re-scans all fetchers per file.
    fetchers: Optional[dict] = None
    platforms: Optional[dict] = None
    try:
        fetchers = discover_fetchers(root)
        platforms = discover_platforms(root)
    except Exception:
        pass
    summaries = [_manifest_summary(p, root, fetchers, platforms) for p in paths]
    return [s for s in summaries if s is not None]


def new_manifest_path(root, name: str, output_dir: str = "./evidence") -> Path:
    """Create a fresh manifest file at <root>/manifests/<name>.yaml and return
    its path. Raises FileExistsError if it already exists, ValueError on a bad
    name."""
    safe = name.strip()
    if not safe or "/" in safe or safe.startswith("."):
        raise ValueError(f"invalid manifest name: {name!r}")
    if not safe.endswith(".yaml"):
        safe += ".yaml"
    mdir = Path(root) / "manifests"
    mdir.mkdir(parents=True, exist_ok=True)
    path = mdir / safe
    if path.exists():
        raise FileExistsError(str(path))
    path.write_text(yaml.safe_dump(init_manifest(output_dir), sort_keys=False))
    return path
