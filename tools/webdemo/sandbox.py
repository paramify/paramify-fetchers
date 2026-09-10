"""The real TUI, made safe to hand to the public.

`python -m tools.webdemo.sandbox` launches the actual FetcherApp against a
private, throwaway copy of the fabricated demo workspace, with every path that
would touch the outside world replaced. It is the app textual-serve spawns —
one process, one private workspace, per browser session (see serve.py).

What a visitor CAN do, for real: browse the whole catalog, add and remove
fetchers, edit config and secret refs, add targets, save, validate, preview,
run the manifest and watch it stream, read the evidence it produced, and walk
the Paramify tab. Their edits are real edits — to their own copy, which is
deleted when they disconnect.

What is replaced, and why:

  api.run              executes fetchers as subprocesses (aws CLI, kubectl, …).
                       Replaced with a paced replay that writes the same
                       fabricated evidence the static demo uses, so the run
                       tab, the evidence tab and the upload tab all still agree.
  api.upload_run       )
  api.issues_upload_run) POST to the Paramify API.
  api.scripts_sync     )
  api.list_programs    ) GET the Paramify API.
  api.list_assessments )

Then, because that list is only correct as of today, `block_network()` severs
outbound TCP for the whole process. A future TUI change that adds an API call
fails loudly in the sandbox instead of quietly reaching a real tenant from a
public demo.
"""

from __future__ import annotations

import atexit
import json
import os
import pickle
import shutil
import socket
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Baked into the image at build time so a session starts with a copy, not a
# fresh catalog scan (see deploy/fly/Dockerfile).
TEMPLATE_DIR = Path(os.environ.get("DEMO_WORKSPACE_TEMPLATE", "/srv/demo-workspace"))

# Discovery, pickled at build time. Walking and jsonschema-validating 183
# fetcher.yaml files costs a few hundred milliseconds, and every session was
# paying it at startup: three sessions opening at once took ~7.8s to first
# paint on a shared vCPU. The fetcher tree is read-only inside the image, so
# one scan at build time serves every session. Kept beside the template rather
# than inside it, so it is not copied per session.
DISCOVERY_CACHE = TEMPLATE_DIR.parent / "discovery.pickle"

# Pacing for the replayed run. Slow enough to read as work happening, fast
# enough that nobody waits: 16 invocations lands around eight seconds.
STEP_SECONDS = float(os.environ.get("DEMO_RUN_STEP", "0.42"))

# Seconds of logo sheen before the welcome screen stops animating, and the rate
# it runs at while it does. See freeze_welcome_sheen() for why both exist.
SHEEN_SECONDS = float(os.environ.get("DEMO_SHEEN_SECONDS", "4.5"))
SHEEN_FPS = int(os.environ.get("DEMO_SHEEN_FPS", "12"))

# textual-serve hard-codes TEXTUAL_FPS=60 in the child environment. Over a
# websocket that is a repaint budget, not a smoothness setting; 24 is past the
# point anyone can see and caps what a runaway animation can cost.
MAX_FPS = os.environ.get("DEMO_MAX_FPS", "24")


# ── network guard ────────────────────────────────────────────────────────── #

class SandboxNetworkError(RuntimeError):
    """Raised when something in the sandbox tries to open a TCP connection."""


def block_network() -> None:
    """Sever outbound TCP for this process.

    The web driver talks to its parent over stdin/stdout pipes, so nothing the
    app legitimately does needs a socket. AF_UNIX is left alone.
    """
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def guard(self, address, *a, **kw):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            raise SandboxNetworkError(
                f"blocked outbound connection to {address!r} — this is the "
                "sandboxed demo, which never reaches a live API"
            )
        return real_connect(self, address, *a, **kw)

    def guard_ex(self, address, *a, **kw):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            return 111  # ECONNREFUSED
        return real_connect_ex(self, address, *a, **kw)

    socket.socket.connect = guard
    socket.socket.connect_ex = guard_ex


# ── the welcome screen's animation ───────────────────────────────────────── #

def freeze_welcome_sheen() -> None:
    """Stop the welcome screen animating once the intro has played.

    WelcomeScreen runs `set_interval(1/30, self._tick)` for the life of the
    screen, and `_tick` repaints the whole PARAMIFY logo every frame. On a
    laptop that is invisible. Over a websocket it is not: the logo is 369
    separately-styled spans, so each repaint is ~15 KB of truecolor escapes and
    the screen streams ~366 KB/s *while nobody is touching it*. Measured on a
    shared-cpu-1x machine that starved everything else — first paint took 12
    seconds and keystrokes went unanswered.

    The reveal is worth keeping, so let it play and then stop: after
    SHEEN_SECONDS `_tick` returns, the screen's timers are cancelled, and idle
    traffic goes to zero (measured: 285 KB/s -> 0.0 KB/s).

    The reveal itself is also dropped from 30 fps to SHEEN_FPS. Its timings are
    all wall-clock (_REVEAL0, _STAGGER, _TYPE_CPS), so a lower frame rate makes
    it chunkier, never slower, and takes the startup burst down with it.
    """
    from framework.tui.screens import welcome as welcome_module
    from framework.tui.screens.welcome import WelcomeScreen

    welcome_module._FPS = SHEEN_FPS  # read by WelcomeScreen.on_mount's set_interval

    original = WelcomeScreen._tick

    def _tick(self) -> None:
        if self._checks_done and (time.monotonic() - self._t0) > SHEEN_SECONDS:
            for timer in list(getattr(self, "_timers", ())):
                timer.stop()  # nothing else on this screen is on a timer
            return
        original(self)

    WelcomeScreen._tick = _tick


# ── per-session workspace ────────────────────────────────────────────────── #

def build_template(destination: Path) -> Path:
    """Build the workspace the sessions are copied from (image build step)."""
    from framework import api
    from tools.webdemo import fixture

    catalog = api.catalog(REPO_ROOT)
    known = {f["name"] for cat in catalog["categories"] for f in cat["fetchers"]}
    workspace = fixture.build(destination, REPO_ROOT, known)

    # Discovery is against REPO_ROOT, not the session workspace, which is
    # correct: the workspace only symlinks to this same read-only tree.
    try:
        DISCOVERY_CACHE.parent.mkdir(parents=True, exist_ok=True)
        DISCOVERY_CACHE.write_bytes(
            pickle.dumps({"catalog": catalog, **api.discover(REPO_ROOT)})
        )
    except OSError as exc:
        print(f"note: could not write {DISCOVERY_CACHE} ({exc}); "
              "sessions will scan the catalog themselves")
    return workspace


def use_cached_discovery() -> bool:
    """Serve the baked discovery instead of re-scanning per session.

    Every call site for these lives in framework/api.py and uses the names
    bound there (`from framework.config_loader import discover_fetchers, …`),
    so rebinding them on that module is the whole job.

    The pickle is written by us at image build time from our own tree; it is
    never visitor-supplied.
    """
    if not DISCOVERY_CACHE.is_file():
        return False
    from framework import api

    cached = pickle.loads(DISCOVERY_CACHE.read_bytes())
    catalog, fetchers, platforms = (
        cached["catalog"], cached["fetchers"], cached["platforms"],
    )
    api.catalog = lambda _root: catalog
    api.discover = lambda _root: {"fetchers": fetchers, "platforms": platforms}
    api.discover_fetchers = lambda _root: fetchers
    api.discover_platforms = lambda _root: platforms
    return True


def session_workspace() -> Path:
    """A private, writable copy of the demo workspace for this session."""
    session = Path(tempfile.mkdtemp(prefix="fetcher-demo-"))
    workspace = session / "workspace"
    if TEMPLATE_DIR.is_dir():
        # symlinks=True keeps fetchers/ and framework/ pointing at the shared
        # read-only checkout instead of copying the whole tree per visitor.
        shutil.copytree(TEMPLATE_DIR, workspace, symlinks=True)
    else:
        build_template(workspace)  # local dev, no baked template
    atexit.register(shutil.rmtree, session, True)
    return workspace


# ── the replayed run ─────────────────────────────────────────────────────── #

def _scripted_run(
    manifest: dict,
    root: Path,
    on_event: Optional[Callable[[dict], None]] = None,
    manifest_path: Optional[Path] = None,
) -> dict:
    """Stand-in for api.run: same events, same files, no subprocesses.

    Deliberately mirrors api.run's shape rather than faking the UI — it writes a
    real run directory with real envelopes and a real _run_metadata.json, so
    everything downstream of a run (the evidence browser, the upload preflight,
    each manifest's last_run) behaves exactly as it does in production.
    """
    from framework import api
    from framework.runner import manifest_loader

    def emit(event: dict) -> None:
        if on_event is not None:
            on_event(event)

    # api.run raises on a schema-invalid manifest before doing anything; the run
    # tab relies on that, so raise identically rather than replaying a run the
    # real thing would have refused.
    schema_errors = manifest_loader.schema_errors(manifest, root)
    if schema_errors:
        raise ValueError("manifest schema invalid:\n  " + "\n  ".join(schema_errors))

    fetchers = api.discover(root)["fetchers"]
    entries = (manifest.get("run") or {}).get("fetchers") or []
    output_dir = (manifest.get("run") or {}).get("output_dir") or "./evidence"

    run_id = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    base = Path(output_dir)
    if not base.is_absolute():
        base = Path.cwd() / base
    run_dir = base / f"run-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    emit({"event": "run_start", "run_id": run_id, "run_dir": str(run_dir),
          "fetchers": [e.get("use") for e in entries]})

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    invocations: list[dict] = []
    overall_ok = True

    for entry in entries:
        use = entry.get("use")
        fetcher = fetchers.get(use)
        if fetcher is None:
            emit({"event": "fetcher_skip", "fetcher": use, "reason": "not discovered"})
            overall_ok = False
            continue

        targets = entry.get("targets") or [None]
        if not fetcher.supports_targets:
            targets = [None]
        emit({"event": "fetcher_start", "fetcher": use, "targets": len(targets),
              "fanout": fetcher.supports_targets})

        for target in targets:
            time.sleep(STEP_SECONDS)
            stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
            name, code, note = _invoke(use, fetcher, run_id, target, run_dir)
            emit({"event": "log_line", "fetcher": use,
                  "line": f"{datetime.now(timezone.utc):%Y-%m-%d} {stamp} "
                          f"{'ERROR' if code else 'INFO'} {use} {note}"})
            if code:
                overall_ok = False
            invocations.append({
                "fetcher_name": use,
                "fetcher_version": fetcher.version,
                "target": target,
                "started_at": started_at,
                "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "duration_sec": round(STEP_SECONDS + len(use) % 5 * 0.4, 2),
                "exit_code": code,
                "outputs": [] if code else [name],
                "stderr_tail": note if code else "",
            })
            emit({"event": "fetcher_result", "fetcher": use, "exit_code": code,
                  "duration_sec": invocations[-1]["duration_sec"], "target": target,
                  "outputs": invocations[-1]["outputs"]})

    completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = {
        "run_id": run_id,
        "manifest": (str(Path(manifest_path).resolve().relative_to(Path(root).resolve()))
                     if manifest_path else None),
        "started_at": started_at,
        "completed_at": completed_at,
        "invocations": invocations,
    }
    metadata_path = run_dir / "_run_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str))

    summary = {
        "run_id": run_id, "run_dir": str(run_dir), "metadata_path": str(metadata_path),
        "ok": overall_ok, "started_at": started_at, "completed_at": completed_at,
        "invocations": invocations, "issue_reports": 0,
    }
    emit({"event": "run_complete", **summary})
    return summary


# One fetcher fails on purpose. A demo where everything passes teaches nobody
# what a failure looks like, and GuardDuty-not-enabled-in-this-region is the
# real-world case the run tab exists to surface.
FAILING = {"aws_guard_duty"}


def _invoke(use: str, fetcher, run_id: str, target: Optional[dict],
            run_dir: Path) -> tuple[str, int, str]:
    from tools.webdemo import fixture

    category = fetcher.category or "demo"
    name = fixture.output_name(use, category, target)
    region = (target or {}).get("region", "us-gov-east-1")
    if use in FAILING and (target is None or region.endswith("east-1")):
        envelope = fixture.synthetic_envelope(use, category, run_id, target)
        envelope["metadata"].update(status="error", exit_code=1)
        envelope["payload"] = {"detectors": [],
                               "note": f"GuardDuty has never been enabled in {region}."}
        (run_dir / name).write_text(json.dumps(envelope, indent=2))
        return name, 1, f"guardduty list-detectors returned no detectors for {region}"

    evidence_set = None
    spec = getattr(fetcher, "evidence_set", None)
    if spec is not None:
        evidence_set = {
            "reference_id": getattr(spec, "reference_id", "") or "",
            "name": getattr(spec, "name", "") or "",
            "instructions": getattr(spec, "instructions", "") or "",
        }
    envelope = fixture.synthetic_envelope(use, category, run_id, target, evidence_set)
    (run_dir / name).write_text(json.dumps(envelope, indent=2))
    return name, 0, f"Evidence saved to {name}"


# ── the replaced Paramify calls ──────────────────────────────────────────── #

DEMO_ASSESSMENTS = [
    {"id": "a1d0c6e8-3f42-4b7a-9c15-7e2b8d4a6109", "name": "Acme Platform — FedRAMP Moderate",
     "type": "fedramp", "status": "in_progress"},
    {"id": "b2e1d7f9-4a53-4c8b-8d26-9f3c7e5b8210", "name": "Acme Platform — SOC 2 Type II",
     "type": "soc2", "status": "in_progress"},
    {"id": "c3f2e801-5b64-4d9c-9e37-0a4d8f6c9321", "name": "Acme Platform — Continuous Monitoring",
     "type": "conmon", "status": "active"},
]

DEMO_PROGRAMS = [
    {"id": "acme-platform", "name": "Acme Platform", "shortName": "ACME"},
    {"id": "acme-govcloud", "name": "Acme GovCloud Enclave", "shortName": "ACME-GC"},
]


def _demo_assessments(assessment_type: Optional[str] = None) -> list[dict]:
    if not assessment_type:
        return list(DEMO_ASSESSMENTS)
    return [a for a in DEMO_ASSESSMENTS if a["type"] == assessment_type]


def _refused(what: str) -> Callable[..., dict]:
    """A push that reports, honestly, that this sandbox does not push."""
    def call(*_a: Any, **_kw: Any) -> dict:
        return {
            "ok": False,
            "uploaded": 0,
            "failed": 0,
            "skipped": 0,
            "errors": [
                f"{what} is disabled in the sandbox — this demo has no Paramify "
                "workspace behind it. Everything up to this point is real: the "
                "manifest, the run, the envelopes on disk and the preflight above."
            ],
        }
    return call


def patch_api() -> None:
    """Swap out every path that runs a subprocess or calls the Paramify API."""
    from framework import api

    api.run = _scripted_run
    api.upload_run = _refused("Evidence upload")
    api.issues_upload_run = _refused("Issue-report intake")
    api.scripts_sync = _refused("Script sync")
    api.list_assessments = _demo_assessments
    api.list_programs = lambda: list(DEMO_PROGRAMS)
    # Every TUI call site goes through the module (`api.upload_run(...)`, never
    # a `from framework.api import upload_run`), so rebinding the attributes is
    # the whole job. tools/webdemo/test_sandbox.py asserts that stays true.


# ── entry point ──────────────────────────────────────────────────────────── #

def sandboxed_app(workspace: Path):
    """A FetcherApp whose quit binding is removed.

    `q` would end the browser session and leave a visitor staring at a Restart
    dialog, which reads as the demo crashing. Everything else keeps its keys.
    """
    from textual.binding import Binding

    from framework.tui.app import FetcherApp
    from framework.tui.screens.welcome import WelcomeScreen
    from framework.tui.screens.workspace import WorkspaceScreen

    for screen in (WelcomeScreen, WorkspaceScreen):
        screen.BINDINGS = [b for b in screen.BINDINGS
                           if getattr(b, "action", "") != "app.quit"]

    class SandboxApp(FetcherApp):
        # CSS_PATH is resolved relative to the module that declares the App
        # subclass, so a relative path here would look for the stylesheet under
        # tools/webdemo/. Pin it to the TUI's own.
        CSS_PATH = str(Path(FetcherApp.__module__ and
                            sys.modules[FetcherApp.__module__].__file__).parent
                       / "styles" / "index.tcss")

        BINDINGS = [
            *FetcherApp.BINDINGS,
            Binding("q", "sandbox_quit", "Quit", show=False),
            Binding("ctrl+q", "sandbox_quit", "Quit", show=False),
        ]

        def action_sandbox_quit(self) -> None:
            self.notify(
                "This is the hosted sandbox — it stays open. Reload the page to "
                "start over with a fresh workspace.",
                title="no need to quit",
                timeout=6,
            )

    return SandboxApp(root_override=str(workspace))


def main() -> None:
    if "--build-template" in sys.argv:
        target = Path(sys.argv[sys.argv.index("--build-template") + 1])
        print(f"built demo workspace template at {build_template(target)}")
        return

    # Before anything imports textual: constants.MAX_FPS is read at import time.
    assert "textual.constants" not in sys.modules, "textual imported too early to cap FPS"
    os.environ["TEXTUAL_FPS"] = MAX_FPS

    workspace = session_workspace()
    os.chdir(workspace)  # a manifest's relative output_dir resolves from here

    # Obviously-fake values so the manifests validate and the Paramify tab has
    # something to show. Nothing can leave the process — see block_network().
    os.environ.update(
        AWS_ACCESS_KEY_ID="ASIAEXAMPLEDEMOKEY01",
        AWS_SECRET_ACCESS_KEY="demo-secret-access-key-not-real",
        AWS_SESSION_TOKEN="demo-session-token-not-real",
        OKTA_API_TOKEN="00demo-okta-token-not-real",
        OKTA_ORG_URL="https://acme.okta.com",
        PARAMIFY_UPLOAD_API_TOKEN="demo-upload-token-not-real",
        PARAMIFY_API_TOKEN="demo-read-token-not-real",
        PARAMIFY_BASE_URL="https://app.paramify.com/api/v0",
    )

    patch_api()
    use_cached_discovery()
    freeze_welcome_sheen()
    block_network()
    sandboxed_app(workspace).run()


if __name__ == "__main__":
    main()
