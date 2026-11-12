"""TUI: the Paramify page's upload plan and upload with batches, channels and stacks.

The planner and the upload run for real against the fake_paramify fixture
(tests/paramify_fake.py behind framework.sync.upload's Client): no socket is
opened (no_network), and the fake records every call.
"""

from __future__ import annotations

import functools
import json
import threading
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

pytest.importorskip("textual", reason="TUI tests need the 'tui' extra")

from textual.widgets import Button, RichLog  # noqa: E402

from framework import api  # noqa: E402
from framework.contract import ManifestEntry  # noqa: E402
from framework.paramify_auth import READ_TOKEN_ENV  # noqa: E402
from framework.runner.manifest_loader import entry_keys  # noqa: E402
from framework.tui.modals import ConfirmModal, PickerModal  # noqa: E402
from framework.tui.screens.manifest import ManifestPage  # noqa: E402
from framework.tui.screens.upload import UploadPage  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
URL = "https://api.example.test"  # conftest.FAKE_PARAMIFY_URL
RUN_ID = "2026-09-01T00-00-00Z"


@pytest.fixture
def paramify(fake_paramify, monkeypatch, no_network):
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")
    monkeypatch.delenv(READ_TOKEN_ENV, raising=False)
    monkeypatch.delenv("PARAMIFY_CUSTOM_TAGS", raising=False)
    # The scripts panel is not under test here.
    monkeypatch.setattr(UploadPage, "_rebuild_scripts", lambda page: None)
    return fake_paramify


def _current_request(fake, ev, channel_index: int = 0):
    today = date.today()
    return fake.add_request(ev.id, ev.channels[channel_index].id, today - timedelta(days=5), today + timedelta(days=5))


@functools.cache
def _fetcher() -> str:
    catalog = api.catalog(REPO_ROOT)
    return next(f["name"] for c in catalog["categories"] for f in c["fetchers"])


def _envelope(name: str, ref: str) -> dict:
    return {"schema_version": "1.0", "payload": {"k": 1}, "metadata": {
        "fetcher_name": name, "fetcher_version": "0.1.0", "run_id": RUN_ID, "status": "success",
        "collected_at": "2026-09-01T00:00:00Z", "category": "cat",
        "evidence_set": {"reference_id": ref, "name": ref}}}


def _workspace(tmp_path: Path, entries: list, run_paramify: dict | None = None) -> Path:
    """A manifest listing one fetcher once per entry, and a run of it recorded with the same settings.

    `entries` is [(the entry's own paramify block, {file name: evidence set})]."""
    name = _fetcher()
    out = tmp_path / "evidence"
    run = out / f"run-{RUN_ID}"
    run.mkdir(parents=True)
    m = api.init_manifest()
    api.set_output_dir(m, str(out))
    if run_paramify:
        m["run"]["paramify"] = dict(run_paramify)
    invocations, recorded = [], {}
    for key, (own, files) in zip(entry_keys([ManifestEntry(use=name)] * len(entries)), entries):
        m["run"]["fetchers"].append({"use": name, **({"paramify": dict(own)} if own else {})})
        for file, ref in files.items():
            (run / file).write_text(json.dumps(_envelope(name, ref)))
        invocations.append({"fetcher_name": name, "fetcher_version": "0.1.0", "target": None,
                            "exit_code": 0, "outputs": list(files), "entry_key": key})
        recorded[key] = {"use": name, **(run_paramify or {}), **own}
    (run / "_run_metadata.json").write_text(json.dumps(
        {"run_id": RUN_ID, "manifest": None, "invocations": invocations, "paramify": recorded}))
    path = tmp_path / "batches.yaml"
    path.write_text(yaml.safe_dump(m))
    return path


async def _until(pilot, done, what: str, timeout: float = 30.0) -> None:
    for _ in range(int(timeout / 0.05)):
        if done():
            return
        await pilot.pause(0.05)
    raise AssertionError(f"timed out waiting for {what}")


async def _confirm(app, pilot) -> list:
    """Open the Paramify page, ask to upload, and return the confirm's lines."""
    await pilot.press("5")
    await pilot.pause()
    page = app.screen.query_one(UploadPage)
    page.rebuild()
    assert not page.query_one("#upload-submit", Button).disabled
    page.action_upload_run()
    await _until(pilot, lambda: isinstance(app.screen, ConfirmModal), "the upload confirm")
    return str(app.screen._message).splitlines()


async def _answer(app, pilot, key: str) -> None:
    await pilot.press(key)
    await app.workers.wait_for_complete()
    await pilot.pause()


def _delivery(lines: list) -> list:
    """The delivery section of a plan: its action, warning and fix lines, then the totals."""
    start = lines.index("delivery") + 1
    end = next(i for i, line in enumerate(lines) if " · " in line)
    return lines[start:end + 1]


def _writes(fake) -> list:
    return [c for c in fake.calls if c[0] != "GET"]


def _log(page) -> str:
    """The log with runs of whitespace as one space: the log wraps long lines."""
    return " ".join(" ".join(line.text for line in page.query_one("#upload-log", RichLog).lines).split())


def _banner(page) -> str:
    rendered = page.query_one("#upload-banner").render()
    return getattr(rendered, "plain", str(rendered)).strip()


async def _uploaded(app, pilot) -> UploadPage:
    page = app.screen.query_one(UploadPage)
    await _until(pilot, lambda: "upload complete" in _banner(page) and _log(page), "the upload")
    return page


def test_an_entry_goes_in_a_new_batch_on_its_channels_current_request(tmp_path, paramify, run_tui):
    st = paramify.add_stack("Prod")
    ev = paramify.add_evidence("EVD-X", channels=[st.id])
    _current_request(paramify, ev)
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X", "b.json": "EVD-X"})], {"stack": st.id})

    async def body(app, pilot):
        return await _confirm(app, pilot)

    lines = run_tui(body, path)
    assert _delivery(lines) == [
        f"  deliver {_fetcher()}: deliver 2 files to AR-1 (stack Prod, channel CH-1): new batch (approved on submit)",
        "1 deliver · 0 noop · 0 refuse · 1 tag",
    ]
    assert not [line for line in lines if line.startswith("!")]
    assert lines[-1] == f"Upload 2 evidence file(s) to {URL}?"
    assert _writes(paramify) == []


def test_each_entry_gets_its_own_batch_or_route(tmp_path, paramify, run_tui):
    st = paramify.add_stack("Prod")
    ev = paramify.add_evidence("EVD-X", channels=[st.id])
    _current_request(paramify, ev)
    paramify.add_evidence("EVD-Y")
    paramify.add_evidence("EVD-Z", channels=[st.id])  # a channel with no artifact request
    w = paramify.add_evidence("EVD-W", channels=[st.id])
    _current_request(paramify, w)
    paramify.add_evidence("EVD-V", channels=[st.id])  # no request either
    name = _fetcher()
    path = _workspace(tmp_path, [
        ({}, {"x_east.json": "EVD-X", "x_west.json": "EVD-X", "x_gov.json": "EVD-X"}),
        ({"approval": "MANUAL"}, {"y.json": "EVD-Y"}),
        ({}, {"z.json": "EVD-Z"}),
        ({"delivery": "direct"}, {"w.json": "EVD-W"}),
        ({"no_request": "evidence"}, {"v.json": "EVD-V"}),
    ], {"stack": st.id})

    async def body(app, pilot):
        return await _confirm(app, pilot)

    assert _delivery(run_tui(body, path)) == [
        f"  deliver {name}: deliver 3 files to AR-1 (stack Prod, channel CH-1): new batch (approved on submit)",
        f"  deliver {name}#1: deliver 1 file to EVD-Y (evidence level): new batch (reviewed in the app)",
        f"  deliver {name}#2: deliver 1 file to EVD-Z direct (channel CH-2): CH-2 has no artifact request",
        "    ! CH-2 has no artifact request; sent direct, as before batches",
        f"  deliver {name}#3: deliver 1 file to EVD-W direct (channel CH-3): delivery: direct",
        f"  deliver {name}#4: deliver 1 file to EVD-V (evidence level): new batch (approved on submit)",
        "    ! evidence-level batch: does not count toward the solution capability",
        "5 deliver · 0 noop · 0 refuse · 5 tag",
    ]


def _two_owners(fake):
    st = fake.add_stack("Prod")
    ev = fake.add_evidence("EVD-X", channels=[st.id, st.id], owners=["alice", "bob"])
    _current_request(fake, ev, 0)
    _current_request(fake, ev, 1)
    return st


def test_the_owner_picks_the_channel_where_a_stack_has_one_per_owner(tmp_path, paramify, run_tui):
    st = _two_owners(paramify)
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X"})], {"stack": st.id, "owner": "bob"})

    async def body(app, pilot):
        return await _confirm(app, pilot)

    assert _delivery(run_tui(body, path)) == [
        f"  deliver {_fetcher()}: deliver 1 file to AR-2 (stack Prod, channel CH-2): new batch (approved on submit)",
        "1 deliver · 0 noop · 0 refuse · 1 tag",
    ]


def test_without_an_owner_the_entry_is_refused_with_the_owners_and_the_fix(tmp_path, paramify, run_tui):
    st = _two_owners(paramify)
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X"})], {"stack": st.id})

    async def body(app, pilot):
        return await _confirm(app, pilot)

    assert _delivery(run_tui(body, path)) == [
        f"  refuse {_fetcher()}: EVD-X has 2 channels on stack Prod, one per owner: CH-1 (alice), CH-2 (bob)",
        "    → fix: set an owner to choose one (paramify manifest set-owner, or paramify upload --owner); "
        "owners: alice, bob",
        "0 deliver · 0 noop · 1 refuse",
    ]


def test_a_stack_and_owner_picked_after_the_run_are_noted_and_route_nothing_yet(tmp_path, paramify, run_tui):
    # The pickers read the fake workspace through the real api.list_stacks and
    # api.list_channel_owners. The run's settings still decide the route.
    _two_owners(paramify)
    paramify.add_stack("Staging")
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X"})])
    name = _fetcher()

    async def pick(app, pilot, button: str, typed: str) -> list:
        app.screen.query_one(ManifestPage).query_one(button, Button).press()
        await _until(pilot, lambda: isinstance(app.screen, PickerModal), f"the {button} picker")
        options = [label for _, label in app.screen._options]
        await pilot.press(*typed, "enter")
        await _until(pilot, lambda: not isinstance(app.screen, PickerModal), f"the {button} picker to close")
        return options

    async def body(app, pilot):
        await pilot.press("2")
        await pilot.pause()
        stacks = await pick(app, pilot, "#manifest-stack", "Prod")
        owners = await pick(app, pilot, "#manifest-owner", "bob")
        page = app.screen.query_one(ManifestPage)
        labels = (str(page.query_one("#manifest-stack", Button).label),
                  str(page.query_one("#manifest-owner", Button).label))
        return stacks, owners, labels, await _confirm(app, pilot)

    stacks, owners, labels, lines = run_tui(body, path)
    assert stacks == ["Prod  (st-1)", "Staging  (st-2)"]
    assert owners == ["alice  (1 evidence set)", "bob  (1 evidence set)"]
    assert labels == ("Prod", "bob")
    assert yaml.safe_load(path.read_text())["run"]["paramify"] == {"stack": "st-1", "stack_name": "Prod", "owner": "bob"}
    assert lines[:2] == [
        f"! the manifest now sets stack Prod for {name}; this run was made with none. "
        "Run the manifest again, or upload with --stack st-1.",
        f"! the manifest now sets owner bob for {name}; this run was made with none. "
        "Run the manifest again, or upload with --owner bob.",
    ]
    # The run had no stack, so the upload still cannot choose a channel.
    assert _delivery(lines)[0] == f"  refuse {name}: EVD-X has 2 channels and no stack is configured"
    assert _writes(paramify) == []


def test_with_batches_off_the_plan_says_so_first_and_sends_direct(tmp_path, paramify, run_tui):
    st = paramify.add_stack("Prod")
    paramify.add_evidence("EVD-X", channels=[st.id])
    paramify.batches_flag_off()
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X"})], {"stack": st.id})

    async def body(app, pilot):
        return await _confirm(app, pilot)

    lines = run_tui(body, path)
    assert lines[0] == ("! batches are off for this workspace (Artifact requests are not enabled for this "
                        "workspace.); every entry is sent direct, as before batches")
    assert _delivery(lines) == [
        f"  deliver {_fetcher()}: deliver 1 file to EVD-X direct (channel CH-1): batches are off for this workspace",
        "1 deliver · 0 noop · 0 refuse · 1 tag",
    ]


def test_yes_uploads_one_batch_and_the_next_plan_finds_it_delivered(tmp_path, paramify, run_tui):
    st = paramify.add_stack("Prod")
    ev = paramify.add_evidence("EVD-X", channels=[st.id], approval="MANUAL")
    ar = _current_request(paramify, ev)
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X", "b.json": "EVD-X"})], {"stack": st.id})
    name = _fetcher()

    async def body(app, pilot):
        await _confirm(app, pilot)
        await _answer(app, pilot, "y")
        page = await _uploaded(app, pilot)
        shown = _log(page), _banner(page)
        return shown, await _confirm(app, pilot)

    (log, banner), again = run_tui(body, path)
    [batch] = paramify._batches
    assert (batch["artifactRequestId"], batch["status"], batch["artifactCount"]) == (ar.id, "APPROVED", 2)
    assert paramify.batch_bodies[0]["whenToApprove"] == "SUBMISSION"  # whatever the set says
    assert "[OK] a.json uploaded set=EVD-X channel=CH-1" in log
    assert "[OK] b.json uploaded set=EVD-X channel=CH-1" in log
    assert banner.startswith("evidence upload complete — uploaded=2 duplicates=0 errors=0")
    entry = json.loads((tmp_path / "evidence" / f"run-{RUN_ID}" / "upload_log.json").read_text())["entries"][name]
    assert (entry["mode"], entry["batch_reference"], entry["channel"]) == ("batch", "BCH-1", "CH-1")
    assert _delivery(again) == [f"  noop {name}: already delivered in BCH-1", "0 deliver · 1 noop · 0 refuse · 1 tag"]


def test_an_entry_held_by_a_failed_file_resumes_its_open_batch(tmp_path, paramify, run_tui):
    st = paramify.add_stack("Prod")
    ev = paramify.add_evidence("EVD-X", channels=[st.id])
    _current_request(paramify, ev)
    paramify.fail_upload("b.json", 503)
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X", "b.json": "EVD-X"})], {"stack": st.id})

    async def body(app, pilot):
        await _confirm(app, pilot)
        await _answer(app, pilot, "y")
        page = await _uploaded(app, pilot)
        first = _log(page), _banner(page)
        paramify._fail_all.clear()  # the outage is over
        plan = await _confirm(app, pilot)
        await _answer(app, pilot, "y")
        page = await _uploaded(app, pilot)
        return first, plan, _banner(page)

    (log, banner), plan, second = run_tui(body, path)
    assert ("[FAIL] b.json error set=EVD-X channel=CH-1 "
            "POST /batches/bt-1/artifacts/upload failed after retrying (HTTP 503: )") in log
    assert banner.startswith("evidence upload complete — uploaded=1 duplicates=0 errors=1")
    assert _delivery(plan) == [
        f"  deliver {_fetcher()}: deliver 1 file to AR-1 (stack Prod, channel CH-1): resume BCH-1 (1 missing)",
        "1 deliver · 0 noop · 0 refuse · 1 tag",
    ]
    assert second.startswith("evidence upload complete — uploaded=1 duplicates=1 errors=0")
    [batch] = paramify._batches
    assert (batch["status"], batch["artifactCount"]) == ("APPROVED", 2)


def test_a_file_the_api_refuses_is_dropped_and_counted_in_the_banner(tmp_path, paramify, run_tui):
    st = paramify.add_stack("Prod")
    ev = paramify.add_evidence("EVD-X", channels=[st.id])
    _current_request(paramify, ev)
    paramify.fail_upload("b.json", 422, "bad file")
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X", "b.json": "EVD-X"})], {"stack": st.id})

    async def body(app, pilot):
        await _confirm(app, pilot)
        await _answer(app, pilot, "y")
        page = await _uploaded(app, pilot)
        return _log(page), _banner(page)

    log, banner = run_tui(body, path)
    assert ("[FAIL] b.json dropped set=EVD-X channel=CH-1 "
            "POST /batches/bt-1/artifacts/upload failed (HTTP 422: bad file)") in log
    assert banner.startswith("evidence upload complete — uploaded=1 duplicates=0 errors=0 dropped=1")


def test_no_on_the_confirm_sends_nothing(tmp_path, paramify, run_tui):
    st = paramify.add_stack("Prod")
    ev = paramify.add_evidence("EVD-X", channels=[st.id])
    _current_request(paramify, ev)
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X"})], {"stack": st.id})

    async def body(app, pilot):
        await _confirm(app, pilot)
        await _answer(app, pilot, "n")
        page = app.screen.query_one(UploadPage)
        return page._busy, page.query_one("#upload-submit", Button).disabled

    assert run_tui(body, path) == (False, False)
    assert _writes(paramify) == []
    assert not (tmp_path / "evidence" / f"run-{RUN_ID}" / "upload_log.json").exists()


def test_yes_on_a_plan_that_failed_sends_nothing(tmp_path, paramify, run_tui, monkeypatch):
    st = paramify.add_stack("Prod")
    paramify.add_evidence("EVD-X", channels=[st.id])
    paramify.fail_route("GET", "/evidence", 401, "token expired")
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X"})], {"stack": st.id})
    started = []
    real_upload = api.upload_run
    monkeypatch.setattr(api, "upload_run", lambda *a, **kw: started.append(1) or real_upload(*a, **kw))

    async def body(app, pilot):
        lines = await _confirm(app, pilot)
        paramify._fail_routes.clear()  # an upload started now would get through
        await _answer(app, pilot, "y")
        return lines, isinstance(app.screen, ConfirmModal)

    lines, still_open = run_tui(body, path)
    assert lines == ["Cannot plan the upload: GET /evidence failed (HTTP 401: token expired)"]
    assert not still_open
    assert started == [] and _writes(paramify) == []


def test_a_second_upload_while_the_plan_is_made_is_refused(tmp_path, paramify, run_tui, monkeypatch):
    st = paramify.add_stack("Prod")
    ev = paramify.add_evidence("EVD-X", channels=[st.id])
    _current_request(paramify, ev)
    path = _workspace(tmp_path, [({}, {"a.json": "EVD-X"})], {"stack": st.id})
    started, release = threading.Event(), threading.Event()
    real_plan = api.plan_upload
    calls = []

    def slow_plan(*a, **kw):
        calls.append(1)
        started.set()
        release.wait(10)
        return real_plan(*a, **kw)

    monkeypatch.setattr(api, "plan_upload", slow_plan)

    async def body(app, pilot):
        await pilot.press("5")
        await pilot.pause()
        page = app.screen.query_one(UploadPage)
        page.action_upload_run()
        await _until(pilot, started.is_set, "the plan to start")
        page.action_upload_run()
        await pilot.pause()
        refused = [str(n.message) for n in app._notifications]
        release.set()
        await _until(pilot, lambda: isinstance(app.screen, ConfirmModal), "the upload confirm")
        return refused

    assert "A Paramify operation is already in progress." in run_tui(body, path)
    assert len(calls) == 1
