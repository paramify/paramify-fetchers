"""Default custom tags: the policy read from upload.yaml, and the Tagger that
applies it. The HTTP boundary is the shared fake workspace behind the real
Client; nothing here touches a tenant.

What matters: tags are additive and re-asserted (one POST per entity per run,
never PATCH), a 403 turns tagging off for the rest of the run with one warning
instead of failing the upload, and a typo in the `tags:` block is a setup
error rather than a silent fallback to the defaults.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import requests

from framework import custom_tags as ct
from framework.paramify.client import Client
from framework.paramify.resources import Resources
from tests.paramify_fake import FakeParamify

NAMES = {"aws": "AWS", "okta": "Okta"}


@pytest.fixture(autouse=True)
def _no_ambient_switch(monkeypatch):
    """The developer's shell must not decide these tests."""
    monkeypatch.delenv(ct.ENV_SWITCH, raising=False)


def _resources(fake):
    return Resources(Client("tok", "https://api.example.test", session=fake.session, sleep=lambda _s: None))


def _tagger(fake=None, policy=None, names=NAMES):
    resources = _resources(fake) if fake is not None else None
    return ct.Tagger(resources, policy=policy or ct.TagPolicy(), display_names=names)


def _tag_posts(fake):
    return [path for method, path, _ in fake.calls if method == "POST" and path.startswith("/custom-tags/")]


# --------------------------------------------------------------------------- #
# Policy from config
# --------------------------------------------------------------------------- #

def test_defaults_when_block_absent():
    p = ct.resolve_tag_policy({})
    assert p == ct.TagPolicy(provenance=ct.DEFAULT_PROVENANCE_TAG, service=True)
    assert ct.resolve_tag_policy(None) == p


def test_false_turns_everything_off():
    p = ct.resolve_tag_policy({"tags": False})
    assert p.provenance is None and p.service is False and not p.enabled
    assert "tags: false" in p.off_reason
    t = ct.build_tagger(None, config={"tags": False})
    assert t.plan("aws") == []
    assert t.tag("evidence", "ev-1", "aws") == {"outcome": "off", "tags": []}
    assert t.summary()["enabled"] is False and "tags: false" in t.summary()["reason"]


# --------------------------------------------------------------------------- #
# The kill switches: the env var, and a caller's --no-tags
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", ["off", "OFF", "false", "no", "0", " off "])
def test_env_switch_turns_the_feature_off(value):
    p = ct.resolve_tag_policy({}, env={ct.ENV_SWITCH: value})
    assert not p.enabled
    assert p.off_reason == f"{ct.ENV_SWITCH}={value.strip()}"


@pytest.mark.parametrize("value", ["", "on", "true", "1", "yes", "banana"])
def test_env_switch_other_values_leave_the_config_in_charge(value):
    assert ct.resolve_tag_policy({}, env={ct.ENV_SWITCH: value}) == ct.TagPolicy()
    assert not ct.resolve_tag_policy({"tags": False}, env={ct.ENV_SWITCH: value}).enabled


def test_env_switch_is_read_from_the_process_environment(monkeypatch):
    monkeypatch.setenv(ct.ENV_SWITCH, "off")
    fake = FakeParamify()
    t = ct.build_tagger(_resources(fake), config={}, display_names=NAMES)
    assert t.tag("evidence", "ev-1", "aws")["outcome"] == "off"
    assert fake.calls == [], "an off tagger writes nothing"


def test_env_switch_wins_before_a_broken_block_is_read():
    # Off means off: a typo in the block must not keep the feature on, and
    # must not stop the run either.
    p = ct.resolve_tag_policy({"tags": {"provenence": "x"}}, env={ct.ENV_SWITCH: "off"})
    assert not p.enabled


def test_override_off_wins_over_everything():
    p = ct.resolve_tag_policy(
        {"tags": {"provenance": "Robots"}}, env={ct.ENV_SWITCH: "on"}, override_off="--no-tags"
    )
    assert not p.enabled and p.off_reason == "--no-tags"
    t = ct.build_tagger(_resources(FakeParamify()), config={}, display_names=NAMES, override_off="--no-tags")
    assert t.summary()["reason"] == "--no-tags" and t.plan("aws") == []


def test_facade_forwards_the_switch_to_every_stage(monkeypatch, tmp_path):
    """`--no-tags` reaches each uploader as custom_tags=False."""
    from types import SimpleNamespace

    from framework import api

    seen = {}

    def stub(name):
        def run(*_a, **kw):
            seen[name] = kw
            return {"ok": True}
        return run

    # The evidence upload runs on the sync engine, not a path-loaded uploader.
    monkeypatch.setattr(api._sync_upload, "run_upload", stub("upload"))
    monkeypatch.setattr(api, "_load_paramify_scripts_uploader",
                        lambda root: SimpleNamespace(sync_scripts=stub("scripts")))
    monkeypatch.setattr(api, "_load_paramify_validator_syncer",
                        lambda root: SimpleNamespace(collect_validators=lambda *a, **k: [],
                                                     sync_validators=stub("validators")))
    api.upload_run(tmp_path, tmp_path, custom_tags=False)
    api.scripts_sync(tmp_path, custom_tags=False)
    api.sync_validators(tmp_path, custom_tags=False)
    assert {k: v["custom_tags"] for k, v in seen.items()} == {
        "upload": False, "scripts": False, "validators": False,
    }


def test_rename_provenance_and_drop_service():
    p = ct.resolve_tag_policy({"tags": {"provenance": "  Collected by robots ", "service": False}})
    assert p.provenance == "Collected by robots"
    assert p.service is False and p.enabled


@pytest.mark.parametrize("off", [False, None])
def test_provenance_off_keeps_service(off):
    p = ct.resolve_tag_policy({"tags": {"provenance": off}})
    assert p.provenance is None and p.service is True and p.enabled


@pytest.mark.parametrize(
    "block, fragment",
    [
        ({"provenence": "x"}, "unknown key"),
        ({"provenance": ""}, "must not be empty"),
        ({"provenance": "x" * 256}, "at most 255"),
        ({"provenance": 7}, "must be a string"),
        ({"service": "yes"}, "true or false"),
        ("AWS", "mapping or false"),
    ],
)
def test_malformed_block_is_a_setup_error(block, fragment):
    with pytest.raises(ValueError, match=fragment):
        ct.resolve_tag_policy({"tags": block})


# --------------------------------------------------------------------------- #
# What gets applied
# --------------------------------------------------------------------------- #

def test_plan_is_provenance_plus_display_name():
    t = _tagger()
    assert t.plan("aws") == [ct.DEFAULT_PROVENANCE_TAG, "AWS"]
    assert t.plan(None) == [ct.DEFAULT_PROVENANCE_TAG]


def test_plan_without_display_name_is_provenance_only(caplog):
    t = _tagger()
    with caplog.at_level(logging.INFO, logger="paramify_custom_tags"):
        assert t.plan("mystery") == [ct.DEFAULT_PROVENANCE_TAG]
        assert t.plan("mystery") == [ct.DEFAULT_PROVENANCE_TAG]
    # Said once per category, not once per resource.
    assert sum("no display_name" in r.message for r in caplog.records) == 1


def test_plan_never_derives_a_service_tag_from_the_slug():
    t = _tagger(policy=ct.TagPolicy(provenance=None, service=True))
    assert t.plan("mystery") == []
    assert t.tag("evidence", "ev-1", "mystery") == {"outcome": "skipped", "tags": []}


# --------------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------------- #

def test_tag_posts_additively_once_per_entity():
    fake = FakeParamify()
    t = _tagger(fake)
    first = t.tag("evidence", "ev-1", "aws")
    again = t.tag("evidence", "ev-1", "aws")
    other = t.tag("scripts", "sc-1", "okta")

    assert first == {"outcome": "applied", "tags": [ct.DEFAULT_PROVENANCE_TAG, "AWS"]}
    assert again["outcome"] == "already"
    assert other["outcome"] == "applied"
    assert _tag_posts(fake) == ["/custom-tags/evidence/ev-1", "/custom-tags/scripts/sc-1"]
    assert fake.tags == {
        ("evidence", "ev-1"): [ct.DEFAULT_PROVENANCE_TAG, "AWS"],
        ("scripts", "sc-1"): [ct.DEFAULT_PROVENANCE_TAG, "Okta"],
    }
    assert t.summary() == {
        "enabled": True, "reason": None,
        "provenance": ct.DEFAULT_PROVENANCE_TAG, "service": True,
        "applied": 2, "failed": 0, "skipped": 0, "disabled": None,
    }


def test_409_counts_as_already_tagged():
    fake = FakeParamify()
    fake.fail_route("POST", r"/custom-tags/.*", 409, "conflict")
    t = _tagger(fake)
    assert t.tag("validators", "v-1", "aws")["outcome"] == "applied"
    assert t.summary()["failed"] == 0


def test_403_disables_the_rest_of_the_run_with_one_warning(caplog):
    fake = FakeParamify()
    fake.fail_route("POST", r"/custom-tags/.*", 403, "forbidden")
    t = _tagger(fake)
    with caplog.at_level(logging.WARNING, logger="paramify_custom_tags"):
        a = t.tag("evidence", "ev-1", "aws")
        b = t.tag("evidence", "ev-2", "aws")
    assert a["outcome"] == b["outcome"] == "forbidden"
    assert len(_tag_posts(fake)) == 1, "after a 403 no further tag requests are sent"
    assert t.disabled and "403" in t.disabled
    assert sum("custom-tags permission" in r.message for r in caplog.records) == 1
    assert t.summary()["skipped"] == 2 and t.summary()["applied"] == 0


def test_other_errors_are_counted_not_raised(caplog):
    fake = FakeParamify()
    fake.fail_route("POST", r"/custom-tags/.*", 500, "boom")
    t = _tagger(fake)
    with caplog.at_level(logging.WARNING, logger="paramify_custom_tags"):
        r = t.tag("evidence", "ev-1", "aws")
    assert r["outcome"] == "error" and "HTTP 500" in r["error"] and "boom" in r["error"]
    assert t.summary()["failed"] == 1 and t.disabled is None


def test_network_failure_is_an_error_not_an_exception(monkeypatch):
    fake = FakeParamify()

    def down(*_a, **_k):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(fake.session, "request", down)
    assert _tagger(fake).tag("evidence", "ev-1", "aws")["outcome"] == "error"


def test_no_resources_means_dry_run():
    t = _tagger(None)
    r = t.tag("evidence", "ev-1", "aws")
    assert r == {"outcome": "dry_run", "tags": [ct.DEFAULT_PROVENANCE_TAG, "AWS"]}
    assert t.summary()["applied"] == 0


# --------------------------------------------------------------------------- #
# Display names come from the category files
# --------------------------------------------------------------------------- #

def _repo_with_categories(tmp_path: Path, **files: str) -> Path:
    cats = tmp_path / "fetchers" / "_categories"
    cats.mkdir(parents=True)
    for name, body in files.items():
        (cats / f"{name}.yaml").write_text(body)
    # discover_platforms validates against the real schema.
    schemas = tmp_path / "framework" / "schemas"
    schemas.mkdir(parents=True)
    real = Path(__file__).resolve().parent.parent / "framework" / "schemas" / "category_schema.json"
    (schemas / "category_schema.json").write_text(real.read_text())
    return tmp_path


def test_display_names_read_from_category_files(tmp_path):
    root = _repo_with_categories(
        tmp_path,
        aws="display_name: AWS\ndescription: AWS fetchers\n",
        okta="description: Okta fetchers\n",   # no display_name -> absent
        empty="",
    )
    assert ct.category_display_names(root) == {"aws": "AWS"}


def test_build_tagger_reads_names_from_root(tmp_path):
    root = _repo_with_categories(tmp_path, aws="display_name: AWS\n")
    t = ct.build_tagger(None, config={}, root=root)
    assert t is not None and t.plan("aws") == [ct.DEFAULT_PROVENANCE_TAG, "AWS"]


def test_unreadable_categories_warn_and_drop_service_tags(tmp_path, caplog):
    root = _repo_with_categories(tmp_path, aws="display_name: 7\n")  # schema-invalid
    with caplog.at_level(logging.WARNING, logger="paramify_custom_tags"):
        assert ct.category_display_names(root) == {}
    assert any("service tags are off" in r.message for r in caplog.records)


def test_every_real_category_declares_a_display_name():
    """The service tag is only as good as the declarations: a category without
    one silently gets the provenance tag alone."""
    repo = Path(__file__).resolve().parent.parent
    from framework.config_loader import discover_platforms

    missing = sorted(c for c, spec in discover_platforms(repo).items() if not spec.display_name)
    assert missing == [], f"categories without display_name: {missing}"
