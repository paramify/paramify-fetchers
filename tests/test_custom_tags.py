"""Default custom tags: the policy read from upload.yaml, and the Tagger that
applies it. The HTTP boundary is a fake session; nothing here touches a tenant.

What matters: tags are additive and re-asserted (one POST per entity per run,
never PATCH), a 403 turns tagging off for the rest of the run with one warning
instead of failing the upload, and a typo in the `tags:` block is a setup
error rather than a silent fallback to the defaults.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from framework import custom_tags as ct


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class RecordingSession:
    """Scripted requests.Session stand-in: answers from `responses` in order
    (the last one repeats), and records every POST."""

    def __init__(self, *responses):
        self.responses = list(responses) or [FakeResponse(200)]
        self.posts = []

    def post(self, url, json=None, timeout=None, **_):
        self.posts.append((url, json))
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


BASE = "https://example.test/api/v0"
NAMES = {"aws": "AWS", "okta": "Okta"}


def _tagger(session=None, policy=None, names=NAMES):
    return ct.Tagger(session, BASE, policy=policy or ct.TagPolicy(), display_names=names)


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
    assert ct.build_tagger(None, BASE, config={"tags": False}) is None


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
    s = RecordingSession(FakeResponse(200))
    t = _tagger(s)
    first = t.tag("evidence", "ev-1", "aws")
    again = t.tag("evidence", "ev-1", "aws")
    other = t.tag("scripts", "sc-1", "okta")

    assert first == {"outcome": "applied", "tags": [ct.DEFAULT_PROVENANCE_TAG, "AWS"]}
    assert again["outcome"] == "already"
    assert other["outcome"] == "applied"
    assert s.posts == [
        (f"{BASE}/custom-tags/evidence/ev-1", {"names": [ct.DEFAULT_PROVENANCE_TAG, "AWS"]}),
        (f"{BASE}/custom-tags/scripts/sc-1", {"names": [ct.DEFAULT_PROVENANCE_TAG, "Okta"]}),
    ]
    assert t.summary() == {
        "provenance": ct.DEFAULT_PROVENANCE_TAG, "service": True,
        "applied": 2, "failed": 0, "skipped": 0, "disabled": None,
    }


def test_409_counts_as_already_tagged():
    t = _tagger(RecordingSession(FakeResponse(409, "conflict")))
    assert t.tag("validators", "v-1", "aws")["outcome"] == "applied"
    assert t.summary()["failed"] == 0


def test_403_disables_the_rest_of_the_run_with_one_warning(caplog):
    s = RecordingSession(FakeResponse(403, "forbidden"))
    t = _tagger(s)
    with caplog.at_level(logging.WARNING, logger="paramify_custom_tags"):
        a = t.tag("evidence", "ev-1", "aws")
        b = t.tag("evidence", "ev-2", "aws")
    assert a["outcome"] == b["outcome"] == "forbidden"
    assert len(s.posts) == 1, "after a 403 no further tag requests are sent"
    assert t.disabled and "403" in t.disabled
    assert sum("custom-tags permission" in r.message for r in caplog.records) == 1
    assert t.summary()["skipped"] == 2 and t.summary()["applied"] == 0


def test_other_errors_are_counted_not_raised(caplog):
    t = _tagger(RecordingSession(FakeResponse(500, "boom")))
    with caplog.at_level(logging.WARNING, logger="paramify_custom_tags"):
        r = t.tag("evidence", "ev-1", "aws")
    assert r["outcome"] == "error" and "HTTP 500" in r["error"]
    assert t.summary()["failed"] == 1 and t.disabled is None


def test_network_failure_is_an_error_not_an_exception():
    class Boom:
        def post(self, *a, **k):
            raise ConnectionError("down")

    t = _tagger(Boom())
    assert t.tag("evidence", "ev-1", "aws")["outcome"] == "error"


def test_no_session_means_dry_run():
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
    t = ct.build_tagger(None, BASE, config={}, root=root)
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
