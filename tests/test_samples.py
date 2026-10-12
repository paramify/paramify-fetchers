"""Tests for evidence samples (framework/samples.py + the api facade).

The properties that matter: a sample keeps the MOST informative record of each
repeated collection and counts the rest; identifiers are replaced by fakes of
the same shape; and a sample in which any known identifier survives is never
written. The last test checks the committed samples themselves.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from framework import api, yaml_io
from framework import samples as s
from tests.conftest import REPO_ROOT, build_fetcher


def envelope(payload, name="t_fetcher", version="0.1.0", target=None,
             collected="2026-09-28T17:00:00Z", exit_code=0):
    return {
        "schema_version": "1.0",
        "metadata": {
            "fetcher_name": name, "fetcher_version": version, "category": "testcat",
            "run_id": "run-x", "target": target or {}, "collected_at": collected,
            "status": "success" if exit_code == 0 else "failed", "exit_code": exit_code,
        },
        "payload": payload,
    }


def write(path: Path, doc) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))
    return path


# --------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------- #

def test_trim_keeps_the_fullest_record_not_the_first():
    payload = {"results": {"vms": [
        {"id": "a", "tags": None, "disk": None},
        {"id": "b", "tags": ["x"], "disk": {"encrypted": True}},
        {"id": "c", "tags": None, "disk": None},
    ]}}
    assert s.trim(payload)["results"]["vms"] == [{"id": "b", "tags": ["x"], "disk": {"encrypted": True}}]


def test_trim_ties_go_to_the_first_record():
    assert s.trim([{"id": "a"}, {"id": "b"}]) == [{"id": "a"}]


def test_trim_shortens_scalar_lists_and_keyed_maps():
    payload = {
        "names": ["a", "b", "c", "d", "e"],
        "status_by_user": {f"u{i}@x.io": "done" for i in range(10)},
        "summary": {"total": 10, "done": 10, "pct": 100, "late": 0},
    }
    out = s.trim(payload)
    assert out["names"] == ["a", "b", "c"]
    assert len(out["status_by_user"]) == 3
    # A dict keyed by field names is not a map of records: kept whole.
    assert out["summary"] == payload["summary"]


def test_profile_counts_nested_records_across_every_parent():
    payload = {
        "metadata": {"api_failures": [{"call": "x"}]},
        "results": {"vaults": [
            {"name": "v1", "keys": [{"id": 1, "rotation": None}, {"id": 2, "rotation": "90d"}]},
            {"name": "v2", "keys": [{"id": 3, "rotation": "30d"}]},
        ]},
    }
    by_path = {c["path"]: c for c in s.profile(payload)}
    # The payload's own metadata block is bookkeeping, not evidence.
    assert set(by_path) == {"results.vaults[]", "results.vaults[].keys[]"}
    keys = by_path["results.vaults[].keys[]"]
    assert keys["records"] == 3
    assert keys["fields"] == {"id": 3, "rotation": 2}


def test_false_and_zero_count_as_filled_null_does_not():
    by_path = {c["path"]: c for c in s.profile({"r": [{"a": False, "b": 0, "c": None}]})}
    assert by_path["r[]"]["fields"] == {"a": 1, "b": 1, "c": 0}


# --------------------------------------------------------------------------- #
# Sanitize
# --------------------------------------------------------------------------- #

def clean(obj, target=None, scrub=()):
    env = envelope(obj, target=target)
    needles = s.collect_needles(env, scrub)
    return s.sanitize(obj, needles), needles


def test_emails_get_fakes_and_provider_service_accounts_keep_their_shape():
    out, _ = clean({"a": "jane.doe@acme.com", "b": "jane.doe@acme.com",
                    "sa": "123456789012-compute@developer.gserviceaccount.com"})
    assert out["a"] == out["b"] == "user1@example.com"
    assert out["sa"].endswith("-compute@developer.gserviceaccount.com")
    assert "123456789012" not in out["sa"]


def test_account_ids_in_arns_keep_the_arn_shape():
    out, _ = clean({"arn": "arn:aws:iam::210987654321:role/x"},
                   target={"account_id": "210987654321"})
    assert out["arn"] == "arn:aws:iam::111111111111:role/x"


def test_numbers_are_not_strings():
    # A 12-digit integer is a byte count, not an account id.
    out, _ = clean({"bytes": 107374182400, "id": "107374182400"})
    assert out["bytes"] == 107374182400
    assert out["id"] != "107374182400"


def test_uuids_and_ips_are_replaced_but_special_ips_are_kept():
    out, _ = clean({
        "sub": "/subscriptions/5f3c2a1e-9b7d-4e6f-a8c0-123456789abc/rg",
        "public": "54.0.0.10/32", "private": "10.99.16.0/20",
        "any": "0.0.0.0/0", "imds": "169.254.169.254",
    })
    assert "5f3c2a1e" not in out["sub"] and out["sub"].startswith("/subscriptions/00000000-")
    assert out["public"].startswith("203.0.113.") and out["public"].endswith("/32")
    assert out["private"].startswith("10.0.") and out["private"].endswith("/20")
    assert out["any"] == "0.0.0.0/0"
    assert out["imds"] == "169.254.169.254"


def test_long_hex_ids_are_replaced_keeping_their_length():
    out, _ = clean({"key_id": "0123456789abcdef0123456789abcdef01234567", "short": "c6a6482d"})
    assert out["key_id"] == "1".zfill(40)
    assert out["short"] == "c6a6482d"


def test_secret_shaped_keys_are_redacted_but_names_and_ids_are_not():
    out, _ = clean({"client_secret": "hunter2", "secret_name": "db-creds",
                    "access_key_id": "AKIA123", "PasswordLastUsed": "2026-01-01"})
    assert out["client_secret"] == "<redacted>"
    assert out["secret_name"] == "db-creds"
    assert out["access_key_id"] == "AKIA123"
    assert out["PasswordLastUsed"] == "2026-01-01"


def test_person_names_and_logins_are_replaced():
    out, _ = clean({"user": {"first_name": "Ada", "last_name": "Lovelace",
                             "user_name": "alovelace", "email": "ada@acme.com"}})
    u = out["user"]
    assert u["first_name"].startswith("Person") and u["last_name"].startswith("Person")
    assert u["user_name"].startswith("user") and "alovelace" not in json.dumps(out)
    assert u["email"].endswith("@example.com")


def test_display_name_is_a_person_only_inside_a_user_record():
    out, _ = clean({
        "roles": [{"display_name": "Global Administrator", "id": "r1"}],
        "members": [{"display_name": "Ada Lovelace", "upn": "ada@acme.com"}],
    })
    assert out["roles"][0]["display_name"] == "Global Administrator"
    assert out["members"][0]["display_name"].startswith("Person")


def test_azure_guest_upn_is_replaced():
    upn = "jane.doe_acme.com#EXT#@janeacme.onmicrosoft.com"
    out, needles = clean({"user_principal_name": upn, "domain_seen": "janeacme.onmicrosoft.com"})
    assert "jane" not in json.dumps(out).lower()
    assert s.find_leaks(out, needles) == []


def test_target_literals_are_replaced_case_insensitively():
    out, _ = clean({"id": "/resourceGroups/RG-ACME-PROD/x"},
                   target={"profile": "acme-prod", "region": "us-east-2"})
    assert "acme" not in out["id"].lower()


def test_common_target_values_are_not_replaced_everywhere():
    out, _ = clean({"network": "default"}, target={"profile": "default"})
    assert out["network"] == "default"


def test_scrub_words_are_replaced():
    out, _ = clean({"bucket": "AcmeCorp-logs"}, scrub=["acmecorp"])
    assert out["bucket"] == "example-logs"


def test_fakes_are_deterministic():
    payload = {"a": ["x@acme.com", "y@acme.com"], "arn": "arn:aws:iam::210987654321:root"}
    assert clean(payload)[0] == clean(payload)[0]


# --------------------------------------------------------------------------- #
# Build + leak check
# --------------------------------------------------------------------------- #

def test_a_person_name_in_free_text_is_reported_as_a_leak():
    payload = {"results": [{"first_name": "Ada", "email": "ada@acme.com",
                            "note": "Ada approved this"}]}
    doc, leaks = s.build_sample(s.Candidate(Path("x.json"), envelope(payload), s.profile(payload)))
    assert leaks == ["Ada"]


def test_identifiers_from_other_files_are_replaced():
    other = envelope({"metadata": {"profile": "acme-prod"}})
    payload = {"results": [{"bucket": "acme-prod-logs"}]}
    cand = s.Candidate(Path("x.json"), envelope(payload), s.profile(payload))
    doc, leaks = s.build_sample(cand, extra=s.collect_needles(other))
    assert leaks == []
    assert "acme-prod" not in json.dumps(doc)


def test_sample_document_shape():
    payload = {"results": {"queues": [{"name": "q1"}, {"name": "q2"}]}}
    doc, leaks = s.build_sample(s.Candidate(Path("x.json"), envelope(payload), s.profile(payload)))
    assert leaks == []
    assert doc["reviewed"] is False and doc["source"] == "live"
    assert doc["captured_on"] == "2026-09-28"
    assert doc["collections"] == [{"path": "results.queues[]", "records": 2, "fields": {"name": 2}}]
    assert doc["payload"] == {"results": {"queues": [{"name": "q1"}]}}


def test_best_candidate_prefers_records_then_current_version():
    empty_new = s.Candidate(Path("a"), envelope({"r": []}, version="0.2.0"), s.profile({"r": []}))
    full_old = s.Candidate(Path("b"), envelope({"r": [{"x": 1}]}, version="0.1.0"), s.profile({"r": [{"x": 1}]}))
    full_new = s.Candidate(Path("c"), envelope({"r": [{"x": 1}]}, version="0.2.0"), s.profile({"r": [{"x": 1}]}))
    assert s.best_candidate([empty_new, full_old], "0.2.0") is full_old
    assert s.best_candidate([empty_new, full_old, full_new], "0.2.0") is full_new


# --------------------------------------------------------------------------- #
# api.backfill_samples, end to end on tmp dirs
# --------------------------------------------------------------------------- #

@pytest.fixture
def two_fetchers(tmp_path):
    fx = {}
    for name in ("good_fetcher", "leaky_fetcher", "empty_fetcher"):
        d = tmp_path / "fetchers" / "testcat" / name
        d.mkdir(parents=True)
        fx[name] = build_fetcher(d, name=name)
    ev = tmp_path / "evidence" / "run-1"
    write(ev / "good.json", envelope({"results": [{"id": "a", "owner": "x@acme.com"}]}, name="good_fetcher"))
    write(ev / "leaky.json", envelope(
        {"results": [{"first_name": "Ada", "note": "Ada did it"}]}, name="leaky_fetcher"))
    write(ev / "empty.json", envelope({"results": []}, name="empty_fetcher"))
    write(ev / "_run_metadata.json", {"not": "evidence"})
    return tmp_path, fx


def test_backfill_writes_clean_samples_and_blocks_leaky_ones(two_fetchers):
    root, fx = two_fetchers
    out = api.backfill_samples(root, root / "evidence", fetchers=fx)
    assert [r["fetcher"] for r in out["written"]] == ["good_fetcher"]
    assert [r["fetcher"] for r in out["blocked"]] == ["leaky_fetcher"]
    assert out["blocked"][0]["leaks"] == ["Ada"]
    assert [r["fetcher"] for r in out["no_records"]] == ["empty_fetcher"]
    assert (fx["good_fetcher"].path / "sample.json").is_file()
    assert not (fx["leaky_fetcher"].path / "sample.json").exists()
    assert "acme" not in (fx["good_fetcher"].path / "sample.json").read_text()


def test_backfill_keeps_existing_samples_unless_forced(two_fetchers):
    root, fx = two_fetchers
    api.backfill_samples(root, root / "evidence", fetchers=fx)
    again = api.backfill_samples(root, root / "evidence", fetchers=fx)
    assert [r["fetcher"] for r in again["skipped"]] == ["good_fetcher"]
    forced = api.backfill_samples(root, root / "evidence", fetchers=fx, force=True)
    assert [r["fetcher"] for r in forced["written"]] == ["good_fetcher"]


def test_backfill_dry_run_writes_nothing(two_fetchers):
    root, fx = two_fetchers
    out = api.backfill_samples(root, root / "evidence", fetchers=fx, dry_run=True)
    assert [r["fetcher"] for r in out["written"]] == ["good_fetcher"]
    assert not (fx["good_fetcher"].path / "sample.json").exists()


def test_sample_status_and_read_sample(two_fetchers):
    root, fx = two_fetchers
    api.backfill_samples(root, root / "evidence", fetchers=fx)
    rows = {r["fetcher"]: r for r in api.sample_status(root, fetchers=fx)}
    assert rows["good_fetcher"]["has_sample"] and not rows["good_fetcher"]["reviewed"]
    assert rows["good_fetcher"]["current"] is True
    assert rows["leaky_fetcher"]["has_sample"] is False
    assert api.read_sample(root, "good_fetcher", fetchers=fx)["fetcher_name"] == "good_fetcher"
    with pytest.raises(ValueError, match="no sample yet"):
        api.read_sample(root, "empty_fetcher", fetchers=fx)


# --------------------------------------------------------------------------- #
# The committed samples
# --------------------------------------------------------------------------- #

COMMITTED = sorted((REPO_ROOT / "fetchers").glob("*/*/" + s.SAMPLE_FILENAME))


@pytest.mark.parametrize("path", COMMITTED, ids=lambda p: p.parent.name)
def test_committed_sample_is_well_formed(path):
    doc = json.loads(path.read_text())
    assert doc["sample_schema_version"] == s.SAMPLE_SCHEMA_VERSION
    meta = yaml_io.load_path(path.parent / "fetcher.yaml")
    assert doc["fetcher_name"] == meta["name"]
    assert meta.get("kind") != "issue_report"
    assert doc["source"] in ("live", "synthetic")
    assert isinstance(doc["reviewed"], bool)
    # No real email domain survives in a committed sample.
    for m in s._EMAIL.finditer(json.dumps(doc)):
        assert s._provider_domain(m.group(0).rsplit("@", 1)[1]), m.group(0)
