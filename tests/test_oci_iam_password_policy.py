"""CIS judgements in `oci_iam_password_policy`, and which policy is judged."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "iam_password_policy" / "fetcher.py"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_iam_password_policy", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pw = _load()

# The three policies an out-of-the-box Default domain returned on the live tenancy.
STANDARD = {"id": "StandardPasswordPolicy", "name": "standardPasswordPolicy", "min_length": 8,
            "num_passwords_in_history": 1, "password_expires_after": 120, "max_incorrect_attempts": 5}
SIMPLE = {"id": "SimplePasswordPolicy", "name": "simplePasswordPolicy", "min_length": 8,
          "max_incorrect_attempts": 20}
DEFAULT = {"id": "PasswordPolicy", "name": "defaultPasswordPolicy", "min_length": 12, "password_strength": "Custom",
           "num_passwords_in_history": 4, "password_expires_after": 120, "max_incorrect_attempts": 5}


def _domain(policies):
    return pw.domain_record({"display_name": "Default", "lifecycle_state": "ACTIVE"}, policies)


def test_oracle_defaults_fail_cis_on_length_and_history_only():
    out = pw.summarize([_domain([STANDARD, SIMPLE, DEFAULT])], None)
    assert out["policies_evaluated"] == 1
    assert out["policies_below_cis_min_length"] == ["Default/defaultPasswordPolicy"]
    assert out["policies_below_cis_history"] == ["Default/defaultPasswordPolicy"]
    assert out["policies_exceeding_cis_expiry"] == []
    assert out["all_policies_meet_cis"] is False


def test_templates_alone_mean_no_policy_of_its_own():
    out = pw.summarize([_domain([STANDARD, SIMPLE])], None)
    assert out["domains_without_own_policy"] == 1
    assert out["all_policies_meet_cis"] is False


def test_unset_rules_fail_rather_than_pass():
    record = pw.password_policy_record({"id": "PasswordPolicy", "min_length": 16})
    assert record["meets_cis_min_length"] is True
    assert record["meets_cis_history"] is False
    assert record["meets_cis_expiry"] is False
    assert record["locks_out_after_bounded_attempts"] is False


def test_group_scoped_policy_is_reported_beside_the_default():
    scoped = {**DEFAULT, "id": "Contractors", "name": "contractorsPolicy", "priority": 1,
              "groups": [{"value": "g-123"}]}
    domain = _domain([DEFAULT, scoped])
    assert domain["default_policy"] == "defaultPasswordPolicy"
    assert domain["group_scoped_policies"] == ["contractorsPolicy"]


def test_unreadable_policies_are_not_a_compliant_domain():
    out = pw.summarize([_domain(None)], None)
    assert out["domains_with_unreadable_policies"] == 1
    assert out["domains_without_own_policy"] == 0
    assert out["all_policies_meet_cis"] is False


def test_scim_paging_follows_total_results():
    class Page:
        def __init__(self, resources, total):
            self.resources, self.total_results = resources, total

    class Client:
        calls = []

        def list_password_policies(self, start_index, count):
            self.calls.append(start_index)
            data = Page([object()] * 50, 120) if start_index < 101 else Page([object()] * 20, 120)
            return type("R", (), {"data": data})()

    client = Client()
    assert len(pw._all_password_policies(client)) == 120
    assert client.calls == [1, 51, 101]
