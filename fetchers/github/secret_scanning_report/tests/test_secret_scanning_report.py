"""github_secret_scanning_report against a fake organization (the `gh` fixture, in fetchers/github/conftest.py).

The fixtures carry a `secret` value on every alert, as GitHub would if hide_secret were ignored: no part of any
secret may reach the report or any file the run leaves behind.
"""

from __future__ import annotations

import pytest

NAME = "secret_scanning_report"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIISYNTHETICkeyMATERIAL\n-----END RSA PRIVATE KEY-----"
GENERIC = {"number": 11, "state": "open", "created_at": "2026-10-07T10:00:00Z", "secret_type": "rsa_private_key",
           "secret_type_display_name": "RSA Private Key", "secret": PRIVATE_KEY, "validity": "unknown",
           "first_location_detected": {"path": "deploy/id_rsa", "start_line": 1}}


def alerts(gh):
    provider = gh.fixture(__file__, "secret_scanning_alerts.json")
    # GitHub returns provider patterns unless secret_type names the generic ones.
    return lambda query: [GENERIC] if "rsa_private_key" in query.get("secret_type", "") else provider


def routes(gh, **extra):
    repos = [gh.repo("api", 101), gh.repo("off", 202), gh.repo("clean", 303)]
    base = f"repos/{gh.ORG}"
    return {
        **gh.org_routes(repos),
        f"{base}/api/secret-scanning/alerts": alerts(gh),
        f"{base}/off/secret-scanning/alerts": (404, {"message": "Secret scanning is disabled on this repository."}),
        f"{base}/clean/secret-scanning/alerts": [],
        **extra,
    }


def secrets(gh):
    every = gh.fixture(__file__, "secret_scanning_alerts.json") + [GENERIC]
    return [a["secret"] for a in every]


def test_one_row_per_open_alert_keyed_to_the_inventory(gh):
    r = gh.run(NAME, routes(gh))
    assert r.code == 0 and r.status is None
    assert r.header[8:] == r.module.COLUMNS
    assert [row["Alert Number"] for row in r.rows] == ["11", "3", "8"]  # sorted by ID; resolved alert 1 left out
    asset = gh.inventory_asset_id(gh.repo("api", 101))
    assert {row["Asset ID"] for row in r.rows} == {asset}
    by = {row["Alert Number"]: row for row in r.rows}
    assert by["3"]["ID"] == f"{asset}/secret-scanning/alerts/3"
    assert (by["3"]["Title"], by["3"]["Secret Type"], by["3"]["Validity"]) == (
        "GitHub Personal Access Token", "github_personal_access_token", "active")
    assert (by["3"]["Location Path"], by["3"]["Location Line"], by["3"]["Has More Locations"]) == (
        "config/settings.py", "12", "True")
    assert by["3"]["Push Protection Bypassed"] == "True" and by["8"]["Push Protection Bypassed"] == "False"
    assert (by["8"]["Location Path"], by["8"]["Publicly Leaked"]) == ("", "True")  # found in an issue, no path
    assert by["11"]["Secret Type"] == "rsa_private_key"  # the generic types are asked for too


def test_the_secret_never_reaches_the_report(gh, tmp_path):
    r = gh.run(NAME, routes(gh))
    assert r.code == 0 and r.rows
    written = "".join(p.read_text() for p in tmp_path.rglob("*") if p.is_file())
    for secret in secrets(gh):
        for part in [secret] + [line for line in secret.splitlines() if len(line) > 8] + [secret[:12], secret[-12:]]:
            assert part not in written
    assert not any("secret" == column.lower() for column in r.header)


def test_every_alert_read_asks_github_to_hide_the_secret(gh):
    r = gh.run(NAME, routes(gh))
    asked = [q for path, q in r.calls if path.endswith("/secret-scanning/alerts")]
    assert asked and all(q["hide_secret"] == "true" and q["state"] == "open" for q in asked)
    assert any("rsa_private_key" in q.get("secret_type", "") for q in asked)


def test_a_row_copies_only_the_fields_it_names():
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path
    spec = spec_from_file_location("ssr_row_test", Path(__file__).resolve().parents[1] / "fetcher.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    leaky = {"secret": "LEAK", "first_location_detected": {"path": "p", "secret": "LEAK", "text": "LEAK"},
             **{field: "LEAK" for field in ("secret_value", "raw", "snippet")}}
    assert "LEAK" not in repr(module.row(leaky))


def test_a_repository_with_secret_scanning_off_adds_no_rows_and_is_not_a_failure(gh):
    r = gh.run(NAME, routes(gh))
    assert r.code == 0 and {row["Repository"] for row in r.rows} == {"acme/api"}


@pytest.mark.parametrize("failure", [
    (403, {"message": "Resource not accessible by personal access token"}),
    (404, {"message": "Not Found"}),
    (503, {"message": "Service Unavailable"}),
])
def test_a_failed_repository_writes_no_report(gh, failure):
    r = gh.run(NAME, routes(gh, **{f"repos/{gh.ORG}/clean/secret-scanning/alerts": failure}))
    assert r.code == 1 and r.files == [] and r.leftovers == []
    assert "no report written" in r.status["error"]


def test_a_failed_generic_walk_writes_no_report(gh):
    provider = gh.fixture(__file__, "secret_scanning_alerts.json")

    def generic_fails(query):
        return (502, {"message": "Bad Gateway"}) if query.get("secret_type") else provider
    r = gh.run(NAME, routes(gh, **{f"repos/{gh.ORG}/api/secret-scanning/alerts": generic_fails}))
    assert r.code == 1 and r.files == []


def test_the_writer_refuses_a_column_outside_the_table(gh, tmp_path):
    import sys
    gh.run(NAME, routes(gh))  # loads _lib/report_csv the way the fetcher does
    dest = tmp_path / "out" / "report.csv"
    with pytest.raises(ValueError):
        sys.modules["report_csv"].write_csv(dest, ["Title"], [{"Title": "t", "Secret": "LEAK"}])
    assert not dest.exists() and not any(p.name.endswith(".tmp") for p in tmp_path.iterdir())
