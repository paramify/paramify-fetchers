"""github_code_scanning_report against a fake organization (the `gh` fixture, in fetchers/github/conftest.py).

The shared report path is pinned in dependabot_report/tests; this pins the code scanning columns, the feature
states that are not failures, and the failure path.
"""

from __future__ import annotations

import pytest

NAME = "code_scanning_report"
GHAS_OFF = (403, {"message": "Advanced Security must be enabled for this repository to use code scanning."})


def routes(gh, **extra):
    repos = [gh.repo("api", 101), gh.repo("never", 202), gh.repo("ghas-off", 303), gh.repo("clean", 404)]
    base = f"repos/{gh.ORG}"
    return {
        **gh.org_routes(repos),
        f"{base}/api/code-scanning/alerts": gh.fixture(__file__, "code_scanning_alerts.json"),
        f"{base}/never/code-scanning/alerts": (404, {"message": "no analysis found"}),
        f"{base}/ghas-off/code-scanning/alerts": GHAS_OFF,
        f"{base}/clean/code-scanning/alerts": [],
        **extra,
    }


def test_one_row_per_open_alert_keyed_to_the_inventory(gh):
    r = gh.run(NAME, routes(gh))
    assert r.code == 0 and r.status is None
    assert r.files[0].name.startswith("github_code_scanning_report_")
    assert r.header[8:] == r.module.COLUMNS
    assert [row["Alert Number"] for row in r.rows] == ["4", "9"]  # the dismissed alert 3 is left out
    asset = gh.inventory_asset_id(gh.repo("api", 101))
    assert {row["Asset ID"] for row in r.rows} == {asset}
    assert r.rows[0]["ID"] == f"{asset}/code-scanning/alerts/4"
    security = r.rows[0]
    assert (security["Title"], security["Severity"], security["Rule Severity"]) == (
        "SQL query built from user-controlled sources", "high", "error")
    assert (security["Rule ID"], security["Rule Tags"]) == ("py/sql-injection", "security, external/cwe/cwe-089")
    assert (security["Tool"], security["Tool Version"], security["Path"], security["Start Line"]) == (
        "CodeQL", "2.19.0", "app/db.py", "42")
    assert security["Commit SHA"] == "0123456789abcdef0123456789abcdef01234567"
    quality = r.rows[1]
    assert (quality["Severity"], quality["Rule Severity"]) == ("note", "note")  # no security severity


def test_only_open_alerts_are_asked_for(gh):
    r = gh.run(NAME, routes(gh))
    asked = [q for path, q in r.calls if path.endswith("/code-scanning/alerts")]
    assert len(asked) == 4 and all(q["state"] == "open" for q in asked)


def test_no_analysis_and_advanced_security_off_add_no_rows_and_are_not_failures(gh):
    r = gh.run(NAME, routes(gh))
    assert r.code == 0
    assert {row["Repository"] for row in r.rows} == {"acme/api"}


@pytest.mark.parametrize("failure", [
    (403, {"message": "Resource not accessible by integration"}, {"X-Accepted-GitHub-Permissions": "security_events=read"}),
    (500, {"message": "Server Error"}),
])
def test_a_failed_repository_writes_no_report(gh, failure):
    r = gh.run(NAME, routes(gh, **{f"repos/{gh.ORG}/clean/code-scanning/alerts": failure}))
    assert r.code == 1 and r.files == [] and r.leftovers == []
    assert "no report written" in r.status["error"]


def test_a_failure_names_the_permission_it_needs(gh):
    denied = (403, {"message": "Resource not accessible by integration"},
              {"X-Accepted-GitHub-Permissions": "security_events=read"})
    r = gh.run(NAME, routes(gh, **{f"repos/{gh.ORG}/api/code-scanning/alerts": denied}))
    assert r.code == 1 and r.status["code"] == "not_authorized" and "security_events=read" in r.status["error"]
