"""github_dependabot_report against a fake organization (the `gh` fixture, in fetchers/github/conftest.py).

Most of what is pinned here is the shared report path (_shared/alert_report.py): open alerts only, the Asset ID
equal to the inventory's identifier, every page read, and no file at all when any read fails.
"""

from __future__ import annotations

import pytest

NAME = "dependabot_report"


def routes(gh, alerts=None, **extra):
    repos = [gh.repo("api", 101), gh.repo("docs", 202), gh.repo("legacy", 303)]
    base = f"repos/{gh.ORG}"
    return {
        **gh.org_routes(repos),
        f"{base}/api/dependabot/alerts": gh.fixture(__file__, "dependabot_alerts.json") if alerts is None else alerts,
        f"{base}/docs/dependabot/alerts": [],
        f"{base}/legacy/dependabot/alerts": (403, {"message": "Dependabot alerts are disabled for this repository."}),
        **extra,
    }


def test_one_row_per_open_alert_keyed_to_the_inventory(gh):
    r = gh.run(NAME, routes(gh))
    assert r.code == 0 and r.status is None and len(r.files) == 1
    assert r.files[0].name == "github_dependabot_report_api_github_test_acme.csv"  # the host, off github.com
    assert r.header == ["ID", "Asset ID", "Repository", "Alert Number", "State", "Created At", "Updated At",
                        "Alert URL", *r.module.COLUMNS]
    assert [row["Alert Number"] for row in r.rows] == ["2", "7"]  # the fixed alert 5 is left out
    asset = gh.inventory_asset_id(gh.repo("api", 101))
    assert asset == f"{gh.API}/repositories/101"
    assert {row["Asset ID"] for row in r.rows} == {asset}
    assert r.rows[0]["ID"] == f"{asset}/dependabot/alerts/2"
    first = r.rows[0]
    assert (first["Severity"], first["CVE ID"], first["GHSA ID"]) == ("critical", "CVE-2026-0001", "GHSA-aaaa-bbbb-cccc")
    assert (first["CVSS Score"], first["CWE IDs"], first["Package"]) == ("9.8", "CWE-89", "django")
    assert first["Description"] == "A synthetic advisory description.\nSecond line."
    second = r.rows[1]
    assert (second["CVSS Score"], second["First Patched Version"], second["EPSS Percentage"]) == ("4.2", "", "")
    assert r.leftovers == []


def test_only_open_alerts_are_asked_for(gh):
    r = gh.run(NAME, routes(gh))
    asked = [q for path, q in r.calls if path.endswith("/dependabot/alerts")]
    assert asked and all(q["state"] == "open" for q in asked)


def test_a_cell_a_spreadsheet_would_run_is_quoted_as_text(gh):
    r = gh.run(NAME, routes(gh))
    assert r.rows[1]["Title"].startswith("'=HYPERLINK(")
    assert r.rows[1]["Description"] == "'-1 starts with a minus sign."
    assert r.rows[1]["Asset ID"].startswith("https://")  # identifiers are never changed


def test_every_page_is_read(gh):
    many = [{"number": n, "state": "open", "security_vulnerability": {"severity": "low"}} for n in range(1, 251)]
    r = gh.run(NAME, routes(gh, alerts=many))
    assert r.code == 0 and len(r.rows) == 250


def test_a_repository_with_alerts_off_adds_no_rows_and_is_not_a_failure(gh):
    r = gh.run(NAME, routes(gh))
    assert r.code == 0
    assert all(row["Repository"] != "acme/legacy" for row in r.rows)


@pytest.mark.parametrize("failure", [
    (403, {"message": "Resource not accessible by personal access token"}),  # the token, not the feature
    (404, {"message": "Not Found"}),
    (502, {"message": "Server Error"}),
])
def test_a_failed_repository_writes_no_report(gh, failure):
    r = gh.run(NAME, routes(gh, **{f"repos/{gh.ORG}/docs/dependabot/alerts": failure}))
    assert r.code == 1 and r.files == [] and r.leftovers == []
    assert "no report written" in r.status["error"]


def test_a_failed_second_page_writes_no_report(gh):
    pages = [{"number": n, "state": "open"} for n in range(1, 151)]

    def paged(query):
        if query.get("page") == "2":
            return 500, {"message": "Server Error"}
        return 200, pages[:100], {"Link": f'<{gh.API}/repos/{gh.ORG}/api/dependabot/alerts?state=open&page=2>; rel="next"'}
    r = gh.run(NAME, routes(gh, **{f"repos/{gh.ORG}/api/dependabot/alerts": paged}))
    assert r.code == 1 and r.files == []


def test_a_token_that_sees_fewer_repositories_than_the_org_has_writes_no_report(gh):
    rs = routes(gh)
    rs[f"orgs/{gh.ORG}"] = {**rs[f"orgs/{gh.ORG}"], "total_private_repos": 4}
    r = gh.run(NAME, rs)
    assert r.code == 1 and r.files == [] and r.status["code"] == "partial_failure"


def test_no_open_alerts_fails_unless_allowed(gh):
    empty = routes(gh, alerts=[])
    r = gh.run(NAME, empty)
    assert r.code == 1 and r.files == [] and r.status["code"] == "bad_config"
    r = gh.run(NAME, empty, GITHUB_REPORT_ALLOW_EMPTY="true")
    assert r.code == 0 and r.rows == [] and r.header[0] == "ID"


def test_bad_target_config_fails_before_any_call(gh):
    r = gh.run(NAME, routes(gh), GITHUB_REPOSITORIES="api", GITHUB_EXCLUDE_REPOSITORIES="docs")
    assert r.code == 1 and r.calls == [] and r.status["code"] == "bad_config"
