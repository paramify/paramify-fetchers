# Paramify FedRAMP VER Report Fetchers

Unlike most categories (which pull evidence *from* a third-party system into
Paramify), these fetchers read *from* Paramify's own REST API and generate the
FedRAMP Consolidated Rules 2026 vulnerability-reporting artifacts:

| Fetcher | Report | Evidence set |
|---|---|---|
| `paramify_accepted_vulnerabilities`      | VER-RPT-AVI | `EVD-PARAMIFY-VER-RPT-AVI` |
| `paramify_vulnerability_detail_report`   | VER-RPT-VDT | `EVD-PARAMIFY-VER-RPT-VDT` |
| `paramify_historical_ver_activity`       | VER-TFR-MRH | `EVD-PARAMIFY-VER-TFR-MRH` |

AVI and VDT are exact partition complements: every project issue is reported in
exactly one of them (accepted vs. not-accepted). MRH is a point-in-time snapshot
carrying both partitions in one document. All three share a single definition of
"accepted" and one issue-fetch/mapping implementation in
[`_shared/ver_common.py`](_shared/ver_common.py), so the reports cannot drift
apart.

## Credentials

A Paramify REST API Bearer token with **read** scope on the target project's
issues and deviations.

| Env var | Required | Purpose |
|---|---|---|
| `PARAMIFY_PROJECT_ID` | yes | Project UUID to scope the report. |
| `PARAMIFY_CERT_PACKAGE_URI` | yes | Certification Package Overview URI written into each report. |
| `PARAMIFY_REPORT_FROM` | yes | ISO start of the report period. |
| `PARAMIFY_REPORT_TO` | no | ISO end; defaults to run time. |
| `PARAMIFY_API_BASE_URL` | no | Defaults to `https://app.paramify.com/api/v0`. Point at stage for testing. |
| `PARAMIFY_HTTP_TIMEOUT` | no | Per-request timeout (seconds). Default 300 — the unfiltered `/issues` call is large. |

## Notes

- **Coverage:** the fetchers keep every OPEN issue regardless of when its status
  last changed, plus anything whose status changed inside the report window.
  This avoids silently dropping open issues with a missing/epoch `statusDate`.
- **Epoch sentinel:** issues with a missing or pre-2000 (`1970-…`)
  `evaluationDate` are treated as never-evaluated — they are not time-accepted
  (the VER-TFR-MAV 192-day clock never started) and are surfaced in a
  VER-TFR-EVU warning to stderr.
- **`_summary`:** each report carries a top-level `_summary` object (count
  breakdowns computed from the report's own arrays). It is a vendor extension —
  the FedRAMP report arrays remain the source of truth.
- **Milestones** are read from the `milestones` array embedded in the `/issues`
  response; there are no per-issue milestone calls.
