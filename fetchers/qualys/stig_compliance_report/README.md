# qualys_stig_compliance_report

Every evaluated posture for one Qualys STIG policy, joined with host, control,
technology, and policy metadata. See [platform setup](../REPORTS.md) and
[example manifest](../../../examples/qualys_reports.yaml).

Output: `qualys_stig_compliance_report_<policy_id>.csv`. Each target has a unique
filename. This is a CONFIGURATION issue report with its own CSV intake mapping.

## CSV mapping

| Columns | Meaning / proposed intake mapping |
| --- | --- |
| Record ID | Unique record ID: SHA-256 of the JSON tuple `(API origin, "stig", policy ID, host ID, control ID, technology ID, instance, STIG ID)`. Stable across result/title changes. |
| Policy ID, Policy Title | Selected policy; one target per policy. |
| Posture ID | Source posture identifier retained for tracing. |
| Host ID, Asset ID, Host Name, IP, Operating System | Stable source asset IDs plus display context. |
| Control ID, Control Title | Qualys control ID and statement. |
| STIG ID | A supplied `V-…` vulnerability ID, or a supplied `SV-…`/`SRG-…` rule reference when no V-ID exists. Never infer a V-ID from a Qualys CID or rule number. |
| Control References | Complete original Qualys reference text. |
| Technology ID, Technology, Instance | Retains separate evaluations of the same control on different technology instances. |
| Result, Previous Result | Source values, including Passed, Failed, Error, and Passed*. Only ordinary Passed should count as an unqualified pass. Passed* may accompany an approved exception; preserve that distinction in intake. |
| Qualys Criticality, Qualys Criticality Value | Source label/value. These are not invented DISA CAT I/II/III values; configure the mapping explicitly. |
| Remediation | Source remediation text; map to Recommendation. Blank when the source omits it. |
| Evaluated At, Modified At | Source evaluation and posture modification timestamps. |
| First Failed, Last Failed, First Passed, Last Passed | Source history, including source `N/A` values. |
| Resolved At | Map to Date Closed. Contains Evaluated At only for ordinary Passed; otherwise blank, including Passed*, Failed, and Error. A Passed posture without a valid evaluation date fails collection. Historical pass dates must not close a currently failing check. |
| Last Compliance Scan | Source host scan timestamp, when present. |
| Exception Status, Exception Expires | Exception context, distinct from the check result. An approved exception does not turn Failed into Passed. |

A control mapping to several V-IDs produces one row per V-ID. When there are no
V-IDs, it produces one row per supplied SV/SRG reference. Duplicate references
within the same control do not duplicate rows. A control without a recognized
STIG reference fails collection, rather than silently disappearing from a report.

Source error results stay in the report. Unscanned assets and unevaluated checks
may be absent from the API; absence does not establish a pass. This fetcher does
not claim a policy's asset assignment proves scan coverage.

## Intake validation

Use Record ID as unique record identity and Host ID as the stable asset key
within one tenant. Map STIG ID to the appropriate rule/control field. Verify
multiple technologies/instances and policies do not overwrite one another.

Test Failed → Passed and Failed → Error transitions. The second must not mark
the issue remediated. Keep approved exceptions visible under your assessment's
exception policy; do not map Exception Status as Result.

Keep `close_cycle: never` during setup. Only use automatic closure after every
policy feeding that assessment is represented and server-side result mappings
have been validated.

See the [observed intake limitations](../REPORTS.md#api-compatibility-and-verification):
ordinary Passed closed the existing issue and Error/Passed* stayed open, but
repeating an already-Passed row created another closed issue. Resolve this intake
behavior before scheduling production uploads; `close_cycle: never` alone does
not prevent it.
