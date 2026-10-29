# azure_change_work_items

Checks that changes made directly in Azure, from the portal or the command line
rather than a deployment, are recorded by an Azure DevOps work item, by matching
`azure_change_provenance` changes to `azure_devops_work_items` records.

## Inputs

| Fetcher | What this reads from it |
|---|---|
| `azure_change_provenance` | each change's origin, caller, caller type, resource and time |
| `azure_devops_work_items` | each work item's type, state, people, created and finished dates, and approval |

Both must be in the same manifest. The runner runs this after them and passes
their files in `$COMPARATOR_INPUTS`. This comparator calls no API and is given
no credentials.

## How a record is matched

Only changes whose `origin` is in `origins` are checked (`direct` by default).
Each gets one status:

| Status | When |
|---|---|
| `excluded` | Its caller is in `excluded_callers`. |
| `no_caller` | Azure recorded no caller, and no named change to the same resource is within 10 minutes to take one from (the rule `azure_change_provenance` uses to give such a row its origin). |
| `not_a_person` | Its caller is an application or another identity that isn't a user. |
| `matched` | Exactly one record work item names the caller and covers the change's time. |
| `ambiguous` | Several do; none is picked. |
| `unmatched` | None does. |

A record work item is one of `record_types` (by default, the types
`azure_devops_work_items` selected) that isn't Removed. It names the caller when
the caller's user principal name equals the login of one of the people in
`record_people`. It covers a change made from `hours_before` hours before the
item was created to `hours_after` hours after it was finished; an item still
open, or in a state its type no longer defines, covers every later change.

A matched or ambiguous change is approved when every work item that records it
is approved, as `azure_devops_work_items` reads approval (an approval state or
an approval comment).

`work_items_cover_changes` is false when a work items file's collection window
starts too late to hold every record a change could have: its start plus
`hours_after` is after the earliest change needing a record. Widen that
fetcher's `lookback_days` if so.

## Output

Writes `azure_change_work_items.json` to `EVIDENCE_DIR`: `results` holds one
verdict per checked change, naming the work items that record it, and `summary`
counts each status and carries `inputs_complete`. If an input is missing, every
summary value is `null`. If an input failed or is partial, the comparison still
runs, and the comparator exits 1 with `input_failed`. If the comparison itself
raises, the file is still written with every summary value `null`, and the
comparator exits 1 with `internal_error`. A bad setting exits 1 with
`bad_config` before anything is read.

See [`docs/comparators_guide.md`](../../../docs/comparators_guide.md).
