# azure_change_work_items

Checks that changes made in Azure outside a pipeline, direct edits from the
portal or the command line and ARM deployments a person ran by hand, are
recorded by an Azure DevOps work item, by matching `azure_change_provenance`
changes to `azure_devops_work_items` records.

## Inputs

| Fetcher | What this reads from it |
|---|---|
| `azure_change_provenance` | each change's origin, caller, caller type, resource, deployment and time |
| `azure_devops_work_items` | each work item's type, state, people, created and finished dates, and approval |

Both must be in the same manifest. The runner runs this after them and passes
their files in `$COMPARATOR_INPUTS`. This comparator calls no API and is given
no credentials.

## How a record is matched

Only changes whose `origin` is in `origins` are checked (`direct` and
`manual_deployment` by default; the summary breaks the counts down by origin).
Each gets one status:

| Status | When |
|---|---|
| `excluded` | Its caller is in `excluded_callers`, such as a Microsoft service that manages resources for you. |
| `application` | Its caller's type is given and isn't a user: an application or another identity. A named caller with no type is matched like a person. Reported apart, with the application id; it needs no record, since a work item can't name it. |
| `no_caller` | Azure recorded no caller, and neither a named change to the same resource within 10 minutes (the rule `azure_change_provenance` uses to give such a row its origin) nor a named change in the same deployment gives one. |
| `matched` | Exactly one record work item names the caller and covers the change's time. |
| `ambiguous` | Several do; none is picked. |
| `unmatched` | None does. |

A record work item is one of `record_types` (by default, the types
`azure_devops_work_items` selected) that isn't Removed. It names the caller when
the caller's user principal name equals the login of one of the people in
`record_people` (by default its assignee, creator or closer). It covers a change
made from `hours_before` hours before the item was created to `hours_after`
hours after it was finished. An item still open, or in a state its type no
longer defines, covers changes up to `open_item_days` days (30) after it was
created or last changed, so an item left open doesn't record every later
change. An item of one of `emergency_types`
may be filed later, up to `emergency_hours_before` hours after the change.

A matched or ambiguous change is approved when every work item that records it
is approved, as `azure_devops_work_items` reads approval (an approval state or
an approval comment); a record whose approval couldn't be read is not approved.
An approval may come after the change: such a change still counts as approved,
and `changes_approved_after_change` counts it unless the late record is one of
`emergency_types`, which are approved after the fact.

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
