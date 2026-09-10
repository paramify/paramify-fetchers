# Traffic metrics

GitHub keeps repository traffic for **14 days**. Ask the API today and you get
the last fortnight; anything older is gone, and no amount of asking later brings
it back. There is no setting for this and no paid tier that changes it.

So the only way to have a year of traffic history is to have been writing it
down all along. [`.github/workflows/traffic.yml`](../.github/workflows/traffic.yml)
runs [`tools/traffic_snapshot.py`](../tools/traffic_snapshot.py) once a day and
merges each reading into dated CSVs on the orphan **`metrics`** branch.

## Reading the history

```bash
git worktree add .metrics metrics          # once
python3 tools/traffic_snapshot.py report --data .metrics
```

```
GitHub traffic — 2026-08-26 to 2026-09-08  (14 days, 14 recorded)

       991 views         209 unique-days
       803 clones        154 unique-days

  Month      Views   Uniq-d    Clones   Uniq-d   Days
  ----------------------------------------------------
  2026-08      396       83       106       46     6
  2026-09      595      126       697      108     8

  Last 14 recorded days
    views   ▂▅▅▁▁▄█▂▄▂▁▁▂▅
    clones  ▁▂▁▁▁▁▄█▃▂▁▃▁▁
```

`--since YYYY-MM-DD` narrows the window; `--json` emits the whole rollup for
piping somewhere else. Refresh the worktree with `git -C .metrics pull` — the
daily commits land on the remote, not in your checkout.

## What the numbers mean

**Views and clones are a daily series.** Each day is stored once, keyed by date.
Totals across any span are exact sums.

**"Unique-days" are not people.** GitHub dedupes visitors within a day, never
across days. One person cloning on ten days is ten uniques. Summed uniques are
an upper bound on distinct humans and nothing more precise than that — the
report labels the column `Uniq-d` rather than `Uniques` for exactly this reason.
There is no way to recover a true monthly unique count; GitHub does not expose
one.

**Referrers and paths are not a series at all.** Each is a rolling 14-day
*total* as of the moment you asked, with no per-day breakdown available. They
cannot be summed across snapshots without counting the same visit up to
fourteen times, so they are stored as dated observations and the report shows
the latest one. Treat them as "where traffic is coming from lately", not as
history.

**The current day is partial.** The snapshot runs at 06:17 UTC, so today's row
covers a few hours. Tomorrow's run overwrites it with the complete day, so this
heals itself; the report flags a still-partial day when it sees one.

**Counts get revised.** GitHub adjusts numbers after the fact (spam filtering,
late aggregation), so a day the API still reports wins over what we stored. Once
a day ages past 14 days it is frozen at its last observed value.

## Setup

The workflow needs one secret. The traffic endpoints require the
**Administration: read** permission, and `administration` is not a key the
workflow `permissions:` block accepts — which means `GITHUB_TOKEN` cannot read
them at any configuration. It has to be a PAT.

1. Create a [fine-grained PAT](https://github.com/settings/personal-access-tokens/new)
   scoped to `paramify/paramify-fetchers`, with **Repository permissions →
   Administration: Read-only**. That is the only permission it needs; pushing to
   `metrics` rides on the workflow's own `GITHUB_TOKEN`.
2. Save it as the repository secret **`TRAFFIC_TOKEN`**.
3. Set an expiry reminder. When the PAT expires the workflow fails loudly, but
   nobody watches a green cron — and 14 days after it stops, data starts being
   lost for good.

## Missing a run is fine

The 14-day retention is also the safety margin: any run still sees every day the
previous one saw. A missed day backfills on the next run, and it takes **14
consecutive failures** to lose anything. That is why the workflow is a plain
daily cron with no retries — the redundancy is already in the data.

Two ways it can quietly stop:

- **GitHub disables scheduled workflows after 60 days of repo inactivity.** Not
  a risk while the repo is busy, but it is silent when it happens.
- **Scheduled runs get dropped under load.** GitHub does not queue them
  forever. Harmless here for the reason above.

Either way the report prints a gap warning:

```
  ⚠ gaps — the snapshot did not run for >14 days; this traffic is gone:
    2026-08-02 .. 2026-09-08
```

Gaps are permanent. If you see one, the fix is to get the workflow running
again, not to backfill — there is nothing to backfill from.

## Why an orphan branch

The data has to be committed somewhere: Actions artifacts expire and caches get
evicted, so neither can hold a multi-year series. Committing to `main` would
mean a bot commit a day — roughly 365 a year — sitting at the top of a public
repo's front page. The `metrics` branch shares no history with `main` and
contains no code, so it costs the main history nothing.

Adding another repo is a matter of `--repo owner/name`; the store layout is
per-directory, so give each one its own `--data` directory.

## Files

| File | Shape | Key |
|---|---|---|
| `views.csv` | daily series | `date` |
| `clones.csv` | daily series | `date` |
| `referrers.csv` | rolling 14-day totals | `observed` |
| `paths.csv` | rolling 14-day totals | `observed` |
| `repo.csv` | point-in-time counters | `date` |

`observed` records the day a row was last confirmed by the API — the difference
between "GitHub said this today" and "this is what we saw before it aged out".
