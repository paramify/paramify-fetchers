# <fetcher_name>

<One sentence: which claim this checks, and which two fetchers' evidence it matches.>

## Inputs

| Fetcher | What this reads from it |
|---|---|
| `<input_fetcher_a>` | <the records being checked> |
| `<input_fetcher_b>` | <the records they are matched to> |

Both must be in the same manifest. The runner runs this after them and passes
their files in `$COMPARATOR_INPUTS`. This comparator calls no API and is given
no credentials.

## How a record is matched

<The join key, any time window, and what each verdict means.>

## Output

Writes `<category>_<short_name>.json` to `EVIDENCE_DIR`: `results` holds one
verdict per record, and `summary` counts them and carries `inputs_complete`. If
an input is missing, every summary value is `null`. If an input failed or is
partial, the comparison still runs, and the comparator exits 1 with
`input_failed`. If the comparison itself raises, the file is still written with
every summary value `null`, and the comparator exits 1 with `internal_error`.

See [`docs/comparators_guide.md`](../../docs/comparators_guide.md).
