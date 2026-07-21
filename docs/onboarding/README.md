# Onboarding tutorial

A hands-on guided tour of this codebase for new developers, generated with
[Lathe](https://github.com/devenjarvis/lathe) and verified live against the
working tree. Part 1 traces one fetcher (`rippling_current_employees`) from its
`fetcher.yaml` through the runner to the evidence envelope — runnable end to
end with fake credentials, so you need no API tokens to follow along.

You can read it right here on GitHub:
[`paramify-fetchers-onboarding/part-01.md`](paramify-fetchers-onboarding/part-01.md)
— everything renders except Lathe's custom callouts, which show as plain
blockquotes.

## Serving it locally (recommended)

With the `lathe` CLI installed, store the tutorial once and serve it — you get
styled callouts, version chips, and the Verify / Add-a-part / Ask buttons that
hand you Claude Code commands:

```bash
# from the repo root
lathe store docs/onboarding/paramify-fetchers-onboarding \
  --tag python --tag compliance --tag cli --tag onboarding --tag architecture \
  --repo https://github.com/paramify/paramify-fetchers.git \
  --repo-branch main \
  --tool python:3.14.5 --tool typer:0.26.7 --tool requests:2.34.2 \
  --source https://github.com/paramify/paramify-fetchers \
  --voice plainspoken \
  --model "claude-opus-4-8"

lathe serve   # opens http://localhost:4242
```

The flags matter: `lathe store` does not read metadata from the directory, so
tags, repo grouping, and toolchain version chips come from the command line.
The directory name becomes the tutorial's slug (`paramify-fetchers-onboarding`),
which keeps `/lathe-extend` and `/lathe-verify` commands consistent across the
team.

## Verifying or extending

In a Claude Code session inside this repo:

```bash
/lathe-verify paramify-fetchers-onboarding    # follow the tutorial end to end in a scratch dir
/lathe-extend paramify-fetchers-onboarding    # write Part 2 (e.g. "author a new fetcher from _template")
```

If you extend the tutorial, commit the new `part-NN.md` from
`~/.lathe/tutorials/paramify-fetchers-onboarding/` back into this directory so
the next clone gets it.
