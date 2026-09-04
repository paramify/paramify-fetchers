# Behaviour cases

Each file here pins what a validator (or a whole evidence set) must return for a
given artifact. `tests/test_validator_behavior.py` runs them through the real
ECMAScript evaluator, so "prove it fails too" is a gate rather than an
instruction nobody can check.

`_cases` is `_`-prefixed, so validator discovery skips it.

**Two kinds of file.** Give one of:

- `validator: <key>` — evaluates that validator alone.
- `evidence_set: <REFERENCE-ID>` — collects every validator naming that set and
  combines their verdicts the way Paramify does (ERROR > FAIL > PASS). This is
  the only way to prove an `integrity` validator actually covers its partner,
  because the partner passes the drifted artifact on its own.

**Verdicts are asserted under `api-today`** — dispositions discarded, every rule
a pass-requirement — because that is what a live tenant does. Override with
`mode: as-designed` on a file when you want to pin the intended semantics too.

Write at least three cases for anything you author: one compliant, one
non-compliant, and one **unreadable** (the key renamed upstream, envelope
intact). The third is the one that catches silent false passes and the one that
gets skipped.

Artifacts are inline and synthetic. Keep them minimal — just the keys the regex
touches, plus the envelope. Never paste real tenant evidence: it carries account
ids and resource names, and `evidence/` is gitignored for that reason.
