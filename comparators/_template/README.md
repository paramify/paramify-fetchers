# comparators/_template — scaffold (NOT BUILT)

Comparators satisfy the same contract as fetchers, but their "source" is a
directory of prior fetcher outputs rather than an external API: they declare
`depends_on: [...]` and read earlier envelopes to do cross-source
reconciliation (e.g. Okta users vs. Rippling employees).

**Status: not built.** No comparator has been ported, and the runner does not
yet honor `depends_on` (`framework/runner/dependency_graph.py`, `logger.py`,
and `retry.py` are empty stubs). This directory is a placeholder for the
eventual starter template — its `fetcher.py`, `fetcher.yaml`, and
`schemas/payload.json` are intentionally empty until the comparator execution
path lands.
