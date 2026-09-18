# framework/reference

Vendored copies of external sources of truth. Nothing here is ours to author —
each file is transcribed or downloaded from an upstream authority, and the point
of committing it is that the version we built against is pinned and diffable.

The bar for landing a file here is that **code reads it**. An upstream document
we only consult by eye gets cited by URL and version instead — see the note at
the bottom on the Paramify API spec, which is the case that tested this rule.

| File | Upstream | Read by |
|---|---|---|
| `ksis.yaml` | [FedRAMP consolidated rules](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) | `api.ksi_coverage()`, `tools/gen_ksi_*.py` |

`ksis.yaml` carries its own header explaining how to re-transcribe it and which
of its fields are FedRAMP's versus our judgment. Read that before touching it.

## What is deliberately *not* here: the Paramify REST API spec

The current published spec is **Paramify REST API v0, spec version 0.9.2**, and
the uploaders are verified against it (see the review note below; they were
originally written against 0.6.0). Read it at
<https://app.paramify.com/api/documentation/> — in the app, Help (?) → API
Documentation. The machine-readable OpenAPI 3.1 document behind that page is
`https://app.paramify.com/api/v0/documentation.json`.

That spec used to be vendored here and was removed on purpose. Please don't
re-add it:

- **Nothing loads it.** It was human reference only, so the repo paid for it
  without any code depending on it.
- **It is 2.4 MB / ~54,000 lines pretty-printed** — roughly a fifth of the
  tracked repo, and the convention that made it readable (a new file per
  version, never overwritten) meant paying that again on every version bump.
- **It is public.** Unlike `ksis.yaml`, it needs no login to read, so committing
  it bought no access we didn't already have.

What actually needed pinning was the *version*, and a version is one line. Cite
it as "Paramify REST API v0 spec 0.9.2" plus the URL above, the way
[`uploaders/paramify_issues/`](../../uploaders/paramify_issues/) does, and bump
that string when the endpoints we call have been re-verified against a newer
spec — recording what changed, as the review note below does.

If you need to review what changed between two versions, diff the live document
against a saved copy in a scratch directory — outside the repo:

```bash
curl -sSfL https://app.paramify.com/api/v0/documentation.json \
  | python3 -m json.tool > /tmp/paramify_api_new.json
diff /tmp/paramify_api_old.json /tmp/paramify_api_new.json
```

## Checked against the v0.9.2 spec (2026-09-18)

Re-verified 0.6.0 → 0.9.2 by diffing the live document structurally (paths,
verbs, parameters, request bodies, response codes) rather than as text. For
every endpoint this repo actually calls — `POST /assessment/{assessmentId}/intake`,
`GET`/`POST /evidence`, `GET /evidence/{id}/artifacts`,
`POST /evidence/{id}/artifacts/upload`, `POST /evidence/{id}/associate`,
`GET`/`POST /scripts`, `PATCH /scripts/{id}`, `GET`/`POST /validators`,
`PATCH /validators/{id}`, `GET /projects`, `GET /assessment` — the request
bodies are **byte-identical in shape**: same properties, same `required` sets.
No path or verb was removed, and nothing we call is deprecated.

Two things did change:

- **`409 Conflict` is now documented on every operation**, via the new
  `components/responses/Conflict`. It is the only response-code change touching
  an endpoint we call. Our clients are inconsistent about it:
  `paramify_scripts` treats a 409 on `POST /evidence/{id}/associate` as
  already-connected and succeeds, while `paramify_validators` raises on it, so a
  re-sync of an already-associated validator is not idempotent. The
  `create_evidence_set` fallbacks also key on `400` + "already exists" only, not
  409. Tracked separately from this pin.
- **12 new paths**, none of which we call: `/pipelines/*` and `/pipeline-jobs/*`
  (the issue-report intake migration, tracked in issue #81) and `/custom-tags`
  plus `/custom-tags/{entity}/{entityId}`.

The error body is unchanged — 0.9.2 only hoisted the inline error object into
`components/schemas/ErrorResponseObject`, so `_error_message` still parses it.

The `v0.8.0` citations in [`docs/validators_design.md`](../../docs/validators_design.md)
and `framework/schemas/validator_schema.json` are left as they are on purpose:
they date empirical checks made against a live tenant on 2026-09-03, not the
spec-shape review above, and the validator endpoints did not change shape
between 0.6.0 and 0.9.2.
