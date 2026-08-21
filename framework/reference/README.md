# framework/reference

Vendored copies of external sources of truth. Nothing here is ours to author —
each file is transcribed or downloaded from an upstream authority, and the point
of committing it is that the version we built against is pinned and diffable.

| File | Upstream | Read by |
|---|---|---|
| `ksis.yaml` | [FedRAMP consolidated rules](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) | `api.ksi_coverage()`, `tools/gen_ksi_*.py` |
| `paramify_api_0.6.0.json` | `https://app.paramify.com/api/v0/documentation.json` | nobody at runtime — human reference |

`ksis.yaml` carries its own header explaining how to re-transcribe it and which
of its fields are FedRAMP's versus our judgment. Read that before touching it.

## `paramify_api_<version>.json`

The Paramify REST API OpenAPI 3.1 spec. **No code loads this** — it is the
contract the uploaders were written against, committed so that "which spec did
this behavior come from" has an answer inside the repo instead of requiring a
login. [`uploaders/paramify_issues/`](../../uploaders/paramify_issues/) cites it
by path.

Refresh by downloading a newer spec **alongside** the existing one rather than
over it:

```bash
curl -sSfL https://app.paramify.com/api/v0/documentation.json \
  -o framework/reference/paramify_api_<new-version>.json
```

In the app the same file is reachable via Help (?) → API Documentation, then the
`/api/v0/documentation.json` link.

Two conventions worth keeping:

- **Version in the filename, new file per version.** Overwriting in place gives
  you a 50,000-line diff of everything that moved in the spec *and* everything
  that moved in the formatting, which is unreadable. A new file beside the old
  one makes `git diff --no-index` between the two the upgrade review, and lets a
  bug report against an older release still point at the spec it shipped with.
- **Pretty-printed, not minified.** It roughly doubles the file size and is the
  only reason the diff above is legible.

Once a version is no longer cited by anything, delete it — this directory pins
what we build against, not a changelog.
