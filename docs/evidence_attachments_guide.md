# Original files accompanying evidence

An evidence fetcher can retain original downloadable files beside its normal
JSON record. Enable this explicitly in fetcher.yaml:

```yaml
output:
  type: json
  path: example_<target>.json
  attachments: true
```

Write the usual raw evidence dict with an attachments array:

```json
{
  "attachments": [
    {
      "path": "_attachments/target-identity/digest.json",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "bytes": 123
    }
  ]
}
```

The example hash and size are placeholders. Each descriptor must match the
actual file. Paths are relative to EVIDENCE_DIR, below _attachments/<scope>/.
Use a target-specific scope; never overwrite another target's originals.
Original files are not top-level evidence outputs and are never enveloped.

The runner copies descriptors to metadata.attachments only for opted-in
fetchers. Without the option, an attachments property is ordinary payload
data. This contract applies to JSON evidence fetchers, not inventory or
issue-report fetchers. A parsing pipeline on the evidence entry is refused.

Native evidence delivery discovers originals through the envelope, not by
globbing arbitrary files. It verifies paths, regular-file type, length and
SHA256, rejects symlinks, hardlinks, traversal, duplicate paths or basenames and missing or
changed files, and sends verified bytes without JSON parsing or rewriting.
Artifact names combine the parent evidence filename and companion basename
to avoid collisions. Descriptors remain in the uploaded record for traceability.
No absolute local paths are added to the uploaded evidence record.

An invalid descriptor or unavailable companion refuses the whole manifest
entry during planning. Originals are rechecked before delivery and when read;
changed or remotely refused originals hold delivery rather than submitting an
incomplete batch. Investigate permanent refusals before retrying.
The native direct/batch routes, channel resolution, retry rules and run-based
deduplication remain responsible for publication. artifact_payload: payload
affects the parent record only; originals stay byte-identical in either mode.

This is an artifact retention contract, not an intake parser or acceptance
mechanism. Upload, original-byte readback, processing and hosted limits must be
qualified separately. The current native client buffers file bytes in memory;
this option does not add streaming upload or remove existing readback guards.

See the [CAT package example](../examples/uds_cat_package_evidence.yaml) and
[fetcher](../fetchers/uds_cat/package_evidence/README.md).
