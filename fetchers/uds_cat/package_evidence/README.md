# CAT package evidence

Collects all retained evidence reachable from the explicitly selected CAT
attestation roots, rather than selecting one scanner. The output is a package
evidence record plus original downloadable files. This is a draft community
fetcher, with real-package qualification still required.

It retains customer and CAT attestations, SBOMs, SARIF and other scanner
reports, policy-evaluation bundles and unknown stored formats. Failed policy
results and unsupported scan outcomes are preserved. Reports are not converted
or interpreted as accepted findings.

## Configure and run

Use the [example manifest](../../../examples/uds_cat_package_evidence.yaml).
All example values are synthetic. Replace them with the intended source and
trusted content digests. The existing token belongs in the runner environment;
the manifest uses the native `${env:CAT_API_TOKEN}` reference.

```bash
paramify describe uds_cat_package_evidence
paramify validate examples/uds_cat_package_evidence.yaml
paramify run examples/uds_cat_package_evidence.yaml
```

| Input | Meaning |
|---|---|
| url | CAT HTTPS origin; paths, embedded credentials, queries and fragments are refused |
| ca_bundle | Optional PEM trust bundle for a private CA; TLS verification stays enabled |
| api_token | Existing credential with read access to this organization's artifacts |
| organization | One exact CAT organization |
| package_ref | Configured package/version/architecture label, not an assertion derived from source |
| attestation_digests | JSON array of trusted SHA256 content digests for all selected run roots |
| subject_digest | SHA256 statement subject or image/package material digest reachable from every root |
| expected_materials | JSON array of exact material names expected for this selection; default empty means not evaluated |
| max_object_bytes | Per-original transfer guard; default 200 MiB |
| max_total_bytes | Total transfer budget per target, including failed transfers; default 1 GiB |
| max_objects | Maximum unique retained originals per target; default 1,000 |

Targets fan out independently. Include the exact run's roots and expected
population; do not substitute a latest run for the run whose evidence is under
review. The fetcher does not infer package identity from a label, discover all
runs, or establish that every required scan ran. Each root must bind the
requested subject through its statement graph; that relationship alone does
not establish which image each individual report scanned.

Use independently trusted roots. A matching content hash verifies integrity
relative to those inputs. It does not verify a signer, issuer, certificate,
timestamp or trust policy. DSSE/Sigstore-wrapped and bare supported in-toto
statements are retained; unsigned statements and unverified signature
containers are explicitly distinguished. Signature verification is always
reported as not_performed in this draft.

## Source reads

The only source request is:

```text
GET /api/v1/artifacts/{organization}/{sha256-content-digest}
```

All downloads stay on the configured origin and organization. Redirects,
encoded transfer bodies, digest mismatches, malformed content lengths and
ambiguous JSON aliases are refused. The HTTP session ignores ambient .netrc,
proxy and requests settings. Credentials and transport exception details are
not included in collection error messages.

The draft follows the CAT artifact download route at source
[c818067a](https://github.com/defenseunicorns-udm/cat/blob/c818067a09c226688acf9ac5988487b8b50d5934/app/internal/server/download_handlers.go)
and the [Chainloop v0.2 renderer](https://github.com/chainloop-dev/chainloop/blob/v1.121.0/pkg/attestation/renderer/chainloop/v02.go).
Supported statements are in-toto v0.1/v1 with Chainloop v0.1.2/v0.2 predicates,
including canonical and protobuf JSON field aliases. Actual deployed server,
runtime and retained artifact compatibility must be qualified separately.

Stored materials are selected by the CAS/inline annotations, not by filename
or a hardcoded scanner list. Linked ATTESTATION materials are followed until
the declared graph closes; repeated content is retrieved once per target.
Policy-evaluation CAS references outside the materials list are included.
Inline STRING values remain in the original statement and evidence record.
Inline stored files are decoded and digest-verified without changing their
original content. Image, chart and package binary references are recorded;
their layers and binaries are not copied as report evidence. Other file
materials without retained content are reported as not_retained and fail
collection rather than disappearing.

The fetcher does not use CAT group/run discovery wrappers because inspected
versions may create internal organization tokens on a cache miss. It does not
use evidence.zip as a completeness oracle because export can skip failed
downloads. Supply pinned roots from an existing authorized read/export
procedure until a supported nonmutating discovery path is qualified. No scan,
credential creation, remediation, infrastructure change or source write is
performed by the collector.

## Output and failure handling

One top-level uds_cat_package_evidence_<identity>.json holds the raw record.
The runner adds its normal envelope, target, run ID and collection status.
Verified originals live below _attachments/<identity>/ with digest-based names
and source filename extensions where usable. Every material edge retains its
original descriptor, parent attestation, content digest, original-file path
and retrieval state. The statements retain subject, source run metadata,
environment/scanner-version fields and policy results without inventing
missing timestamps or versions. Configured package labels remain separate.
Artifact effective dates use collection time; original scan clocks remain in
the files and statement record. Scan freshness requires separate evaluation.

The optional [original-file contract](../../../docs/evidence_attachments_guide.md)
lets the native evidence uploader send the record and originals to the same
Evidence Set through its existing routing, authentication, deduplication and
retry behavior. It preserves original bytes even when a report happens to look
like a Paramify JSON envelope. Missing, changed, unsafe or malformed local
companions refuse delivery; originals changed after planning hold delivery
rather than submitting an incomplete batch.

A failed read, missing expected material, wrong subject, malformed statement,
size/digest mismatch or exceeded transfer budget yields a nonzero exit, native
failure status and a diagnostic record with verified partial originals.
Unverified or interrupted bytes are not attached. Invalid configuration or an
unwritable output can fail before a record exists; the native failure channel
still records the reason. Existing output names are never overwritten.

A successful collection is not a successful scan. For example, an original
unsupported-scan outcome can be collected successfully while preserving that
the benchmark scan did not complete. The record's scan_acceptance is always
not_evaluated. Empty expected_materials leaves expected_population as
not_configured. graph_complete describes the selected declared graph, not all
possible runs or all required scanners.

## Publication and interpretation

Collection does not publish. Use the maintained evidence upload workflow after
reviewing its preview and obtaining applicable destination authority. This
fetcher defines no hosted IDs, control mappings, validators or acceptance.

Companion originals are evidence attachments, not issue-report intake. Do not
attach a parsing pipeline to this evidence entry: the native delivery extension
refuses that combination so attestations and SBOMs cannot become scanner
findings accidentally. A separately qualified native intake path and preset
must select the actual supported report if findings are needed. No JSON-to-XML
conversion, automatic finding resolution or cycle closure is added here.

CAT's OpenSCAP results concern image filesystems and STIG content. They do not
establish node or Kubernetes runtime benchmark conformance. The collector also
retains the other CAT scanner materials without asserting their control value.

## Qualification checklist

The automated checks use synthetic packages, a temporary local HTTPS CAT
endpoint and the native runner/uploader against an in-process fake Paramify
API. They exercise multi-target isolation, graph traversal, original-byte
delivery, repeat-upload deduplication and adverse collection/delivery cases.
They do not establish real service compatibility or assessment acceptance.

Before operational use:

1. Record the installed CAT/Chainloop versions and least-privilege reader's
   actual permissions. Verify source reads do not create credentials or mutate
   assessed infrastructure. Never grant administrator access just to collect.
2. Select a real package/run, verify trusted roots and subject/report joins,
   reconcile expected scanner/material population, and review failed,
   unsupported, absent, non-CAS and unknown cases.
3. Measure complete original and archive sizes, largest file and counts. Size
   suitability is provisional. Defaults are collector guards, not hosted API
   limits; native artifact readback separately caps files at 200 MiB.
4. Under actual upload authority, verify each original's hosted bytes and hash,
   the record's associations, correct environment/run/time attribution and an
   unchanged rerun. Retain failed publication attempts and incomplete results.
5. Qualify scanner presets separately, obtain Engineering and Cyber review,
   and confirm the recurring operator, access, retention and failure procedure.
