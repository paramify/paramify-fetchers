# NIST CMVP

This category checks whether the cryptographic modules you depend on are
currently FIPS 140-2 or FIPS 140-3 validated. It reads the public certificate
page that the NIST Cryptographic Module Validation Program (CMVP) publishes for
each module:

`https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/<NUMBER>`

No credential is needed.

| Fetcher | Certificates come from | Credential |
|---|---|---|
| `nist_cmvp_module_validation_status` | `certificates` config: `4816, 4282` or `AWS-LC=4816, ...` | none |

## Set it up

Add the fetcher to your manifest and list your certificate numbers:

```yaml
run:
  fetchers:
    - use: nist_cmvp_module_validation_status
      config:
        certificates: "AWS-LC=4816, 4282"
```

Or use the manifest builder:

```bash
paramify manifest add nist_cmvp_module_validation_status
paramify manifest set-config nist_cmvp_module_validation_status certificates="AWS-LC=4816, 4282"
```

The label before `=` is optional. It is copied into the evidence so that a
reader knows what each module is.

## What a record says

A certificate is validated only when all of these are true:

- The page is for that certificate number.
- Status is Active.
- Standard is FIPS 140-2 or FIPS 140-3.
- The sunset date is today or later (UTC).

Every other certificate gets a `reason`. The first five are verdicts: the
certificate is not validated (`validated: false`). The last two mean the run
could not check the certificate, so `validated` is `null`:

| Reason | Meaning |
|---|---|
| `historical` | Status is Historical. |
| `revoked` | Status is Revoked. |
| `sunset_passed` | Status is Active, but the sunset date is before today. All FIPS 140-2 certificates sunset on 9/21/2026. |
| `status_unknown` | Status is missing or has another value, or the standard is not FIPS 140-2 or FIPS 140-3. |
| `not_found` | NIST has no page for the number (HTTP 404 or 410), or the page heading names a different number. |
| `parse_error` | The page could not be read, for example a missing sunset date. An HTTP 200 page with no `Certificate #` heading and no Details rows, such as a maintenance or block page, is also a `parse_error`, not `not_found`. |
| `fetch_error` | The page could not be fetched after retries. |

Each record also carries the module name, vendor, standard, status, historical
reason, sunset date, overall level, module type, embodiment, caveat, security
level exceptions and validation history.

A `parse_error` or `fetch_error` on any certificate makes the run exit 1, but
the other certificates are still checked and written. The run reports
`rate_limited` if a certificate was still answered with HTTP 429 after retries,
`target_unreachable` if every certificate was a `fetch_error`, and
`partial_failure` otherwise. The other reasons are verdicts, so the run still
exits 0.

When any certificate could not be checked, the summary's
`certificates_validated`, `certificates_not_validated` and verdict counts
(`historical`, `revoked`, `sunset_passed`, `status_unknown`, `not_found`) are
`null`. The `parse_error` and `fetch_error` counts are still written. A validator
that reads one of the null counts finds no number and fails, instead of passing
on a partial read.

## Settings

| Setting | Env | Default |
|---|---|---|
| `certificates` | `NIST_CMVP_CERTIFICATES` | required |
| `base_url` (category) | `NIST_CMVP_BASE_URL` | `https://csrc.nist.gov` |

Requests go one at a time, with a 30-second timeout. A timeout, connection
error, HTTP 429 or HTTP 5xx is retried twice. On HTTP 429 the retry waits for a
numeric `Retry-After` header, up to 60 seconds.
