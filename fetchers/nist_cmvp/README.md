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

Every other certificate is not validated, and `reason` says why:

| Reason | Meaning |
|---|---|
| `historical` | Status is Historical. |
| `revoked` | Status is Revoked. |
| `sunset_passed` | Status is Active, but the sunset date is before today. All FIPS 140-2 certificates sunset on 9/21/2026. |
| `status_unknown` | Status is missing or has another value, or the standard is not FIPS 140-2 or FIPS 140-3. |
| `not_found` | NIST has no page for the number (HTTP 404), or the page is for a different number. |
| `parse_error` | The page could not be read, for example a missing sunset date. |
| `fetch_error` | The page could not be fetched after retries. |

Each record also carries the module name, vendor, standard, status, historical
reason, sunset date, overall level, module type, embodiment, caveat, security
level exceptions and validation history.

A `parse_error` or `fetch_error` on any certificate makes the run exit 1, but
the other certificates are still checked and written. The other reasons are
verdicts, so the run still exits 0.

## Settings

| Setting | Env | Default |
|---|---|---|
| `certificates` | `NIST_CMVP_CERTIFICATES` | required |
| `base_url` (category) | `NIST_CMVP_BASE_URL` | `https://csrc.nist.gov` |

Requests go one at a time, with a 30-second timeout. A timeout, connection
error or HTTP 5xx is retried twice.
