# Security policy

Fetchers run with read access to your cloud accounts and security tools, so we
take reports about this code seriously.

## Reporting a vulnerability

**Please don't open a public issue or discussion for a security problem.**

Report it privately through GitHub instead:
[**Report a vulnerability**](https://github.com/paramify/paramify-fetchers/security/advisories/new)
(the repo's **Security** tab → **Report a vulnerability**). Only the maintainers
can see the report.

Useful things to include:

- what the problem is and what an attacker could do with it
- the fetcher, uploader or CLI command involved, and the version or commit
- steps or a minimal manifest that reproduce it
- any logs or output, **with credentials and real evidence removed**

We'll acknowledge the report, keep you posted while we fix it, and credit you in
the advisory if you'd like.

## Supported versions

Fixes land on `main` and ship in the next release. We don't patch older
releases, so run the latest one.

## What counts

In scope:

- a fetcher that writes to, or changes, the system it reads from
- credentials or tokens leaking into evidence files, logs or uploads
- the uploader sending data anywhere other than the configured Paramify API
- command injection or path traversal through a manifest, config or target value
- the container image in [`deploy/`](deploy/) exposing secrets or running with
  more privilege than it needs

Not in scope: weaknesses in the third-party platforms the fetchers read from,
or in Paramify itself. Report those to the vendor, or for Paramify to
[Paramify support](https://support.paramify.com).

## Running fetchers safely

- Give each fetcher read-only credentials scoped to what it collects. Most
  platforms' `fetchers/<category>/README.md` lists the permissions they need.
- Keep secrets in environment variables or your secret manager, never in a
  manifest or a commit.
- Treat evidence files as sensitive: they describe your infrastructure's
  configuration. Keep `evidence/` out of version control and out of shared
  storage.
