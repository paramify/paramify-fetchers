# Security policy

Fetchers run with read access to your cloud accounts and security tools. Thus we
take reports about this code seriously.

## Reporting a vulnerability

**Do not open a public issue or discussion for a security problem.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/paramify/paramify-fetchers/security/advisories/new).
You can also open the repo's **Security** tab and select **Report a vulnerability**.
Only the maintainers can see the report.

Include these items if you can:

- the problem, and what an attacker can do with it
- the fetcher, uploader or CLI command, and the version or commit
- the steps, or a minimal manifest, that reproduce the problem
- logs or output, **with credentials and real evidence removed**

We will acknowledge your report and tell you about our progress on the fix. If
you want credit, we will name you in the advisory.

## Supported versions

Fixes go into `main` and ship in the next release. We do not patch earlier
releases, so use the latest one.

## What is in scope

In scope:

- a fetcher that writes to, or changes, the system that it reads from
- credentials or tokens that leak into evidence files, logs or uploads
- an uploader that sends data to a destination other than the configured
  Paramify API
- command injection or path traversal through a manifest, config or target value
- a container image in [`deploy/`](deploy/) that exposes secrets or runs with
  more privilege than it needs

Out of scope: weaknesses in the third-party platforms that the fetchers read
from, or in Paramify itself. Report those to the vendor. For Paramify, contact
[Paramify support](https://support.paramify.com).

## Running fetchers safely

- Give each fetcher read-only credentials that cover only what it collects. Most
  platforms' `fetchers/<category>/README.md` lists the permissions they need.
- Keep secrets in environment variables or your secret manager. Never put them
  in a manifest or a commit.
- Treat evidence files as sensitive data, because they describe the
  configuration of your infrastructure. Keep `evidence/` out of version control
  and out of shared storage.
