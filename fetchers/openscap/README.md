# OpenSCAP fetchers

Read-only evidence from OpenSCAP scan results: the XCCDF results files and ARF reports `oscap xccdf eval` writes. The
fetcher doesn't run scans; it reads the files your scans already produce, from an Azure Blob Storage container or a
local directory.

## Setup

1. Have each scan write its results where the fetcher can read them, for example:

   ```
   oscap xccdf eval --profile <profile> --results-arf /results/$(hostname)-$(date +%F).arf.gz <datastream.xml>
   ```

   `--results` (XCCDF) and `--results-arf` (ARF) both work, gzipped or not. A host scanned more than once counts only
   its newest result, so keep older files if you like; they don't skew the counts. OVAL results files
   (`--oval-results`) are skipped.
2. Point the fetcher at them, one of:
   - **Azure Blob Storage:** set `OPENSCAP_RESULTS_CONTAINER_URL`, such as
     `https://<account>.blob.core.windows.net/<container>` (or the `blob.core.usgovcloudapi.net` endpoint in Azure
     Government), and give the run's Azure identity **Storage Blob Data Reader** on that container. The identity is
     picked up the usual way: a managed identity, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_CLIENT_SECRET`, or an
     Azure CLI login. In Azure Government, also set `AZURE_AUTHORITY_HOST=https://login.microsoftonline.us`. Only
     files ending `.xml`, `.xml.gz`, `.arf` or `.arf.gz` are read.
   - **Local directory:** set `OPENSCAP_RESULTS_DIR` to a folder holding the files; subfolders are read too.

   Set `OPENSCAP_RESULTS_PREFIX` to read only part of the container or folder, such as `scans/`.
3. Set `OPENSCAP_EXPECTED_TARGETS` to the hosts that must have a result, comma-separated, matching the XCCDF target
   name (usually the host name). It has no default: until it is set, the expected-target check fails.
4. Set `OPENSCAP_MAX_AGE_DAYS`, the oldest a host's latest scan may be. It also has no default, and the age check fails
   until it is set.

| Fetcher | Evidence set | Shows |
| --- | --- | --- |
| `benchmark_results` | `EVD-OPENSCAP-BENCHMARK-RESULTS` | Each host's latest benchmark evaluation: profile, failed rules by severity, errors, waived rules and scan age |

Rule text, check content and remediation are never copied, and XML is parsed with defusedxml. A file that can't be
read or parsed fails the run and leaves every verdict unknown, since it could hide a host's latest result.
