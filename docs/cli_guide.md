# The `paramify` CLI

The TUI and the AI-agent skills do all their work through the `paramify`
command. Thus you can script anything that you can do in them. The README's
[quickstart](../README.md#using-the-cli) shows a typical run from start to
finish. This guide is the full reference.

**You need:** [the repo installed](../README.md#install).

---

## Commands

Every `paramify` subcommand at a glance:

```bash
paramify list                  # discovered fetchers (flat)
paramify catalog               # categories → fetchers → editable fields
paramify describe <fetcher>    # one fetcher's config / secrets / target fields
paramify ksi                   # FedRAMP KSI coverage
paramify doctor   [manifest]   # preflight: Python, CLIs/packages, manifest, upload
paramify manifests             # discovered run manifests (manifests/*.yaml)
paramify validate <manifest>   # validate a manifest without running
paramify run      <manifest>   # run it
paramify runs                  # past runs under an output dir (newest first)
paramify evidence <file>       # read one evidence file, or an issue-report sidecar
paramify upload   [run-dir]    # push a run's evidence to Paramify (default: latest run)
paramify issues   <sub>        # send a run's issue reports into assessment pipelines; list/close their jobs
paramify programs <sub>        # list workspace programs; turn them into targets
paramify assessments <sub>     # list workspace assessments; point issue reports at one
paramify capabilities <sub>    # read solution capabilities and the narratives they claim
paramify artifacts <sub>       # list/download the artifacts already attached to evidence sets
paramify manifest <sub>        # build/edit a manifest (see below)
paramify scripts  <sub>        # sync fetcher entry scripts to Paramify (see below)
paramify validators <sub>      # check registry validators; sync them to Paramify
paramify tui                   # the terminal UI
```

> Back-compat: `python -m framework.runner <cmd>` and `python -m framework.tui`
> still work and are exactly equivalent to the corresponding `paramify`
> subcommands.

## Preflight with `paramify doctor`

Before a real run, `paramify doctor <manifest>` preflights the environment —
Python, the CLIs and pip packages each category needs, whether the manifest can
run at all, whether its secret env vars hold usable values, and whether an upload
would work — and exits non-zero if anything's missing, so it drops straight into
CI:

```text
$ paramify doctor examples/minimal_run.yaml
✅ Python 3.11.9 (need ≥ 3.10)

Required CLIs:
  ✅ curl     /usr/bin/curl  (okta)
  ✅ jq       /opt/homebrew/bin/jq  (okta)

Upload:
  ❌ API token not set — PARAMIFY_UPLOAD_API_TOKEN (or PARAMIFY_API_TOKEN)
  → production: https://app.paramify.com/api/v0  (default)
  (informational — collecting without uploading is fine)

✅ Manifest valid (examples/minimal_run.yaml): 2 entries

Manifest secrets (examples/minimal_run.yaml):
  ❌ okta_phishing_resistant_mfa  missing: OKTA_API_TOKEN, OKTA_ORG_URL
  ❌ gitlab_ci_cd_pipeline_config  missing: GITLAB_TOKEN_1, GITLAB_TOKEN_2

Issues found — see above.
```

Passing a manifest scopes every dependency check to the categories it actually
uses, so a GitLab-only run is never told to install the aws CLI or the Azure
SDKs. Each category declares what it needs in
`fetchers/_categories/<name>.yaml`; version pins come from `requirements.txt`.
The declarations are themselves tested (`tests/test_category_requires.py`) — an
import or a shelled-out binary that nothing declares fails the suite, because
doctor's report is only as good as what the category files say.

The manifest is validated exactly the way `paramify validate` does it, so a
misspelled fetcher name, a missing required config key, or an unmapped declared
secret fails here rather than at run time — none of which a secret-presence check
can see, since a secret the manifest never mapped leaves nothing to check.

Secret *values* are checked, not just their presence. A whitespace-only value
counts as missing (it reads as set and fails at the API), and values that look
like copy-paste artifacts — surrounding quotes, a trailing newline from
`$(cat file)`, a `*_URL` with no scheme — are reported as warnings that never
affect the exit code, since a legitimate value can look odd:

```text
Manifest secrets (manifest.yaml):
  ✅ okta_phishing_resistant_mfa  (OKTA_API_TOKEN, OKTA_ORG_URL)
  ⚠️  OKTA_ORG_URL: name reads as a URL but the value has no http(s):// scheme
```

Two flags worth knowing:

- `--probe` authenticates against each cloud category and prints which identity
  answered (caller ARN, Azure principal and subscription, GCP account and
  project). Without it doctor only checks that variables are *set* — which says
  nothing for the ambient credential chains, where the working path sets no
  variable at all. It makes network calls, so it is opt-in, and a failed probe
  is reported without failing the command.
- `--require-upload` makes a missing API token fail the exit code. By default
  upload readiness is reported but not gated, since collecting without
  uploading is a legitimate workflow.

## Building a manifest

`paramify manifest <sub>` edits a manifest file in place (`-f/--file`, default
`./manifest.yaml`). It reads each `fetcher.yaml` and warns which secrets and
config are still missing until the manifest is runnable.

Nothing ships at `./manifest.yaml`, so the one you build there is yours — commit
it or don't, as you prefer. `paramify manifest new <name>` starts one under
`manifests/`. For a worked reference see
[`example_manifest.yaml`](../example_manifest.yaml); [`examples/`](../examples/) holds
smaller per-scenario samples.

![Building a run manifest, then preflighting it with paramify doctor](demo/doctor.gif)

```bash
paramify manifest init [--output-dir DIR]            # start a manifest at -f/--file
paramify manifest new <name> [--output-dir DIR]      # create manifests/<name>.yaml
paramify manifest add <fetcher>                      # add a fetcher
paramify manifest remove <fetcher>
paramify manifest set-config <fetcher> key=value
paramify manifest set-secret <fetcher> <secret_name> <ENV_VAR>
paramify manifest add-target <fetcher> k=v ... [--secret name=ENV_VAR ...]
paramify manifest set-target <fetcher> <index> k=v ... [--secret name=ENV_VAR ...]
paramify manifest remove-target <fetcher> <index>
paramify manifest set-platform-config <category> key=value
paramify manifest set-passthrough <category> ENV_VAR ...
paramify manifest set-output-dir <dir>
paramify manifest show [--json]
```

Every `manifest` subcommand also accepts `--json`, emitting a stable
`{"ok", "path", "errors"}` object — so an agent can build a manifest step by step
and read `errors` to see what's still missing.

## Collect, then upload

Collection and upload are separate stages on purpose. The runner only collects;
pushing to Paramify is a second step, run against the enveloped run directory:

```bash
paramify run manifest.yaml          # collect → enveloped JSON in run-<ts>/
paramify upload                     # upload the latest run (get-or-create evidence
                                    # set by reference_id, multipart artifacts)
```

`paramify upload` takes an optional run directory (default: the latest run under
`--output-dir`) and supports `--dry-run`, `--config`, and `--json`; the same
uploader can also be invoked directly as
`python -m uploaders.paramify_evidence <run-dir>`. It is idempotent within a run,
talks Paramify REST v0 over HTTPS only, and reads `PARAMIFY_UPLOAD_API_TOKEN`
(with optional `PARAMIFY_API_BASE_URL`). See
[`uploaders/paramify_evidence/README.md`](../uploaders/paramify_evidence/README.md)
for how to create a Paramify API key with the required permissions. Chaining the two stages is the
customer's job, not the runner's; `run_and_upload.sh` at the repo root is
example glue.

## Scan results, not evidence

Some tools don't need you to assert anything — they already computed the findings.
A Nessus export or a Wiz misconfiguration report *is* the answer, and Paramify has
a parser for it. Those go through a second kind of fetcher, `kind: issue_report`,
which writes the tool's own file untouched to `run-<ts>/issue-reports/` and posts
it to a Paramify **assessment**, where it becomes issues rather than evidence:

```bash
paramify assessments select my_scanner_report   # pick the assessment by name, once
paramify run manifest.yaml                      # raw report → run-<ts>/issue-reports/
paramify issues upload                          # → POST /pipelines/{id}/intake + /process
```

The file is never wrapped or rewritten — the intake parser reads the vendor's own
CSV/XML/JSON/Nessus structure, so anything added to it breaks the parse. That one
constraint is what makes this a separate kind with a separate uploader instead of
a flag on the existing one. Wiz ships the first three — STIG compliance, Issues
report and vulnerability findings (see [`fetchers/wiz/README.md`](../fetchers/wiz/README.md#issue-reports));
to write another, start from [`issue_report_fetchers_guide.md`](issue_report_fetchers_guide.md).

## Inventory

A third kind, `kind: inventory`, lists every asset of some kind (cloud resources,
hosts, devices) as one record per asset, so Paramify's Inventory can be generated
instead of kept by hand. It uploads to an evidence set like any evidence, and an
inventory pipeline attached to that set turns each record into an Inventory item.
Because the pipeline reads the file as the whole estate, `paramify upload` sends
an inventory only when the run collected all of it. See
[`inventory_fetchers_guide.md`](inventory_fetchers_guide.md).

## See what a platform has (discovery)

A third kind of fetcher, `kind: discovery`, lists what a set of credentials can
see in a platform (groups, campaigns, projects and so on) and whether each could
be read. It is never uploaded; it helps you decide which fetchers to run and how
to configure them.

```bash
paramify run manifest.yaml                    # → run-<ts>/discovery/<fetcher>.json
```

KnowBe4 and AWS have one today (`knowbe4_discovery_beta`, `aws_discovery_beta`). See [`discovery.md`](discovery.md).

## Show how evidence is generated (optional)

Beyond the evidence itself, you can push each fetcher's **entry script** to
Paramify and link it to that fetcher's evidence set — so the tenant shows *how*
each piece of evidence was collected. This is a **provisioning** step, separate
from upload: run it when `fetchers/**` change, not on every collection.

```bash
paramify scripts sync --dry-run     # preview the plan (read-only)
paramify scripts sync               # push entry scripts + associate to evidence sets
```

It reconciles the tenant to the repo GitOps-style — keyed off a marker in each
script's `description` and the `fetcher.yaml` `version`, with a sha256 drift guard
(warn/skip unless `--force`) — and supports `--reassociate` and `--json`. Like the
uploader it talks Paramify REST v0 over HTTPS only and reads
`PARAMIFY_UPLOAD_API_TOKEN`. See
[`uploaders/paramify_scripts/README.md`](../uploaders/paramify_scripts/README.md) for
the full model, or [`uploader_guide.md`](uploader_guide.md#5-sync-scripts-and-validators-optional)
for how it fits alongside evidence upload.

## Fanning out across Paramify programs

Fanning a fetcher out across the programs in a Paramify workspace is its own
step, because the API takes project UUIDs while people know their programs by
name. `paramify programs` closes that gap — list what's there, pick by name, and
it writes the targets for you:

```bash
paramify programs list                       # name + UUID for every program
paramify programs target                     # choose interactively, then wire them up
paramify programs target --all \
    --cert-uri https://example.gov/cpo --report-from 2026-01-01
```

With no fetcher argument it targets every manifest entry that takes a program, so
one command fans all of them out at once. Re-running it tops the manifest up
rather than duplicating targets.

Which manifest it edits is chosen, never assumed. With no `-f/--file` it lists
the discovered manifests — `manifests/*.yaml` plus a legacy `./manifest.yaml` —
and you pick one by number; a lone candidate is used outright and named. `-f`
takes a path or a bare name (`-f azure`, `-f azure.yaml`), resolved against
`manifests/` and the repo root so it works from any directory in the tree. A `-f`
that matches nothing is an error, not an empty manifest.

A target carries only what varies per program — `project_id` and its readable
`program_name`. Everything shared is written once to `platforms.paramify.config`:
the Certification Package Overview URI (not in Paramify's API, one value per
workspace) and the report period start. Every interactive run shows both with
whatever the manifest holds today as the prompt default — enter keeps it and
writes nothing, typing over it updates it — so `paramify programs target` is
equally how you add a program and how you roll the report window forward.
Passing `--cert-uri`/`--report-from` overwrites what's there without asking.

`--report-from` is checked for an ISO date up front — an unparseable one produces
an empty report window, which drops every closed issue from the report without
failing.

Both subcommands need `PARAMIFY_API_TOKEN` with read scope and accept `--json`
(under `--json` nothing prompts, so pass the flags).
