# The `paramify` CLI

The TUI and the AI-agent skills do all their work through the `paramify`
command. Thus you can script anything that you can do in them. This guide starts
with a typical run from start to finish, then gives the full reference.

**You need:** [the repo installed](../README.md#install).

---

## A typical run

This run wires one Okta fetcher into a new manifest, runs it, and uploads the evidence:

```bash
# 1. Browse available fetchers by category
paramify catalog

# 2. Start a manifest and wire in your fetchers
paramify manifest init
paramify manifest add okta_phishing_resistant_mfa
paramify manifest set-secret okta_phishing_resistant_mfa api_token OKTA_API_TOKEN
paramify manifest set-secret okta_phishing_resistant_mfa org_url OKTA_ORG_URL
# The manifest builder reports missing secrets after each step.
# Keep going until it says the manifest is runnable.

# 3. Set your credentials and run
export OKTA_API_TOKEN=<your token>
export OKTA_ORG_URL=https://your-org.okta.com
paramify validate manifest.yaml
paramify run     manifest.yaml         # evidence → ./evidence/run-<timestamp>/

# 4. Upload to Paramify
export PARAMIFY_UPLOAD_API_TOKEN=<your token>   # see uploaders/paramify_evidence/README.md for setup
paramify upload                                  # push the latest run
```

Most services have a credential setup guide in their fetcher directory. For
example, [`fetchers/okta/README.md`](../fetchers/okta/README.md) shows how to
create an Okta API token and which admin role it needs.

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
> still work. They do exactly the same as the matching `paramify` subcommands.

## Preflight with `paramify doctor`

Before a real run, `paramify doctor <manifest>` examines the environment:

- the Python version
- the CLIs and pip packages that each category needs
- whether the manifest can run
- whether its secret environment variables hold usable values
- whether an upload can work

If something is missing, doctor exits non-zero. Thus you can put it straight
into CI:

```text
$ paramify doctor examples/minimal_run.yaml
✅ Python 3.11.9 (need ≥ 3.11)

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

When you give doctor a manifest, it limits each dependency check to the
categories that the manifest uses. Thus doctor never tells a GitLab-only run to
install the aws CLI or the Azure SDKs. Each category declares what it needs in
`fetchers/_categories/<name>.yaml`, and the version pins come from
`requirements.txt`. A test (`tests/test_category_requires.py`) examines these
declarations. If a fetcher imports a module or calls a binary that no category
declares, the suite fails. This matters because the doctor report can only be as
correct as the category files.

Doctor validates the manifest the same way as `paramify validate`. Thus these
errors fail here, not at run time:

- a misspelled fetcher name
- a missing required config key
- a declared secret that the manifest does not map

A check for secret presence cannot find these errors. A secret that the manifest
never maps gives that check nothing to examine.

Doctor examines secret *values*, not only their presence. A value with only
whitespace counts as missing, because it looks set but fails at the API. Some
values look like copy-paste errors: surrounding quotes, a trailing newline from
`$(cat file)`, or a `*_URL` with no scheme. Doctor reports these as warnings, and
they never change the exit code, because a correct value can look odd:

```text
Manifest secrets (manifest.yaml):
  ✅ okta_phishing_resistant_mfa  (OKTA_API_TOKEN, OKTA_ORG_URL)
  ⚠️  OKTA_ORG_URL: name reads as a URL but the value has no http(s):// scheme
```

Two flags are useful to know:

- `--probe` signs in to each cloud category and prints the identity that
  answered: the caller ARN, the Azure principal and subscription, or the GCP
  account and project. Without this flag, doctor only examines whether variables
  are *set*. That tells you nothing about ambient credential chains, where the
  working setup sets no variable. The probe makes network calls, so you must ask
  for it. A failed probe shows in the report but does not fail the command.
- `--require-upload` makes a missing API token fail the exit code. By default,
  doctor reports whether an upload can work but does not fail on it, because
  collecting without uploading is a valid workflow.

## Building a manifest

`paramify manifest <sub>` edits a manifest file in place (`-f/--file`, default
`./manifest.yaml`). It reads each `fetcher.yaml` and tells you which secrets and
config are still missing, until the manifest can run.

The repo does not ship a `./manifest.yaml`, so the one that you build there is
yours. You can commit it or not. `paramify manifest new <name>` starts a manifest
in `manifests/`. For a full sample, see
[`example_manifest.yaml`](../example_manifest.yaml). [`examples/`](../examples/)
holds smaller samples, one for each scenario.

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

Every `manifest` subcommand also accepts `--json` and returns a stable
`{"ok", "path", "errors"}` object. Thus an agent can build a manifest step by
step and read `errors` to find what is still missing.

## Collect, then upload

Collection and upload are separate stages on purpose. The runner only
collects. The upload to Paramify is a second step, which you run on the
enveloped run directory:

```bash
paramify run manifest.yaml          # collect → enveloped JSON in run-<ts>/
paramify upload                     # upload the latest run (get-or-create evidence
                                    # set by reference_id, multipart artifacts)
```

`paramify upload` takes an optional run directory. The default is the latest
run under `--output-dir`. It supports `--dry-run`, `--config` and `--json`. You
can also call the same uploader directly as
`python -m uploaders.paramify_evidence <run-dir>`.

The uploader is idempotent within a run. It talks to Paramify REST v0 over HTTPS
only, and it reads `PARAMIFY_UPLOAD_API_TOKEN` (and the optional
`PARAMIFY_API_BASE_URL`).
[`uploaders/paramify_evidence/README.md`](../uploaders/paramify_evidence/README.md)
shows how to create a Paramify API key with the necessary permissions.

The runner does not chain the two stages. That is the customer's job, and
`run_and_upload.sh` at the repo root is a sample script for it.

## Scan results, not evidence

Some tools already calculate the findings, so you do not need to make a claim
about them. A Nessus export or a Wiz misconfiguration report *is* the answer,
and Paramify has a parser for it. These reports go through a second kind of
fetcher, `kind: issue_report`. It writes the original file of the tool, with no
changes, to `run-<ts>/issue-reports/`. Then it posts the file to a Paramify
**assessment**, where it becomes issues, not evidence:

```bash
paramify assessments select my_scanner_report   # pick the assessment by name, once
paramify run manifest.yaml                      # raw report → run-<ts>/issue-reports/
paramify issues upload                          # → POST /pipelines/{id}/intake + /process
```

The runner never wraps or rewrites the file. The intake parser reads the
original CSV, XML, JSON or Nessus structure of the vendor, so any addition breaks
the parse. This one constraint is why issue reports are a separate kind with a
separate uploader, not a flag on the evidence uploader. Wiz ships the first
three: STIG compliance, the Issues report and vulnerability findings (see
[`fetchers/wiz/README.md`](../fetchers/wiz/README.md#issue-reports)). To write
another, start from [`issue_report_fetchers_guide.md`](issue_report_fetchers_guide.md).

## Inventory

A third kind, `kind: inventory`, lists every asset of one type (cloud
resources, hosts or devices), with one record for each asset. Thus Paramify can
generate its Inventory, and nobody needs to keep it by hand. An inventory
uploads to an evidence set like any other evidence. Then an inventory pipeline on
that set turns each record into an Inventory item. The pipeline reads the file as
the full estate, so `paramify upload` sends an inventory only when the run
collected all of it. See [`inventory_fetchers_guide.md`](inventory_fetchers_guide.md).

## See what a platform has (discovery)

A fourth kind of fetcher, `kind: discovery`, lists what a set of credentials
can see in a platform (groups, campaigns, projects and similar items). It also
records whether it could read each one. Discovery output never uploads. It helps
you decide which fetchers to run and how to configure them.

```bash
paramify run manifest.yaml                    # → run-<ts>/discovery/<fetcher>.json
```

KnowBe4 and AWS each have one at this time (`knowbe4_discovery_beta`,
`aws_discovery_beta`). See [`discovery.md`](discovery.md).

## Show how evidence is generated (optional)

You can also push the **entry script** of each fetcher to Paramify and link it
to the evidence set of that fetcher. Then the tenant shows *how* the fetcher
collected each piece of evidence. This is a **provisioning** step, separate from
upload. Run it when `fetchers/**` changes, not on every collection.

```bash
paramify scripts sync --dry-run     # preview the plan (read-only)
paramify scripts sync               # push entry scripts + associate to evidence sets
```

The sync makes the tenant match the repo, in GitOps style. It uses a marker in
the `description` of each script and the `version` in `fetcher.yaml`. A sha256
drift guard warns and skips a changed script unless you give `--force`. The sync
also supports `--reassociate` and `--json`. Like the uploader, it talks to
Paramify REST v0 over HTTPS only and reads `PARAMIFY_UPLOAD_API_TOKEN`. For the
full model, see
[`uploaders/paramify_scripts/README.md`](../uploaders/paramify_scripts/README.md).
For how it fits with evidence upload, see
[`uploader_guide.md`](uploader_guide.md#5-sync-scripts-and-validators-optional).

## Fanning out across Paramify programs

To run a fetcher across the programs in a Paramify workspace, you need a
separate step. The API takes project UUIDs, but people know their programs by
name. `paramify programs` closes that gap. You list the programs and pick them by
name, and it writes the targets for you:

```bash
paramify programs list                       # name + UUID for every program
paramify programs target                     # choose interactively, then wire them up
paramify programs target --all \
    --cert-uri https://example.gov/cpo --report-from 2026-01-01
```

With no fetcher argument, it targets every manifest entry that takes a
program. Thus one command fans out all of them at once. When you run it again,
it adds to the manifest and does not duplicate targets.

The command never guesses which manifest to edit. With no `-f/--file`, it lists
the manifests that it finds: `manifests/*.yaml` and a legacy `./manifest.yaml`.
You pick one by number. If there is only one, the command uses it and shows its
name. `-f` takes a path or a bare name (`-f azure`, `-f azure.yaml`). The command
looks for the name in `manifests/` and the repo root, so `-f` works from any
directory in the tree. A `-f` that matches nothing is an error, not an empty
manifest.

A target holds only the values that change for each program: `project_id` and
its readable `program_name`. The command writes the shared values once, to
`platforms.paramify.config`:

- the Certification Package Overview URI, which is not in the Paramify API and
  has one value for each workspace
- the start of the report period

Each interactive run shows the two values and uses the current manifest values as
the defaults. Press Enter to keep a value and write nothing, or type a new value
to change it. Thus `paramify programs target` adds a program and also moves the
report window forward. `--cert-uri` and `--report-from` replace the current
values without a prompt.

The command examines `--report-from` for an ISO date before it does anything
else. A date that it cannot parse gives an empty report window, and that window
silently drops every closed issue from the report.

The two subcommands need `PARAMIFY_API_TOKEN` with read scope, and they accept
`--json`. With `--json`, nothing prompts, so give the flags.
