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
paramify preset   <fetcher>    # settings for a pipeline fetcher's Paramify preset
paramify upload   [run-dir]    # push a run's evidence to Paramify (default: latest run)
paramify stacks                # list the workspace's stacks (name, id)
paramify status   <manifest>   # what each fetcher has in Paramify; exit 1 until all are ready, 2 on errors
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

### Tab completion

To complete commands and options with Tab, install completion for your shell
once, then open a new shell:

```bash
paramify --install-completion
```

`paramify samples show <Tab>` also completes fetcher names. It lists only the
fetchers that have a sample. `paramify` must be on your `PATH` (for example, an
active virtual environment) when you press Tab.

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
paramify manifest exclude <category|fetcher> <pattern> [--reason TEXT] [--field NAME]
paramify manifest unexclude <category|fetcher> [pattern] [--field NAME] [--all]
paramify manifest set-passthrough <category> ENV_VAR ...
paramify manifest set-output-dir <dir>
paramify manifest show [--json]
```

`exclude` and `unexclude` edit exclusion lists, such as resource exclusions
([pattern lists](config_injection_guide.md#5-leave-resources-out-of-scope)).
They never touch a pattern list that shows more when it grows, such as
`azure_change_provenance`'s `value_paths`; set that one with `set-config`.

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
run under `--output-dir`. It sends one batch for each fetcher entry in the run.
The batch goes through the channel of the evidence set when the set has one.
When a batch cannot be used, the upload sends the entry
[direct](uploader_guide.md#when-a-batch-cannot-be-used), the way it did before
batches.

| Flag | Effect |
|---|---|
| `--dry-run` | Lists what would upload. Makes no API calls and needs no token. Routing shows as unknown. |
| `--plan` | Reads the workspace (no changes) and prints the full plan. Applies nothing. |
| `--stack STACK` | Sends every entry to this stack (an id or a name). It replaces the stack the run recorded. |
| `--owner USERNAME` | Where a stack has one channel per owner, uses this owner's channel. It replaces the owner the run recorded. |
| `--with-validators` | Syncs validators for the evidence sets of the run before the batches go out. If the sync fails, the upload sends no batch. With `--dry-run`, it only names the sync it would do. |
| `--no-tags` | Skips the default custom tags for this upload. |
| `--config`, `-f`, `-o` | Choose the uploader config, the manifest, and the output directory. |
| `--json` | Prints the summary: the legacy counts, plus `dropped`, `plan`, `entries`, `outcomes`, `batches` and, with `--with-validators`, `validators`. |

Set the stack in the manifest under `run.paramify` (`stack`, `stack_name`,
`owner`, `approval`, `delivery`, `no_request`). An entry can set the same keys in its own `paramify`
block. List the stacks in the workspace with `paramify stacks`. Write one into a
manifest with `paramify manifest set-stack MANIFEST STACK [--fetcher NAME]`.
With a token, the command looks up the stack and stores its id and name. Check
the stack ids against the workspace with `paramify validate --online`.

When an evidence set has two channels on the stack, one for each owner, the
upload needs an owner. Write one with
`paramify manifest set-owner MANIFEST USERNAME [--fetcher NAME]`. An empty
USERNAME removes it. The owner is read only where it breaks such a tie. See
[Owner](uploader_guide.md#owner). `paramify validate --online` gives a note for
an owner who has no channel in the workspace.

Uploading the same run again changes nothing. The upload finds the batch it made
for that run. A new run makes a new batch. If a temporary failure holds a batch
open, run the same upload again to resume it. Each new batch, and each new
evidence set, gets the approval mode `SUBMISSION` unless `approval` says
otherwise: Paramify approves the batch when the upload submits it, whatever
mode the set has. The upload never changes an existing set. The routing rules and each
refusal are in [`uploader_guide.md`](uploader_guide.md#how-a-run-is-delivered).

The upload talks to Paramify REST v0 over HTTPS only, and it reads
`PARAMIFY_UPLOAD_API_TOKEN` (and the optional `PARAMIFY_API_BASE_URL`).
[`uploaders/paramify_evidence/README.md`](../uploaders/paramify_evidence/README.md)
shows how to create a Paramify API key with the necessary permissions.

`uploaders/paramify_evidence/uploader.py` still works for old schedules, but it
is deprecated. It hands the run to the same upload and prints a notice. Use
`paramify upload`.

The runner does not chain the two stages. That is the customer's job, and
`deploy/run-and-upload.sh <manifest> [stack]` is a sample script for it. It
uploads the run it just collected.

A script that chains the stages needs the run directory. Two flags of
`paramify run` give it:

| Flag | Stdout | Stderr |
|---|---|---|
| `--print-run-dir` | The run directory, on one line. | The usual progress output: each result, the reason for each failure, and each skipped entry, setup error and note. |
| `--json` | The run summary. | Nothing. |

The run summary has `run_dir`, `ok` and one record for each invocation in
`invocations`. A failed invocation has `error`: the reason the fetcher gave, or
else its last stderr line. It can also have `error_code`. Three lists name the
entries that need attention. Each item has `entry_key` and `fetcher`:

- `skipped`: the entry did not run. `reason` tells why, for example
  `not discovered`.
- `setup_errors`: the setup failed before the fetcher started. `error` tells why.
- `notes`: the run changed something for the entry, for example it dropped an
  optional secret. `note` tells what.

## Check the setup in Paramify

`paramify status` reads the workspace and reports, for each evidence fetcher in
a manifest, what Paramify has for it. It changes nothing.

```bash
paramify status manifests/acme.yaml
```

| Column | Meaning |
|---|---|
| evidence set | `ok` when the set exists. `create` when the first scripts sync makes it. |
| script | The state that `paramify scripts sync --dry-run` reports: `ok`, `update`, `create`, `drift` or `error`. |
| validators | The registry validators that Paramify pairs with the set, out of all of them. `none` when the registry has none for the set. |
| capabilities | The solution capabilities that hold a pair from this set. |
| artifacts | The artifacts on the set. |
| ready | The set exists, its script is in sync, it has each registry validator, and it has an artifact. |

A line under the table counts each column across the fetchers. Scan-report
fetchers go to an assessment, not to an evidence set, so the table leaves them out.

Every read goes to one workspace: the base URL from `paramify.base_url` in the
uploader config (`upload.yaml` or `--config`), else `PARAMIFY_API_BASE_URL`,
else app.paramify.com. The first line of the output names it.

`?` in a cell means the read for it failed, so the value is unknown. The error
is shown under the table. `-` means nothing was read, because there is no API
token. Without a token, the command shows only what the manifest and the
registry hold, and leaves out the line of counts.

`--json` prints the full status. In it, an unknown value is `null`: the
evidence set's `exists` and `artifact_count`, and each validator's `paired`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Every fetcher is ready. |
| 1 | Some fetchers are not ready yet. A sync, a validator pair or an upload can fix it. |
| 2 | The command cannot tell, and waiting will not change that: the manifest or the uploader config cannot be read, there is no API token, a workspace read failed (for example, an expired token gets HTTP 401), the manifest names a fetcher that does not exist, or the manifest has no evidence fetchers. |

A deployment can wait for 0 before it runs headless, and stop on 2:

```bash
until paramify status manifests/acme.yaml >/dev/null; do
  [ $? -eq 2 ] && exit 2
  sleep 60
done
```

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

### `paramify preset <fetcher>`

Building the inventory pipeline's preset in Paramify takes a sample file, a data
path, a unique ID field and a rule for the parent component. `paramify preset
sophos_endpoint_inventory` prints them from the fetcher's `pipeline:` block and
its newest run, and lists the other fetchers that share the same ID scheme. With
no run yet, the sample and the `asset_type` values are missing, so run the
fetcher first. It reads runs from `<repo>/evidence`; `-f MANIFEST` uses that
manifest's `output_dir`, and `--output-dir` overrides both. `--json` prints the
same facts as data.

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
