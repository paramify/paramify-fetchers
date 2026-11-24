# Using the terminal UI with `paramify tui`

The TUI does the same work as the `paramify` CLI, from one screen. You can find
fetchers, build a manifest, run it, read the evidence, choose validators, and
send the results to Paramify. The TUI and the CLI use the same code
(`framework.api`), so they give the same results.

This guide explains each tab and its keys. For each task in full, read the
guide for that task. This guide links to them.

## Start the TUI

```bash
paramify tui                                # open the welcome screen
paramify tui --manifest manifests/prod.yaml # open this manifest directly
paramify tui --at ~/paramify-fetchers       # use the repo at this path
```

The TUI reads the `.env` at the repo root, as `paramify run` and
`paramify upload` do. A variable that you export wins over the `.env` value.

The TUI does not connect to Paramify when it starts. It reads your workspace
only when you open the **Paramify** tab, the **Validators** tab, or a picker
that lists workspace items.

## The welcome screen

The welcome screen lists the manifests in the repo: the `.yaml` files in
`manifests/`, and `manifest.yaml` at the repo root. It also checks the repo,
the fetcher catalog, the manifests and the uploader.

A new clone has no `manifests/` directory, so the list is empty. To try the
TUI with the zero-credential demo, copy the demo manifest into `manifests/`:

```bash
mkdir -p manifests && cp examples/demo.yaml manifests/
paramify tui
```

| Key | What it does |
|---|---|
| `enter` | Open the selected manifest |
| `n` | Make a new manifest |
| `d` | Delete the selected manifest (it asks first) |
| `q` | Quit |

`n` asks for two things: the manifest name, then the Paramify stack that its
uploads go to. If you have no API token, or you press `esc`, the TUI makes the
manifest without a stack. You can set the stack later on the **Fetchers** tab.

## Keys on every tab

| Key | What it does |
|---|---|
| `1` to `6` | Go to a tab: Fetchers, Run, Evidence, Validators, Paramify, Pipelines |
| `/` | Go to the search box on the **Fetchers** tab |
| `m` | Open a different manifest |
| `E` | Open the environment view (see [The environment view](#the-environment-view)) |
| `U` | Open the update screen (see [Updates](#updates)) |
| `r` | Read the fetcher catalog again |
| `esc` | Leave a text field, so that the keys in this table work again |
| `q` | Quit |

The footer shows the keys for the area that you are in. When a text field has
focus, it takes all typed letters, so press `esc` first.

## 1 · Fetchers

The **Fetchers** tab has three areas:

- **Catalog** (top left): all the fetchers in the repo, grouped by kind and
  category.
- **Detail** (top right): the contract of the selected fetcher, or the detail
  of the selected manifest entry.
- **Manifest** (bottom): the settings and entries of the open manifest.

Press `tab` to move between the areas.

### Find and add fetchers

| Key | What it does |
|---|---|
| `/` | Filter the catalog. Type part of a name, a category or a platform. |
| `↑` `↓` or `j` `k` | Move in the catalog |
| `a` or `enter` | Add the selected fetcher to the manifest |

The detail area shows the contract of the selected fetcher: what it collects,
the secrets and config that it needs, and its evidence set.

### The manifest settings

The settings row is above the entries:

| Setting | What it sets | Read more |
|---|---|---|
| **output dir** | The directory that runs write to | [Run manifest guide](run_manifest_guide.md#1-start-a-manifest) |
| **stack** | The Paramify stack that uploads go to | [Choose the stack](uploader_guide.md#choose-the-stack-in-the-manifest) |
| **owner** | The owner whose channel uploads use, when a stack has one channel for each owner | [Owner](uploader_guide.md#owner) |
| **frequency** | How often the manifest runs. Each evidence set uses this frequency, unless an entry sets its own. | [Frequency](uploader_guide.md#set-the-collection-frequency) |
| **env** | How many variables still need a value. Select it to open the environment view. | [The environment view](#the-environment-view) |

With an API token, **stack** and **owner** show a list from your workspace.
Without a token, you type the value.

Each change saves the manifest immediately.

### Edit the entries

Select an entry in the manifest list, then press a key:

| Key | What it does |
|---|---|
| `a` | Go to the catalog filter, to find a fetcher to add |
| `e` | Edit the entry: its config, its secrets, and its Paramify settings for this entry only |
| `x` | Remove the entry (it asks first) |
| `t` | Edit the targets of a fan-out fetcher. In the targets list, `a` adds, `e` edits and `x` removes a target. |
| `A` | Scan-report fetchers only: point the entry at a Paramify assessment, and choose how its cycle closes ([pipelines guide](pipelines_guide.md#2-point-it-at-an-assessment)) |
| `P` | Pipeline fetchers only: show the preset sheet to copy into the Paramify app ([pipeline fetchers guide](pipeline_fetchers_guide.md)) |
| `v` | Validate the manifest |
| `p` | Show the manifest YAML |

The line below the entries shows the problems that stop the manifest from
running, for example a missing secret.

`A` and `P` show in the footer only for an entry that can use them.

## 2 · Run

Press `ctrl+r` or `enter` to run the manifest. The tab shows each fetcher's
status while it runs, a live log, and a pass, fail and skip count at the end.

Before the run starts, the TUI does two checks:

1. **Variables.** If a variable that a fetcher needs has no value, the run does
   not start. The environment view opens and names the variables. Give them
   values, then press `ctrl+r` again.
2. **Manifest.** If the manifest does not validate, the TUI shows the problems
   and asks if you want to run anyway.

The TUI cannot stop a run. Each fetcher stops at its timeout.

## 3 · Evidence

The **Evidence** tab lists the runs in the manifest's output directory. The
newest run is first.

| Key | What it does |
|---|---|
| `↑` `↓` | Select a run |
| `enter` | On a run: go to its files. On a file: open it. |
| `ctrl+r` | Read the runs again |

An evidence file opens with its envelope: the metadata, the evidence set and
the payload. A scan report opens as a preview of its rows.

### Find why a fetcher failed

The **Run** tab shows the first part of the error. For the full error, open the
run's `_run_metadata.json` in the run directory. The record for each fetcher
has an `error` and a `stderr_tail`. The runner removes the secret values from
both. For each field in the envelope, see the
[envelope guide](envelope_guide.md).

## 4 · Validators β

The **Validators** tab sets which validators each fetcher tracks. The left list
shows the fetchers in the manifest. The right list shows the validators for the
selected fetcher, in a Paramify section and a community section. Each validator
shows its latest result in Paramify.

| Key | What it does |
|---|---|
| `←` `→` | Move between the fetchers and the validators |
| `space` | Track or untrack the selected validator |
| `a` | Set the fetcher back to its default validators |
| `enter` | Open the validator window |

By default, an entry tracks every Paramify-made validator for its evidence set.
Your first change writes the exact list to the entry's `validators:`. If you
untrack a validator, the status counts stop including it. The TUI does not
remove it from Paramify. Read
[choosing validators](run_manifest_guide.md#choose-the-validators-each-fetcher-tracks).

### The validator window

The validator window shows:

- the validator's latest result in Paramify
- a test of the validator on your latest run
- the regex, the rules, the evidence sets and the file

| Key | What it does |
|---|---|
| `t` | Test the validator on your latest run again |
| `a` | Ask Claude why the validator fails, and for a fix (see below) |
| `c` | Copy the report that Ask Claude sends: the validator, the evidence it read, and the result |
| `w` | Write Claude's fix to the validator file (it asks first) |
| `space` | Track or untrack the validator |
| `esc` or `q` | Close the window. While Claude works, `esc` stops Claude. |

> **Note:** `a` has two meanings. On the tab, `a` sets the defaults. In the
> window, `a` asks Claude.

The test runs the regex with Node, because Paramify runs validators as
JavaScript. If Node is not installed, the window tells you to install it
(`brew install node`).

**Ask Claude** needs the `claude` command (Claude Code) on your `PATH`. Before
the first request in a session, the window shows what it will send and asks
you. The TUI tests Claude's fix on your run before it shows the fix. `w`
appears only for a fix that passes on every file. To turn off Ask Claude, set
`PARAMIFY_ASK_CLAUDE=0`. Without Claude Code, use `c` and paste the report into
a different tool.

After `w`, send the fix to Paramify with `v` on the **Paramify** tab.

## 5 · Paramify

The **Paramify** tab shows what Paramify has for each evidence fetcher in the
manifest. It needs `PARAMIFY_API_TOKEN` or `PARAMIFY_UPLOAD_API_TOKEN`. For
the permissions that each feature needs, see the
[API key permissions](../uploaders/paramify_evidence/README.md).

The tab has two views. Press `[` and `]` to change the view.

- **By fetcher:** one row for each fetcher, with its evidence set, script,
  validators, linked capabilities, artifacts, and if it is ready. Below the
  grid, the selected fetcher's evidence set and the capabilities that its
  validators prove.
- **By capability:** the solution capabilities, and the validator and evidence
  pairs that prove each one.

| Key | What it does |
|---|---|
| `[` `]` | Change the view |
| `/` | Filter the rows |
| `w` | Hide the fetchers that are ready. Press again to show all. |
| `ctrl+r` | Read the workspace again |
| `u` | Upload the newest run that has evidence |
| `s` | Sync the fetcher scripts to their evidence sets |
| `v` | Sync the validators: make, pair and update them |

`u`, `s` and `v` each show a plan first, and change nothing until you confirm.
Only one of them can run at a time. Read
[upload a run](uploader_guide.md) and
[sync scripts and validators](uploader_guide.md#5-sync-scripts-and-validators-optional).

Paramify links validator and evidence pairs to capabilities. You make these
links in the Paramify app. The TUI shows them, but it does not make them.

## 6 · Pipelines β

The **Pipelines** tab sends scan reports into Paramify's assessment pipelines.
It lists the manifest's scan-report fetchers and the reports from the newest
run.

| Key | What it does |
|---|---|
| `i` | Send the scan reports to their assessments' pipelines, and process them (it asks first) |
| `j` | Show the recent pipeline jobs, newest first. Press `enter` on a failed or queued job to retry or cancel it. |
| `C` | Close the current cycle of an assessment (it asks first) |
| `ctrl+r` | Read the runs again |

> **Caution:** A closed cycle cannot open again. When a cycle closes, Paramify
> closes each open issue that the cycle did not see.

To point a scan-report fetcher at an assessment, use `A` on the **Fetchers**
tab. Read the [pipelines guide](pipelines_guide.md).

## The environment view

Press `E`, or select **env** on the **Fetchers** tab. The view lists the
variables that the manifest needs and that have no value. It puts them in two
groups: variables that stop a run, and variables that stop an upload. It shows
only the variable names, never the values.

Select **Add blank lines to .env** to write the missing names to the `.env` at
the repo root. Then put a value after each `=`. When you close the view, the
TUI reads the environment again.

The CLI equivalent is `paramify env -m <manifest>`
([CLI guide](cli_guide.md)).

## Updates

When a newer version is on your branch, the header shows a notice, for example
`↑ 2 new commits on main · press U`. Press `U` to open the update screen. It
shows the same plan as `paramify update`: the change in version, whether your
manifests still pass, which of your fetchers change, and what breaks.

Select **Apply** to update. If the update breaks something in your clone, the
TUI asks a second time. After the update, restart the TUI. Read the
[versioning guide](versioning_guide.md#update-with-paramify-update).

`u` also opens the update screen, except on the **Paramify** tab, where `u`
uploads.

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| A key does nothing | A text field has focus. Press `esc`, then press the key again. |
| The run does not start, and the environment view opens | A variable has no value. Set it in your shell or in the repo-root `.env`, then press `ctrl+r`. |
| `A` says "Add a scan report first" | The selected entry is not a scan-report fetcher, or the manifest has none. |
| The **Paramify** tab shows an error about the token | Set `PARAMIFY_API_TOKEN` or `PARAMIFY_UPLOAD_API_TOKEN`, then press `ctrl+r`. |
| The validator test says Node is not installed | Install Node (`brew install node`), then press `t`. |
| `a` in the validator window says Claude is not installed | Install Claude Code, or press `c` to copy the report. |
| After an update, the TUI shows old behavior | Restart the TUI. |
