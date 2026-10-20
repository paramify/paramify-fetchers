# Working in a private copy

You want to build fetchers for your own environment without publishing that work,
and you still want Paramify's improvements as they ship. This guide covers how.

**Don't fork this repo — mirror it.** Keep a private copy in your own
organization, add Paramify's repo as a git *remote*, and merge our release tags
into your work. A GitHub fork is not what delivers upstream changes; a remote is.
The fork relationship only adds GitHub's "Compare & pull request" button, and it
costs you your privacy to get it.

This repo is public, so reading it needs no token, invitation, or access grant
from us. Nothing below requires Paramify to give you anything.

## Why not a fork

Two things about GitHub forks are worth knowing before anyone clicks the button.

**A fork of a public repo is public, permanently.** Forks inherit the upstream's
visibility, and GitHub disables the visibility setting on forks — there is no
"make it private later." The only escape is asking GitHub Support to detach the
fork, which severs the relationship entirely and leaves you with a private copy
you could have made directly. (The private forks your team may remember are a
GitHub Enterprise feature for *internal* repos; they don't apply to a public
upstream like this one.)

**Commits pushed to a fork are recoverable from the public upstream, forever.**
Every commit in a fork network stays reachable by SHA from every other repo in
that network, including ours. Deleting the branch, deleting the whole fork, or
force-pushing over it does not revoke access. If a credential lands in a commit,
no later push can take it back.

That second point matters more here than in an average repo, because fetcher code
is not generic. It carries your tenant and subscription IDs, your resource group
and endpoint names, and the population scope of each control. If you keep control
narratives alongside the code, it also carries your boundary's stated exceptions
and limitations. In a public fork, all of that is a searchable description of
your compliance posture.

A private mirror has none of these properties, and costs you nothing you need.

## What you'll end up with

```
        paramify/paramify-fetchers        public — Paramify's repo, source of releases
                 │
      ┌──────────┴───────────┐
      │  a git remote         │  a real GitHub fork
      │  (read-only, no fork) │  (optional — most teams never need one)
      ▼                       ▼
 your-org/paramify-fetchers    your-org/paramify-fetchers
   PRIVATE — your real work      PUBLIC — stays empty except for
   • your own `main`               scrubbed branches you deliberately
   • your fetchers and configs      send us as pull requests
   • your Paramify contact
     invited as a collaborator
```

The private repo is where everything happens. The public fork, if you ever create
one, holds nothing sensitive.

## 1. Create your private copy

Create an empty private repository in your organization — no README, no
`.gitignore`, nothing. Then copy this repo into it.

Your private copy must share **full git history** with ours. If you instead
download the files and commit them into a fresh repo, the two repos have no
commits in common, and every future update from us becomes an
`--allow-unrelated-histories` merge that conflicts in every file. That's
unworkable, and the mistake isn't obvious until your first update.

### Recommended: GitHub's importer

*Your new repo → Import code*, or **+ → Import repository**. Source URL:

```
https://github.com/paramify/paramify-fetchers.git
```

The importer copies all branches, tags, and history. No local commands, nothing
to get wrong.

### Alternative: the command line

If your GitHub instance can't reach external URLs for imports, do it in a
**throwaway bare clone** — not in the repo you'll be working in:

```bash
git clone --bare https://github.com/paramify/paramify-fetchers.git
cd paramify-fetchers.git
git push --mirror https://github.com/your-org/paramify-fetchers.git
cd .. && rm -rf paramify-fetchers.git      # delete it now, don't keep it around
```

The throwaway-and-delete sequence isn't ceremony. `git push --mirror` force-writes
every ref at the destination **and deletes destination refs that don't exist
locally**. Run from a directory that only knows about your own repo, it can only
ever affect your own repo. Never add this command to a repo that also has
Paramify's remote configured, and never run it from your working clone — step 2
adds a guard for exactly this.

### Then check that it worked

Tags showing up only proves tags copied. Compare the full ref lists:

```bash
git ls-remote https://github.com/paramify/paramify-fetchers.git | sort > /tmp/upstream-refs
git ls-remote https://github.com/your-org/paramify-fetchers.git | sort > /tmp/my-refs
diff /tmp/upstream-refs /tmp/my-refs
```

Differences should appear **only** in `refs/pull/*` — GitHub generates those per
repository and never copies them.

Next, confirm your repo has a default branch set, and that a fresh clone lands on
it with our history underneath:

```bash
git clone https://github.com/your-org/paramify-fetchers.git
cd paramify-fetchers
git branch --show-current     # must print a branch name, not nothing
git log --oneline -3          # must show Paramify's commits
```

Do not skip this. If your repo's default branch is unset, cloning gives you a
working copy with **no branch checked out** — and the first person to start
committing quietly begins a brand-new history with no ancestor in common with
ours. That produces the same broken state as copying files in, and the ref
comparison above won't catch it. Set the default branch in your repo's settings
before anyone clones.

Finally, invite your Paramify contact to the private repo as an **outside
collaborator**. Review, pull requests, and pairing on a fetcher all happen here,
in your repo, under your access controls. Paramify never needs access to your
systems — only to this repo, and only if you want our help in it.

## 2. Point your copy at Paramify's repo

In your working clone:

```bash
git remote add upstream https://github.com/paramify/paramify-fetchers.git

# guard: make it structurally impossible to push to Paramify's repo
git remote set-url --push upstream no_push

# keep Paramify's release tags in their own namespace
git config remote.upstream.tagOpt --no-tags
git config --add remote.upstream.fetch '+refs/tags/*:refs/tags/paramify/*'
```

Both of the last two settings prevent real problems.

**The push guard.** You now have a repo that knows about both your private repo
and ours. `no_push` means a mistyped or copy-pasted push aimed at `upstream` fails
immediately instead of sending your private branches somewhere public.

**The tag namespace.** Git keeps all tags in one flat list, with no separation by
remote. The day you tag your own `v0.4.0-beta` for an internal release and we
publish a `v0.4.0-beta` of our own, the names collide — and a plain
`git fetch upstream --tags` handles that collision badly. It prints
`! [rejected] v0.4.0-beta (would clobber existing tag)` and then **exits
successfully**. The warning scrolls past in a wall of fetch output, a script sees
exit code 0, and `git merge v0.4.0-beta` merges *your own* commit while everyone
believes they just took Paramify's release.

With the config above, our tags arrive as `refs/tags/paramify/v0.4.0-beta` and
yours stay untouched at `refs/tags/v0.4.0-beta`. They can never collide again.

## 3. Pull in Paramify releases

When Paramify publishes a release, two commands:

```bash
git fetch upstream
git merge refs/tags/paramify/v0.4.0-beta
# resolve any conflicts, run the tests, push
```

Use the full `refs/tags/paramify/...` form. It's unambiguous about whose tag
you're merging, and it's the only form that works — tags land in `refs/tags/`, so
there is no `upstream/v0.4.0-beta`. (That `remote/name` shorthand is for branches
only.)

**Merge our release tags, not `upstream/main`.** Releases here are curated rather
than cut on every merge (see [`releasing_guide.md`](releasing_guide.md) if you're curious how),
so a tag is a reviewed, named, fixed point — which is what your change-control
process wants to reference. `upstream/main` is a moving target.

To see exactly what you've changed relative to a Paramify release — useful when an
assessor asks, and worth capturing before an audit:

```bash
git diff refs/tags/paramify/v0.4.0-beta..main
```

## 4. Organizing your work

| Branch | What it holds |
|---|---|
| `main` | Your integration branch and your default branch: your fetchers, manifests, and config, plus merged Paramify releases |
| `feat/*` | One per fetcher or change, opened as a pull request into `main` |

One long-lived branch is deliberate. It's tempting to keep `main` as an untouched
copy of ours and work on a second branch, but the "Paramify's code vs. our code"
distinction is already carried by the remote and by the release tags. Encoding it
a second time in branch names makes your default branch the one nobody works on,
so pull requests target the wrong branch by default and GitHub's conventions fight
you the whole way. It's your repo — use your `main`.

Merge conflicts stay rare either way, because most of your work will be **new
files**: `fetchers/<tool>_<thing>/` directories and your own manifests. Conflicts
show up only where you've edited shared framework code — which is exactly where
you'd want a human looking anyway.

Several people can work different fetchers in parallel on separate `feat/*`
branches; there's no need to build a container until the fetchers themselves run
correctly.

**Your manifests are yours, and nothing ignores them.** A manifest describes
which evidence you collect, so under FedRAMP you'll usually want it in version
control — commit `manifest.yaml`, or organize several under `manifests/`, however
suits you. We deliberately ship nothing at `./manifest.yaml`, so a manifest you
create there can never conflict with one of ours on merge. Start from
[`example_manifest.yaml`](../example_manifest.yaml) or the samples in
[`examples/`](../examples).

## 5. Two things that will fight you

**Don't bump the version.** `pyproject.toml` and `CHANGELOG.md` will conflict on
every release you merge if you're also editing them. Leave the version at whatever
we shipped. If you need your own build identifier, add a SemVer local suffix —
`0.4.0-beta+yourorg.3` — which no Paramify release will ever collide with.

**Never commit a credential.** `.env` and `.env.*` are already ignored, and
nothing else in the repo should ever hold a secret. The framework resolves
`${env:VAR}` from the environment at run time, so a manifest refers to secrets *by
name* and never contains their values — that's what makes committing a manifest
safe at all. Point those names at whatever your organization already uses: Azure
Key Vault, AWS Secrets Manager, HashiCorp Vault, or environment variables injected
by your runner. See [`config_injection_guide.md`](config_injection_guide.md).

In a private repo a leaked secret is recoverable. If you ever create the public
fork described below, it isn't — so build the habit now.

## 6. If you build something worth sending back

Most of what you build will be specific to your tenant and belongs only in your
private repo. Occasionally something is genuinely general — a framework fix, or a
fetcher other teams would want. Two ways to get it to us.

**Simplest: hand it to your Paramify contact.** They already have collaborator
access to your private repo. They pull the change and land it in the public repo
through a Paramify-side branch. You need no public GitHub presence at all — worth
noting for your security review, since a public fork is itself visible in our
forks list, and "this company is building a FedRAMP evidence pipeline" is a signal
some organizations would rather not publish.

**If you'd rather send the pull request yourself:** fork
`paramify/paramify-fetchers` normally, add your fork as a third remote, and push
only a branch built on one of our releases:

```bash
git remote add fork https://github.com/your-org/paramify-fetchers.git

git checkout -b feat/azure-nsg-rules refs/tags/paramify/v0.4.0-beta
git cherry-pick <just the general-purpose commits>   # remove tenant identifiers first
git push fork feat/azure-nsg-rules
# then open the pull request against paramify/paramify-fetchers
```

Branching from our release tag rather than your `main` is the important part: the
branch cannot contain your private commits, because they were never in its
history. Cherry-pick the specific commits you mean to publish; don't merge your
work into it.

> **Never push your `main` to `fork`.** That publishes your entire private
> history, permanently, for the reasons in [Why not a fork](#why-not-a-fork).
> There is no undo.

## What Paramify commits to

Once you've made your mirror, **our published history is append-only.** No
force-pushes to `main`, no rewritten or moved tags, no history rewrites.

This matters to you directly: if we rewrote published history, your work would sit
on top of commits that no longer exist in our repo, and your next merge would
either conflict everywhere or quietly reintroduce whatever we removed — with no
clean way back. So we don't do it. If something ever makes it unavoidable, you'll
hear from us with a migration path; it won't arrive as a surprise in a `git fetch`.

## Questions your security review will ask

| Question | Answer |
|---|---|
| Can we fork it and make the fork private? | No. GitHub disables visibility changes on forks; a fork of a public repo stays public |
| Can we fork now and clean it up later? | No. Commits in a fork network stay reachable by SHA from the public upstream even after the fork is deleted |
| Does Paramify need access to our systems? | No. Only to this repo, only as an outside collaborator, and only if you want our help in it. Nothing here reaches into your environment |
| Do we need credentials or a license to read Paramify's repo? | No. It's public; `git fetch` needs no authentication |
| Does any of our code leave our organization? | Only what you deliberately push to a public fork — which is optional, and which most teams never create |
| How do we revoke Paramify's access? | Remove the outside collaborator from your private repo. Your mirror keeps working; it only needs read access to a public repo |
| Where do secrets live? | Never in the repo. Referenced by name, resolved from your secret store at run time |
