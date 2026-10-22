# Giving a fetcher its config and secrets

A fetcher doesn't inherit your shell's environment. The runner injects its
config and secrets from your manifest. This guide builds
[`examples/with_platform_config.yaml`](../examples/with_platform_config.yaml)
and runs it.

![Keys declared in the repo, values you set in the manifest, and paramify run merging them into the only env vars the fetcher sees](img/config_injection/flow.svg)

**You need:** [the repo installed](../README.md#install)

---

## 1. Look up the keys

`describe` lists a fetcher's config and secrets with their env vars. Platform
keys and defaults live in category files, like
[`rippling.yaml`](../fetchers/_categories/rippling.yaml).

![describe shows exclude_aws_managed_roles as boolean config and api_token as a required Rippling secret](img/config_injection/01-keys.png)

<details><summary>Copy the commands</summary>

```bash
paramify describe aws_iam_roles | grep -A2 config
paramify describe rippling_all_employees
```
</details>

## 2. Set the values

Platform config covers a category. An entry's `config` overrides it.
`set-secret` stores an env var name, never the value. AWS already passes both
passthrough variables, so `set-passthrough` here only shows the syntax.

![The manifest builder writing each value, flagging the missing api_token secret until set-secret runs](img/config_injection/02-manifest.png)

<details><summary>Copy the commands</summary>

```bash
paramify manifest init -f config.yaml
paramify manifest add aws_iam_roles -f config.yaml
paramify manifest add rippling_all_employees -f config.yaml
paramify manifest set-platform-config rippling page_size=250 -f config.yaml
paramify manifest set-config aws_iam_roles exclude_aws_managed_roles=true -f config.yaml
paramify manifest add-target aws_iam_roles profile=gov_readonly -f config.yaml
paramify manifest set-passthrough aws AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN -f config.yaml
paramify manifest set-secret rippling_all_employees api_token RIPPLING_API_TOKEN -f config.yaml
```
</details>

**Key names aren't checked.** A misspelled key is saved, passes `validate`,
and never reaches the fetcher.

A string config field can also be `${env:VAR}`, read from the environment at
run time. If `VAR` is unset or empty, the next value down applies (platform
config, then the default), and the run prints a note. Integer and boolean
fields and target fields don't take `${env:VAR}` (a target's secrets do), and
`manifest` and `validate` refuse one there.

## 3. Check it

It matches the worked example.

![manifest show printing both entries and the platforms block, then validate reporting OK](img/config_injection/03-validate.png)

<details><summary>Copy the commands</summary>

```bash
paramify manifest show -f config.yaml
paramify validate config.yaml
```
</details>

## 4. Run it

Both entries fail with a fake token, but Rippling's evidence shows
`limit=250`, not the default 100.

![paramify run failing both entries, then the Rippling evidence's error URL carrying limit=250](img/config_injection/04-run.png)

<details><summary>Copy the commands</summary>

```bash
RIPPLING_API_TOKEN=fake-token paramify run config.yaml
paramify evidence evidence/run-<timestamp>/rippling_all_employees.json
```
</details>

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Secret reference ${env:…} could not be resolved` | Export that variable in the shell that runs `paramify`. |
| `NOTE target selects AWS_PROFILE; ignored ambient credentials …` | Expected: a target's `profile:` overrides static AWS keys. Remove it to use them. |

**More detail:** [shared platform config](run_manifest_guide.md#4-set-shared-config-once)
