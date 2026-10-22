# Paramify Fetchers, Part 2: Author a fetcher and sign the contract

> [!RECALL]
> Before we build: your fetcher reads an env var you exported in your shell but never declared in `fetcher.yaml`. What does the runner do with it — and which of the two test paths from Part 1 (direct invocation vs. `paramify run`) is the only one that would catch the mistake?

In Part 1 you followed a fetcher somebody else wrote. Today `paramify list` goes from 172 to 173, and the 173rd is yours.

The evidence we'll collect is one of the oldest items on any security questionnaire: TLS certificate expiry. An expired certificate is the classic silent outage — nothing breaks until the moment everything does — and "show me your certificate inventory and expiry dates" is a standing audit request. No fetcher in the catalog collects it yet, and it has a property that makes it ideal for learning the authoring path: the data source is the public TLS handshake itself. No API token, no tenant, no sandbox.

By the end of this part, you'll have authored `tls_certificate_expiry` from the template — a new fetcher *and* a new category — taken it through the same smoke-test-then-runner gauntlet as Part 1, and finished with something Part 1 never gave you: a green run. `[OK] exit=0`, envelope `status: "success"`, real certificate facts in the payload.

## What you'll build

A complete new fetcher at `fetchers/tls/certificate_expiry/`: a `fetcher.yaml` with an *empty* secrets list and two config knobs (`host`, default `paramify.com`; `port`, default 443), and a `fetcher.py` that opens one verified TLS connection using only the Python standard library and records the serving certificate — subject, issuer, validity window, subject-alternative names, and a computed `days_remaining`. You'll register a new `tls` category, watch discovery accept your YAML, smoke-test the script in both directions (success against a real host, honest failure against a fake one), and run it through the runner to a success envelope.

## Prerequisites

- **Part 1 completed** — the `paramify` CLI installed (`pip install -e .`), the repo cloned, and the mental model: four pieces, one contract, envelope at the end.
- Same toolchain as Part 1: Python 3.11+ (verified against 3.14.5).
- Network egress to `paramify.com:443`.
- Still no credentials. That's the point of this particular fetcher.

## Name first, code later

The naming scheme carries real weight here, so settle it before touching files (`docs/porting_guide.md`, step 1). The **category** is the source-system family: this evidence comes from public TLS endpoints, so the category is `tls`. The **short name** is the specific evidence: `certificate_expiry`. The globally unique fetcher name joins them: `tls_certificate_expiry`. And the *directory* is the short name only — `fetchers/tls/certificate_expiry/`, not `fetchers/tls/tls_certificate_expiry/`. The porting playbook calls naming the directory with the long form a convention violation: discovery would still find it, but every reference fetcher in the repo uses short-name directories, and the next reader's expectations matter more than the glob.

Check for a collision, then scaffold — the category directory and its `_categories` entry are both new, because no `tls` category exists yet:

```bash
test ! -d fetchers/tls/certificate_expiry && echo "path OK"
mkdir -p fetchers/tls
cp -r fetchers/_template fetchers/tls/certificate_expiry
```

A new category needs one more file: `fetchers/_categories/tls.yaml`. Categories usually carry shared connection config — Part 1's `rippling.yaml` declared `base_url` and `page_size` for every Rippling fetcher — but ours has no shared connection to describe, and a description-only file validates fine:

```yaml
description: >
  Public TLS endpoints. Certificate evidence collected by direct handshake;
  no credentials required.
```

Don't run `paramify list` yet — the copied template still says `name: <category>_<short_name>`, and those placeholders are valid YAML, so discovery would happily list a fetcher named `<category>_<short_name>`. Fill in the real YAML first.

## A `fetcher.yaml` with an empty secrets list

Replace the template's `fetcher.yaml` with the real self-description:

```yaml
name: tls_certificate_expiry
version: 0.1.0
description: Collects the serving TLS certificate for a host — subject, issuer,
  validity window, and days until expiry. Evidence for certificate lifecycle
  management.
category: tls

supports_targets: false

runtime:
  type: python
  entry: fetcher.py

output:
  type: json
  path: tls_certificate_expiry.json

secrets: []
```

That last line deserves a pause. The schema requires the `secrets` key on every fetcher (`framework/schemas/fetcher_schema.json` lists it under `required`), but it sets no minimum length — so `secrets: []` is legal, and it means something different from leaving the key out. Omission is a schema error; declared emptiness is a statement: *this fetcher reads no credentials, and that's a fact about it, not an oversight.* The runner's whitelist enforces the statement — with nothing declared, your subprocess gets the seven inherited vars, `PYTHONUNBUFFERED`, `EVIDENCE_DIR`, and whatever config you declare next.

Which brings back Part 1's trapdoor in a new costume. Our script will read `TLS_CERT_HOST` and `TLS_CERT_PORT`. Those are knobs, not credentials, so they belong in `config_schema` — and if you skip declaring them, the runner strips them and your fetcher silently collects from the default host forever. Add the knobs, below `secrets`:

```yaml
config_schema:
  host:
    type: string
    default: paramify.com
    env: TLS_CERT_HOST
    description: Hostname whose serving certificate to collect.
  port:
    type: integer
    default: 443
    env: TLS_CERT_PORT
    description: TLS port to connect to.
```

One block remains. Every fetcher carries an `evidence_set` identity — one fetcher, one evidence set (`docs/authoring_fetcher_guide.md`, step 2): the runner copies it into the envelope's metadata, and the uploader uses `reference_id` as its get-or-create idempotency key. Note what stays *out* of this block: no control mappings, no pass/fail linkage — that lives on the Paramify side, per the collect-facts principle from Part 1.

```yaml
evidence_set:
  reference_id: EVD-TLS-CERTIFICATE-EXPIRY
  name: TLS Certificate Expiry
  instructions: 'Script: fetcher.py. Opens a verified TLS connection to the
    configured host and records the peer certificate: subject, issuer,
    validity window, SANs, and computed days remaining.'
```

Now ask discovery what it thinks:

```bash
paramify list | head -1
paramify describe tls_certificate_expiry
```

```
Discovered 173 fetchers:

tls_certificate_expiry  v0.1.0  (category=tls)
  Collects the serving TLS certificate for a host — subject, issuer, validity window, and days until expiry. ...
  supports_targets: False
  config:
    - host (string, optional) default=paramify.com
    - port (integer, optional) default=443
```

One hundred eight. The catalog grew because a YAML file passed a schema — no registration, no central list to edit. Notice `describe` shows your config knobs and no secrets section at all: the empty list renders as honest silence.

The YAML makes promises; the script has to keep them.

## Collection that can defend itself

Open the copied `fetcher.py` and look at what the template actually does before you change it. It builds an empty `evidence: dict = {}`, writes it to the output path, logs success — and `main()` returns `None`, which Python's exit machinery treats as 0. Run the template unedited and you get a clean exit and a plausible evidence file containing nothing: the exact silent-empty-success Part 1 spent a section forbidding. That's not sloppiness — the template hands you the frame and leaves the two parts that make evidence trustworthy, collection and failure detection, deliberately blank. They're yours.

The collection function opens one verified connection and harvests the certificate. The stdlib does the heavy lifting: [`ssl.create_default_context()`](https://docs.python.org/3/library/ssl.html#ssl.create_default_context) verifies both the certificate chain and the hostname by default, so a connection that survives it is itself a verification result. Replace the template body — first the connect-and-capture half:

```python
def collect_certificate(host: str, port: int, failures: List[Dict[str, Any]]) -> Dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                protocol = tls.version()
    except (OSError, ssl.SSLError) as e:
        failures.append({"host": host, "port": port,
                         "type": type(e).__name__, "message": str(e)})
        logger.warning("Could not collect certificate from %s:%d: %s", host, port, e)
        return {}
```

(You'll need `import socket` and `import ssl` at the top, plus `List`/`Dict`/`Any` from `typing` — the same imports rippling's fetcher carries.) The `server_hostname=host` argument matters twice: it sends SNI so multi-tenant hosts present the right certificate, and it's the name the default context checks the certificate against. The 30-second socket timeout is the fetcher being a good citizen *inside* the runner's 600-second budget from Part 1 — fail fast, record it, move on.

What lands in `cert` is a dict — [`getpeercert()`](https://docs.python.org/3/library/ssl.html#ssl.SSLSocket.getpeercert) on a *verified* connection returns keys like `subject`, `issuer`, `notAfter`, and `subjectAltName` (on an unverified one it returns an empty dict, which is one reason we keep verification on). The validity dates are strings in a fixed C-locale format — `'Aug 14 16:12:49 2026 GMT'` — and the stdlib ships the exact converter: [`ssl.cert_time_to_seconds()`](https://docs.python.org/3/library/ssl.html#ssl.cert_time_to_seconds) turns one into integer epoch seconds. The second half of the function flattens and derives:

```python
    not_after = cert.get("notAfter", "")
    expires_epoch = ssl.cert_time_to_seconds(not_after) if not_after else None
    days_remaining = None
    if expires_epoch is not None:
        days_remaining = int((expires_epoch - datetime.now(timezone.utc).timestamp()) // 86400)

    return {
        "subject": rdns_to_dict(cert.get("subject", ())),
        "issuer": rdns_to_dict(cert.get("issuer", ())),
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "days_remaining": days_remaining,
        "subject_alt_names": [name for _, name in cert.get("subjectAltName", ())],
        "serial_number": cert.get("serialNumber"),
        "tls_protocol": protocol,
    }
```

`days_remaining` is derivation, not interpretation — arithmetic on a collected fact. What this payload deliberately lacks is a `status: "expiring_soon"` or any threshold: whether 64 days is fine or alarming is a Paramify-side judgment. The `subject`/`issuer` flattener is three lines (the cert encodes names as nested tuples of relative distinguished names):

```python
def rdns_to_dict(rdns) -> Dict[str, str]:
    flat: Dict[str, str] = {}
    for rdn in rdns:
        for key, value in rdn:
            flat[key] = value
    return flat
```

What about input that almost works? Point this at a host and port that answer TCP but don't speak TLS — port 80, say — and `wrap_socket` raises an `SSLError`, which the `except` clause converts into a ledger entry and an empty dict: recorded, not crashed. An unresolvable host fails earlier, in `create_connection`, as an `OSError` — same ledger, same honesty.

> [!DESIGN-NOTE]
> **Is an expired certificate a collection failure?**
>
> Awkwardly: yes, under this design. The default context *refuses* the handshake on an expired certificate, so the fetcher records an `SSLCertVerificationError` in `failures` and exits 1 — even though "this certificate is expired" is precisely the fact a GRC engineer wants captured. The verification error message, recorded verbatim in the ledger, *is* the evidence in that case — and deciding what it means still stays out of the fetcher.
>
> The alternative — disabling verification to collect facts about bad certificates — costs more than it looks: an unverified `getpeercert()` returns `{}`, so you'd need the binary certificate form plus a DER parser (the `cryptography` package — a new dependency, which the playbook says goes in `requirements.txt`). That's a legitimate v2 of this fetcher, and exercise 2. For v0.x we take the strict context and the honest failure.

Now `main()`. The template gives you the logging setup, the `EVIDENCE_DIR` handling, and the JSON write; the middle becomes the config reads (matching the env names you declared) and the collection call:

```python
    host = os.environ.get("TLS_CERT_HOST", "paramify.com")
    port = int(os.environ.get("TLS_CERT_PORT", "443"))

    failures: List[Dict[str, Any]] = []
    certificate = collect_certificate(host, port, failures)

    result = {
        "source": "tls",
        "host": host,
        "port": port,
        "certificate": certificate,
        "failures": failures,
        "retrieved_at": current_timestamp(),
    }
```

One piece is left, and it's the piece the template deliberately withholds: the ending. You watched `rippling_current_employees` end `main()` in Part 1 — write the file, then let the ledger decide the exit code, then wire `sys.exit(main())` at the bottom (the template's bare `main()` call discards the return value, which is how it always exits 0). Write that ending now, same pattern: log the failure count at error level if the ledger is non-empty and return 1; otherwise return 0. When you're done, a failed collection must exit 1 *and* still have written the JSON file with the failures inside it.

## The smoke test, both directions

Part 1's smoke test aimed for a *useful failure* — a 401 proving the wiring. Yours can do better, because the source is public:

```bash
EVIDENCE_DIR=/tmp/verify python fetchers/tls/certificate_expiry/fetcher.py
echo "exit: $?"
```

```
... INFO tls_certificate_expiry Evidence saved to /tmp/verify/tls_certificate_expiry.json
exit: 0
```

And the payload holds real facts (yours will differ — `days_remaining` shrinks by one every midnight UTC, which is rather the point of collecting it):

```json
"certificate": {
  "subject": {"commonName": "paramify.com"},
  "issuer": {"countryName": "US", "organizationName": "Google Trust Services", "commonName": "WE1"},
  "not_after": "Aug 14 16:12:49 2026 GMT",
  "days_remaining": 64,
  "tls_protocol": "TLSv1.3"
}
```

> [!PREDICT]
> Now the other direction: run it with `TLS_CERT_HOST=no-such-host.invalid`. Three predictions before you do — what exit code, will the JSON file still be written, and where in the file does the failure show up?

```bash
TLS_CERT_HOST=no-such-host.invalid EVIDENCE_DIR=/tmp/verify \
  python fetchers/tls/certificate_expiry/fetcher.py
echo "exit: $?"
```

```
... WARNING tls_certificate_expiry Could not collect certificate from no-such-host.invalid:443: [Errno 8] nodename nor servname provided, or not known
... ERROR tls_certificate_expiry Encountered 1 collection failures
exit: 1
```

Exit 1, file written anyway, failure recorded in the `failures` ledger with an empty `certificate` — the Part 1 pattern, now flowing from code you wrote. (The exact DNS error text is platform-specific; Linux phrases it differently than macOS.) If you got `exit: 0` here, your `main()` ending — the part you wrote — isn't consulting the ledger, or `sys.exit` isn't wired.

## Through the runner, green this time

The runner's path is the one you walked in Part 1, with one difference worth noticing at each step. Build the manifest:

```bash
paramify manifest init -f /tmp/tour2/manifest.yaml --output-dir /tmp/tour2/evidence
paramify manifest add tls_certificate_expiry -f /tmp/tour2/manifest.yaml
paramify validate /tmp/tour2/manifest.yaml
```

```
Wrote /tmp/tour2/manifest.yaml
Wrote /tmp/tour2/manifest.yaml
OK  manifest valid; 1 fetcher entries
```

No *"not yet runnable: missing secret"* warning this time. In Part 1 the builder nagged until you mapped `api_token` to an env var; your YAML declares no secrets, so the manifest is runnable the moment the fetcher is added. The config knobs need nothing either — `host` and `port` have defaults, and defaults flow in from the `config_schema` without a line of manifest config. Run it:

```bash
paramify run /tmp/tour2/manifest.yaml
```

```
Run 2026-06-10T19-27-02Z → /tmp/tour2/evidence/run-2026-06-10T19-27-02Z

  RUN   tls_certificate_expiry
        [OK] exit=0 duration=0.181s

_run_metadata.json → /tmp/tour2/evidence/run-2026-06-10T19-27-02Z/_run_metadata.json
```

Your first `[OK]`. Open the enveloped output and compare it against Part 1's failure envelope:

```json
"metadata": {
  "fetcher_name": "tls_certificate_expiry",
  "status": "success",
  "exit_code": 0,
  "evidence_set": {
    "reference_id": "EVD-TLS-CERTIFICATE-EXPIRY",
    "name": "TLS Certificate Expiry"
  }
}
```

`status: "success"`, exit code 0, no `error` field — the stderr tail only appears on failure — and the `evidence_set` block you wrote in YAML, copied verbatim into the metadata, ready for the uploader to get-or-create by `reference_id`. The contract you read in Part 1 is now a contract you've satisfied from both sides.

## Checkpoint

**Run this to verify your work so far** (repo root, venv active):

```bash
paramify list | head -1
python -m pytest tests -q
```

Expected output:

```
Discovered 173 fetchers:
..............................                                           [100%]
30 passed in 2.88s
```

The suite doesn't count fetchers — it guards the CLI/API/TUI parity from Part 1 — so passing here confirms your new category and fetcher broke nothing structural. The count line is the one that should have moved: 172 before, 173 with yours. (The absolute number grows with every release — what matters is that it moved by one.)

**Likely errors:**

- If `paramify list` shows a fetcher literally named `<category>_<short_name>`, you copied the template and ran discovery before editing `fetcher.yaml` — the placeholders are valid YAML and the schema can't tell them from real values.
- If the count still says `Discovered 172 fetchers`, discovery isn't seeing your directory: check that it's `fetchers/tls/certificate_expiry/` (a directory whose name starts with `_` is skipped by design, and a misplaced `fetcher.yaml` is invisible).
- If discovery errors with `'secrets' is a required property`, you deleted the `secrets` key instead of emptying it — the schema requires the key to exist; `secrets: []` is the declared-empty form.
- If the positive smoke test fails with `SSLCertVerificationError` against a host you trust, you're likely behind a TLS-intercepting corporate proxy — your machine sees the proxy's certificate, not the host's. Try another network, and note that this, too, is the fetcher honestly reporting what it observed.
- If the negative smoke test exits 0, your `main()` ending isn't returning 1 on a non-empty ledger, or `sys.exit(main())` isn't at the bottom — `main()` called bare discards the return value.

## What's next

Your fetcher collects from exactly one host per run, configured by a knob. But a certificate inventory wants *all* the hosts — and the framework already has the machinery for that: fan-out. In Part 3 we turn the `host` knob into a `target_schema`, let the runner invoke the fetcher once per target with per-target env vars and isolated failures, and look at how the AWS category runs the same idea at production scale with its optional `profile`/`region` targets. The question to carry there: once one fetcher runs twelve times in a single run, what should "the fetcher failed" even mean?

Before the exercises, two sentences in your own words, for a skeptical colleague: why does this fetcher exit 1 when it *can't reach* a host, but would be wrong to exit 1 because a reachable host's certificate *expires next week*? If your answer doesn't draw the line between collecting facts and interpreting them, draw it again.

## Exercises

1. **Turn the knob.** Point your manifest at a different host with `paramify manifest set-config tls_certificate_expiry host=github.com -f /tmp/tour2/manifest.yaml`, rerun, and confirm the change in the envelope payload. Then name which of the three config layers from Part 1 (category defaults ← platform values ← per-fetcher config) supplied the value this time, and which supplied it before.
2. **Collect the un-collectable.** Make a v2 that records evidence even from hosts with invalid certificates — test against `expired.badssl.com`. You'll need a second, unverified connection and the binary certificate form (an unverified `getpeercert()` returns an empty dict), plus the `cryptography` package to parse the DER bytes — which means a `requirements.txt` entry, per the playbook's category-setup rules. Keep the verified attempt as the primary record; mark the unverified one as such in the payload.
3. **Fan it out.** Convert the fetcher to `supports_targets: true` with a `target_schema` mapping `host` (required) and `port` (optional) to env vars, and set `output.aggregation: per_target`. The worked example is `fetchers/gitlab/ci_cd_pipeline_config/fetcher.yaml`. What changes about the output filenames in the run directory — and what stops making sense about your `config_schema`?
4. **Race the two timeouts.** Your socket timeout is 30 seconds; add `runtime.timeout: 30` to `fetcher.yaml` as well, then explain the difference between the two failure modes: a socket timeout lands in your ledger as exit 1, while a runner kill records exit 124 — written by the runner, because your `except` block never gets to run. Which one would you rather see in an envelope, and why?

## Sources

This part was researched from the repository working tree (branch `main`, June 10, 2026) and the Python standard library documentation; every command output shown — discovery, both smoke tests, the manifest build, the green run, and the test suite — was captured live from a real build of this fetcher, which was then removed so you can build it yourself.

**Repository docs and code**

1. [`docs/authoring_a_fetcher.md`](https://github.com/paramify/paramify-fetchers/blob/80fc0f0/docs/authoring_a_fetcher.md) — the new-vs-port decision, scaffolding steps, and the `evidence_set` identity block (one fetcher = one evidence set; no control linkage in the fetcher).
2. [`docs/porting_playbook.md`](https://github.com/paramify/paramify-fetchers/blob/80fc0f0/docs/porting_playbook.md) — the collision pre-flight, the short-name directory convention, and where new dependencies go.
3. [`docs/fetcher_contract.md`](https://github.com/paramify/paramify-fetchers/blob/80fc0f0/docs/fetcher_contract.md) — the runtime contract this part writes against: minimal env, stderr logging, exit codes 0 / non-zero / reserved 124.
4. `fetchers/_template/fetcher.yaml` and `fetcher.py` — the skeleton, including the deliberately blank failure detection this part fills in.
5. `framework/schemas/fetcher_schema.json` — `secrets` as a required key with no minimum length, which is what makes `secrets: []` legal.
6. `fetchers/_categories/rippling.yaml` and `fetchers/rippling/current_employees/fetcher.py` — Part 1's controlling example, reused here as the pattern for category config and the failure-ledger ending.

**Standard library**

7. [Python `ssl` — `create_default_context`, `getpeercert`, `cert_time_to_seconds`](https://docs.python.org/3/library/ssl.html#ssl.create_default_context) — default verification of certificate and hostname, the certificate dict's keys and date format, the empty dict on unverified connections, and the epoch converter.
