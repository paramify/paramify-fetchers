# Hosted sandbox — Fly.io

The real terminal console, running in a browser, with every destructive and
outbound path removed. Complements `tools/webdemo/` (the static frame-replay
demo): that one is free and always up, this one lets someone actually drive the
app.

    fly launch --no-deploy --copy-config --config deploy/fly/fly.toml
    fly deploy --config deploy/fly/fly.toml --dockerfile deploy/fly/Dockerfile

Run both **from the repo root** — the Dockerfile copies from the repo, so the
build context has to be the repo, not `deploy/fly/`.

Locally, no Fly involved:

    docker build -f deploy/fly/Dockerfile -t fetcher-demo .
    docker run --rm -p 8000:8000 fetcher-demo      # http://localhost:8000

Or without Docker: `pip install -e ".[tui,webdemo]"` then
`python -m tools.webdemo.serve`.

## Shape

`textual-serve` spawns **one process per browser session** and bridges its
stdin/stdout to xterm.js over a websocket. Each of those processes gets its own
throwaway workspace under `/tmp`, copied from the one baked into the image, and
deleted when the socket closes. Verified: three concurrent sessions, three
separate workspaces, nothing left behind afterwards.

So a visitor's edits are *real* edits — add a fetcher, add targets, save,
delete a manifest — to a copy nobody else sees. Reloading the page is the reset
button.

## What makes it safe to expose

| Path | In the sandbox |
| --- | --- |
| `api.run` | Replaced. Writes the same fabricated envelopes and a real `_run_metadata.json`, paced so the run tab streams — but spawns no subprocess, so the aws CLI / kubectl / checkov are never invoked (and are not in the image). |
| `api.upload_run`, `api.issues_upload_run`, `api.scripts_sync` | Replaced with a refusal that says so in the log pane. |
| `api.list_programs`, `api.list_assessments` | Canned Acme assessments, so the assessment picker works without an API call. |
| Everything else | Real. |
| Outbound TCP | Severed process-wide (`sandbox.block_network`). That list above is only correct as of today; a future TUI change that adds an API call raises here instead of quietly reaching a real tenant from a public URL. |
| Tenant data | Fabricated. Fictional "Acme" across two GovCloud accounts. Our own `evidence/` and `manifests/` are not in the image — the Dockerfile copies an explicit list of paths rather than `COPY . .`. |
| Filesystem | Server and sessions run as uid 10001; `/app` and the baked template are root-owned, so a session can only write inside its own `/tmp` copy. |
| Credentials | The only tokens present are strings like `demo-upload-token-not-real`, set so the manifests validate and the Paramify tab has something to render. |

## Cost and abuse

`min_machines_running = 0` with `auto_stop_machines = "suspend"` means it sleeps
between visitors and a machine only runs while someone is using it. The first
hit after an idle period pays a second or so of wake-up, which lands on the
"starting a private workspace" card the page already shows.

Concurrency — not requests/sec — is the resource that matters, because each
session is a ~90 MB process. `[http_service.concurrency]` caps it at 10
connections on a 1 GB machine, which is what keeps a public URL from being
turned into a fork bomb. Raise the memory before raising the limit.

## Performance

It was unusably laggy on the first deploy — 12 s to first paint, keystrokes
unanswered. Two causes, both measured rather than guessed (the scripts are
throwaway; drive `/ws` with aiohttp and count bytes, don't try to eyeball it
in a headless browser):

**The welcome screen animated forever.** `WelcomeScreen` runs
`set_interval(1/30, self._tick)` for the life of the screen and repaints the
whole PARAMIFY logo every frame. The logo is 369 separately-styled spans, so
each repaint is ~15 KB of truecolor escapes: the screen streams **366 KB/s
while nobody is touching it**, and both the app and textual-serve's parent pay
to encode and forward it. The render itself is only ~0.9% of a core — the cost
is entirely in the bytes. `sandbox.freeze_welcome_sheen()` drops the reveal to
12 fps and cancels the timer once it has played.

**Every session re-scanned the catalog.** Walking and jsonschema-validating
183 `fetcher.yaml` files at startup, per session. The tree is read-only in the
image, so `--build-template` now pickles one scan to `/srv/discovery.pickle`
and `sandbox.use_cached_discovery()` rebinds the four discovery functions on
`framework.api` to serve it.

Also moved the machine from `iad` to `sjc` (`den` is deprecated), worth ~40 ms
per keystroke from Utah.

| | before | after |
| --- | --- | --- |
| first paint, one session | 12,036 ms | 1,405 ms |
| keystroke → paint, one session | no response | **88 ms** |
| first paint, 3 at once | never | 3,614 ms |
| keystroke → paint, 3 at once | no response | 123–211 ms |
| welcome screen, idle | 366 KB/s, forever | 112 KB/s for 4.5 s, then **0** |

Knobs, all env vars with the defaults in `fly.toml`: `DEMO_SHEEN_SECONDS`,
`DEMO_SHEEN_FPS`, `DEMO_MAX_FPS` (textual-serve forces `TEXTUAL_FPS=60`;
the sandbox resets it before textual is imported), `DEMO_RUN_STEP`.

88 ms is essentially the round trip, so the remaining lever is the machine:
three *simultaneous* cold starts still take ~3.6 s, which is Python and Textual
importing three times on a shared vCPU. `shared-cpu-2x` would roughly halve it.
Left at `1x` because visitors do not arrive in the same 100 ms and it scales to
zero between them.

## Two things that will bite

- **`DEMO_PUBLIC_URL` must be the URL the browser loads.** textual-serve builds
  the session websocket URL from it, and only an `https` value produces
  `wss://`. Get it wrong and the page works in local testing, then hangs
  forever on "starting a private workspace" behind Fly's TLS terminator. It is
  set in `fly.toml`; change it when you rename the app.
- **The terminal font is patched at boot.** `textual.js` hard-codes
  `fontFamily: "'Roboto Mono', Monaco, 'Courier New', monospace"` with no way
  to override it, and Courier's block glyphs (`█ ╗ ═ │ ─`) do not fill their
  cell — the PARAMIFY logo renders striped and every panel border renders as
  disconnected pipes. `serve.patched_statics()` copies textual-serve's static
  tree and rewrites that literal to the viewer's own terminal font. It raises
  at boot if a textual-serve upgrade moves the string, rather than silently
  serving broken borders.
