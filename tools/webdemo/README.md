# Web demos of the terminal console

Two ways to show `paramify tui` to someone who has not installed it. They share
the fabricated workspace in `fixture.py` and nothing else.

| | Static replay | Hosted sandbox |
| --- | --- | --- |
| Files | `capture.py`, `page.py` | `sandbox.py`, `serve.py`, `deploy/fly/` |
| Output | one 63 KB HTML file | a URL |
| Needs | nothing — any static host | a machine (Fly config included) |
| Interaction | a scripted tour: click the screens, watch a run stream | the real app — add fetchers, edit, save, run |
| Costs | nothing, never sleeps | a process per session, scales to zero |

Reach for the static one for a link in an email; the sandbox for someone who
wants to drive it. `deploy/fly/README.md` covers the sandbox; the rest of this
file is the static replay.

## Static replay

    python -m tools.webdemo.capture

writes two files into `tools/webdemo/dist/`:

| file                   | use                                                    |
| ---------------------- | ------------------------------------------------------ |
| `demo.html`            | complete document — drop on any static host            |
| `demo.fragment.html`   | same page without `<html>`/`<head>`/`<body>`, for the Artifact publisher |

~63 KB, one file, no server, no credentials.

## How it works

1. **`fixture.py`** builds a throwaway workspace under `/tmp` that looks like a
   repo checkout to `api.find_repo_root` — `fetchers/` and `framework/` are
   symlinked to the real tree, so the catalog tab shows the genuine fetcher
   catalog. `manifests/` and `evidence/` are fabricated: a fictional "Acme"
   tenant across two GovCloud accounts. **Our own evidence is never used** — real
   runs carry live subscription, tenant and project identifiers.

2. **`capture.py`** runs the actual `FetcherApp` headless through Textual's
   `run_test` pilot and grabs the composited character grid at each point of a
   scripted storyboard. Nothing is redrawn by hand, so the demo cannot drift
   from the TUI's real appearance — re-run the capture after a UI change and the
   page is current.

   Two scenes are animated deterministically rather than off the wall clock:
   the welcome screen's logo sheen by rewinding `WelcomeScreen._t0`, and the run
   console by feeding `api.run`-shaped event dicts into
   `RunPage._handle_event` (which the run module deliberately keeps
   worker-free).

3. **`page.py`** deflates the style table, frames and scene graph into the page
   and inflates them in the browser with `DecompressionStream`. 870 KB of frame
   data ships as ~43 KB.

## Editing the demo

- **Storyboard** — `storyboard()` in `capture.py`. Add a `scene(name, frames)`
  wherever you want a screen; drive the app with `pilot.press(...)` or by
  calling the page's own actions.
- **What's clickable** — `HOTSPOTS` in `capture.py` maps a label on screen to
  the scene a click opens. Rects are resolved by *finding the text in the
  captured grid*, and a label that no longer appears fails the capture rather
  than shipping a dead click target. `"row"` widens a hit to the enclosing
  panel border, so table rows are clickable end to end.
- **Keys** — `SCENE_KEYS`; `1`–`5` are added to every workspace scene.
- **Fictional data** — `fixture.py`. `_manifests()` checks every name against
  the live catalog, so a renamed fetcher is a capture error.

`#<scene>` in the URL opens that screen directly (`…/demo.html#evidence.file`).

## Two rendering details worth knowing

Both were visible bugs before they were fixed, and both will come back if the
CSS in `page.py` is loosened:

- **Line height must equal the font size.** Block-drawing glyphs (`█`, `╗`, `═`)
  only tile seamlessly when the line box has no extra leading — any more and the
  PARAMIFY logo and every panel border show horizontal seams.
- **Cells matching the screen background paint no background.** At that tight
  line height a cell's background box overlaps the row above it, which hid the
  descenders — every underscore in every fetcher name disappeared. The screen
  background sits on the container instead, and rows paint in descending
  z-index so the few cells that *do* carry a background (status pills, zebra
  stripes, the row cursor) still don't cover the row above.
