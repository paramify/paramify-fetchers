"""Render the captured frames into a single self-contained web page.

The payload (style table, frames, scene graph) is deflated and base64'd into the
page, then inflated in the browser with DecompressionStream — 870 KB of frame
data becomes ~43 KB of markup, which keeps the demo a single file you can drop
on any static host.

Two outputs come out of render_page():
  * `standalone` — a complete document, for the repo / any static host.
  * `fragment`   — the same page without doctype/html/head/body, which is what
                   the Artifact publisher wants (it supplies that wrapper).
"""

from __future__ import annotations

import base64
import json
import zlib
from typing import Any

TITLE = "Paramify Fetcher Console"

CSS = """
:root {
  /* Page chrome: a cool, blue-biased paper so the Tokyo Night terminal reads as
     a lifted object rather than a hole in the page. */
  --ground: #eef1f6;
  --panel: #ffffff;
  --ink: #14161f;
  --ink-2: #4c5468;
  --ink-3: #7b8397;
  --rule: #d5dae4;
  --accent: #1467ff;
  --accent-soft: #e3ebff;
  /* Semantic colours are the TUI's own, so the legend and the screen agree. */
  --ok: #4a8f2f;
  --warn: #9a6b16;
  --fail: #c0304c;
  /* The terminal's own ground travels with the frames, not with the theme. */
  --term-bg: #1a1b26;
  --shadow: 0 1px 2px rgba(20, 22, 31, .06), 0 18px 44px -12px rgba(20, 22, 31, .28);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground: #0e0f16;
    --panel: #171923;
    --ink: #e6e9f2;
    --ink-2: #a2aabd;
    --ink-3: #6e7689;
    --rule: #262a37;
    --accent: #6f9dff;
    --accent-soft: #1b2440;
    --ok: #9ece6a;
    --warn: #e0af68;
    --fail: #f7768e;
    --shadow: 0 1px 2px rgba(0, 0, 0, .5), 0 24px 56px -16px rgba(0, 0, 0, .7);
  }
}
:root[data-theme="dark"] {
  --ground: #0e0f16;
  --panel: #171923;
  --ink: #e6e9f2;
  --ink-2: #a2aabd;
  --ink-3: #6e7689;
  --rule: #262a37;
  --accent: #6f9dff;
  --accent-soft: #1b2440;
  --ok: #9ece6a;
  --warn: #e0af68;
  --fail: #f7768e;
  --shadow: 0 1px 2px rgba(0, 0, 0, .5), 0 24px 56px -16px rgba(0, 0, 0, .7);
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--ground);
  color: var(--ink);
  font: 400 14px/1.55 ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
        "DejaVu Sans Mono", monospace;
  -webkit-font-smoothing: antialiased;
}

.wrap { max-width: 1480px; margin: 0 auto; padding: 34px 26px 60px; }

/* ── masthead ───────────────────────────────────────────────────────────── */
.mast { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 20px 32px;
        padding-bottom: 20px; border-bottom: 1px solid var(--rule); }
.mast-id { flex: 1 1 380px; min-width: 0; }
.eyebrow { font-size: 11px; letter-spacing: .16em; text-transform: uppercase;
           color: var(--ink-3); margin: 0 0 10px; }
h1 { font-family: Archivo, ui-sans-serif, system-ui, sans-serif;
     font-weight: 620; font-size: clamp(26px, 3.4vw, 40px); line-height: 1.08;
     letter-spacing: -.022em; margin: 0; text-wrap: balance; }
.lede { margin: 12px 0 0; max-width: 66ch; color: var(--ink-2); font-size: 13px; }
.lede b { color: var(--ink); font-weight: 600; }

.badge { flex: 0 0 auto; align-self: flex-end; max-width: 30ch;
         border-left: 2px solid var(--accent); padding: 2px 0 2px 12px;
         font-size: 11.5px; line-height: 1.5; color: var(--ink-2); }
.badge strong { display: block; color: var(--ink); font-weight: 600;
                letter-spacing: .04em; text-transform: uppercase; font-size: 10.5px; }

/* ── terminal window ────────────────────────────────────────────────────── */
.term-shell { margin-top: 26px; background: var(--panel); border: 1px solid var(--rule);
              border-radius: 10px; box-shadow: var(--shadow); overflow: hidden; }
.term-bar { display: flex; align-items: center; gap: 14px; padding: 9px 14px;
            border-bottom: 1px solid var(--rule); font-size: 11.5px; color: var(--ink-3); }
.term-cmd { color: var(--ink-2); white-space: nowrap; overflow: hidden;
            text-overflow: ellipsis; }
.term-cmd i { color: var(--accent); font-style: normal; }
.term-dim { margin-left: auto; white-space: nowrap; font-variant-numeric: tabular-nums; }

/* The grid itself. Sized in character cells measured at runtime, then scaled
   down as one block so the aspect ratio survives a narrow viewport. */
.term-scroll { background: var(--term-bg); overflow-x: auto; }
.term-scale { transform-origin: top left; }
.term { position: relative; background: var(--term-bg);
        font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
                     "DejaVu Sans Mono", monospace;
        font-size: var(--fs); line-height: var(--lh);
        font-variant-ligatures: none; letter-spacing: 0; }
.term .ln { position: relative; white-space: pre; height: var(--lh); }
.term .hot { position: absolute; appearance: none; -webkit-appearance: none;
             border: 0; padding: 0; margin: 0; font: inherit; color: inherit;
             cursor: pointer; border-radius: 2px; background: transparent;
             transition: background .12s, box-shadow .12s; }
.term .hot:hover, .term .hot:focus-visible {
  background: rgba(122, 162, 247, .17);
  box-shadow: inset 0 0 0 1px rgba(122, 162, 247, .55);
  outline: none;
}

/* ── caption + controls ─────────────────────────────────────────────────── */
.caption { display: flex; align-items: baseline; gap: 10px; padding: 13px 2px 0;
           font-size: 12.5px; color: var(--ink-2); min-height: 40px; }
.caption .mark { color: var(--accent); flex: 0 0 auto; }
.caption .txt { flex: 1 1 auto; }

.controls { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 20px 28px;
            align-items: flex-start; justify-content: space-between; }

.tour { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { display: inline-flex; align-items: baseline; gap: 7px; padding: 6px 11px;
        border: 1px solid var(--rule); background: var(--panel); color: var(--ink-2);
        border-radius: 5px; font: inherit; font-size: 12px; cursor: pointer;
        transition: border-color .12s, color .12s, background .12s; }
.chip:hover { color: var(--ink); border-color: var(--ink-3); }
.chip[aria-current="true"] { border-color: var(--accent); background: var(--accent-soft);
                             color: var(--ink); }
.chip .n { font-size: 10px; color: var(--ink-3); font-variant-numeric: tabular-nums; }
.chip[aria-current="true"] .n { color: var(--accent); }
.chip:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.legend { display: flex; flex-wrap: wrap; gap: 5px 14px; font-size: 11.5px;
          color: var(--ink-3); align-items: center; }
kbd { font: inherit; font-size: 10.5px; padding: 2px 5px; border: 1px solid var(--rule);
      border-bottom-width: 2px; border-radius: 4px; background: var(--panel);
      color: var(--ink-2); }

.foot { margin-top: 30px; padding-top: 18px; border-top: 1px solid var(--rule);
        font-size: 11.5px; color: var(--ink-3); display: flex; flex-wrap: wrap;
        gap: 6px 22px; }
.foot .sw { display: inline-flex; align-items: center; gap: 6px; }
.foot .dot { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }

.fallback { padding: 40px 20px; text-align: center; color: var(--ink-2); font-size: 13px; }

@media (prefers-reduced-motion: reduce) {
  .term .hot { transition: none; }
  .chip { transition: none; }
}
"""


def _js() -> str:
    return r"""
const $ = (s) => document.querySelector(s);
const term = $("#term"), scale = $("#scale"), styleEl = $("#frame-styles");
const caption = $("#caption-txt"), tour = $("#tour");

const grid = document.createElement("div");
grid.id = "grid";

let D = null, scene = null, timer = null, cw = 8, lh = 16;

// ── payload ─────────────────────────────────────────────────────────────── //
async function load() {
  const b64 = document.getElementById("payload").textContent.trim();
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  if (!("DecompressionStream" in window)) throw new Error("no DecompressionStream");
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
  return JSON.parse(await new Response(stream).text());
}

// One CSS class per captured style, so a span costs a class reference instead of
// an inline declaration.
function installStyles(styles) {
  const flag = (f, bit) => (f & bit) !== 0;
  styleEl.textContent = styles.map(([fg, bg, f], i) => {
    const d = [];
    if (fg) d.push("color:" + fg);
    if (bg) d.push("background:" + bg);
    if (flag(f, 1)) d.push("font-weight:700");
    if (flag(f, 2)) d.push("font-style:italic");
    if (flag(f, 4)) d.push("text-decoration:underline");
    if (flag(f, 8)) d.push("opacity:.62");
    if (flag(f, 16)) d.push("text-decoration:line-through");
    return `.s${i}{${d.join(";")}}`;
  }).join("");
}

const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

function paint(frameIndex) {
  const lines = D.frames[frameIndex];
  let html = "";
  for (let r = 0; r < D.rows; r++) {
    const line = lines[r] || [];
    // Descending z-index: where a row does paint a background (a status pill, a
    // zebra stripe, the row cursor) it must not cover the descenders of the row
    // above it, so earlier rows paint last.
    html += `<div class="ln" style="z-index:${D.rows - r}">`;
    for (const [sid, text] of line) html += `<span class="s${sid}">${esc(text)}</span>`;
    html += "</div>";
  }
  grid.innerHTML = html;
}

// ── layout: measure one character cell, then scale the block to fit ─────── //
function measure() {
  const probe = document.createElement("div");
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
  probe.className = "ln";
  probe.textContent = "M".repeat(100);
  grid.appendChild(probe);
  cw = probe.getBoundingClientRect().width / 100;
  lh = parseFloat(getComputedStyle(term).lineHeight);
  probe.remove();
  term.style.background = D.bg;
  $("#scroll").style.background = D.bg;
  term.style.width = D.cols * cw + "px";
  term.style.height = D.rows * lh + "px";
  fit();
}

function fit() {
  const avail = $("#scroll").clientWidth;
  const natural = D.cols * cw;
  // Shrink to fit, but stop at a floor and let the strip scroll instead —
  // scaling a 160-column grid into a phone width makes the text illegible.
  const k = Math.max(0.55, Math.min(1, avail / natural));
  scale.style.transform = `scale(${k})`;
  scale.style.height = D.rows * lh * k + "px";
  scale.style.width = natural + "px";
}

// ── scenes ──────────────────────────────────────────────────────────────── //
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

function go(name) {
  if (!D.scenes[name]) return;
  clearTimeout(timer);
  scene = name;
  const sc = D.scenes[name];
  // replaceState, not a hash assignment: the demo would otherwise stack a
  // history entry for every screen and swallow the browser's back button.
  history.replaceState(null, "", "#" + name);
  caption.textContent = sc.hint || "";
  for (const chip of tour.children)
    chip.setAttribute("aria-current", String(chip.dataset.scene === String(sc.tab)));
  if (sc.frames.length === 1 || reduced) {
    paint(sc.frames[sc.frames.length - 1]);
    hotspots(sc);
    if (reduced && sc.next) { scene = sc.next; go(sc.next); }
    return;
  }
  play(sc, 0);
}

function play(sc, i) {
  paint(sc.frames[i]);
  // Hotspots only once the sequence has settled: a click target that moves
  // under the pointer mid-animation is worse than none.
  hotspots(i === sc.frames.length - 1 ? sc : null);
  const wait = Array.isArray(sc.durations) ? sc.durations[i] : sc.durations || 160;
  timer = setTimeout(() => {
    if (i + 1 < sc.frames.length) return play(sc, i + 1);
    if (sc.next) return go(sc.next);
    if (sc.loop_from != null) return play(sc, sc.loop_from);
    hotspots(sc);
  }, wait);
}

function hotspots(sc) {
  for (const el of [...grid.parentElement.querySelectorAll(".hot")]) el.remove();
  if (!sc) return;
  for (const spot of sc.hotspots || []) {
    const [row, col, w, h] = spot.rect;
    const el = document.createElement("button");
    el.className = "hot";
    el.type = "button";
    el.tabIndex = 0;
    el.setAttribute("aria-label", "open " + spot.go.replace(".", ": "));
    el.style.left = col * cw + "px";
    el.style.top = row * lh + "px";
    el.style.width = w * cw + "px";
    el.style.height = h * lh + "px";
    el.addEventListener("click", () => go(spot.go));
    term.appendChild(el);
  }
}

addEventListener("keydown", (e) => {
  const sc = D.scenes[scene];
  if (!sc || e.metaKey || e.altKey) return;
  const key = (e.ctrlKey ? "Control+" : "") + e.key;
  const target = (sc.keys || {})[key];
  if (target) { e.preventDefault(); go(target); }
});

addEventListener("resize", () => { fit(); hotspots(D.scenes[scene]); });

addEventListener("hashchange", () => {
  const asked = decodeURIComponent(location.hash.slice(1));
  if (D && D.scenes[asked] && asked !== scene) go(asked);
});

// ── boot ────────────────────────────────────────────────────────────────── //
load().then((data) => {
  D = data;
  term.appendChild(grid);
  installStyles(D.styles);
  for (const [i, label] of D.tabs.entries()) {
    const chip = document.createElement("button");
    chip.className = "chip";
    chip.type = "button";
    chip.dataset.scene = String(i);
    chip.innerHTML = `<span class="n">${i + 1}</span>${label}`;
    chip.addEventListener("click", () => go(D.tabScenes[i]));
    tour.appendChild(chip);
  }
  // A #scene fragment opens straight onto that screen, so a particular view
  // can be linked to directly.
  const asked = decodeURIComponent(location.hash.slice(1));
  const start = D.scenes[asked] ? asked : D.start;
  paint(D.scenes[start].frames[0]);
  measure();
  go(start);
}).catch((err) => {
  $("#scroll").innerHTML =
    '<p class="fallback">This demo needs a browser with DecompressionStream ' +
    "(Chrome 80+, Safari 16.4+, Firefox 113+).</p>";
  console.error(err);
});
"""


def render_page(frames, scenes: dict[str, Any], cols: int, rows: int,
                tab_labels: list[str], tab_scenes: list[str],
                start: str = "welcome") -> tuple[str, str]:
    payload = {
        "cols": cols,
        "rows": rows,
        "styles": frames.styles,
        "frames": frames.frames,
        "scenes": scenes,
        "tabs": tab_labels,
        "tabScenes": tab_scenes,
        "start": start,
        "bg": frames.bg,
    }
    blob = base64.b64encode(
        zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 9)
    ).decode()

    body = f"""<title>{TITLE}</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;620&display=swap">
<style>{CSS}
.term {{ --fs: 13px; --lh: 13px; }}
</style>

<div class="wrap">
  <header class="mast">
    <div class="mast-id">
      <p class="eyebrow">Paramify &middot; fetchers &middot; terminal console</p>
      <h1>Fetcher Console</h1>
      <p class="lede">Five tabs: browse the fetcher catalog, assemble a run manifest,
      watch a collection stream in, read the evidence it produced, and push it to
      Paramify. <b>Click the screen</b> or use the keys below.</p>
    </div>
    <p class="badge"><strong>Static demo</strong>Every frame was recorded from the
    real terminal UI. The tenant is fictional and nothing here calls a live API.</p>
  </header>

  <div class="term-shell">
    <div class="term-bar">
      <span class="term-cmd"><i>$</i> paramify tui --manifest manifests/aws-prod.yaml</span>
      <span class="term-dim">{cols}&times;{rows}</span>
    </div>
    <div class="term-scroll" id="scroll">
      <div class="term-scale" id="scale"><div class="term" id="term"></div></div>
    </div>
  </div>

  <p class="caption"><span class="mark">&rsaquo;</span><span class="txt" id="caption-txt"></span></p>

  <div class="controls">
    <div class="tour" id="tour"></div>
    <div class="legend">
      <span><kbd>1</kbd>&ndash;<kbd>5</kbd> tabs</span>
      <span><kbd>&uarr;</kbd><kbd>&darr;</kbd> rows</span>
      <span><kbd>enter</kbd> open</span>
      <span><kbd>esc</kbd> back</span>
      <span><kbd>/</kbd> filter</span>
      <span><kbd>a</kbd> add</span>
      <span><kbd>p</kbd> preview</span>
      <span><kbd>ctrl</kbd>+<kbd>r</kbd> run</span>
    </div>
  </div>

  <footer class="foot">
    <span class="sw"><span class="dot" style="background:var(--ok)"></span>collected</span>
    <span class="sw"><span class="dot" style="background:var(--warn)"></span>partial or skipped</span>
    <span class="sw"><span class="dot" style="background:var(--fail)"></span>failed</span>
    <span>183 fetchers &middot; 14 categories</span>
  </footer>
</div>

<style id="frame-styles"></style>
<script type="application/octet-stream" id="payload">{blob}</script>
<script>{_js()}</script>
"""

    # The Artifact publisher supplies doctype/head/body itself, so `fragment`
    # is the page as written; `standalone` adds the wrapper for a static host.
    standalone = (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<style>:root{color-scheme:light dark}body{margin:0}</style>\n"
        "</head>\n<body>\n" + body + "</body>\n</html>\n"
    )
    return standalone, body
