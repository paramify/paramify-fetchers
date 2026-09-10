"""Serve the sandboxed TUI over the web (textual-serve).

    python -m tools.webdemo.serve                  # http://localhost:8000
    DEMO_PUBLIC_URL=https://x.fly.dev … --port 8080

textual-serve spawns the command below once per browser session and bridges its
stdin/stdout to an xterm.js terminal over a websocket. Each session therefore
gets its own process AND its own throwaway workspace (see sandbox.py), so one
visitor deleting a manifest or running a collection cannot affect another.

`public_url` has to be the URL the browser sees, not the bind address: it is
what the websocket URL is built from, and an https public URL is what makes
that a wss:// connection. Behind Fly's TLS terminator the two differ, so it
comes from the environment.
"""

from __future__ import annotations

import argparse
import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TEMPLATES = Path(__file__).resolve().parent / "templates"
TITLE = "Paramify Fetcher Console"

# textual.js constructs xterm.js with this font list baked in and exposes no way
# to override it. Courier's block-drawing glyphs (█ ╗ ═ │ ─) do not fill their
# cell, so the PARAMIFY logo renders striped and every panel border renders as
# disconnected pipe characters. Rewriting it to the viewer's own terminal font
# fixes both, on every platform, with no font download.
XTERM_FONT_FROM = "fontFamily:\"'Roboto Mono', Monaco, 'Courier New', monospace\""
XTERM_FONT_TO = (
    'fontFamily:"ui-monospace, SFMono-Regular, \'SF Mono\', Menlo, Consolas, '
    "'DejaVu Sans Mono', 'Liberation Mono', monospace\""
)


def patched_statics() -> Path:
    """A copy of textual-serve's static tree with the terminal font rewritten.

    Fails loudly rather than silently serving the original: if a textual-serve
    upgrade changes that literal, the demo's borders quietly break, and a
    stacktrace at boot is far easier to notice than that.
    """
    import textual_serve

    source = Path(textual_serve.__file__).parent / "static"
    target = Path(tempfile.mkdtemp(prefix="fetcher-demo-static-")) / "static"
    shutil.copytree(source, target)
    atexit.register(shutil.rmtree, target.parent, True)

    script = target / "js" / "textual.js"
    text = script.read_text(encoding="utf-8")
    if XTERM_FONT_FROM not in text:
        raise SystemExit(
            "could not find xterm's font declaration in textual.js — "
            "textual-serve changed it. Update XTERM_FONT_FROM in "
            f"{__file__} (looked for: {XTERM_FONT_FROM})"
        )
    script.write_text(text.replace(XTERM_FONT_FROM, XTERM_FONT_TO), encoding="utf-8")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(prog="tools.webdemo.serve", description=__doc__)
    parser.add_argument("--host", default=os.environ.get("DEMO_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    parser.add_argument("--public-url", default=os.environ.get("DEMO_PUBLIC_URL"))
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    from textual_serve.server import Server

    public_url = args.public_url or f"http://localhost:{args.port}"
    # -u so the app's output reaches the parent unbuffered; the web driver is a
    # stdout protocol and a buffered child stalls the terminal.
    command = f"{sys.executable} -u -m tools.webdemo.sandbox"

    print(f"serving {TITLE} at {public_url}  (command: {command})", flush=True)
    Server(
        command=command,
        host=args.host,
        port=args.port,
        title=TITLE,
        public_url=public_url,
        templates_path=TEMPLATES,
        statics_path=patched_statics(),
    ).serve(debug=args.debug)


if __name__ == "__main__":
    main()
