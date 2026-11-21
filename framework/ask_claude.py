"""Ask Claude about a failing validator: `claude -p`, no tools, streamed.

Ported from the error card (branch feat/tui-error-card), keeping only the
runner: Claude Code in print mode as a subprocess. The prompt is the validator,
how it failed on the user's own evidence, and that evidence, and it is all
Claude gets: claude runs with no tools at all, in a fresh empty folder, and
without the variables in the repo's .env or the manifest's secrets, so it can
read nothing else of the user's. The answer streams back as stream-json, one
JSON object per line, which StreamParser turns into small events a UI can
render.

Sends data to Anthropic under the user's own Claude Code login, so:
  * PARAMIFY_ASK_CLAUDE=0 turns it off (enabled()), for teams that cannot send
    data to an AI service;
  * the UI shows what it sends and asks once per session before the first call.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set

ENV_SWITCH = "PARAMIFY_ASK_CLAUDE"
ENV_MODEL = "PARAMIFY_ASK_CLAUDE_MODEL"
# No tools: the prompt already holds the validator and the evidence, and a tool
# could read (and send) any file the user can.
NO_TOOLS = ""
MAX_TURNS = 4
TIMEOUT_SEC = 150.0
INSTALL_HINT = (
    "Claude Code isn't installed here (no `claude` on PATH). Get it from "
    "https://claude.com/claude-code (npm install -g @anthropic-ai/claude-code), run `claude` once "
    "to sign in, then try again."
)
# Env vars a nested claude should not inherit: the ones that mark "inside a
# Claude Code session" and change how it starts.
_DROP_ENV = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SSE_PORT")
# Paramify's own tokens, which need not be in .env (an export works too).
_PARAMIFY_TOKENS = ("PARAMIFY_API_TOKEN", "PARAMIFY_UPLOAD_API_TOKEN")
_ENV_REF = re.compile(r"\$\{env:([^}]+)\}")


def enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """False when PARAMIFY_ASK_CLAUDE is 0/false/no/off."""
    value = (os.environ if env is None else env).get(ENV_SWITCH, "")
    return value.strip().lower() not in ("0", "false", "no", "off")


def find_claude(path: Optional[str] = None) -> Optional[str]:
    return shutil.which("claude", path=path)


def build_command(exe: str, *, max_turns: int = MAX_TURNS, model: Optional[str] = None) -> List[str]:
    """The `claude -p` invocation. The prompt goes on stdin, so the report never
    shows in a process listing."""
    cmd = [
        exe, "-p",
        "--output-format", "stream-json",
        "--verbose",                       # stream-json in print mode requires it
        "--include-partial-messages",      # token-by-token text, so the answer streams
        "--tools", NO_TOOLS,               # no tools exist in the session: it can't read a file
        "--permission-mode", "dontAsk",    # anything else is refused, never prompted
        "--max-turns", str(max_turns),
        "--strict-mcp-config",             # no MCP servers: faster start, nothing else reachable
        "--no-session-persistence",
    ]
    if model:
        cmd += ["--model", model]
    return cmd


# How much of the evidence file goes in the prompt. Validators anchor on a few
# keys, so the head of the file is nearly always enough to see its shape.
EVIDENCE_CHARS = 12_000

# The first backtick span after "Regex:"; anything after it on the line is ignored.
REGEX_LINE = re.compile(r"^[\s*]*Regex[\s*:]*`(?P<regex>[^`\n]+)`[^\n]*$", re.M)


def build_validator_prompt(validator: Mapping[str, Any], rules: Iterable[str], result: Mapping[str, Any],
                           evidence_name: str, evidence: str) -> str:
    """The question for a validator that failed on the user's own evidence.

    `rules` are the validator's rules in plain words; `result` is the
    validator_eval result (verdict and per-rule trace) on `evidence`.
    """
    traced = []
    for words, rule in zip(rules, result.get("rules") or []):
        read = "nothing" if rule.get("lhs") is None else json.dumps(rule.get("lhs"))
        traced.append(f"  {rule.get('index')}. {words}: {'holds' if rule.get('held') else 'FAILS'} (read {read})")
    shown = evidence if len(evidence) <= EVIDENCE_CHARS else evidence[:EVIDENCE_CHARS] + "\n…(cut)"
    return (
        "A Paramify validator fails on a fetcher's evidence. Work out why, and propose a corrected "
        "regex when the regex is the problem.\n\n"
        "How Paramify evaluates it: the regex is ECMAScript, compiled with the g and s flags (never m), "
        "and runs over the whole evidence file. MATCH_COUNT is the number of matches; MATCH_GROUP n is "
        "capture group n of the first match. Every rule must hold. Keep the named groups in the same "
        "order so the rules still read the right group. Do not change the rules.\n\n"
        "If the regex reads the evidence correctly and the evidence shows the control is not met, say "
        "so and propose no regex. Do not edit anything.\n\n"
        "Answer for someone who runs fetchers but did not write the validator. Plain words, under 90 "
        "words, no headings and no preamble, in exactly this shape:\n"
        "Why: one or two sentences.\n"
        "Regex: the corrected regex on one line in single backticks, or none.\n\n"
        f"Validator {validator.get('key')}: {validator.get('name')}\n"
        f"Claims: {validator.get('statement')}\n"
        f"Regex: {validator.get('regex')}\n"
        f"Result on the evidence below: {result.get('verdict')}, {result.get('matchCount', 0)} matches\n"
        "Rules:\n" + "\n".join(traced) + "\n\n"
        f"The evidence file {evidence_name}:\n\n{shown}\n"
    )


def proposed_regex(answer: str) -> Optional[str]:
    """The regex on the answer's `Regex:` line, or None when it proposes none."""
    m = REGEX_LINE.search(answer or "")
    if not m:
        return None
    regex = m.group("regex").strip()
    return regex if regex and regex.lower() != "none" else None


# --------------------------------------------------------------------------- #
# stream-json
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Event:
    kind: str  # turn | text | text_full | tool | final | error
    text: str = ""


def _tool_label(name: str, inp: Mapping[str, Any], cwd: Optional[str]) -> str:
    if name == "Read":
        target = str(inp.get("file_path") or "")
        if cwd and target.startswith(cwd.rstrip("/") + "/"):
            target = target[len(cwd.rstrip("/")) + 1:]
        return f"reading {target}" if target else "reading a file"
    if name == "Grep":
        return f"searching for {inp.get('pattern', '')!s}".rstrip()
    if name == "Glob":
        return f"looking for {inp.get('pattern', '')!s}".rstrip()
    return f"using {name}"


@dataclass
class StreamParser:
    """Turns stream-json lines into Events. Keeps just enough state to avoid
    showing a turn's text twice: once as deltas, once in the full message."""

    cwd: Optional[str] = None
    _deltas: bool = False
    _tools_seen: set = field(default_factory=set)

    def feed(self, line: str) -> List[Event]:
        line = line.strip()
        if not line:
            return []
        try:
            obj = json.loads(line)
        except ValueError:
            return []
        if not isinstance(obj, dict):
            return []
        kind = obj.get("type")
        if kind == "stream_event":
            return self._stream_event(obj.get("event") or {})
        if kind == "assistant":
            return self._assistant(obj.get("message") or {})
        if kind == "result":
            text = obj.get("result")
            if obj.get("is_error") or str(obj.get("subtype", "")).startswith("error"):
                sub = obj.get("subtype") or "error"
                if sub == "error_max_turns":
                    return [Event("error", "Claude ran out of turns before it answered.")]
                return [Event("error", str(text or (obj.get("errors") or [sub])[0]))]
            return [Event("final", str(text or ""))]
        return []

    def _stream_event(self, ev: Mapping[str, Any]) -> List[Event]:
        et = ev.get("type")
        if et == "message_start":
            self._deltas = False
            return [Event("turn")]
        if et == "content_block_delta":
            delta = ev.get("delta") or {}
            if delta.get("type") == "text_delta" and delta.get("text"):
                self._deltas = True
                return [Event("text", delta["text"])]
        return []

    def _assistant(self, msg: Mapping[str, Any]) -> List[Event]:
        out: List[Event] = []
        texts = []
        for block in msg.get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and block.get("text"):
                texts.append(block["text"])
            elif block.get("type") == "tool_use":
                tid = block.get("id") or id(block)
                if tid not in self._tools_seen:
                    self._tools_seen.add(tid)
                    out.append(Event("tool", _tool_label(str(block.get("name")), block.get("input") or {},
                                                         self.cwd)))
        if texts and not self._deltas:
            # No partial messages (an older claude): show the whole turn at once.
            out.insert(0, Event("text_full", "".join(texts)))
        return out


# --------------------------------------------------------------------------- #
# Running it
# --------------------------------------------------------------------------- #


@dataclass
class Outcome:
    answer: str = ""
    error: Optional[str] = None
    cancelled: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.answer) and not (self.error or self.cancelled or self.timed_out)


def secret_names(root: Optional[Path], manifest: Any = None) -> Set[str]:
    """The variables claude must not inherit: each one named in the repo's
    .env (set or not), each one a ${env:...} reference in the manifest reads,
    and Paramify's tokens. Names only; no value is read here."""
    names: Set[str] = set(_PARAMIFY_TOKENS)
    if root is not None:
        from framework import envgen  # lazy: keeps this module light
        path = Path(root) / ".env"
        try:
            names |= set(envgen.assigned(path.read_text()))
        except OSError:
            pass

    def walk(node: Any) -> None:
        if isinstance(node, str):
            names.update(m.strip() for m in _ENV_REF.findall(node))
        elif isinstance(node, Mapping):
            for value in node.values():
                walk(value)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value)

    walk(manifest)
    return names


def child_env(env: Optional[Mapping[str, str]] = None, drop: Iterable[str] = ()) -> Dict[str, str]:
    """The environment claude runs with: ours (PATH, HOME and the rest Claude
    Code needs to start and sign in), minus `drop`: the fetchers' secrets,
    from secret_names()."""
    out = dict(os.environ if env is None else env)
    for name in (*_DROP_ENV, *drop):
        out.pop(name, None)
    return out


def ask(
    prompt: str,
    *,
    exe: str,
    on_event: Callable[[Event], None],
    cancel: Optional[threading.Event] = None,
    timeout: float = TIMEOUT_SEC,
    model: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    drop: Iterable[str] = (),
    popen: Callable[..., Any] = subprocess.Popen,
) -> Outcome:
    """Run claude -p, stream its events to on_event, and return the outcome.

    claude runs with no tools, in a fresh empty folder removed afterwards, with
    child_env(env, drop): pass secret_names() as `drop`.

    Blocking: call it from a worker thread. Setting `cancel` (or the timeout
    passing) kills the process; the outcome says which.
    """
    with tempfile.TemporaryDirectory(prefix="paramify-ask-claude-") as cwd:
        return _ask_in(prompt, cwd=cwd, exe=exe, on_event=on_event, cancel=cancel or threading.Event(),
                       timeout=timeout, model=model, env=child_env(env, drop), popen=popen)


def _ask_in(prompt: str, *, cwd: str, exe: str, on_event: Callable[[Event], None], cancel: threading.Event,
            timeout: float, model: Optional[str], env: Dict[str, str], popen: Callable[..., Any]) -> Outcome:
    cmd = build_command(exe, model=model)
    try:
        proc = popen(cmd, cwd=cwd, env=env,
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     text=True, encoding="utf-8", errors="replace", bufsize=1)
    except OSError as exc:
        return Outcome(error=f"could not start claude: {exc}")

    state = {"timed_out": False, "cancelled": False}
    stderr_chunks: List[str] = []

    def watch() -> None:
        deadline = time.monotonic() + timeout
        while proc.poll() is None:
            if cancel.wait(0.1):
                state["cancelled"] = proc.poll() is None
                break
            if time.monotonic() > deadline:
                state["timed_out"] = True
                break
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    def drain() -> None:
        try:
            for chunk in proc.stderr:
                stderr_chunks.append(chunk)
        except (OSError, ValueError):
            pass

    watcher = threading.Thread(target=watch, daemon=True)
    drainer = threading.Thread(target=drain, daemon=True)
    watcher.start()
    drainer.start()
    try:
        proc.stdin.write(prompt)
        proc.stdin.close()
    except (OSError, ValueError):
        pass

    parser = StreamParser(cwd=cwd)
    final: Optional[str] = None
    error: Optional[str] = None
    current: List[str] = []
    try:
        for line in proc.stdout:
            for ev in parser.feed(line):
                if ev.kind == "turn":
                    current = []
                elif ev.kind == "text":
                    current.append(ev.text)
                elif ev.kind == "text_full":
                    current = [ev.text]
                elif ev.kind == "final":
                    final = ev.text
                elif ev.kind == "error":
                    error = ev.text
                on_event(ev)
    except (OSError, ValueError):
        pass
    code = proc.wait()
    cancel.set()  # stop the watcher
    watcher.join(timeout=1)
    drainer.join(timeout=1)

    if state["timed_out"]:
        return Outcome(answer="".join(current), timed_out=True, error=f"no answer after {int(timeout)}s")
    if state["cancelled"]:
        return Outcome(answer="".join(current), cancelled=True)
    answer = final if final else "".join(current)
    if error:
        return Outcome(answer=answer, error=error)
    if code != 0 and not answer:
        tail = "".join(stderr_chunks).strip().splitlines()
        return Outcome(error=(tail[-1] if tail else f"claude exited with code {code}"))
    if not answer:
        return Outcome(error="claude finished without an answer")
    return Outcome(answer=answer.strip())
