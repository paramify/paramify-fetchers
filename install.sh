#!/usr/bin/env bash
# Install paramify-fetchers: clone the repo, install the `paramify` CLI into a
# virtualenv inside the clone, and link it into ~/.local/bin.
#
#   curl -fsSL https://raw.githubusercontent.com/paramify/paramify-fetchers/main/install.sh | bash
#
# Set these to change the defaults, e.g. `curl ... | PARAMIFY_REF=v0.6.0-beta bash`:
#   PARAMIFY_DIR       where to clone                        (~/paramify-fetchers)
#   PARAMIFY_REF       branch or release tag to clone        (main)
#   PARAMIFY_EXTRAS    pip extras, e.g. all,azure; '' = CLI  (all)
#   PARAMIFY_REPO_URL  repo to clone                         (the GitHub repo)
#
# In a terminal it shows progress and offers to add ~/.local/bin to your PATH
# and to open the TUI. Without one (CI, scripts) it prints plain lines and asks
# nothing. NO_COLOR turns colour off. It uses uv for the install when uv is on
# your PATH, and pip otherwise.
#
# Running it again reinstalls into an existing clone and leaves its code alone.
# Everything is inside main(), so a download cut short runs nothing.

set -euo pipefail

main() {
  local dir="${PARAMIFY_DIR:-$HOME/paramify-fetchers}"
  local ref="${PARAMIFY_REF:-}"
  local extras="${PARAMIFY_EXTRAS-all}"
  local repo="${PARAMIFY_REPO_URL:-https://github.com/paramify/paramify-fetchers.git}"
  local bin_dir="$HOME/.local/bin"

  setup_terminal
  printf '\n%s\n\n' "$(bold "paramify-fetchers installer")"

  # Prerequisites.
  command -v git >/dev/null 2>&1 || die "git is not installed." "$(hint git)"
  local python="" has_uv=""
  command -v uv >/dev/null 2>&1 && has_uv=1
  if python="$(find_python)"; then
    ok "Python $(py_version "$python") and git"
  elif [ -n "$has_uv" ]; then
    ok "git (no Python 3.11+ on your PATH, so uv will provide Python $UV_PYTHON)"
  else
    die "Python 3.11 or later is required, and none is on your PATH." "$(hint python)"
  fi

  # The clone.
  if [ -d "$dir/.git" ] && [ -d "$dir/framework" ]; then
    ok "Using the existing clone at $(tilde "$dir")"
  elif [ -e "$dir" ]; then
    die "$(tilde "$dir") exists and is not a paramify-fetchers clone." "Set PARAMIFY_DIR to install somewhere else."
  else
    run_step "Cloning to $(tilde "$dir")" git clone --quiet ${ref:+--branch "$ref"} "$repo" "$dir"
    ok "Cloned paramify-fetchers $(project_version "$dir") to $(tilde "$dir")" "$STEP_SECS"
  fi

  # The virtualenv and dependencies.
  local installer="pip" venv="$dir/.venv"
  [ -z "$has_uv" ] || installer="uv"
  # A virtualenv on an older Python (left by an earlier manual install, say)
  # can't install this project, so rebuild it.
  if [ -x "$venv/bin/python" ] && ! "$venv/bin/python" -c "$PY_OK" >/dev/null 2>&1; then
    ok "Replacing .venv, which uses Python $(py_version "$venv/bin/python")"
    rm -rf "$venv"
  fi
  if [ ! -x "$venv/bin/python" ]; then
    if [ -n "$python" ]; then
      "$python" -m venv "$venv" >/dev/null 2>&1 \
        || die "Could not create a virtualenv with $python." "$(hint venv "$python")"
    else
      # --seed puts pip in the venv too, for anyone who later runs .venv/bin/pip.
      run_step "Getting Python $UV_PYTHON with uv" uv venv --quiet --seed --python "$UV_PYTHON" "$venv"
      ok "Installed Python $(py_version "$venv/bin/python") with uv" "$STEP_SECS"
    fi
  fi
  local target="."
  [ -z "$extras" ] || target=".[$extras]"
  run_step "Installing dependencies with $installer" install_deps "$dir" "$target" "$installer"
  ok "Installed dependencies with $installer" "$STEP_SECS"

  # The link onto PATH.
  mkdir -p "$bin_dir"
  if [ -e "$bin_dir/paramify" ] && [ ! -L "$bin_dir/paramify" ]; then
    die "$(tilde "$bin_dir")/paramify exists and is not a link from this installer." "Remove it, then run this again."
  fi
  ln -sfn "$dir/.venv/bin/paramify" "$bin_dir/paramify"
  ok "Linked paramify into $(tilde "$bin_dir")"
  local total=$SECONDS  # before any question, so think time isn't counted

  # PATH: offer to add ~/.local/bin to the shell profile.
  local cmd="paramify" new_terminal=""
  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *)
      local profile line
      profile="$(shell_profile)"
      line="$(path_line)"
      if [ -n "$profile" ] && [ -f "$profile" ] && grep -qF "$line" "$profile"; then
        new_terminal=1
      elif [ -n "$profile" ] && [ -n "$INTERACTIVE" ] \
        && ask "Add $(tilde "$bin_dir") to your PATH in $(tilde "$profile")?"; then
        mkdir -p "$(dirname "$profile")"
        printf '\n# Added by the paramify-fetchers installer\n%s\n' "$line" >>"$profile"
        ok "Added $(tilde "$bin_dir") to your PATH in $(tilde "$profile")"
        new_terminal=1
      else
        cmd=".venv/bin/paramify"
        printf '\n  %s is not on your PATH. To run paramify from anywhere, add this to your shell profile:\n' "$(tilde "$bin_dir")"
        printf '    %s\n' "$line"
      fi
      ;;
  esac

  printf '\n  %s %s\n' "$(green "Done")" "$(dim "in ${total}s")"

  # Offer the TUI, or say how to start.
  if [ -n "$INTERACTIVE" ] && "$dir/.venv/bin/python" -c 'import textual' >/dev/null 2>&1 \
    && ask "Open the paramify TUI now?"; then
    printf '\n  Next time: %s\n\n' "$(bold "cd $(tilde "$dir") && $cmd tui")"
    cd "$dir"
    exec .venv/bin/paramify tui </dev/tty >/dev/tty 2>&1
  fi
  printf '\n  Try it (no credentials needed):\n'
  [ -z "$new_terminal" ] || printf '    %s\n' "$(dim "# open a new terminal first, so PATH is updated")"
  printf '    %s\n' "$(bold "cd $(tilde "$dir")")"
  printf '    %s\n\n' "$(bold "$cmd run examples/demo.yaml")"
}

install_deps() {
  local dir="$1" target="$2" installer="$3"
  cd "$dir"
  if [ "$installer" = uv ]; then
    uv pip install --quiet --python .venv/bin/python -e "$target"
  else
    .venv/bin/python -m pip install --quiet --disable-pip-version-check -e "$target"
  fi
}

# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

setup_terminal() {
  TTY_OUT="" COLOR="" INTERACTIVE="" STEP_SECS=0 STEP_PID=""
  [ -t 1 ] && TTY_OUT=1
  if [ -n "$TTY_OUT" ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then COLOR=1; fi
  # Questions read the terminal itself: under `curl | bash`, stdin is the script.
  if [ -n "$TTY_OUT" ] && [ -z "${CI:-}" ] && (exec </dev/tty) 2>/dev/null; then INTERACTIVE=1; fi
  STEP_LOG="$(mktemp "${TMPDIR:-/tmp}/paramify-install.XXXXXX")"
  trap 'cleanup' EXIT
  trap 'cleanup; printf "\n"; exit 130' INT TERM
}

cleanup() {
  [ -z "$STEP_PID" ] || kill "$STEP_PID" 2>/dev/null || true
  [ -z "$TTY_OUT" ] || printf '\033[?25h'
  rm -f "$STEP_LOG"
}

# Runs a command with a spinner and elapsed time, and sets STEP_SECS. On failure
# it shows the end of the command's output and exits.
run_step() {
  local label="$1"; shift
  local start=$SECONDS
  if [ -n "$TTY_OUT" ]; then
    local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏) i=0
    ("$@") >"$STEP_LOG" 2>&1 &
    STEP_PID=$!
    printf '\033[?25l'
    while kill -0 "$STEP_PID" 2>/dev/null; do
      printf '\r\033[K  %s %s %s' "$(cyan "${frames[i % 10]}")" "$label" "$(dim "$((SECONDS - start))s")"
      i=$((i + 1))
      sleep 0.1
    done
    printf '\r\033[K\033[?25h'
    if wait "$STEP_PID"; then STEP_PID=""; STEP_SECS=$((SECONDS - start)); return 0; fi
    STEP_PID=""
  else
    printf '  ... %s\n' "$label"
    if ("$@") >"$STEP_LOG" 2>&1; then STEP_SECS=$((SECONDS - start)); return 0; fi
  fi
  printf '  %s %s\n\n' "$(red "✗")" "$label" >&2
  tail -n 20 "$STEP_LOG" | sed 's/^/    /' >&2
  exit 1
}

# ok "message" [seconds]
ok() {
  if [ -n "${2:-}" ]; then
    printf '  %s %s %s\n' "$(green "✓")" "$1" "$(dim "(${2}s)")"
  else
    printf '  %s %s\n' "$(green "✓")" "$1"
  fi
}

# die "what went wrong" ["how to fix it"]
die() {
  printf '\n  %s %s\n' "$(red "✗")" "$1" >&2
  [ -z "${2:-}" ] || printf '    %s\n' "$2" >&2
  printf '\n' >&2
  exit 1
}

# ask "question" -> 0 for yes (the default), 1 for no.
ask() {
  local answer
  printf '\n  %s %s ' "$1" "$(dim "[Y/n]")"
  read -r answer </dev/tty || answer=n
  case "$answer" in [nN]*) return 1 ;; *) return 0 ;; esac
}

paint() { if [ -n "$COLOR" ]; then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi; }
bold() { paint 1 "$1"; }
dim() { paint 2 "$1"; }
red() { paint 31 "$1"; }
green() { paint 32 "$1"; }
cyan() { paint 36 "$1"; }

# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #

PY_OK='import sys; sys.exit(sys.version_info < (3, 11))'  # pyproject's requires-python
UV_PYTHON=3.12                                             # what uv installs when no Python fits

# Prints the first python on PATH that is 3.11 or later, newest name first, so
# a Mac whose python3 is the system 3.9 still finds Homebrew's python3.12.
find_python() {
  local candidate
  for candidate in python3.15 python3.14 python3.13 python3.12 python3.11 python3 python; do
    if "$candidate" -c "$PY_OK" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

py_version() {
  "$1" -c 'import platform; print(platform.python_version())'
}

project_version() {
  sed -n 's/^version = "\(.*\)"/v\1/p' "$1/pyproject.toml" 2>/dev/null | head -n 1
}

# The profile file for the user's login shell, or nothing for a shell we don't know.
shell_profile() {
  case "$(basename "${SHELL:-}")" in
    zsh) printf '%s' "${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash) if [ "$(uname -s)" = Darwin ]; then printf '%s' "$HOME/.bash_profile"; else printf '%s' "$HOME/.bashrc"; fi ;;
    fish) printf '%s' "$HOME/.config/fish/config.fish" ;;
  esac
}

path_line() {
  # shellcheck disable=SC2016  # written literally, for the shell to expand later
  case "$(basename "${SHELL:-}")" in
    fish) printf '%s' 'fish_add_path $HOME/.local/bin' ;;
    *) printf '%s' 'export PATH="$HOME/.local/bin:$PATH"' ;;
  esac
}

# The command that installs what's missing on this OS.
hint() {
  local what="$1" os pm=""
  os="$(uname -s)"
  if command -v apt-get >/dev/null 2>&1; then pm=apt
  elif command -v dnf >/dev/null 2>&1; then pm=dnf
  fi
  case "$what:$os:$pm" in
    git:Darwin:*) echo "Install it with: xcode-select --install" ;;
    git:*:apt) echo "Install it with: sudo apt install git" ;;
    git:*:dnf) echo "Install it with: sudo dnf install git" ;;
    python:Darwin:*)
      if command -v brew >/dev/null 2>&1; then echo "Install it with: brew install python@3.12"
      else echo "Install it from https://www.python.org/downloads/ (or with Homebrew: brew install python@3.12)"; fi ;;
    python:*:apt) echo "Install it with: sudo apt install python3.12 python3.12-venv" ;;
    python:*:dnf) echo "Install it with: sudo dnf install python3.12" ;;
    venv:*:apt) echo "Install the venv module with: sudo apt install python$("$2" -c 'import sys; print("%d.%d" % sys.version_info[:2])')-venv" ;;
    *) echo "Install it with your system's package manager, then run this again." ;;
  esac
}

# Shows a path under $HOME as ~/...
tilde() {
  # shellcheck disable=SC2088  # a literal ~ for display
  case "$1" in
    "$HOME"/*) printf '~/%s' "${1#"$HOME"/}" ;;
    *) printf '%s' "$1" ;;
  esac
}

main "$@"
