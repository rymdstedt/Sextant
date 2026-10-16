#!/bin/bash
# SessionStart hook for Claude Code cloud sessions: make pytest, ruff and the `sextant` CLI work
# immediately. Idempotent; the container state is cached after it completes.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# System libraries: WeasyPrint (PDF) needs Pango, cairosvg (diagrams in Word) needs Cairo.
missing=()
ldconfig -p | grep -q "libpango-1.0.so" || missing+=(libpango-1.0-0)
ldconfig -p | grep -q "libpangoft2-1.0.so" || missing+=(libpangoft2-1.0-0)
ldconfig -p | grep -q "libcairo.so.2" || missing+=(libcairo2)
if [ ${#missing[@]} -gt 0 ]; then
  SUDO=""
  [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null && SUDO="sudo"
  if ! { $SUDO apt-get update -qq && $SUDO apt-get install -y -qq --no-install-recommends "${missing[@]}" fontconfig; }; then
    echo "session-start: could not install ${missing[*]}; PDF/diagram rendering may fail" >&2
  fi
fi

# Python environment (3.12 like CI and the Docker image; any 3.11+ works).
PY="$(command -v python3.12 || command -v python3)"
if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv
fi
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -e ".[dev]"

# Bundled Open Sans for fontconfig, so diagrams rendered to PNG (Word) use the theme font.
mkdir -p "$HOME/.fonts/sextant"
cp -u src/sextant/themes/_fonts/*/*.ttf "$HOME/.fonts/sextant/" 2>/dev/null || true
command -v fc-cache >/dev/null && fc-cache -f "$HOME/.fonts" >/dev/null 2>&1 || true

# Make the venv the default for every command in the session.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  {
    echo "export VIRTUAL_ENV=\"$PWD/.venv\""
    echo "export PATH=\"$PWD/.venv/bin:\$PATH\""
  } >> "$CLAUDE_ENV_FILE"
fi

echo "session-start: $(.venv/bin/python --version), sextant $(.venv/bin/sextant version 2>/dev/null | awk '{print $2}') ready"
