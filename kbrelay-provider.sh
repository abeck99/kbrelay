#!/usr/bin/env bash
# Self-contained launcher for the kbrelay provider.
#
# Everything lives in your home directory, so it survives SteamOS updates and needs no pacman
# packages and no `steamos-readonly disable`:
#   uv                ~/.local/bin/uv
#   Python + Tk       ~/.local/share/uv/python/
#   cryptography      ~/.cache/uv/
#
#   ./kbrelay-provider.sh --setup   first time: installs uv, downloads Python and the libraries,
#                                   adds "kbrelay provider" to the application menu
#   ./kbrelay-provider.sh           start the provider (any extra arguments go to provider.py)
set -euo pipefail

DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
PYTHON_VERSION=3.12
LOG="$HOME/.cache/kbrelay/provider.log"

find_uv() {
  for candidate in "$(command -v uv 2>/dev/null || true)" "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

run_provider() {
  # Always use uv's standalone Python (it bundles Tk); the system Python may lack it.
  UV_PYTHON_PREFERENCE=only-managed exec "$UV" run --quiet --python "$PYTHON_VERSION" "$DIR/provider.py" "$@"
}

if ! UV="$(find_uv)"; then
  if [[ "${1:-}" != "--setup" ]]; then
    echo "uv isn't installed yet; run: $0 --setup" >&2
    command -v notify-send >/dev/null && notify-send "kbrelay" "Run kbrelay-provider.sh --setup in a terminal first"
    exit 1
  fi
  echo "==> Installing uv into ~/.local/bin"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  UV="$(find_uv)" || { echo "uv install failed" >&2; exit 1; }
fi

if [[ "${1:-}" == "--setup" ]]; then
  echo "==> Downloading Python $PYTHON_VERSION and dependencies (first time only)"
  UV_PYTHON_PREFERENCE=only-managed "$UV" run --quiet --python "$PYTHON_VERSION" "$DIR/provider.py" --help >/dev/null
  chmod +x "$DIR/kbrelay-provider.sh"

  mkdir -p "$HOME/.local/share/applications"
  cat > "$HOME/.local/share/applications/kbrelay-provider.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=kbrelay provider
Comment=Type into a remote computer
Exec="$DIR/kbrelay-provider.sh"
Icon=input-keyboard
Terminal=false
Categories=Utility;
EOF
  echo "==> Added 'kbrelay provider' to the application menu"

  if [[ ! -f "$HOME/.config/kbrelay/config.json" ]]; then
    echo "==> Next: create ~/.config/kbrelay/config.json and a key (see README)"
  fi
  exit 0
fi

# Launched from a menu or Steam there's no terminal, so keep a log for troubleshooting.
if [[ ! -t 2 ]]; then
  mkdir -p "$(dirname "$LOG")"
  exec 2>>"$LOG"
fi
run_provider "$@"
