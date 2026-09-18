#!/usr/bin/env bash
# Self-contained launcher for the kbrelay receiver (e.g. on SteamOS).
#
# Everything lives in your home directory, so SteamOS updates leave it alone:
#   uv                ~/.local/bin/uv
#   Python            ~/.local/share/uv/python/
#   cryptography      ~/.cache/uv/
#   service           ~/.config/systemd/user/kbrelay-receiver.service
#
#   ./kbrelay-receiver.sh --setup     first time: installs uv, downloads Python and cryptography,
#                                     checks /dev/uinput access, installs a systemd user service
#   ./kbrelay-receiver.sh --dry-run   print incoming keys instead of typing them (good first test)
#   ./kbrelay-receiver.sh             run in the foreground
set -euo pipefail

DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
PYTHON_VERSION=3.12
SERVICE="$HOME/.config/systemd/user/kbrelay-receiver.service"

find_uv() {
  for candidate in "$(command -v uv 2>/dev/null || true)" "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

if ! UV="$(find_uv)"; then
  if [[ "${1:-}" != "--setup" ]]; then
    echo "uv isn't installed yet; run: $0 --setup" >&2
    exit 1
  fi
  echo "==> Installing uv into ~/.local/bin"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  UV="$(find_uv)" || { echo "uv install failed" >&2; exit 1; }
fi

run_receiver() {
  UV_PYTHON_PREFERENCE=only-managed exec "$UV" run --quiet --python "$PYTHON_VERSION" "$DIR/receiver.py" "$@"
}

if [[ "${1:-}" != "--setup" ]]; then
  run_receiver "$@"
fi

echo "==> Downloading Python $PYTHON_VERSION and cryptography (first time only)"
UV_PYTHON_PREFERENCE=only-managed "$UV" run --quiet --python "$PYTHON_VERSION" "$DIR/receiver.py" --help >/dev/null
chmod +x "$DIR/kbrelay-receiver.sh"

if [[ -w /dev/uinput ]]; then
  echo "==> /dev/uinput is writable by $(id -un): good"
else
  cat <<'EOF'
!!  /dev/uinput isn't writable by this user. Fix it once with (needs sudo; on SteamOS set a
!!  password first with `passwd`):
      echo uinput | sudo tee /etc/modules-load.d/uinput.conf && sudo modprobe uinput
      echo 'KERNEL=="uinput", SUBSYSTEM=="misc", OPTIONS+="static_node=uinput", TAG+="uaccess"' \
        | sudo tee /etc/udev/rules.d/60-kbrelay-uinput.rules
      sudo udevadm control --reload && sudo udevadm trigger --name-match=uinput
!!  then log out and back in, and re-run --setup.
EOF
fi

mkdir -p "$(dirname "$SERVICE")"
cat > "$SERVICE" <<EOF
[Unit]
Description=kbrelay receiver
After=network-online.target

[Service]
ExecStart="$DIR/kbrelay-receiver.sh"
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable kbrelay-receiver.service >/dev/null
echo "==> Installed and enabled the kbrelay-receiver user service (starts when you log in)"

if [[ -f "$HOME/.config/kbrelay/config.json" ]]; then
  systemctl --user restart kbrelay-receiver.service
  echo "==> Started. Logs: journalctl --user -u kbrelay-receiver -f"
else
  echo "==> Next: create ~/.config/kbrelay/config.json and a key (see README), then:"
  echo "      systemctl --user start kbrelay-receiver"
fi
