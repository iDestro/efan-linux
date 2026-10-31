#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

INSTALL_SHELL=0
for arg in "$@"; do
  case "$arg" in
    --shell) INSTALL_SHELL=1 ;;
    -h | --help)
      cat <<'EOF'
Usage: ./setup.sh [--shell]

  --shell   also add the shell integration source line to ~/.bashrc or ~/.zshrc
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

GO_BIN=""
if command -v go >/dev/null 2>&1; then
  GO_BIN="$(command -v go)"
fi

if [ -n "$GO_BIN" ]; then
  echo "Building static binary with $GO_BIN ..."
  CGO_ENABLED=0 "$GO_BIN" build -trimpath -ldflags "-s -w" -o efan ./cmd/efan
elif [ -x ./efan ]; then
  echo "Go toolchain not found; using the existing ./efan binary."
else
  echo "Go 1.26.4+ is required to build efan; install Go or use a release binary." >&2
  exit 1
fi

mkdir -p "$HOME/.config/efan" "$HOME/.config/efan/shell" "$HOME/.local/bin" "$HOME/.local/share/applications"

if [ ! -f "$HOME/.config/efan/key.pem" ]; then
  dll="${EFAN_CLIENT_DLL:-}"
  if [ -z "$dll" ]; then
    for candidate in \
      "$HOME/Downloads/efan-extract/client.dll" \
      "$HOME/Downloads/efanapp/client.dll"; do
      if [ -f "$candidate" ]; then
        dll="$candidate"
        break
      fi
    done
  fi
  if [ -n "$dll" ]; then
    ./efan extract-key --dll "$dll"
  else
    echo
    echo "client.dll was not found. Extract the key before logging in:"
    echo "  ./efan extract-key --dll /path/to/client.dll"
    echo
  fi
fi

install -m755 ./efan "$HOME/.local/bin/efan"
if [ -f shell/efan.sh ]; then
  install -m644 shell/efan.sh "$HOME/.config/efan/shell/efan.sh"
fi
if [ -f scripts/efan-desktop ]; then
  install -m755 scripts/efan-desktop "$HOME/.local/bin/efan-desktop"
fi
for desktop in efan-login.desktop efan-connect.desktop efan-start.desktop efan-stop.desktop; do
  if [ -f "$desktop" ]; then
    sed "s|@EFAN_DESKTOP@|$HOME/.local/bin/efan-desktop|g" "$desktop" \
      >"$HOME/.local/share/applications/$desktop"
    chmod 644 "$HOME/.local/share/applications/$desktop"
  fi
done

if [ "$INSTALL_SHELL" = 1 ]; then
  case "${SHELL##*/}" in
    zsh) rc="$HOME/.zshrc" ;;
    *) rc="$HOME/.bashrc" ;;
  esac
  marker="# efan shell integration"
  if [ -f "$rc" ] && grep -qF "$marker" "$rc"; then
    echo "Shell integration already present in $rc"
  else
    touch "$rc"
    cp "$rc" "$rc.efan-backup.$(date +%s)" 2>/dev/null || true
    {
      printf '\n%s\n' "$marker"
      printf 'source %q\n' "$HOME/.config/efan/shell/efan.sh"
    } >>"$rc"
    echo "Shell integration added to $rc"
  fi
fi

echo
echo "Installed: $HOME/.local/bin/efan"
echo "Next:      efan login"
echo "Start:     eval \"\$(efan on)\""
echo "Wrapper:   source ~/.config/efan/shell/efan.sh"
echo "           efan on"
echo "Stop:      efan off"
