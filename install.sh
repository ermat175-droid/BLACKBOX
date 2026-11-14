#!/usr/bin/env bash
# BLACKBOX installer — set up the venv, dependencies and the `blackbox` command.
set -euo pipefail

BB_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
VENV="$BB_DIR/.venv"
BIN_DIR="${BLACKBOX_BIN:-$HOME/.local/bin}"

c_grn=$'\033[32m'; c_red=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
ok()  { printf '%s✓%s %s\n' "$c_grn" "$c_off" "$*"; }
die() { printf '%serror: %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }

printf '\n%sInstalling BLACKBOX%s\n\n' "$c_dim" "$c_off"

# 1. Python
command -v python3 >/dev/null 2>&1 || die "python3 is required"
PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
python3 -c 'import sys;exit(0 if sys.version_info[:2]>=(3,11) else 1)' \
  || die "python 3.11+ required (found $PYV)"
ok "python $PYV"

# 2. venv + deps
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$BB_DIR/requirements.txt"
ok "dependencies installed into .venv"

# 3. the `blackbox` command on PATH
chmod +x "$BB_DIR/bin/blackbox"
mkdir -p "$BIN_DIR"
ln -sf "$BB_DIR/bin/blackbox" "$BIN_DIR/blackbox"
ok "command installed: $BIN_DIR/blackbox"

# 4. prerequisites (informational — not fatal)
printf '\n%sChecking lab prerequisites:%s\n' "$c_dim" "$c_off"
command -v docker >/dev/null 2>&1 && ok "docker found" \
  || printf '  %s!%s docker not found — needed to run target sites (install docker)\n' "$c_red" "$c_off"
[ -r /sys/kernel/btf/vmlinux ] && ok "kernel BTF present" \
  || printf '  %s!%s no /sys/kernel/btf/vmlinux — Tetragon eBPF sensor needs a BTF kernel\n' "$c_red" "$c_off"

cat <<EOF

${c_grn}Done.${c_off}
EOF
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) printf '  %s%s is not on your PATH — add it:%s\n    export PATH="%s:\$PATH"\n' \
       "$c_dim" "$BIN_DIR" "$c_off" "$BIN_DIR" ;;
esac
cat <<EOF
  Next:
    blackbox doctor      # verify docker + kernel
    blackbox up          # start the console  ->  http://127.0.0.1:8000/ui/
    blackbox up --lan    # let friends on your Wi-Fi watch live
EOF
