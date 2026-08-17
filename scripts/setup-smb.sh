#!/bin/sh
set -eu

public_ip=
env_file=./.env
serve_config=./tailscale-config/serve.json

usage() {
  echo "usage: $0 --public-ip <Tailscale IPv4> [--env <file>] [--serve-config <file>]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --public-ip) public_ip=$2; shift 2 ;;
    --env) env_file=$2; shift 2 ;;
    --serve-config) serve_config=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$public_ip" ] || { usage; exit 2; }
case "$public_ip" in
  *[!0-9.]*|'') echo "invalid Tailscale IPv4 address: $public_ip" >&2; exit 2 ;;
esac
old_ifs=$IFS
IFS=.
set -- $public_ip
IFS=$old_ifs
[ "$#" -eq 4 ] || { echo "invalid IPv4 address: $public_ip" >&2; exit 2; }
for octet in "$@"; do
  [ -n "$octet" ] && [ "$octet" -ge 0 ] 2>/dev/null \
    && [ "$octet" -le 255 ] 2>/dev/null || {
      echo "invalid IPv4 address: $public_ip" >&2
      exit 2
    }
done
[ "$1" -eq 100 ] && [ "$2" -ge 64 ] && [ "$2" -le 127 ] || {
  echo "not a Tailscale CGNAT address (100.64.0.0/10): $public_ip" >&2
  exit 2
}

python_command=${PYTHON:-python3}
command -v "$python_command" >/dev/null 2>&1 || {
  echo "python3 is required to update the declarative Tailscale config" >&2
  exit 1
}
[ -f "$env_file" ] || { echo "environment file not found: $env_file" >&2; exit 1; }

temporary_env=$(mktemp "${env_file}.smb.XXXXXX")
cleanup() { rm -f "$temporary_env"; }
trap cleanup EXIT HUP INT TERM
awk -v ip="$public_ip" '
  BEGIN { saw_ip=0; saw_cache=0 }
  /^TS_IP_ADDRESS=/ {
    print "TS_IP_ADDRESS=\047" ip "\047"
    saw_ip=1
    next
  }
  /^SMB_CACHE_SIZE=/ {
    print "SMB_CACHE_SIZE=\0472G\047"
    saw_cache=1
    next
  }
  { print }
  END {
    if (!saw_ip) print "TS_IP_ADDRESS=\047" ip "\047"
    if (!saw_cache) print "SMB_CACHE_SIZE=\0472G\047"
  }
' "$env_file" > "$temporary_env"
chmod 600 "$temporary_env"
mv "$temporary_env" "$env_file"
trap - EXIT HUP INT TERM

mkdir -p "$(dirname "$serve_config")"
"$python_command" - "$serve_config" <<'PY'
import json
import os
from pathlib import Path
import sys

path = Path(sys.argv[1])
if path.exists():
    document = json.loads(path.read_text(encoding="utf-8"))
else:
    document = {}
tcp = document.setdefault("TCP", {})

# SMB unified mode: retain the HTTPS recovery/admin endpoint, remove temporary
# SFTP/FTPS listeners, and expose only SMB for filesystem clients.
for port in ["2222", "990", *[str(value) for value in range(30000, 30010)]]:
    tcp.pop(port, None)
tcp["445"] = {"TCPForward": "127.0.0.1:1445"}

temporary = path.with_name(path.name + ".smb.tmp")
temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY

echo "Anonymous SMB unified mode enabled for Tailscale IP $public_ip."
echo "Share: //$public_ip/iCloud"
echo
echo "Stop legacy adapters, restart Tailscale, then start SMB:"
echo "  docker compose --profile sftp --profile ftps stop sftp ftps"
echo "  docker compose restart tailscale"
echo "  docker compose --profile smb up -d --build smb"
echo
echo "Optional trusted-LAN host publication (anonymous read/write):"
echo "  docker compose -f compose.yaml -f compose.smb-host.yaml --profile smb up -d --build"
