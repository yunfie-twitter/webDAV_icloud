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

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}
python_command=${PYTHON:-python3}
command -v "$python_command" >/dev/null 2>&1 || {
  echo "python3 is required to update the declarative Tailscale config" >&2
  exit 1
}
[ -f "$env_file" ] || { echo "environment file not found: $env_file" >&2; exit 1; }
for required in ./pki/runtime/server.pem ./pki/runtime/server-key.pem; do
  [ -s "$required" ] || {
    echo "FTPS TLS material is missing: $required" >&2
    exit 1
  }
done

existing_password=$(sed -n 's/^ICLOUD_FTPS_PASSWORD=//p' "$env_file" | tail -n 1)
case "$existing_password" in "''"|'""') existing_password= ;; esac
new_password=
if [ -z "$existing_password" ]; then
  new_password=$(openssl rand -hex 32)
fi

temporary_env=$(mktemp "${env_file}.ftps.XXXXXX")
cleanup() { rm -f "$temporary_env"; }
trap cleanup EXIT HUP INT TERM
awk -v ip="$public_ip" -v password="$new_password" '
  BEGIN { saw_ip=0; saw_password=0; saw_cache=0 }
  /^TS_IP_ADDRESS=/ {
    print "TS_IP_ADDRESS=\047" ip "\047"
    saw_ip=1
    next
  }
  /^ICLOUD_FTPS_PASSWORD=/ {
    if (password != "") print "ICLOUD_FTPS_PASSWORD=\047" password "\047"
    else print
    saw_password=1
    next
  }
  /^FTPS_CACHE_SIZE=/ {
    print "FTPS_CACHE_SIZE=\0471G\047"
    saw_cache=1
    next
  }
  { print }
  END {
    if (!saw_ip) print "TS_IP_ADDRESS=\047" ip "\047"
    if (!saw_password) print "ICLOUD_FTPS_PASSWORD=\047" password "\047"
    if (!saw_cache) print "FTPS_CACHE_SIZE=\0471G\047"
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
forwarding = {990: 2990, **{port: port for port in range(30000, 30010)}}
for exposed, target in forwarding.items():
    tcp[str(exposed)] = {"TCPForward": f"127.0.0.1:{target}"}
temporary = path.with_name(path.name + ".ftps.tmp")
temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY

echo "FTPS configuration enabled for Tailscale IP $public_ip."
if [ -n "$new_password" ]; then
  echo
  echo "FTPS PASSWORD (store in the client password manager):"
  echo "$new_password"
fi
echo
echo "Restart Tailscale and start FTPS:"
echo "  docker compose restart tailscale"
echo "  docker compose --profile ftps up -d ftps"
