#!/bin/sh
set -eu

authorized_key=
output=./sftp

usage() {
  echo "usage: $0 --authorized-key <client-public-key> [--output <directory>]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --authorized-key) authorized_key=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$authorized_key" ] || { usage; exit 2; }
command -v ssh-keygen >/dev/null 2>&1 || {
  echo "ssh-keygen is required (install openssh-client)" >&2
  exit 1
}
[ -s "$authorized_key" ] || {
  echo "client public key is missing or empty: $authorized_key" >&2
  exit 1
}
ssh-keygen -l -f "$authorized_key" >/dev/null

authorized_keys="$output/authorized_keys"
host_key="$output/ssh_host_ed25519_key"
for destination in "$authorized_keys" "$host_key" "$host_key.pub"; do
  [ ! -e "$destination" ] || {
    echo "refusing to overwrite existing SFTP key material: $destination" >&2
    exit 1
  }
done

umask 077
mkdir -p "$output"
ssh-keygen -q -t ed25519 -N '' \
  -C icloud-webdav-sftp-host \
  -f "$host_key"
cp "$authorized_key" "$authorized_keys"
chmod 600 "$authorized_keys" "$host_key"
chmod 644 "$host_key.pub"

echo "SFTP host key fingerprint:"
ssh-keygen -l -f "$host_key.pub"
echo
echo "SFTP authorized client key:"
ssh-keygen -l -f "$authorized_keys"
echo
echo "SFTP key material created in $output"
echo "Start with: docker compose --profile sftp up -d sftp"
