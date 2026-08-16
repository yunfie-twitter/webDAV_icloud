#!/bin/sh
set -eu

: "${ICLOUD_WEBDAV_PASSWORD:?ICLOUD_WEBDAV_PASSWORD is required}"
: "${SFTP_CACHE_SIZE:=1G}"

authorized_keys=/etc/icloud-sftp/authorized_keys
host_key=/etc/icloud-sftp/ssh_host_ed25519_key
config=/runtime/rclone.conf

for required in "$authorized_keys" "$host_key"; do
  [ -s "$required" ] || {
    echo "SFTP setup is incomplete: $required is missing or empty" >&2
    echo "Run: sh scripts/setup-sftp.sh --authorized-key /path/to/client.pub" >&2
    exit 1
  }
done

umask 077
obscured_password=$(
  printf '%s\n' "$ICLOUD_WEBDAV_PASSWORD" | rclone obscure -
)
cat > "$config" <<EOF
[encrypted-webdav]
type = webdav
url = http://gateway:8080/
vendor = other
user = icloud
pass = $obscured_password
EOF
unset obscured_password ICLOUD_WEBDAV_PASSWORD

exec rclone serve sftp encrypted-webdav: \
  --config "$config" \
  --addr 127.0.0.1:2022 \
  --authorized-keys "$authorized_keys" \
  --key "$host_key" \
  --cache-dir /cache \
  --vfs-cache-mode writes \
  --vfs-cache-max-size "$SFTP_CACHE_SIZE" \
  --vfs-cache-max-age 1h \
  --vfs-write-back 1s \
  --dir-cache-time 5s \
  --poll-interval 0 \
  --no-modtime \
  --no-checksum \
  --umask 077 \
  --log-level INFO \
  --stats 0
