#!/bin/sh
set -eu

: "${ICLOUD_WEBDAV_PASSWORD:?ICLOUD_WEBDAV_PASSWORD is required}"
: "${ICLOUD_FTPS_PASSWORD:?ICLOUD_FTPS_PASSWORD is required; generate a separate FTPS password}"
: "${FTPS_PUBLIC_IP:?FTPS_PUBLIC_IP is required; set TS_IP_ADDRESS in .env}"
: "${FTPS_CACHE_SIZE:=1G}"

certificate=/etc/icloud-ftps/pki/server.pem
private_key=/etc/icloud-ftps/pki/server-key.pem
config=/runtime/rclone.conf

for required in "$certificate" "$private_key"; do
  [ -s "$required" ] || {
    echo "FTPS setup is incomplete: $required is missing or empty" >&2
    echo "Run scripts/setup-mtls.sh before enabling the FTPS profile." >&2
    exit 1
  }
done

case "$FTPS_PUBLIC_IP" in
  *[!0-9.]*|'')
    echo "FTPS_PUBLIC_IP must be the direct Tailscale IPv4 address" >&2
    exit 2
    ;;
esac
old_ifs=$IFS
IFS=.
set -- $FTPS_PUBLIC_IP
IFS=$old_ifs
[ "$#" -eq 4 ] || {
  echo "FTPS_PUBLIC_IP must contain four IPv4 octets" >&2
  exit 2
}
for octet in "$@"; do
  [ -n "$octet" ] && [ "$octet" -ge 0 ] 2>/dev/null \
    && [ "$octet" -le 255 ] 2>/dev/null || {
      echo "FTPS_PUBLIC_IP contains an invalid IPv4 octet" >&2
      exit 2
    }
done
[ "$1" -eq 100 ] && [ "$2" -ge 64 ] && [ "$2" -le 127 ] || {
  echo "FTPS_PUBLIC_IP must be a Tailscale CGNAT address (100.64.0.0/10)" >&2
  exit 2
}

umask 077
obscured_webdav_password=$(
  printf '%s\n' "$ICLOUD_WEBDAV_PASSWORD" | rclone obscure -
)
cat > "$config" <<EOF
[encrypted-webdav]
type = webdav
url = http://gateway:8080/
vendor = other
user = icloud
pass = $obscured_webdav_password
EOF
unset obscured_webdav_password ICLOUD_WEBDAV_PASSWORD

ftps_password=$ICLOUD_FTPS_PASSWORD
unset ICLOUD_FTPS_PASSWORD

# Supplying --cert and --key makes rclone's FTP server use TLS. The listener is
# kept on loopback in the Tailscale network namespace; only raw TCP forwards in
# serve.json expose the control and passive ports to the tailnet.
exec rclone serve ftp encrypted-webdav: \
  --config "$config" \
  --addr 127.0.0.1:2990 \
  --public-ip "$FTPS_PUBLIC_IP" \
  --passive-port 30000-30009 \
  --cert "$certificate" \
  --key "$private_key" \
  --user icloud \
  --pass "$ftps_password" \
  --cache-dir /cache \
  --vfs-cache-mode writes \
  --vfs-cache-max-size "$FTPS_CACHE_SIZE" \
  --vfs-cache-max-age 1h \
  --vfs-write-back 1s \
  --dir-cache-time 5s \
  --poll-interval 0 \
  --no-modtime \
  --no-checksum \
  --umask 077 \
  --log-level INFO \
  --stats 0
