#!/bin/sh
set -eu

: "${ICLOUD_WEBDAV_PASSWORD:?ICLOUD_WEBDAV_PASSWORD is required}"
: "${SMB_CACHE_SIZE:=2G}"

rclone_config=/runtime/rclone.conf
samba_config=/runtime/smb.conf
mount_path=/srv/icloud

umask 077
# These paths live on Compose tmpfs mounts because the container root is
# read-only. Samba creates its message socket and crash directory below them.
mkdir -p /var/lib/samba/private /var/log/samba/cores
chmod 0700 /var/lib/samba/private /var/log/samba/cores

obscured_webdav_password=$(
  printf '%s\n' "$ICLOUD_WEBDAV_PASSWORD" | rclone obscure -
)
cat > "$rclone_config" <<EOF
[encrypted-webdav]
type = webdav
url = http://gateway:8080/
vendor = other
user = icloud
pass = $obscured_webdav_password
EOF
unset obscured_webdav_password ICLOUD_WEBDAV_PASSWORD

cat > "$samba_config" <<'EOF'
[global]
    workgroup = WORKGROUP
    server string = iCloud Encrypted SMB Gateway
    server role = standalone server
    security = user
    map to guest = Bad User
    guest account = smbguest
    restrict anonymous = 0

    # Loopback is used by Tailscale Serve. eth0 accepts the optional Docker
    # host-port mapping from compose.smb-host.yaml.
    interfaces = lo eth0
    bind interfaces only = yes
    smb ports = 1445
    disable netbios = yes

    server min protocol = SMB2_10
    server max protocol = SMB3
    server signing = auto
    smb encrypt = off
    ntlm auth = ntlmv2-only

    load printers = no
    printing = bsd
    printcap name = /dev/null
    disable spoolss = yes
    unix extensions = no

    logging = stdout
    log level = 1
    max log size = 0

[iCloud]
    path = /srv/icloud
    comment = Encrypted iCloud storage
    browseable = yes
    read only = no
    guest ok = yes
    guest only = yes
    force user = smbguest
    force group = smbguest
    create mask = 0660
    force create mode = 0660
    directory mask = 0770
    force directory mode = 0770
    inherit permissions = yes
    oplocks = no
    level2 oplocks = no
    kernel oplocks = no
    strict locking = yes
EOF

rclone mount encrypted-webdav: "$mount_path" \
  --config "$rclone_config" \
  --allow-other \
  --uid 10002 \
  --gid 10002 \
  --file-perms 0660 \
  --dir-perms 0770 \
  --cache-dir /cache \
  --vfs-cache-mode full \
  --vfs-cache-max-size "$SMB_CACHE_SIZE" \
  --vfs-cache-max-age 1h \
  --vfs-write-back 2s \
  --dir-cache-time 5s \
  --poll-interval 0 \
  --no-modtime \
  --no-checksum \
  --attr-timeout 1s \
  --log-level INFO \
  --stats 0 &
rclone_pid=$!

cleanup() {
  if [ -n "${samba_pid:-}" ]; then
    kill "$samba_pid" 2>/dev/null || true
    wait "$samba_pid" 2>/dev/null || true
  fi
  fusermount3 -u "$mount_path" 2>/dev/null || true
  kill "$rclone_pid" 2>/dev/null || true
  wait "$rclone_pid" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

attempt=0
while ! mountpoint -q "$mount_path"; do
  if ! kill -0 "$rclone_pid" 2>/dev/null; then
    echo "rclone WebDAV mount exited before SMB startup" >&2
    wait "$rclone_pid"
    exit 1
  fi
  attempt=$((attempt + 1))
  [ "$attempt" -lt 100 ] || {
    echo "timed out waiting for the encrypted WebDAV mount" >&2
    exit 1
  }
  sleep 0.1
done

smbd --foreground --no-process-group --debug-stdout --configfile="$samba_config" &
samba_pid=$!
wait "$samba_pid"
