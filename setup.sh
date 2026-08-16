#!/bin/sh
set -eu

command -v docker >/dev/null 2>&1 || {
  echo "Docker with Compose v2 is required." >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required." >&2
  exit 1
}

if [ ! -t 0 ]; then
  echo "setup.sh must be run from an interactive terminal." >&2
  exit 1
fi

restore_tty() { stty echo 2>/dev/null || true; }
trap restore_tty EXIT HUP INT TERM

read_secret() {
  prompt=$1
  printf '%s' "$prompt" >&2
  stty -echo
  IFS= read -r secret_value
  stty echo
  printf '\n' >&2
  REPLY=$secret_value
}

env_quote() {
  # Compose dotenv single-quoted values are literal; only quote itself needs
  # escaping. This keeps $, #, spaces, and backslashes out of interpolation.
  escaped=$(printf '%s' "$1" | sed "s/'/\\\\'/g")
  printf "'%s'" "$escaped"
}

yes_no() {
  prompt=$1
  default=$2
  printf '%s' "$prompt"
  IFS= read -r answer
  answer=${answer:-$default}
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

if [ -e .env ] && ! yes_no '.env already exists. Replace its settings? [y/N]: ' n; then
  echo "Setup cancelled without changing .env."
  exit 0
fi

printf 'Apple ID: '
IFS= read -r apple_id
[ -n "$apple_id" ] || { echo "Apple ID is required." >&2; exit 2; }
read_secret 'Apple ID password (stored only in chmod 600 .env): '
apple_password=$REPLY

read_secret 'Tailscale OAuth client secret (tskey-client-...): '
tailscale_secret=$REPLY
case "$tailscale_secret" in
  tskey-client-*) ;;
  *) echo "An OAuth client secret beginning with tskey-client- is required." >&2; exit 2 ;;
esac
case "$tailscale_secret" in
  *ephemeral=true*)
    echo "Refusing ephemeral=true for this persistent server." >&2
    exit 2
    ;;
  *ephemeral=false*) ;;
  *\?*) tailscale_secret="${tailscale_secret}&ephemeral=false" ;;
  *) tailscale_secret="${tailscale_secret}?ephemeral=false" ;;
esac

printf 'Tailscale tag [tag:icloud-webdav]: '
IFS= read -r tailscale_tag
tailscale_tag=${tailscale_tag:-tag:icloud-webdav}
case "$tailscale_tag" in
  tag:*[!a-zA-Z0-9_-]*|tag:|'')
    echo "tag must look like tag:icloud-webdav" >&2
    exit 2
    ;;
esac
printf 'Additional tailscale up arguments (optional): '
IFS= read -r tailscale_extra
ts_extra_args="--advertise-tags=$tailscale_tag"
[ -z "$tailscale_extra" ] || ts_extra_args="$ts_extra_args $tailscale_extra"

random_suffix=$(openssl rand -hex 4)
default_hostname="icloud-gw-$random_suffix"
echo "WARNING: Hostnames are visible to the tailnet. If you later request a"
echo "publicly trusted certificate, its DNS name can also appear in public"
echo "certificate-transparency logs. Do not use a personal name or location."
printf 'Privacy-safe machine hostname [%s]: ' "$default_hostname"
IFS= read -r ts_hostname
ts_hostname=${ts_hostname:-$default_hostname}
case "$ts_hostname" in
  ''|*[!a-z0-9-]*)
    echo "hostname must contain only lowercase a-z, 0-9, and hyphen" >&2
    exit 2
    ;;
esac
printf 'Full MagicDNS name for automatic Tailscale certificate: '
IFS= read -r ts_fqdn
case "$ts_fqdn" in
  "$ts_hostname".*.ts.net) ;;
  *)
    echo "Enter the full name, for example: $ts_hostname.tail12345.ts.net" >&2
    exit 2
    ;;
esac

printf 'iCloud authentication method [sms/device]: '
IFS= read -r auth_method
auth_method=${auth_method:-sms}
case "$auth_method" in sms|device) ;; *) echo "use sms or device" >&2; exit 2 ;; esac

keybroker_socket=/run/icloud-keybroker/keybroker.sock
printf 'Host Key Broker socket [%s]: ' "$keybroker_socket"
IFS= read -r selected_socket
keybroker_socket=${selected_socket:-$keybroker_socket}

webdav_password=$(openssl rand -hex 32)
postgres_password=$(openssl rand -hex 32)

mkdir -p tailscale-config caddy-ip-sites
printf '%s\n' \
  '{' \
  '  "TCP": {' \
  '    "443": {' \
  '      "TCPForward": "127.0.0.1:443"' \
  '    }' \
  '  }' \
  '}' > tailscale-config/serve.json

if [ -e ./pki/runtime/server.pem ]; then
  for required in \
    ./pki/runtime/server-key.pem ./pki/runtime/client-ca.pem \
    ./pki/client/server-ca.pem ./pki/client/client.pem \
    ./pki/client/client-key.pem; do
    [ -f "$required" ] || {
      echo "Existing PKI is incomplete: $required is missing." >&2
      exit 1
    }
  done
  if ! openssl x509 -in ./pki/runtime/server.pem -noout -checkhost "$ts_hostname"; then
    echo "Existing mTLS server certificate does not match $ts_hostname." >&2
    echo "Move the existing pki directory aside and rerun setup." >&2
    exit 1
  fi
  echo "Reusing the existing mTLS PKI for $ts_hostname."
elif [ -n "$ts_fqdn" ]; then
  sh scripts/setup-mtls.sh --output ./pki --hostname "$ts_hostname" --fqdn "$ts_fqdn"
else
  sh scripts/setup-mtls.sh --output ./pki --hostname "$ts_hostname"
fi

umask 077
environment_file=.env.setup.$$
trap 'restore_tty; rm -f "$environment_file"' EXIT HUP INT TERM
{
  printf 'ICLOUD_APPLE_ID=%s\n' "$(env_quote "$apple_id")"
  printf 'ICLOUD_PASSWORD=%s\n' "$(env_quote "$apple_password")"
  printf 'ICLOUD_WEBDAV_PASSWORD=%s\n' "$(env_quote "$webdav_password")"
  printf 'POSTGRES_PASSWORD=%s\n' "$(env_quote "$postgres_password")"
  printf 'ICLOUD_AUTH_METHOD=%s\n' "$(env_quote "$auth_method")"
  printf 'TS_AUTHKEY=%s\n' "$(env_quote "$tailscale_secret")"
  printf 'TS_HOSTNAME=%s\n' "$(env_quote "$ts_hostname")"
  printf 'TS_CERT_DOMAIN=%s\n' "$(env_quote "$ts_fqdn")"
  printf 'TS_IP_ADDRESS=\n'
  printf 'TS_EXTRA_ARGS=%s\n' "$(env_quote "$ts_extra_args")"
  printf 'TS_SERVE_CONFIG_DIR=%s\n' "$(env_quote './tailscale-config')"
  printf 'MTLS_PKI_DIR=%s\n' "$(env_quote './pki')"
  printf 'CADDY_IP_SITES_DIR=%s\n' "$(env_quote './caddy-ip-sites')"
  printf 'KEYBROKER_SOCKET=%s\n' "$(env_quote "$keybroker_socket")"
  printf 'KEYBROKER_GID=10001\n'
} > "$environment_file"
mv "$environment_file" .env
chmod 600 .env
trap restore_tty EXIT HUP INT TERM

echo "WebDAV username: icloud"
echo "WebDAV password: generated and stored as ICLOUD_WEBDAV_PASSWORD in chmod 600 .env"

docker compose config --quiet
docker compose build gateway

if yes_no 'Initialize recovery keys and encrypted CAS? [Y/n]: ' y; then
  docker compose run --rm --no-deps auth \
    encryption-init --config /data/icloud-webdav.toml \
    --recovery-public-file /data/.state/recovery-public.json
  echo "Store the displayed Recovery Secret offline before continuing."
  printf 'Press Enter after the offline copy is complete.'
  IFS= read -r ignored
fi

echo "Starting interactive Apple ID authentication ($auth_method)."
docker compose run --rm --no-deps auth

if yes_no 'Start the complete stack now? [Y/n]: ' y; then
  if [ ! -S "$keybroker_socket" ]; then
    echo "Key Broker socket not found: $keybroker_socket" >&2
    echo "Authentication and configuration are complete, but the stack was not started." >&2
    echo "Start the host Key Broker, then run: docker compose up -d" >&2
    exit 0
  fi
  docker compose up -d
  echo "Tailscale status: docker compose exec tailscale tailscale status"
fi

echo "Setup complete. WebDAV password was generated and stored in .env."
echo "Import the files under pki/client into the WebDAV client."
echo "Move pki/offline to offline storage after issuing required certificates."
