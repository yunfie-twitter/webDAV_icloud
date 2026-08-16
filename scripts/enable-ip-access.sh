#!/bin/sh
set -eu

# MSYS/Git Bash otherwise rewrites OpenSSL subjects such as /CN=address into
# a Windows filesystem path.
case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*)
    MSYS2_ARG_CONV_EXCL='/CN='
    export MSYS2_ARG_CONV_EXCL
    ;;
esac

ip=
pki=./pki
caddy_output=./caddy-ip-sites

usage() {
  echo "usage: $0 --ip <Tailscale IPv4> [--pki <directory>] [--caddy-output <directory>]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ip) ip=$2; shift 2 ;;
    --pki) pki=$2; shift 2 ;;
    --caddy-output) caddy_output=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$ip" ] || { usage; exit 2; }
command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}

# Tailscale IPv4 addresses are allocated from 100.64.0.0/10. Restricting the
# generated site to that range prevents accidental exposure on a public or LAN
# address if the operator mistypes the value.
if ! printf '%s\n' "$ip" | awk -F. '
  NF != 4 { exit 1 }
  {
    for (i = 1; i <= 4; i++) {
      if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1
    }
    if ($1 != 100 || $2 < 64 || $2 > 127) exit 1
  }
'; then
  echo "not a valid Tailscale IPv4 address (100.64.0.0/10): $ip" >&2
  exit 2
fi

server_ca="$pki/client/server-ca.pem"
server_ca_key="$pki/offline/server-ca-key.pem"
client_ca="$pki/runtime/client-ca.pem"
server_cert="$pki/runtime/server-ip.pem"
server_key="$pki/runtime/server-ip-key.pem"
caddy_site="$caddy_output/ip.caddy"

for required in "$server_ca" "$server_ca_key" "$client_ca"; do
  [ -f "$required" ] || {
    echo "required PKI file is missing: $required" >&2
    echo "Restore the offline Server CA key only for this certificate-issuance step." >&2
    exit 1
  }
done
for destination in "$server_cert" "$server_key" "$caddy_site"; do
  [ ! -e "$destination" ] || {
    echo "refusing to overwrite existing direct-IP configuration: $destination" >&2
    exit 1
  }
done

umask 077
mkdir -p "$pki/runtime" "$caddy_output"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/icloud-webdav-ip-cert.XXXXXX")
cleanup() {
  rm -f "$temporary/server-ip.csr" "$temporary/server-ip.ext" \
    "$temporary/server-ip.pem" "$temporary/server-ip-key.pem" \
    "$temporary/ip.caddy"
  rmdir "$temporary" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

openssl req -new -newkey rsa:3072 -noenc \
  -subj "/CN=$ip" \
  -keyout "$temporary/server-ip-key.pem" \
  -out "$temporary/server-ip.csr"
printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n' \
  "$ip" > "$temporary/server-ip.ext"
openssl x509 -req -sha256 -days 397 \
  -in "$temporary/server-ip.csr" \
  -CA "$server_ca" \
  -CAkey "$server_ca_key" \
  -CAserial "$pki/offline/server-ca.srl" -CAcreateserial \
  -extfile "$temporary/server-ip.ext" \
  -out "$temporary/server-ip.pem"

openssl verify -CAfile "$server_ca" "$temporary/server-ip.pem"
openssl x509 -in "$temporary/server-ip.pem" -noout -checkip "$ip"

cat > "$temporary/ip.caddy" <<EOF
https://$ip {
    bind 127.0.0.1
    tls /etc/caddy/pki/server-ip.pem /etc/caddy/pki/server-ip-key.pem {
        protocols tls1.3
        client_auth {
            mode require_and_verify
            trust_pool file /etc/caddy/pki/client-ca.pem
        }
    }
    reverse_proxy gateway:8080 {
        flush_interval -1
    }
}
EOF

mv "$temporary/server-ip.pem" "$server_cert"
mv "$temporary/server-ip-key.pem" "$server_key"
mv "$temporary/ip.caddy" "$caddy_site"
chmod 644 "$server_cert" "$caddy_site"
chmod 600 "$server_key"

cat <<EOF
Direct HTTPS certificate created for $ip.

Add this line to .env:
TS_IP_ADDRESS=$ip

Then validate and restart Caddy:
  docker compose config --quiet
  docker compose up -d --force-recreate caddy

IP clients must trust this Server CA:
  $server_ca

Move $pki/offline back to offline storage now.
EOF
