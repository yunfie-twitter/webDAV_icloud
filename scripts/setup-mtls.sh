#!/bin/sh
set -eu

# MSYS/Git Bash otherwise rewrites OpenSSL subjects such as /CN=name into a
# Windows filesystem path. Relative certificate paths still convert normally.
case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*)
    MSYS2_ARG_CONV_EXCL='/CN='
    export MSYS2_ARG_CONV_EXCL
    ;;
esac

output=./pki
hostname=
fqdn=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    --hostname) hostname=$2; shift 2 ;;
    --fqdn) fqdn=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$hostname" ]; then
  printf 'Privacy-safe Tailscale hostname: '
  IFS= read -r hostname
fi
case "$hostname" in
  ''|*[!a-z0-9-]*)
    echo "hostname must contain only lowercase a-z, 0-9, and hyphen" >&2
    exit 2
    ;;
esac
case "$fqdn" in
  ''|*[!a-z0-9.-]*)
    [ -z "$fqdn" ] || {
      echo "fqdn must contain only lowercase a-z, 0-9, dot, and hyphen" >&2
      exit 2
    }
    ;;
esac

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required" >&2
  exit 1
}

umask 077
mkdir -p "$output/runtime" "$output/client" "$output/offline"
for existing in server-ca-key.pem client-ca-key.pem server-key.pem client-key.pem; do
  if [ -e "$output/runtime/$existing" ] \
    || [ -e "$output/client/$existing" ] \
    || [ -e "$output/offline/$existing" ]; then
    echo "refusing to overwrite existing PKI in $output" >&2
    exit 1
  fi
done

temporary=$(mktemp -d "${TMPDIR:-/tmp}/icloud-webdav-mtls.XXXXXX")
cleanup() {
  rm -f "$temporary/server.csr" "$temporary/client.csr" \
    "$temporary/server.ext" "$temporary/client.ext"
  rmdir "$temporary" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

openssl req -x509 -newkey rsa:3072 -noenc -sha256 -days 3650 \
  -subj "/CN=iCloud WebDAV Server CA" \
  -keyout "$output/offline/server-ca-key.pem" \
  -out "$output/client/server-ca.pem"
openssl req -x509 -newkey rsa:3072 -noenc -sha256 -days 3650 \
  -subj "/CN=iCloud WebDAV Client CA" \
  -keyout "$output/offline/client-ca-key.pem" \
  -out "$output/runtime/client-ca.pem"

openssl req -new -newkey rsa:3072 -noenc \
  -subj "/CN=$hostname" \
  -keyout "$output/runtime/server-key.pem" -out "$temporary/server.csr"
if [ -n "$fqdn" ]; then
  printf 'subjectAltName=DNS:%s,DNS:%s\nextendedKeyUsage=serverAuth\n' \
    "$hostname" "$fqdn" > "$temporary/server.ext"
else
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' \
    "$hostname" > "$temporary/server.ext"
fi
openssl x509 -req -sha256 -days 397 \
  -in "$temporary/server.csr" \
  -CA "$output/client/server-ca.pem" \
  -CAkey "$output/offline/server-ca-key.pem" \
  -CAserial "$output/offline/server-ca.srl" -CAcreateserial \
  -extfile "$temporary/server.ext" -out "$output/runtime/server.pem"

openssl req -new -newkey rsa:3072 -noenc \
  -subj "/CN=icloud-webdav-client" \
  -keyout "$output/client/client-key.pem" -out "$temporary/client.csr"
printf 'extendedKeyUsage=clientAuth\n' > "$temporary/client.ext"
openssl x509 -req -sha256 -days 397 \
  -in "$temporary/client.csr" \
  -CA "$output/runtime/client-ca.pem" \
  -CAkey "$output/offline/client-ca-key.pem" \
  -CAserial "$output/offline/client-ca.srl" -CAcreateserial \
  -extfile "$temporary/client.ext" -out "$output/client/client.pem"

chmod 644 "$output/runtime/server.pem" "$output/runtime/client-ca.pem" \
  "$output/client/server-ca.pem" "$output/client/client.pem"
chmod 600 "$output/runtime/server-key.pem" "$output/client/client-key.pem" \
  "$output/offline/server-ca-key.pem" "$output/offline/client-ca-key.pem"

echo "mTLS PKI created in $output"
echo "WebDAV client files are in: $output/client"
echo "Move $output/offline away from the server after issuing certificates."
