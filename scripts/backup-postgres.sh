#!/bin/sh
set -eu

: "${BACKUP_AGE_RECIPIENT:?set a dedicated age recipient}"

backup_dir=${BACKUP_DIRECTORY:-./backups}
database=${POSTGRES_DB:-icloud_gateway}
database_user=${POSTGRES_USER:-gateway}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)

umask 077
mkdir -p "$backup_dir"
temporary=$(mktemp "$backup_dir/.postgres-$timestamp.XXXXXX.age")
trap 'rm -f "$temporary"' EXIT HUP INT TERM

docker compose exec -T postgres \
  pg_dump --format=custom --no-owner --no-privileges \
  --username "$database_user" --dbname "$database" \
  | age --encrypt --recipient "$BACKUP_AGE_RECIPIENT" --output "$temporary"

destination="$backup_dir/postgres-$timestamp.dump.age"
mv "$temporary" "$destination"
trap - EXIT HUP INT TERM
printf '%s\n' "$destination"
