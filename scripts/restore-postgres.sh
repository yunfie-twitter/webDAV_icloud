#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 BACKUP.dump.age" >&2
  exit 2
fi
: "${BACKUP_AGE_IDENTITY:?set the path to the dedicated age identity}"

database=${POSTGRES_DB:-icloud_gateway}
database_user=${POSTGRES_USER:-gateway}

echo "Refusing to continue without explicit empty-database acknowledgement." >&2
: "${RESTORE_TO_EMPTY_DATABASE:?set RESTORE_TO_EMPTY_DATABASE=yes after verifying the target is empty}"
if [ "$RESTORE_TO_EMPTY_DATABASE" != "yes" ]; then
  echo "RESTORE_TO_EMPTY_DATABASE must equal yes" >&2
  exit 2
fi

age --decrypt --identity "$BACKUP_AGE_IDENTITY" "$1" \
  | docker compose exec -T postgres \
      pg_restore --exit-on-error --no-owner --no-privileges \
      --username "$database_user" --dbname "$database"
