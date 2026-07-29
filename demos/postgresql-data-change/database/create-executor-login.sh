#!/bin/sh
set -eu

if [ -z "${AUTHS_EXECUTOR_PASSWORD:-}" ]; then
  echo "AUTHS_EXECUTOR_PASSWORD is required" >&2
  exit 1
fi

psql --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=executor_password="$AUTHS_EXECUTOR_PASSWORD" <<'SQL'
ALTER ROLE auths_executor LOGIN PASSWORD :'executor_password';
SQL
