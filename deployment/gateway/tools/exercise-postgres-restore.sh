#!/usr/bin/env bash
# A real physical backup plus WAL restore to a named point on the disposable
# PostgreSQL fixture. This rehearses the database mechanics, not replay continuity.
set -euo pipefail
fixture=product/stores/auths-stores/tests/postgres_tls/compose.yaml
source_id=$(docker compose -f "$fixture" ps -q postgres)
: "${source_id:?start the PostgreSQL fixture first}"
: "${RUNNER_TEMP:?a disposable runner directory is required}"
work=$(mktemp -d "$RUNNER_TEMP/auths-pitr.XXXXXXXX")
restore_name="auths-pitr-$(basename "$work")"
cleanup() {
  docker rm -f "$restore_name" >/dev/null 2>&1 || true
  sudo rm -rf -- "$work"
}
trap cleanup EXIT
sql() { docker exec -u postgres "$source_id" psql -U auths -d auths_lifecycle -v ON_ERROR_STOP=1 -Atc "$1"; }
sql "ALTER SYSTEM SET archive_mode = 'on'" >/dev/null
sql "ALTER SYSTEM SET archive_command = 'cp %p /var/lib/postgresql/data/operator-wal/%f'" >/dev/null
docker exec -u postgres "$source_id" mkdir -p /var/lib/postgresql/data/operator-wal
docker restart "$source_id" >/dev/null
for attempt in {1..60}; do
  if docker exec "$source_id" pg_isready -U auths -d auths_lifecycle >/dev/null; then break; fi
  sleep 1
done
sql 'CREATE TABLE auths_operator_restore_marker (id integer PRIMARY KEY); INSERT INTO auths_operator_restore_marker VALUES (1)' >/dev/null
docker exec -u postgres "$source_id" pg_basebackup -U auths -D /tmp/operator-base -Fp -Xs -c fast
sql 'INSERT INTO auths_operator_restore_marker VALUES (2)' >/dev/null
sql "SELECT pg_create_restore_point('auths-before-cutover')" >/dev/null
sql 'INSERT INTO auths_operator_restore_marker VALUES (3)' >/dev/null
wal=$(sql 'SELECT pg_walfile_name(pg_current_wal_lsn())')
sql 'SELECT pg_switch_wal()' >/dev/null
for attempt in {1..60}; do
  if docker exec "$source_id" test -f "/var/lib/postgresql/data/operator-wal/$wal"; then break; fi
  sleep 1
done
docker exec "$source_id" test -f "/var/lib/postgresql/data/operator-wal/$wal"
docker cp "$source_id:/tmp/operator-base" "$work/base"
docker cp "$source_id:/var/lib/postgresql/data/operator-wal" "$work/archive"
cat >> "$work/base/postgresql.auto.conf" <<'CONFIG'
restore_command = 'cp /archive/%f %p'
recovery_target_name = 'auths-before-cutover'
recovery_target_action = 'promote'
archive_mode = 'off'
CONFIG
touch "$work/base/recovery.signal"
# The disposable image's postgres user is UID/GID 999. Preserve ownership of
# copied PostgreSQL files; these are fixture database bytes, never provider secrets.
sudo chown -R 999:999 "$work/base" "$work/archive"
sudo chmod 700 "$work/base"
docker run -d --name "$restore_name" \
  -v "$work/base:/var/lib/postgresql/data" \
  -v "$work/archive:/archive:ro" \
  -v "$(pwd)/product/stores/auths-stores/tests/postgres_tls:/fixture:ro" \
  postgres:17.10-bookworm >/dev/null
for attempt in {1..60}; do
  if docker exec "$restore_name" psql -U auths -d auths_lifecycle -Atc 'SELECT NOT pg_is_in_recovery()' 2>/dev/null | grep -qx t; then break; fi
  sleep 1
done
observed=$(docker exec "$restore_name" psql -U auths -d auths_lifecycle -v ON_ERROR_STOP=1 -Atc "SELECT string_agg(id::text, ', ' ORDER BY id) FROM auths_operator_restore_marker")
[[ "$observed" == '1, 2' ]]
printf '%s\n' '{"schema":"auths.gateway-restore-exercise/1","backup":"physical-with-wal","target":"named-restore-point","before_target_retained":true,"after_target_excluded":true,"replay_continuity_claim":false}'
