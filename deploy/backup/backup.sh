#!/bin/sh
# Phantom SOAR database backup, listing, verification and restore (POSIX sh; runs inside the "backup"
# compose service, see docs/DEPLOYMENT.md). Connection settings come from the standard libpq variables
# (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE).
#
#   backup.sh loop             dump now, then every BACKUP_INTERVAL_SECONDS (container default command)
#   backup.sh once             one dump, then exit
#   backup.sh list             list the dumps in BACKUP_DIR
#   backup.sh verify [FILE]    restore FILE (default: newest) into a scratch database, check it, drop it
#   backup.sh restore FILE     restore FILE into PGDATABASE; DESTRUCTIVE (see below)
#
# Settings (environment):
#   BACKUP_DIR                 where dumps are written                       (default /backups)
#   BACKUP_REPORTS_DIR         reports directory to archive, if present      (default /reports)
#   BACKUP_KEEP                number of newest dumps to keep                (default 14)
#   BACKUP_INTERVAL_SECONDS    loop interval                                 (default 86400)
#   BACKUP_VERIFY_DB           scratch database name for "verify"            (default <PGDATABASE>_restore_check)
#   BACKUP_CONFIRM_RESTORE     must equal PGDATABASE for "restore" to run
#
# Files: phantom_soar_<UTC timestamp>.dump (pg_dump custom format) with a .sha256 next to it, and
# phantom_reports_<UTC timestamp>.tar.gz when the reports directory has files. A dump is written under
# a temporary name, checked with pg_restore --list and a checksum is recorded before it gets its final name.
set -eu

BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_REPORTS_DIR="${BACKUP_REPORTS_DIR:-/reports}"
BACKUP_KEEP="${BACKUP_KEEP:-14}"
BACKUP_INTERVAL_SECONDS="${BACKUP_INTERVAL_SECONDS:-86400}"
PGDATABASE="${PGDATABASE:-phantom_soar}"
export PGDATABASE

log() { printf '%s [backup] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

require_number() {
  case "$2" in
    '' | *[!0-9]*) die "$1 must be a positive whole number, got '$2'" ;;
  esac
  [ "$2" -ge 1 ] || die "$1 must be at least 1"
}

latest_dump() {
  # Timestamps sort lexicographically, so the last name is the newest.
  # shellcheck disable=SC2012  # names are our own timestamped pattern
  ls -1 "$BACKUP_DIR"/phantom_soar_*.dump 2> /dev/null | sort | tail -n 1
}

wait_for_db() {
  tries=0
  until pg_isready -q; do
    tries=$((tries + 1))
    [ "$tries" -le 30 ] || die "database is not accepting connections"
    sleep 2
  done
}

prune() {
  # Keep the newest BACKUP_KEEP dumps and the newest BACKUP_KEEP report archives.
  # shellcheck disable=SC2012
  ls -1 "$BACKUP_DIR"/phantom_soar_*.dump 2> /dev/null | sort -r | tail -n +"$((BACKUP_KEEP + 1))" | while read -r old; do
    log "pruning $old"
    rm -f -- "$old" "$old.sha256"
  done
  # shellcheck disable=SC2012
  ls -1 "$BACKUP_DIR"/phantom_reports_*.tar.gz 2> /dev/null | sort -r | tail -n +"$((BACKUP_KEEP + 1))" | while read -r old; do
    log "pruning $old"
    rm -f -- "$old"
  done
}

do_backup() {
  require_number BACKUP_KEEP "$BACKUP_KEEP"
  mkdir -p "$BACKUP_DIR"
  [ -w "$BACKUP_DIR" ] || die "$BACKUP_DIR is not writable by uid $(id -u); chown the host directory to that uid"
  wait_for_db
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  final="$BACKUP_DIR/phantom_soar_$stamp.dump"
  tmp="$final.partial"
  trap 'rm -f -- "$tmp" "$BACKUP_DIR/phantom_reports_$stamp.tar.gz.partial"' EXIT

  log "dumping database '$PGDATABASE' on '${PGHOST:-local socket}'"
  pg_dump --format=custom --compress=6 --no-owner --no-privileges --file="$tmp"
  pg_restore --list "$tmp" > /dev/null || die "the new dump is not readable by pg_restore"
  mv -- "$tmp" "$final"
  (cd "$BACKUP_DIR" && sha256sum "phantom_soar_$stamp.dump" > "phantom_soar_$stamp.dump.sha256")
  log "wrote $final ($(wc -c < "$final") bytes)"

  if [ -d "$BACKUP_REPORTS_DIR" ] && [ -n "$(ls -A "$BACKUP_REPORTS_DIR" 2> /dev/null)" ]; then
    rtmp="$BACKUP_DIR/phantom_reports_$stamp.tar.gz.partial"
    tar -czf "$rtmp" -C "$BACKUP_REPORTS_DIR" .
    mv -- "$rtmp" "$BACKUP_DIR/phantom_reports_$stamp.tar.gz"
    log "wrote $BACKUP_DIR/phantom_reports_$stamp.tar.gz"
  else
    log "no files in $BACKUP_REPORTS_DIR; skipping the reports archive"
  fi
  trap - EXIT
  prune
}

resolve_file() {
  # An explicit argument may be a bare file name inside BACKUP_DIR or a path.
  if [ -n "${1:-}" ]; then
    case "$1" in
      */*) printf '%s\n' "$1" ;;
      *) printf '%s\n' "$BACKUP_DIR/$1" ;;
    esac
  else
    latest_dump
  fi
}

check_file() {
  [ -n "$1" ] && [ -f "$1" ] || die "no dump file found (looked for: ${1:-newest dump in $BACKUP_DIR})"
  if [ -f "$1.sha256" ]; then
    (cd "$(dirname "$1")" && sha256sum -c "$(basename "$1").sha256" > /dev/null) || die "checksum mismatch for $1"
    log "checksum OK for $1"
  else
    log "WARNING: no checksum file next to $1"
  fi
  pg_restore --list "$1" > /dev/null || die "$1 is not a readable pg_dump custom-format archive"
}

do_verify() {
  file="$(resolve_file "${1:-}")"
  check_file "$file"
  wait_for_db
  scratch="${BACKUP_VERIFY_DB:-${PGDATABASE}_restore_check}"
  [ "$scratch" != "$PGDATABASE" ] || die "BACKUP_VERIFY_DB must differ from the live database"
  log "restoring $file into scratch database '$scratch' (the live database is not touched)"
  psql -q -v ON_ERROR_STOP=1 -d postgres -c "DROP DATABASE IF EXISTS \"$scratch\"" -c "CREATE DATABASE \"$scratch\""
  # Always drop the scratch database again.
  trap 'psql -q -d postgres -c "DROP DATABASE IF EXISTS \"$scratch\"" > /dev/null 2>&1 || true' EXIT
  pg_restore --no-owner --no-privileges --exit-on-error -d "$scratch" "$file"
  tables="$(psql -At -d "$scratch" -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")"
  revision="$(psql -At -d "$scratch" -c "SELECT version_num FROM alembic_version" 2> /dev/null || true)"
  users="$(psql -At -d "$scratch" -c "SELECT count(*) FROM users" 2> /dev/null || true)"
  alerts="$(psql -At -d "$scratch" -c "SELECT count(*) FROM alerts" 2> /dev/null || true)"
  [ "${tables:-0}" -gt 0 ] || die "restored database has no tables"
  [ -n "$revision" ] || die "restored database has no alembic_version row (not a Phantom SOAR schema?)"
  log "RESTORE CHECK OK: tables=$tables alembic_revision=$revision users=${users:-?} alerts=${alerts:-?} (file: $file)"
}

do_restore() {
  [ -n "${1:-}" ] || die "usage: backup.sh restore FILE   (FILE is a name inside $BACKUP_DIR or a path)"
  file="$(resolve_file "$1")"
  check_file "$file"
  [ "${BACKUP_CONFIRM_RESTORE:-}" = "$PGDATABASE" ] \
    || die "refusing to overwrite '$PGDATABASE': stop the backend and worker first, then set BACKUP_CONFIRM_RESTORE=$PGDATABASE"
  wait_for_db
  log "restoring $file over '$PGDATABASE' (existing objects are dropped first, in one transaction)"
  pg_restore --clean --if-exists --no-owner --no-privileges --single-transaction --exit-on-error -d "$PGDATABASE" "$file"
  revision="$(psql -At -d "$PGDATABASE" -c "SELECT version_num FROM alembic_version" 2> /dev/null || true)"
  log "RESTORE DONE: alembic_revision=${revision:-unknown}. Start the backend again; it applies any newer migrations."
}

cmd="${1:-loop}"
[ "$#" -eq 0 ] || shift
case "$cmd" in
  loop)
    require_number BACKUP_INTERVAL_SECONDS "$BACKUP_INTERVAL_SECONDS"
    while :; do
      do_backup || log "backup failed; will retry in ${BACKUP_INTERVAL_SECONDS}s"
      sleep "$BACKUP_INTERVAL_SECONDS"
    done
    ;;
  once) do_backup ;;
  list) ls -lh "$BACKUP_DIR" ;;
  verify) do_verify "${1:-}" ;;
  restore) do_restore "${1:-}" ;;
  *) die "unknown command '$cmd' (loop | once | list | verify [FILE] | restore FILE)" ;;
esac
