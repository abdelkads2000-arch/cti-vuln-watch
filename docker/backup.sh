#!/usr/bin/env bash
# Periodic pg_dump with retention. Runs forever inside the "backup" container.
set -uo pipefail

interval_s=$(( ${BACKUP_INTERVAL_HOURS:-24} * 3600 ))
retention=${BACKUP_RETENTION_DAYS:-14}

log() { printf '{"ts":"%s","service":"backup","msg":"%s"}\n' "$(date -Iseconds)" "$1"; }

while true; do
  file="/backups/cti_$(date +%Y%m%d_%H%M%S).dump"
  if pg_dump --format=custom --file="$file.tmp" && mv "$file.tmp" "$file"; then
    touch /tmp/last_backup_ok
    log "backup ok: $(basename "$file") ($(du -h "$file" | cut -f1))"
  else
    rm -f "$file.tmp" /tmp/last_backup_ok
    log "backup FAILED"
  fi
  find /backups -name 'cti_*.dump' -mtime +"$retention" -print -delete \
    | while read -r f; do log "purged $(basename "$f")"; done
  sleep "$interval_s"
done
