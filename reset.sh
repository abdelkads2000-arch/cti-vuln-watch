#!/usr/bin/env bash
# DESTRUCTIVE: stop services and delete the database volume.
# .env and ./backups are kept (restore possible from backups).
source "$(dirname "$0")/scripts/_common.sh"
require_docker
echo "ATTENTION : la base de données va être SUPPRIMÉE (volume pgdata)."
echo "Le fichier .env et le dossier ./backups sont conservés."
read -r -p "Taper RESET pour confirmer : " answer
[[ "$answer" == "RESET" ]] || { echo "Annulé."; exit 1; }
docker compose down -v --remove-orphans
echo "Réinitialisé. Relancer avec ./start.sh"
