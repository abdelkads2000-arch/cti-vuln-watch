#!/usr/bin/env bash
# Shared helpers for start/stop/logs/reset/cti scripts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { echo "ERREUR: $*" >&2; exit 1; }

require_docker() {
  command -v docker >/dev/null 2>&1 \
    || die "Docker introuvable. Installer Docker Desktop, Rancher Desktop (moteur dockerd/moby) ou Docker Engine. Voir README > Dépannage."
  docker info >/dev/null 2>&1 \
    || die "Le démon Docker ne répond pas. Démarrer Docker Desktop / Rancher Desktop puis relancer."
  docker compose version >/dev/null 2>&1 \
    || die "Docker Compose v2 introuvable (commande 'docker compose')."
}

# Random URL-safe secret without depending on openssl being installed.
random_secret() {
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}"
}

# Set KEY=value in .env only if the key is currently empty.
fill_if_empty() {
  local key="$1" value="$2"
  if grep -qE "^${key}=$" .env; then
    sed -i.bak "s|^${key}=$|${key}=${value}|" .env && rm -f .env.bak
    echo "  - ${key} généré automatiquement"
  fi
}

ensure_env() {
  if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "Fichier .env créé à partir de .env.example"
  fi
  fill_if_empty POSTGRES_PASSWORD "$(random_secret 32)"
  fill_if_empty WEB_ADMIN_PASSWORD "$(random_secret 20)"
  chmod 600 .env 2>/dev/null || true
  mkdir -p backups
  # On Linux hosts the backup container (uid 999) must be able to write here.
  [[ "$(uname -s)" == "Linux" ]] && chmod 0777 backups || true
}
