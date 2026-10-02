#!/usr/bin/env bash
# Build and start every service, wait for healthchecks.
source "$(dirname "$0")/scripts/_common.sh"
require_docker
ensure_env
echo "Démarrage des services..."
docker compose up -d --build --wait --wait-timeout 180
docker compose ps
echo "OK. Logs : ./logs.sh   |   Arrêt : ./stop.sh"
