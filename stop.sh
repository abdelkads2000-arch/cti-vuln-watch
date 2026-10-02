#!/usr/bin/env bash
# Stop services. Data (database volume, backups) is kept.
source "$(dirname "$0")/scripts/_common.sh"
require_docker
docker compose down
