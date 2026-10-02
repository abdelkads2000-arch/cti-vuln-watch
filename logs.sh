#!/usr/bin/env bash
# Follow logs. Usage: ./logs.sh [service...]   e.g. ./logs.sh db backup
source "$(dirname "$0")/scripts/_common.sh"
require_docker
docker compose logs -f --tail=200 "$@"
