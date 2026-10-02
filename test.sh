#!/usr/bin/env bash
# Run the test suite inside a container (recorded fixtures only, no network calls).
# Usage: ./test.sh [pytest args]   e.g. ./test.sh tests/unit -k scoring
source "$(dirname "$0")/scripts/_common.sh"
require_docker
ensure_env
docker compose up -d --wait db
docker compose --profile tools build test
exec docker compose --profile tools run --rm -T test "${@:-tests}"
