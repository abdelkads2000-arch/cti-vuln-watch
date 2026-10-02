#!/usr/bin/env bash
# worker : apply migrations then run the scheduler (long-running).
# cti ...: run a CLI command (used by ./cti).
# test   : run the test suite.
set -euo pipefail

case "${1:-worker}" in
  worker)
    cti db upgrade
    exec cti worker
    ;;
  test)
    shift
    exec python -m pytest "$@"
    ;;
  cti)
    shift
    exec cti "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
