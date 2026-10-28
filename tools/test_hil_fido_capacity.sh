#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
umask 077
export PYTHONPATH="$root/tests${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -u -m hil.fido_capacity "$@"
