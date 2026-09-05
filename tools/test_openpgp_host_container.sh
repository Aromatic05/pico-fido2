#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
image="${OPENPGP_TEST_IMAGE:-localhost/pico-fido2-piv-test:jammy}"

fail() {
    echo "openpgp-host: $*" >&2
    exit 1
}

command -v "$runtime" >/dev/null || fail "$runtime not found"
[[ -f pico-openpgp/tests/docker/jammy/Dockerfile ]] || fail 'run from pico-fido2 repository root'

if ! "$runtime" image exists "$image" >/dev/null 2>&1; then
    "$runtime" build -f pico-openpgp/tests/docker/jammy/Dockerfile \
        -t "$image" pico-openpgp
fi

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run /work/pytest-cache
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log

/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1

cd /work/run
rm -f memory.flash emulator.log
/work/build/pico_fido2 >emulator.log 2>&1 &
emu_pid=$!
sleep 1
kill -0 "$emu_pid" 2>/dev/null || { cat emulator.log >&2; exit 1; }

cd /src/pico-openpgp
PYTHONPATH=/src/pico-openpgp/tests \
    pytest -q -o cache_dir=/work/pytest-cache tests -W ignore::DeprecationWarning
INNER
