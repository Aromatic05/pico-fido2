#!/usr/bin/env bash
set -euo pipefail

runtime="${CONTAINER_RUNTIME:-podman}"
image="${FIDO_TEST_IMAGE:-localhost/pico-fido2-fido-test:bookworm}"

fail() {
    echo "fido-host: $*" >&2
    exit 1
}

command -v "$runtime" >/dev/null || fail "$runtime not found"
[[ -f pico-fido/tests/docker/bookworm/Dockerfile ]] || fail 'run from pico-fido2 repository root'

if ! "$runtime" image exists "$image" >/dev/null 2>&1; then
    "$runtime" build -f pico-fido/tests/docker/bookworm/Dockerfile \
        -t "$image" pico-fido
fi

"$runtime" run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run /work/pytest-cache
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log

hid_dir=$(python3 - <<'PY'
import pathlib
import fido2.hid
print(pathlib.Path(fido2.hid.__file__).parent)
PY
)
cp /src/pico-fido/tests/docker/fido2/__init__.py "$hid_dir/__init__.py"
cp /src/pico-fido/tests/docker/fido2/emulation.py "$hid_dir/emulation.py"

cd /work/run
rm -f memory.flash emulator.log pcscd.log
/usr/sbin/pcscd --foreground >pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup() {
    [[ -z "$emu_pid" ]] || kill "$emu_pid" 2>/dev/null || true
    [[ -z "$emu_pid" ]] || wait "$emu_pid" 2>/dev/null || true
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1

/work/build/pico_fido2 >emulator.log 2>&1 &
emu_pid=$!
sleep 1
kill -0 "$emu_pid" 2>/dev/null || { cat emulator.log >&2; exit 1; }

cd /src/pico-fido
PYTHONPATH=/src/pico-fido/tests \
    pytest -q -o cache_dir=/work/pytest-cache tests/pico-fido
INNER
