#!/usr/bin/env bash
set -euo pipefail
image="localhost/pico-fido2-ykman-test:5.9.2"
podman image exists "$image"
podman run --rm -i --network none -v "$PWD:/src:ro" "$image" bash -s <<'INNER'
set -euo pipefail
mkdir -p /work/build /work/run
cmake -S /src -B /work/build -DENABLE_EMULATION=1 -DCMAKE_BUILD_TYPE=Release >/work/cmake.log
cmake --build /work/build -j"$(nproc)" >/work/build.log
hid_dir=$(python3 - <<'PY'
from pathlib import Path
import fido2.hid
print(Path(fido2.hid.__file__).parent)
PY
)
cp /src/pico-fido/tests/docker/fido2/__init__.py "$hid_dir/__init__.py"
cp /src/pico-fido/tests/docker/fido2/emulation.py "$hid_dir/emulation.py"
cd /work/run
rm -f memory.flash emulator.log
/usr/sbin/pcscd --foreground >/work/pcscd.log 2>&1 &
pcsc_pid=$!
emu_pid=""
cleanup(){
    if [ -n "$emu_pid" ]; then kill "$emu_pid" 2>/dev/null || true; wait "$emu_pid" 2>/dev/null || true; fi
    kill "$pcsc_pid" 2>/dev/null || true
}
trap cleanup EXIT
sleep 1
for phase in prepare after-enable after-disable; do
    /work/build/pico_fido2 >emulator.log 2>&1 &
    emu_pid=$!
    sleep 1
    kill -0 "$emu_pid"
    echo "EMULATOR_PHASE=$phase"
    timeout 22s python3 -u /src/tests/host_fido_alwaysuv_lifecycle.py "$phase"
    kill "$emu_pid" 2>/dev/null || true
    wait "$emu_pid" 2>/dev/null || true
    emu_pid=""
    sleep 1
done
echo "FIDO_ALWAYSUV_REAL_SOURCE_RESTART_LIFECYCLE: PASS"
echo "No physical USB device was accessed."
INNER
